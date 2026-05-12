import socket
import threading
import struct
import time
import logging
import select
from collections import deque

# --- КОНФИГУРАЦИЯ ---
REMOTE_RELAY = "64.188.65.59"
REMOTE_PORT = 10398  # ИЗМЕНЕНО: порт должен совпадать с сервером!
SECRET_KEY = "3F4W6f27iIIUaD91u3jGI16uL4sudZ1uykuhzFOmlAc"

# Данные для конечного пользователя
PROXY_USER = "admin"
PROXY_PASS = "3F4W6f27iIIUaD91u3jGI16uL4sudZ1uykuhzFOmlAc"

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Настройки пула туннелей
MIN_TUNNELS = 10
MAX_TUNNELS = 80

class TunnelPool:
    def __init__(self):
        self.tunnels = deque()
        self.lock = threading.Lock()
        self.creating = 0
        
    def add_tunnel(self, conn):
        with self.lock:
            self.tunnels.append(conn)
            self.creating = max(0, self.creating - 1)
            logger.info(f"[POOL] Tunnel added. Active: {len(self.tunnels)}, Creating: {self.creating}")
    
    def get_tunnel(self):
        with self.lock:
            if self.tunnels:
                return self.tunnels.popleft()
            return None
    
    def active_count(self):
        with self.lock:
            return len(self.tunnels)
    
    def creating_count(self):
        with self.lock:
            return self.creating

tunnel_pool = TunnelPool()

def handle_socks5_client(client_conn):
    """Обработка SOCKS5 клиента через туннель"""
    try:
        # 1. Выбор метода аутентификации
        header = client_conn.recv(2)
        if not header or len(header) < 2:
            return
        
        version, nmethods = struct.unpack("!BB", header)
        if version != 5:
            return
            
        methods = client_conn.recv(nmethods)
        
        # Требуем аутентификацию
        client_conn.sendall(struct.pack("!BB", 0x05, 0x02))
        
        # 2. Аутентификация
        auth_header = client_conn.recv(2)
        if not auth_header or len(auth_header) < 2:
            return
            
        auth_version, user_len = struct.unpack("!BB", auth_header)
        username = client_conn.recv(user_len).decode()
        
        pass_len_byte = client_conn.recv(1)
        if not pass_len_byte:
            return
            
        pass_len = pass_len_byte[0]
        password = client_conn.recv(pass_len).decode()
        
        if username == PROXY_USER and password == PROXY_PASS:
            client_conn.sendall(struct.pack("!BB", 0x01, 0x00))
        else:
            logger.warning(f"Invalid credentials: {username}")
            client_conn.sendall(struct.pack("!BB", 0x01, 0x01))
            client_conn.close()
            return
        
        # 3. Получение запроса
        request = client_conn.recv(4)
        if len(request) < 4:
            return
            
        version, cmd, _, atype = struct.unpack("!BBBB", request)
        
        # Разбор адреса
        if atype == 1:  # IPv4
            address = socket.inet_ntoa(client_conn.recv(4))
        elif atype == 3:  # Доменное имя
            domain_len = client_conn.recv(1)[0]
            address = client_conn.recv(domain_len).decode()
        else:
            client_conn.close()
            return
            
        port = struct.unpack("!H", client_conn.recv(2))[0]
        logger.debug(f"Request: {address}:{port}")
        
        # 4. Подключение к цели
        target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target.settimeout(10)
        
        try:
            target.connect((address, port))
            # Отправляем успешный ответ
            bind_addr = target.getsockname()
            reply = struct.pack("!BBBBIH", 
                0x05, 0x00, 0x00, 0x01,
                struct.unpack("!I", socket.inet_aton(bind_addr[0]))[0],
                bind_addr[1]
            )
            client_conn.sendall(reply)
            
        except Exception as e:
            logger.error(f"Connection failed to {address}:{port}: {e}")
            reply = struct.pack("!BBBBIH", 0x05, 0x04, 0x00, 0x01, 0, 0)
            client_conn.sendall(reply)
            client_conn.close()
            target.close()
            return
        
        # 5. Двунаправленная пересылка данных
        transfer_data(client_conn, target)
        
    except Exception as e:
        logger.debug(f"SOCKS5 handling error: {e}")
    finally:
        try: client_conn.close()
        except: pass

def transfer_data(conn1, conn2):
    """Эффективная двунаправленная пересылка данных"""
    sockets = [conn1, conn2]
    
    try:
        while True:
            readable, _, exceptional = select.select(sockets, [], sockets, 1)
            
            if exceptional:
                break
                
            for sock in readable:
                try:
                    data = sock.recv(16384)
                    if not data:
                        return
                    
                    if sock is conn1:
                        conn2.sendall(data)
                    else:
                        conn1.sendall(data)
                        
                except (socket.error, BrokenPipeError, ConnectionResetError):
                    return
                    
    except Exception:
        pass
    finally:
        try: conn1.close()
        except: pass
        try: conn2.close()
        except: pass

def create_single_tunnel():
    """Создание одного туннеля"""
    try:
        logger.info(f"[CONNECT] Creating tunnel to {REMOTE_RELAY}:{REMOTE_PORT}")
        
        tunnel = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tunnel.settimeout(10)
        tunnel.connect((REMOTE_RELAY, REMOTE_PORT))
        
        # Настройка keepalive
        tunnel.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        tunnel.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
        tunnel.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 5)
        tunnel.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
        
        # Отправка ключа авторизации
        logger.info(f"[AUTH] Sending secret key to relay...")
        tunnel.sendall(SECRET_KEY.encode())
        
        # Добавляем в пул
        tunnel_pool.add_tunnel(tunnel)
        logger.info(f"[READY] Tunnel ready. Waiting for client data...")
        
        # Ждем клиента через этот туннель
        handle_socks5_client(tunnel)
        
    except Exception as e:
        logger.error(f"[FAIL] Tunnel creation failed: {e}")
        with tunnel_pool.lock:
            tunnel_pool.creating = max(0, tunnel_pool.creating - 1)

def tunnel_manager():
    """Управление пулом туннелей"""
    logger.info(f"[START] Tunnel manager starting...")
    logger.info(f"[CONFIG] Target: {REMOTE_RELAY}:{REMOTE_PORT}")
    logger.info(f"[CONFIG] Key: {SECRET_KEY[:10]}...")
    
    while True:
        try:
            active = tunnel_pool.active_count()
            creating = tunnel_pool.creating_count()
            
            needed = MIN_TUNNELS - active - creating
            
            if active < MIN_TUNNELS and needed > 0:
                logger.info(f"[POOL] Active: {active}, Creating: {creating}, Need: {needed}")
                
                for _ in range(min(needed, 5)):
                    t = threading.Thread(target=create_single_tunnel, daemon=True)
                    t.start()
                    with tunnel_pool.lock:
                        tunnel_pool.creating += 1
                    time.sleep(0.05)
                    
            elif active >= MAX_TUNNELS:
                time.sleep(1)
                
            # Периодический лог
            if active > 0 and time.time() % 60 < 0.5:
                logger.info(f"[POOL] Status: {active} active, {creating} creating")
                
            time.sleep(0.5)
            
        except Exception as e:
            logger.error(f"[ERROR] Manager: {e}")
            time.sleep(1)

if __name__ == "__main__":
    logger.info("=" * 60)
    logger.info("SOCKS5 NAT Client Starting...")
    logger.info("=" * 60)
    
    try:
        tunnel_manager()
    except KeyboardInterrupt:
        logger.info("[STOP] Stopped by user")
    except Exception as e:
        logger.error(f"[FATAL] {e}")