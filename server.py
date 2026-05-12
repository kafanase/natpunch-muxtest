import socket
import threading
import select
import time
import struct
import logging
from collections import deque

# --- КОНФИГУРАЦИЯ ---
LISTEN_PORT = 10398  # Единственный порт для всего
SECRET_KEY = "3F4W6f27iIIUaD91u3jGI16uL4sudZ1uykuhzFOmlAc"
ROMANIA_IP = "193.233.114.5"  # IP ноды в Румынии

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Пул авторизованных туннелей с улучшенным управлением
class TunnelPool:
    def __init__(self, max_size=100):
        self.pool = deque()
        self.lock = threading.Lock()
        self.max_size = max_size
        self.active_count = 0
        
    def add(self, conn, addr):
        with self.lock:
            if len(self.pool) < self.max_size:
                self.pool.append((conn, addr, time.time()))
                self.active_count += 1
                return True
            return False
    
    def get(self):
        with self.lock:
            # Очистка мертвых соединений
            while self.pool:
                conn, addr, _ = self.pool[0]
                if self._is_alive(conn):
                    self.pool.popleft()
                    self.active_count -= 1
                    return conn, addr
                else:
                    self.pool.popleft()
                    self.active_count -= 1
            return None, None
    
    def _is_alive(self, conn):
        try:
            # Проверка на живость через select с нулевым таймаутом
            ready = select.select([conn], [], [], 0)
            if ready[0]:
                # Сокет доступен для чтения - это может означать закрытие
                data = conn.recv(1, socket.MSG_PEEK)
                if not data:
                    return False
            return True
        except:
            return False
    
    def size(self):
        with self.lock:
            return self.active_count

tunnel_pool = TunnelPool(max_size=100)

# Мультиплексор для эффективной обработки соединений
class ConnectionMultiplexer:
    def __init__(self):
        self.connections = {}
        self.lock = threading.Lock()
        self.buffer_size = 32768  # 32KB буфер
        
    def add_pair(self, client_conn, target_conn, addr):
        pair_id = id(client_conn)
        with self.lock:
            self.connections[pair_id] = {
                'client': client_conn,
                'target': target_conn,
                'addr': addr,
                'created': time.time(),
                'bytes_sent': 0,
                'bytes_received': 0
            }
        return pair_id
    
    def remove_pair(self, pair_id):
        with self.lock:
            if pair_id in self.connections:
                pair = self.connections[pair_id]
                try: pair['client'].close()
                except: pass
                try: pair['target'].close()
                except: pass
                del self.connections[pair_id]
    
    def get_stats(self):
        with self.lock:
            active = len(self.connections)
            total_bytes = sum(p['bytes_sent'] + p['bytes_received'] for p in self.connections.values())
            return active, total_bytes

multiplexer = ConnectionMultiplexer()

def handle_data_transfer(client_conn, tunnel_conn, pair_id):
    """Эффективная пересылка данных с мультиплексированием"""
    sockets = [client_conn, tunnel_conn]
    timeout = 300  # 5 минут таймаут
    
    try:
        while True:
            readable, _, exceptional = select.select(sockets, [], sockets, timeout)
            
            if exceptional:
                break
                
            if not readable:
                # Таймаут - проверяем, живы ли еще соединения
                if not all(multiplexer._is_alive(s) for s in sockets):
                    break
                continue
            
            for sock in readable:
                try:
                    data = sock.recv(multiplexer.buffer_size)
                    if not data:
                        return  # Соединение закрыто
                    
                    # Определяем, кому отправлять
                    if sock is client_conn:
                        tunnel_conn.sendall(data)
                        with multiplexer.lock:
                            if pair_id in multiplexer.connections:
                                multiplexer.connections[pair_id]['bytes_sent'] += len(data)
                    else:
                        client_conn.sendall(data)
                        with multiplexer.lock:
                            if pair_id in multiplexer.connections:
                                multiplexer.connections[pair_id]['bytes_received'] += len(data)
                                
                except (socket.error, BrokenPipeError, ConnectionResetError):
                    return
                    
    except Exception as e:
        logger.debug(f"Transfer error: {e}")
    finally:
        multiplexer.remove_pair(pair_id)

def handle_tunnel_connection(tunnel_conn, addr):
    """Обработка входящего туннельного соединения"""
    try:
        # Установка keepalive
        tunnel_conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        tunnel_conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
        tunnel_conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
        tunnel_conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)
        
        # Авторизация с таймаутом
        tunnel_conn.settimeout(5.0)
        auth_data = tunnel_conn.recv(1024).decode().strip()
        
        if auth_data == SECRET_KEY:
            tunnel_conn.settimeout(None)
            if tunnel_pool.add(tunnel_conn, addr):
                logger.info(f"Tunnel authorized from {addr[0]}:{addr[1]} (pool: {tunnel_pool.size()})")
                return True
            else:
                logger.warning(f"Tunnel pool full, rejecting {addr}")
        else:
            logger.warning(f"Invalid auth from {addr}")
            
        tunnel_conn.close()
        return False
        
    except Exception as e:
        logger.error(f"Tunnel auth error: {e}")
        try: tunnel_conn.close()
        except: pass
        return False

def handle_client_connection(client_conn, addr):
    """Обработка клиентского SOCKS5 соединения"""
    tunnel_conn, tunnel_addr = tunnel_pool.get()
    
    if not tunnel_conn:
        logger.warning(f"No available tunnels for client {addr}")
        try:
            # Отправляем SOCKS5 ошибку
            client_conn.sendall(struct.pack("!BB", 0x05, 0x01))  # General failure
        except:
            pass
        finally:
            try: client_conn.close()
            except: pass
        return
    
    try:
        # Создаем пару для мультиплексирования
        pair_id = multiplexer.add_pair(client_conn, tunnel_conn, addr)
        
        # Запускаем transfer в отдельном потоке
        thread = threading.Thread(
            target=handle_data_transfer,
            args=(client_conn, tunnel_conn, pair_id),
            daemon=True
        )
        thread.start()
        
        logger.debug(f"Connection pair created: {addr} -> tunnel {tunnel_addr}")
        
    except Exception as e:
        logger.error(f"Error setting up transfer: {e}")
        try: client_conn.close()
        except: pass
        try: tunnel_conn.close()
        except: pass

def start_server():
    """Запуск единого сервера на одном порту"""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    
    try:
        server_sock.bind(('0.0.0.0', LISTEN_PORT))
        server_sock.listen(256)
        logger.info(f"Server started on port {LISTEN_PORT}")
        logger.info(f"Expected tunnel from Romania: {ROMANIA_IP}")
        
    except Exception as e:
        logger.error(f"Failed to bind port {LISTEN_PORT}: {e}")
        return
    
    # Запуск мониторинга
    threading.Thread(target=monitor_connections, daemon=True).start()
    
    while True:
        try:
            conn, addr = server_sock.accept()
            
            # Фильтрация по IP
            if addr[0] == ROMANIA_IP:
                # Это туннельное соединение из Румынии
                threading.Thread(
                    target=handle_tunnel_connection,
                    args=(conn, addr),
                    daemon=True
                ).start()
            else:
                # Это клиентское SOCKS5 соединение
                threading.Thread(
                    target=handle_client_connection,
                    args=(conn, addr),
                    daemon=True
                ).start()
                
        except Exception as e:
            logger.error(f"Accept error: {e}")
            time.sleep(0.1)

def monitor_connections():
    """Мониторинг состояния сервера"""
    last_stats_time = time.time()
    
    while True:
        try:
            current_time = time.time()
            if current_time - last_stats_time >= 30:  # Каждые 30 секунд
                active_pairs, total_bytes = multiplexer.get_stats()
                logger.info(f"Stats: {tunnel_pool.size()} tunnels, {active_pairs} active connections, "
                           f"{total_bytes/1024/1024:.2f} MB transferred")
                last_stats_time = current_time
                
            time.sleep(5)
            
        except Exception as e:
            logger.error(f"Monitor error: {e}")
            time.sleep(10)

if __name__ == "__main__":
    try:
        start_server()
    except KeyboardInterrupt:
        logger.info("Server stopped")
    except Exception as e:
        logger.error(f"Fatal error: {e}")