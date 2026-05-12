import socket
import threading
import struct
import time

# --- КОНФИГУРАЦИЯ ---
REMOTE_RELAY = "89.144.32.194"
REMOTE_PORT = 10398
SECRET_KEY = "3F4W6f27iIIUaD91u3jGI16uL4sudZ1uykuhzFOmlAc"  # Ключ для авторизации туннеля (между нодой и реле)

# Данные для конечного пользователя (логин/пароль для вашего браузера или бота)
PROXY_USER = "admin"
PROXY_PASS = "3F4W6f27iIIUaD91u3jGI16uL4sudZ1uykuhzFOmlAc"

def handle_socks5_logic(client_conn):
    """Реализация SOCKS5 (RFC 1928) с авторизацией (RFC 1929)"""
    try:
        # 1. Выбор метода аутентификации
        header = client_conn.recv(2)
        if not header or len(header) < 2: return
        version, nmethods = struct.unpack("!BB", header)
        methods = client_conn.recv(nmethods)
        
        # Сообщаем клиенту, что требуем Username/Password (метод 0x02)
        client_conn.sendall(struct.pack("!BB", 0x05, 0x02))

        # 2. Процесс авторизации (Sub-negotiation)
        auth_header = client_conn.recv(2)
        if not auth_header or len(auth_header) < 2: return
        auth_version, user_len = struct.unpack("!BB", auth_header)
        username = client_conn.recv(user_len).decode()
        
        pass_len_data = client_conn.recv(1)
        if not pass_len_data: return
        pass_len = ord(pass_len_data)
        password = client_conn.recv(pass_len).decode()

        if username == PROXY_USER and password == PROXY_PASS:
            # Успех (0x01, 0x00)
            client_conn.sendall(struct.pack("!BB", 0x01, 0x00))
        else:
            # Отказ (0x01, 0x01)
            print(f"[-] Неверный логин/пароль от пользователя: {username}")
            client_conn.sendall(struct.pack("!BB", 0x01, 0x01))
            client_conn.close()
            return

        # 3. Получение запроса на соединение (Request)
        request = client_conn.recv(4)
        if not request or len(request) < 4: return
        version, cmd, _, atype = struct.unpack("!BBBB", request)
        
        if atype == 1: # IPv4
            address = socket.inet_ntoa(client_conn.recv(4))
        elif atype == 3: # Domain name
            domain_len_data = client_conn.recv(1)
            if not domain_len_data: return
            domain_len = ord(domain_len_data)
            address = client_conn.recv(domain_len).decode()
        else:
            client_conn.close()
            return

        port = struct.unpack("!H", client_conn.recv(2))[0]
        print(f"[>] Запрос на соединение с {address}:{port}")

        # 4. Соединение с целевым ресурсом
        target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target.settimeout(10)
        try:
            target.connect((address, port))
            bind_info = target.getsockname()
            res_addr = socket.inet_aton(bind_info[0])
            reply = struct.pack("!BBBBIH", 0x05, 0x00, 0x00, 0x01, 
                                struct.unpack("!I", res_addr)[0], bind_info[1])
            client_conn.sendall(reply)
        except Exception as e:
            print(f"[!] Не удалось соединиться с целью {address}: {e}")
            reply = struct.pack("!BBBBIH", 0x05, 0x04, 0x00, 0x01, 0, 0)
            client_conn.sendall(reply)
            client_conn.close()
            return

        # 5. Пересылка данных (Relay)
        def forward(src, dst):
            try:
                while True:
                    data = src.recv(16384)
                    if not data: break
                    dst.sendall(data)
            except: pass
            finally:
                try: src.close()
                except: pass
                try: dst.close()
                except: pass

        threading.Thread(target=forward, args=(client_conn, target), daemon=True).start()
        forward(target, client_conn)

    except Exception as e:
        print(f"[-] Ошибка в логике SOCKS5: {e}")
        client_conn.close()

def create_tunnel():
    """Создает одно туннельное соединение и авторизует его на реле"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(20)
        s.connect((REMOTE_RELAY, REMOTE_PORT))
        # Важно: отправляем ключ и убеждаемся, что он ушел
        s.sendall(f"{SECRET_KEY}\n".encode())
        
        # Переходим к ожиданию клиента от Relay-сервера
        handle_socks5_logic(s)
    except Exception as e:
        # Если не удалось подключиться к Relay, просто тихо ждем
        pass

def tunnel_manager():
    """Постоянно поддерживает пул соединений"""
    print(f"[*] Попытка установить туннели к {REMOTE_RELAY}:{REMOTE_PORT}...")
    while True:
        # Ограничиваем количество одновременных попыток создания туннеля,
        # чтобы не забить лимиты ОС, но при этом быстро восполнять пул.
        if threading.active_count() < 50:
            t = threading.Thread(target=create_tunnel, daemon=True)
            t.start()
        time.sleep(0.1)

if __name__ == "__main__":
    print(f"[*] SOCKS5 Нода в Румынии запущена.")
    print(f"[*] Ожидание пользователей с логином: {PROXY_USER}")
    try:
        tunnel_manager()
    except KeyboardInterrupt:
        print("\n[*] Остановка...")
