# START OF FILE: network_utils.py

import json
import socket
import logging # Для логирования сетевых операций

# Настройка базового логирования
# В реальном приложении конфигурация логирования может быть сложнее
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

DEFAULT_BUFFER_SIZE = 8192
HEADER_LENGTH = 10  # Длина заголовка, указывающего размер сообщения

class NetworkError(Exception):
    """Базовый класс для сетевых ошибок в этом модуле."""
    pass

class ConnectionClosedError(NetworkError):
    """Ошибка, возникающая при неожиданном закрытии соединения."""
    pass

class MessageFormatError(NetworkError):
    """Ошибка, связанная с неправильным форматом сообщения."""
    pass


def send_json_message(sock: socket.socket, data_dict: dict):
    """
    Сериализует словарь в JSON, кодирует в UTF-8 и отправляет через сокет.
    Сначала отправляется заголовок с длиной сообщения.

    Args:
        sock: Активный сокет для отправки.
        data_dict: Словарь с данными для отправки.

    Raises:
        socket.error: Если произошла ошибка сокета при отправке.
        TypeError: Если data_dict не является словарем.
    """
    if not isinstance(data_dict, dict):
        raise TypeError("Данные для отправки должны быть словарем.")
    try:
        json_data = json.dumps(data_dict, ensure_ascii=False)
        encoded_data = json_data.encode('utf-8')
        # Формируем заголовок: длина сообщения, дополненная пробелами до HEADER_LENGTH
        header = f"{len(encoded_data):<{HEADER_LENGTH}}".encode('utf-8')
        
        sock.sendall(header + encoded_data)
        logging.debug(f"Sent to {sock.getpeername()}: Header='{header.decode()}', Data='{json_data[:100]}...' (len={len(encoded_data)})")
    except socket.error as e:
        logging.error(f"Socket error during send to {sock.getpeername() if sock else 'N/A'}: {e}")
        raise
    except Exception as e: # Другие возможные ошибки, например, при сериализации JSON
        logging.error(f"Error during JSON message preparation or send: {e}")
        raise NetworkError(f"Failed to send JSON message: {e}")


def receive_json_message(sock: socket.socket, timeout: float = None) -> dict | None:
    """
    Получает JSON-сообщение из сокета.
    Сначала читает заголовок, чтобы определить длину сообщения, затем читает само сообщение.

    Args:
        sock: Активный сокет для получения данных.
        timeout: Опциональный таймаут для операции получения. Если None, используется таймаут сокета.

    Returns:
        Словарь с полученными данными или None, если соединение закрыто или произошла ошибка.

    Raises:
        ConnectionClosedError: Если соединение было закрыто удаленной стороной во время чтения.
        MessageFormatError: Если формат заголовка или JSON некорректен.
        socket.timeout: Если истек таймаут ожидания данных.
        socket.error: Если произошла другая ошибка сокета.
    """
    original_timeout = sock.gettimeout()
    if timeout is not None:
        sock.settimeout(timeout)
    
    try:
        # 1. Получаем заголовок (длина сообщения)
        header_data = b""
        while len(header_data) < HEADER_LENGTH:
            chunk = sock.recv(HEADER_LENGTH - len(header_data))
            if not chunk:
                logging.warning(f"Connection closed by {sock.getpeername()} while receiving header.")
                raise ConnectionClosedError("Connection closed while receiving header.")
            header_data += chunk
        
        try:
            msg_len_str = header_data.decode('utf-8').strip()
            if not msg_len_str: # Пустой заголовок после strip
                 logging.error(f"Received empty message length header from {sock.getpeername()}.")
                 raise MessageFormatError("Received empty message length header.")
            msg_len = int(msg_len_str)
        except (ValueError, UnicodeDecodeError) as e:
            logging.error(f"Invalid message length header from {sock.getpeername()}: '{header_data.decode(errors='replace')}'. Error: {e}")
            raise MessageFormatError(f"Invalid message length header: {e}")

        if msg_len == 0: # Получено сообщение нулевой длины (например, keep-alive или ack без данных)
            logging.debug(f"Received zero-length message indication from {sock.getpeername()}.")
            return {} # Возвращаем пустой словарь для консистентности

        # 2. Получаем тело сообщения
        data = b""
        while len(data) < msg_len:
            chunk = sock.recv(min(msg_len - len(data), DEFAULT_BUFFER_SIZE))
            if not chunk:
                logging.warning(f"Connection closed by {sock.getpeername()} while receiving message body (expected {msg_len}, got {len(data)}).")
                raise ConnectionClosedError("Connection closed while receiving message body.")
            data += chunk
        
        try:
            decoded_json = data.decode('utf-8')
            message_dict = json.loads(decoded_json)
            logging.debug(f"Received from {sock.getpeername()}: '{decoded_json[:100]}...' (len={msg_len})")
            return message_dict
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            logging.error(f"Invalid JSON or encoding in message body from {sock.getpeername()}. Error: {e}. Data (first 100 bytes): '{data[:100].decode(errors='replace')}'")
            raise MessageFormatError(f"Invalid JSON or encoding in message body: {e}")

    except socket.timeout:
        logging.warning(f"Socket timeout while receiving from {sock.getpeername() if sock else 'N/A'}.")
        raise # Передаем исключение socket.timeout дальше
    except ConnectionClosedError: # Уже залогировано
        raise
    except MessageFormatError: # Уже залогировано
        raise
    except socket.error as e:
        logging.error(f"Socket error during receive from {sock.getpeername() if sock else 'N/A'}: {e}")
        raise
    except Exception as e:
        logging.error(f"Unexpected error during receive from {sock.getpeername() if sock else 'N/A'}: {e}")
        raise NetworkError(f"Unexpected error during receive: {e}")
    finally:
        if timeout is not None: # Восстанавливаем исходный таймаут сокета
            sock.settimeout(original_timeout)


def create_server_socket(host: str, port: int, listen_backlog: int = 5) -> socket.socket:
    """
    Создает, биндит и начинает слушать серверный сокет.

    Args:
        host: Хост для биндинга (например, '0.0.0.0' или 'localhost').
        port: Порт для биндинга.
        listen_backlog: Максимальное количество ожидающих соединений.

    Returns:
        Серверный сокет, готовый к принятию соединений.

    Raises:
        socket.error: Если не удалось создать или настроить сокет.
    """
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Разрешает повторное использование адреса
        server_sock.bind((host, port))
        server_sock.listen(listen_backlog)
        logging.info(f"Server socket created and listening on {host}:{port}")
        return server_sock
    except socket.error as e:
        logging.error(f"Failed to create or bind server socket on {host}:{port}: {e}")
        server_sock.close() # Закрываем сокет, если произошла ошибка
        raise


def connect_to_server(host: str, port: int, timeout: float = 5.0) -> socket.socket | None:
    """
    Устанавливает соединение с сервером.

    Args:
        host: Хост сервера.
        port: Порт сервера.
        timeout: Таймаут для попытки соединения.

    Returns:
        Клиентский сокет, подключенный к серверу, или None в случае неудачи.
    """
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.settimeout(timeout) # Устанавливаем таймаут на операцию connect
    try:
        client_sock.connect((host, port))
        logging.info(f"Successfully connected to server {host}:{port}")
        client_sock.settimeout(None) # Сбрасываем таймаут после успешного соединения (для блокирующих операций)
        return client_sock
    except socket.timeout:
        logging.warning(f"Connection to {host}:{port} timed out after {timeout}s.")
        client_sock.close()
        return None
    except socket.error as e:
        logging.error(f"Failed to connect to server {host}:{port}: {e}")
        client_sock.close()
        return None
    except Exception as e: # Другие возможные ошибки
        logging.error(f"Unexpected error connecting to server {host}:{port}: {e}")
        client_sock.close()
        return None

# --- Тестовый блок ---
if __name__ == "__main__":
    import threading
    import time

    TEST_HOST = "127.0.0.1"
    TEST_PORT = 12399 # Используем другой порт для теста, чтобы не конфликтовать с основным приложением

    # --- Тестовый сервер ---
    def simple_server():
        logging.info("Test server starting...")
        try:
            server_sock = create_server_socket(TEST_HOST, TEST_PORT)
        except socket.error:
            logging.error("Test server could not start. Exiting thread.")
            return

        try:
            logging.info(f"Test server listening on {TEST_HOST}:{TEST_PORT}. Waiting for connection...")
            conn, addr = server_sock.accept()
            logging.info(f"Test server accepted connection from {addr}")
            with conn:
                # 1. Получить сообщение от клиента
                received_data = receive_json_message(conn)
                if received_data:
                    logging.info(f"Test server received: {received_data}")
                    # 2. Отправить ответ клиенту
                    response = {"status": "ok", "message": "Data received by test server", "echo": received_data}
                    send_json_message(conn, response)
                    logging.info("Test server sent response.")
                else:
                    logging.warning("Test server received no data or error.")
        except NetworkError as e:
            logging.error(f"Test server network error: {e}")
        except socket.error as e:
            logging.error(f"Test server socket error: {e}")
        except Exception as e:
            logging.error(f"Test server unexpected error: {e}")
        finally:
            logging.info("Test server shutting down socket.")
            server_sock.close()
            logging.info("Test server thread finished.")

    # --- Тестовый клиент ---
    def simple_client():
        logging.info("Test client starting...")
        time.sleep(0.5) # Даем серверу немного времени на запуск

        client_sock = connect_to_server(TEST_HOST, TEST_PORT)
        if client_sock:
            with client_sock:
                try:
                    # 1. Отправить сообщение серверу
                    message_to_send = {"action": "test", "payload": {"value": 123, "name": "Тест"}}
                    send_json_message(client_sock, message_to_send)
                    logging.info(f"Test client sent: {message_to_send}")

                    # 2. Получить ответ от сервера
                    response_data = receive_json_message(client_sock)
                    if response_data:
                        logging.info(f"Test client received: {response_data}")
                        if response_data.get("status") == "ok" and response_data.get("echo") == message_to_send:
                            logging.info("Test client: Send/Receive cycle SUCCESSFUL!")
                        else:
                            logging.error("Test client: Send/Receive cycle FAILED - response mismatch.")
                    else:
                        logging.error("Test client: No response received or error.")
                except NetworkError as e:
                    logging.error(f"Test client network error: {e}")
                except socket.error as e:
                    logging.error(f"Test client socket error: {e}")
                except Exception as e:
                    logging.error(f"Test client unexpected error: {e}")
            logging.info("Test client finished.")
        else:
            logging.error("Test client could not connect to server.")

    print("--- Testing Network Utils ---")
    # Запускаем сервер в отдельном потоке
    server_thread = threading.Thread(target=simple_server, daemon=True)
    server_thread.start()

    # Запускаем клиент
    simple_client()

    # Ждем завершения серверного потока (не обязательно, т.к. он daemon)
    server_thread.join(timeout=2) # Даем серверу время завершиться, если он еще работает
    print("--- Network Utils Test Finished ---")

# END OF FILE: network_utils.py