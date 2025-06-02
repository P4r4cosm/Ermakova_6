# START OF FILE: base_node_app.py
import socket
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk, simpledialog
import threading
import logging
import os # Для работы с путями к файлам конфигурации
import json # Добавлен импорт json, он используется в save/load_configuration
import datetime # Добавлен импорт datetime, он используется для lcg_seed_counter
from elgamal_utils import LCG, PrimeManager, ElGamalCrypto
from certificate_manager import Certificate, CertificateStore
from network_utils import send_json_message, receive_json_message, create_server_socket, \
                          ConnectionClosedError, MessageFormatError

# Настройка логирования (можно вынести в отдельный logging_config.py)
# Здесь просто для примера, чтобы логи шли и в консоль, и в GUI
logger = logging.getLogger(__name__) # Получаем логгер для этого модуля
if not logger.hasHandlers(): # Предотвращаем дублирование хендлеров при многократном запуске/импорте
    logger.setLevel(logging.DEBUG) # Устанавливаем уровень логирования
    # Консольный хендлер
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO) # Уровень для консоли
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    # (GUI хендлер будет добавлен в классе приложения)


class GuiHandler(logging.Handler):
    """ Пользовательский обработчик логирования для вывода сообщений в Tkinter Text widget. """
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget
        self.text_widget.config(state=tk.DISABLED) # Изначально только для чтения

    def emit(self, record):
        msg = self.format(record)
        self.text_widget.config(state=tk.NORMAL)
        self.text_widget.insert(tk.END, msg + "\n")
        self.text_widget.see(tk.END) # Автопрокрутка
        self.text_widget.config(state=tk.DISABLED)


class BaseNodeApp:
    def __init__(self, root, node_id, default_port, config_file_name="node_config.json"):
        self.root = root
        self.node_id = node_id
        self.default_port = default_port
        self.port = default_port # Может быть изменено из конфигурации или GUI
        
        self.config_file_path = os.path.join(os.path.dirname(__file__) or ".", "configs", f"{self.node_id.replace('@','_at_')}_{config_file_name}")
        os.makedirs(os.path.dirname(self.config_file_path), exist_ok=True)


        # Криптографические параметры и ключи
        self.p = None
        self.g = None
        self.lcg_seed_counter = int(datetime.datetime.now().timestamp() * 1000) # Базовый сид
        self.lcg = LCG(self.lcg_seed_counter) # Основной LCG для узла

        self.key_pair_encryption = {"private_xe": None, "public_ye": None}
        self.key_pair_signature = {"private_xs": None, "public_ys": None}

        # Сертификаты
        self.own_certificate = None # Собственный сертификат узла
        # Хранилище для сертификатов других узлов (RCA, LCA, другие клиенты)
        # Директория для хранения будет специфична для каждого узла
        cert_store_dir = os.path.join(os.path.dirname(__file__) or ".", "node_data", self.node_id.replace('@','_at_'), "certs")
        self.certificate_store = CertificateStore(storage_dir=cert_store_dir)

        self.server_socket = None
        self.server_thread = None
        self.is_server_running = False

        self.setup_gui()
        self.load_configuration() # Загрузка p, g, ключей, порта и т.д.

        # Добавляем GUI-обработчик в логгер всего модуля
        # Это позволит всем логам из elgamal_utils, certificate_manager и т.д. (если они используют logger = logging.getLogger(__name__))
        # также попадать в GUI, если их уровень DEBUG или выше.
        # Однако, лучше настроить это более гранулярно. Пока для простоты так.
        gui_log_handler = GuiHandler(self.log_text)
        gui_log_handler.setLevel(logging.DEBUG) # Уровень для GUI
        gui_log_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logging.getLogger().addHandler(gui_log_handler) # Добавляем к корневому логгеру
        
        logger.info(f"Приложение '{self.node_id}' инициализировано.")
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)


    def get_next_lcg_seed(self):
        """ Возвращает новый сид и инкрементирует счетчик. """
        self.lcg_seed_counter += 1
        return self.lcg_seed_counter

    def setup_gui(self):
        self.root.title(f"Узел PKI: {self.node_id}")
        self.root.geometry("800x600")

        # --- Основной контейнер ---
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # --- Панель управления (будет заполнена в дочерних классах) ---
        self.control_panel = ttk.Labelframe(main_frame, text="Управление узлом")
        self.control_panel.pack(fill=tk.X, pady=5)
        # Пример кнопки, которая может быть общей
        ttk.Button(self.control_panel, text="Сохранить конфигурацию", command=self.save_configuration).pack(side=tk.LEFT, padx=5)
        ttk.Button(self.control_panel, text="Запустить сервер", command=self.start_server_action).pack(side=tk.LEFT, padx=5)
        ttk.Button(self.control_panel, text="Остановить сервер", command=self.stop_server_action).pack(side=tk.LEFT, padx=5)


        # --- Вкладки для разной информации ---
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=5)

        # Вкладка "Ключи и Сертификат"
        self.keys_certs_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.keys_certs_tab, text="Ключи и Сертификат")
        self.create_keys_certs_tab_widgets(self.keys_certs_tab)
        
        # Вкладка "Логи"
        log_frame = ttk.Frame(self.notebook)
        self.notebook.add(log_frame, text="Логи операций")
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=10, state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # --- Строка состояния ---
        self.status_bar = ttk.Label(main_frame, text=f"Готов. Порт: {self.port}", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM, ipady=2)

    def create_keys_certs_tab_widgets(self, parent_tab):
        """ Создает виджеты для вкладки 'Ключи и Сертификат'. Может быть переопределено. """
        frame = ttk.Frame(parent_tab, padding="5")
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Параметр p:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.p_display = ttk.Label(frame, text="N/A")
        self.p_display.grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)

        ttk.Label(frame, text="Параметр g:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        self.g_display = ttk.Label(frame, text="N/A")
        self.g_display.grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)

        ttk.Label(frame, text="Публ. ключ (шифр.) YE:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
        self.ye_display = ttk.Label(frame, text="N/A")
        self.ye_display.grid(row=2, column=1, sticky=tk.W, padx=5, pady=2)
        
        ttk.Label(frame, text="Публ. ключ (подпись) YS:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=2)
        self.ys_display = ttk.Label(frame, text="N/A")
        self.ys_display.grid(row=3, column=1, sticky=tk.W, padx=5, pady=2)

        ttk.Label(frame, text="Собственный сертификат:").grid(row=4, column=0, sticky=tk.NW, padx=5, pady=2)
        self.own_cert_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, height=8, width=60, state=tk.DISABLED)
        self.own_cert_text.grid(row=4, column=1, sticky=tk.NSEW, padx=5, pady=2)
        frame.columnconfigure(1, weight=1) # Позволяет текстовому полю растягиваться
        frame.rowconfigure(4, weight=1)

    def update_key_displays(self):
        """ Обновляет отображение p, g и публичных ключей в GUI. """
        self.p_display.config(text=str(self.p) if self.p else "N/A")
        self.g_display.config(text=str(self.g) if self.g else "N/A")
        self.ye_display.config(text=str(self.key_pair_encryption["public_ye"]) if self.key_pair_encryption["public_ye"] else "N/A")
        self.ys_display.config(text=str(self.key_pair_signature["public_ys"]) if self.key_pair_signature["public_ys"] else "N/A")

        self.own_cert_text.config(state=tk.NORMAL)
        self.own_cert_text.delete(1.0, tk.END)
        if self.own_certificate:
            self.own_cert_text.insert(tk.END, str(self.own_certificate.to_dict())) # Или str(self.own_certificate)
        else:
            self.own_cert_text.insert(tk.END, "Сертификат отсутствует.")
        self.own_cert_text.config(state=tk.DISABLED)


    def save_configuration(self):
        """ Сохраняет текущую конфигурацию узла (p, g, ключи, порт) в файл. """
        config_data = {
            "node_id": self.node_id,
            "port": self.port,
            "p": self.p,
            "g": self.g,
            "lcg_seed_counter": self.lcg_seed_counter,
            "key_pair_encryption": self.key_pair_encryption,
            "key_pair_signature": self.key_pair_signature,
            # Собственный сертификат сохраняется через CertificateStore, если нужно
            # Здесь можно сохранить путь или сам сертификат в виде dict
            "own_certificate": self.own_certificate.to_dict() if self.own_certificate else None
        }
        try:
            with open(self.config_file_path, 'w', encoding='utf-8') as f:
                json.dump(config_data, f, indent=4, ensure_ascii=False)
            logger.info(f"Конфигурация сохранена в {self.config_file_path}")
            messagebox.showinfo("Сохранение", "Конфигурация успешно сохранена.", parent=self.root)
        except Exception as e:
            logger.error(f"Ошибка сохранения конфигурации: {e}")
            messagebox.showerror("Ошибка", f"Не удалось сохранить конфигурацию: {e}", parent=self.root)

    def load_configuration(self):
        """ Загружает конфигурацию узла из файла. """
        try:
            if os.path.exists(self.config_file_path):
                with open(self.config_file_path, 'r', encoding='utf-8') as f:
                    config_data = json.load(f)
                
                self.port = config_data.get("port", self.default_port)
                self.p = config_data.get("p")
                self.g = config_data.get("g")
                self.lcg_seed_counter = config_data.get("lcg_seed_counter", int(datetime.datetime.now().timestamp() * 1000))
                self.lcg = LCG(self.lcg_seed_counter) # Переинициализируем LCG с загруженным сидом

                self.key_pair_encryption = config_data.get("key_pair_encryption", {"private_xe": None, "public_ye": None})
                self.key_pair_signature = config_data.get("key_pair_signature", {"private_xs": None, "public_ys": None})
                
                own_cert_data = config_data.get("own_certificate")
                if own_cert_data:
                    self.own_certificate = Certificate.from_dict(own_cert_data)
                    # Добавляем/обновляем его в локальном хранилище
                    self.certificate_store.add_certificate(self.own_certificate, save_to_file=True)


                logger.info(f"Конфигурация загружена из {self.config_file_path}")
                self.status_bar.config(text=f"Конфигурация загружена. Порт: {self.port}")
            else:
                logger.warning(f"Файл конфигурации {self.config_file_path} не найден. Используются значения по умолчанию.")
                self.status_bar.config(text=f"Файл конфигурации не найден. Порт: {self.port}")
        except Exception as e:
            logger.error(f"Ошибка загрузки конфигурации: {e}")
            messagebox.showerror("Ошибка загрузки", f"Не удалось загрузить конфигурацию: {e}", parent=self.root)
        finally:
            self.update_key_displays() # Обновляем GUI в любом случае


    def start_server_action(self):
        if self.is_server_running:
            logger.warning("Сервер уже запущен.")
            messagebox.showwarning("Сервер", "Сервер уже запущен.", parent=self.root)
            return

        new_port_str = simpledialog.askstring("Порт сервера", 
                                              f"Введите порт для сервера (текущий: {self.port}):",
                                              initialvalue=str(self.port), parent=self.root)
        if new_port_str:
            try:
                new_port = int(new_port_str)
                if not (1024 <= new_port <= 65535):
                    raise ValueError("Порт должен быть в диапазоне 1024-65535")
                self.port = new_port
            except ValueError as e:
                messagebox.showerror("Ошибка порта", str(e), parent=self.root)
                return
        else: # Пользователь нажал "Отмена"
            return


        try:
            self.server_socket = create_server_socket('0.0.0.0', self.port)
            self.is_server_running = True
            self.server_thread = threading.Thread(target=self.server_listen_loop, daemon=True)
            self.server_thread.start()
            logger.info(f"Сервер запущен на порту {self.port}.")
            self.status_bar.config(text=f"Сервер работает на порту {self.port}.")
            messagebox.showinfo("Сервер", f"Сервер успешно запущен на порту {self.port}.", parent=self.root)
        except Exception as e:
            logger.error(f"Ошибка запуска сервера: {e}")
            messagebox.showerror("Ошибка сервера", f"Не удалось запустить сервер: {e}", parent=self.root)
            self.is_server_running = False
            if self.server_socket:
                self.server_socket.close()

    def server_listen_loop(self):
        """ Основной цикл прослушивания сервера. """
        if not self.server_socket:
            logger.error("server_listen_loop вызван без активного серверного сокета.")
            self.is_server_running = False
            return

        while self.is_server_running:
            try:
                conn, addr = self.server_socket.accept()
                logger.info(f"Получено соединение от {addr}")
                # Для каждого клиента создаем новый поток для обработки
                client_handler_thread = threading.Thread(
                    target=self.handle_client_connection, args=(conn, addr), daemon=True
                )
                client_handler_thread.start()
            except socket.timeout: # Если у сокета установлен таймаут (здесь нет, но на всякий случай)
                continue 
            except OSError as e: # Например, если сокет был закрыт
                if self.is_server_running: # Если сервер должен работать, но произошла ошибка
                    logger.error(f"Ошибка сокета в цикле прослушивания: {e}")
                break # Выход из цикла, если сокет закрыт или ошибка
            except Exception as e:
                logger.error(f"Непредвиденная ошибка в цикле прослушивания сервера: {e}")
                # Можно добавить небольшую задержку перед повторной попыткой accept
                import time
                time.sleep(0.1)


    def handle_client_connection(self, conn: socket.socket, addr):
        """ Обрабатывает входящее клиентское соединение. """
        try:
            with conn:
                # Сначала читаем "команду" или тип запроса
                # Это может быть простой текстовой строкой перед JSON
                # Или часть самого JSON-сообщения
                # Для примера, пусть первое сообщение будет JSON с полем "command"
                
                request_data = receive_json_message(conn, timeout=30.0) # Таймаут на получение первого сообщения
                if not request_data:
                    logger.warning(f"От {addr} не получены данные или соединение закрыто до получения команды.")
                    return

                command = request_data.get("command")
                payload = request_data.get("payload")

                logger.info(f"От {addr} получена команда: {command}, данные: {str(payload)[:100]}...")

                # Обработка команды (должна быть реализована в дочерних классах)
                response_data = self.process_command(command, payload, addr)
                
                if response_data is not None: # Если есть что ответить
                    send_json_message(conn, response_data)
                    logger.info(f"Отправлен ответ {str(response_data)[:100]}... для {addr} по команде {command}")
                else:
                    # Некоторые команды могут не требовать ответа или ответ уже был отправлен внутри process_command
                    logger.info(f"Для команды {command} от {addr} ответ не сформирован или не требуется.")

        except ConnectionClosedError:
            logger.warning(f"Соединение с {addr} было неожиданно закрыто.")
        except MessageFormatError as e:
            logger.error(f"Ошибка формата сообщения от {addr}: {e}")
            # Можно отправить сообщение об ошибке клиенту, если соединение еще живо
            try:
                send_json_message(conn, {"status": "error", "message": f"Message format error: {e}"})
            except:
                pass # Игнорируем ошибки при отправке ответного сообщения об ошибке
        except socket.timeout:
            logger.warning(f"Таймаут при обмене данными с {addr}.")
        except Exception as e:
            logger.error(f"Ошибка при обработке клиента {addr}: {e}")
            import traceback
            logger.debug(traceback.format_exc())
            try:
                send_json_message(conn, {"status": "error", "message": f"Internal server error: {e}"})
            except:
                pass
        finally:
            logger.info(f"Завершение обработки соединения с {addr}.")


    def process_command(self, command: str, payload: dict, addr) -> dict | None:
        """
        Абстрактный метод для обработки команд. Должен быть переопределен в дочерних классах.
        Возвращает словарь с ответом или None, если ответ не требуется или уже отправлен.
        """
        logger.warning(f"Получена неизвестная или необработанная команда '{command}' от {addr}.")
        return {"status": "error", "message": f"Unknown or unhandled command: {command}"}


    def stop_server_action(self):
        if not self.is_server_running:
            logger.warning("Сервер не запущен.")
            messagebox.showwarning("Сервер", "Сервер не запущен.", parent=self.root)
            return

        self.is_server_running = False
        if self.server_socket:
            try:
                # Чтобы прервать server_socket.accept(), можно подключиться к нему
                # или просто закрыть. Закрытие - более прямой способ.
                self.server_socket.close() 
                logger.info("Серверный сокет закрыт.")
            except Exception as e:
                logger.error(f"Ошибка при закрытии серверного сокета: {e}")
        
        if self.server_thread and self.server_thread.is_alive():
            self.server_thread.join(timeout=1.0) # Даем потоку немного времени на завершение
            if self.server_thread.is_alive():
                logger.warning("Поток сервера не завершился корректно.")

        self.server_socket = None
        self.server_thread = None
        logger.info("Сервер остановлен.")
        self.status_bar.config(text=f"Сервер остановлен. Порт: {self.port}")
        messagebox.showinfo("Сервер", "Сервер успешно остановлен.", parent=self.root)

    def on_closing(self):
        """ Обработчик закрытия окна приложения. """
        logger.info("Запрос на закрытие приложения...")
        if self.is_server_running:
            if messagebox.askyesno("Выход", "Сервер активен. Остановить сервер и выйти?", parent=self.root):
                self.stop_server_action()
            else:
                return # Отмена закрытия
        
        # Здесь можно добавить сохранение конфигурации перед выходом, если есть несохраненные изменения
        # self.save_configuration() 
        
        self.root.destroy()
        logger.info("Приложение закрыто.")


# Для демонстрации: простой запуск базового окна
# В реальности этот класс будет наследоваться
if __name__ == "__main__":
    import datetime # нужен для lcg_seed_counter в __init__
    
    root_tk = tk.Tk()
    app = BaseNodeApp(root_tk, "BaseNodeTest", 10000)
    
    # Добавим кнопку для генерации p, g (для теста, обычно это делает RCA)
    def gen_pg_test():
        if app.p and app.g:
            if not messagebox.askyesno("Параметры", "p и g уже существуют. Перегенерировать?", parent=root_tk):
                return
        try:
            app.p = PrimeManager.generate_prime(64, app.get_next_lcg_seed()) # 64-битные для скорости
            app.g = PrimeManager.find_generator(app.p, app.get_next_lcg_seed())
            if app.g is None:
                messagebox.showerror("Ошибка", "Не удалось найти генератор g.", parent=root_tk)
                app.p = app.g = None
                return
            logger.info(f"Сгенерированы тестовые p={app.p}, g={app.g}")
            app.update_key_displays()
        except Exception as e:
            logger.error(f"Ошибка генерации p,g: {e}")
            messagebox.showerror("Ошибка", f"Ошибка генерации p,g: {e}", parent=root_tk)

    ttk.Button(app.control_panel, text="Сгенерировать P и G (тест)", command=gen_pg_test).pack(side=tk.LEFT, padx=5)
    
    root_tk.mainloop()

# END OF FILE: base_node_app.py