# START OF FILE: client_app.py
import os
import socket
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, scrolledtext
import logging
import datetime 
import json 

from base_node_app import BaseNodeApp
from elgamal_utils import ElGamalCrypto, MessageUtils, PrimeManager # Добавил PrimeManager на случай если понадобится для временных p,g
from certificate_manager import Certificate 
from network_utils import connect_to_server, send_json_message, receive_json_message, \
                          ConnectionClosedError, MessageFormatError, NetworkError

logger = logging.getLogger(__name__)

class ClientApp(BaseNodeApp):
    def __init__(self, root, node_id, default_port, 
                 lca_default_host="127.0.0.1", lca_default_port=10001):
        if "@" not in node_id:
            raise ValueError("Client node_id должен быть в формате 'name@LCA_ID'")
        
        # 1. Инициализация атрибутов, не зависящих от GUI или super()
        self.lca_host = lca_default_host
        self.lca_port = lca_default_port
        self.lca_certificate = None 
        self.rca_certificate = None 

        # 2. Вызов super().__init__()
        # Он вызовет BaseNodeApp.setup_gui() и ClientApp.load_configuration() (переопределенный)
        super().__init__(root, node_id, default_port, config_file_name="client_config.json")
        self.root.title(f"Клиент: {self.node_id}")

        # 3. Создание специфичных для клиента GUI элементов
        self.create_client_specific_gui()

        # 4. Обновление GUI полей lca_host и lca_port значениями, 
        # которые могли быть загружены в self.lca_host/port из ClientApp.load_configuration()
        if hasattr(self, 'lca_ip_entry'): # Проверка на всякий случай
            self.lca_ip_entry.delete(0, tk.END)
            self.lca_ip_entry.insert(0, self.lca_host)
        if hasattr(self, 'lca_port_entry'):
            self.lca_port_entry.delete(0, tk.END)
            self.lca_port_entry.insert(0, str(self.lca_port))
            
        # 5. Загрузка и отображение известных сертификатов (теперь GUI полностью готово)
        self.load_known_certificates() 

        # 6. Финальные проверки и логирование
        if self.p and self.g and not self.own_certificate:
             logger.warning(f"Клиент '{self.node_id}' имеет p и g, но нет собственного сертификата. Запросите у своего LCA.")
        elif not self.p or not self.g:
             logger.warning(f"Клиент '{self.node_id}' не имеет параметров p и g. Получите их от LCA.")


    def create_client_specific_gui(self):
        """ Добавляет специфичные для Клиента элементы в GUI. """
        client_panel = ttk.Labelframe(self.control_panel, text="Действия клиента")
        client_panel.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10, pady=5)

        ttk.Button(client_panel, text="1. Сгенерировать ключи", command=self.generate_client_keys_action).pack(side=tk.LEFT, padx=5)
        
        lca_conn_frame = ttk.Frame(client_panel)
        lca_conn_frame.pack(side=tk.LEFT, padx=10)
        ttk.Label(lca_conn_frame, text="LCA IP:").grid(row=0, column=0, sticky=tk.W)
        self.lca_ip_entry = ttk.Entry(lca_conn_frame, width=15)
        self.lca_ip_entry.grid(row=0, column=1, sticky=tk.W)
        # self.lca_ip_entry.insert(0, self.lca_host) # Будет вставлено в __init__ после создания

        ttk.Label(lca_conn_frame, text="LCA Port:").grid(row=1, column=0, sticky=tk.W)
        self.lca_port_entry = ttk.Entry(lca_conn_frame, width=7)
        self.lca_port_entry.grid(row=1, column=1, sticky=tk.W)
        # self.lca_port_entry.insert(0, str(self.lca_port)) # Будет вставлено в __init__ после создания


        ttk.Button(client_panel, text="2. Запросить сертификат у LCA", command=self.request_certificate_from_lca_action).pack(side=tk.LEFT, padx=5)

        # --- Вкладка для обмена сообщениями ---
        self.messaging_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.messaging_tab, text="Обмен сообщениями")
        self.create_messaging_tab_widgets(self.messaging_tab)

        # --- Вкладка для известных сертификатов ---
        self.known_certs_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.known_certs_tab, text="Известные сертификаты")
        self.create_known_certs_tab_widgets(self.known_certs_tab)


    def create_messaging_tab_widgets(self, parent_tab):
        frame = ttk.Frame(parent_tab, padding="5")
        frame.pack(fill=tk.BOTH, expand=True)
        
        send_frame = ttk.LabelFrame(frame, text="Отправить сообщение")
        send_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(send_frame, text="ID Получателя:").grid(row=0, column=0, padx=5, pady=2, sticky=tk.W)
        self.recipient_id_entry = ttk.Entry(send_frame, width=40)
        self.recipient_id_entry.grid(row=0, column=1, padx=5, pady=2, sticky=tk.EW)
        
        ttk.Label(send_frame, text="IP Получателя:").grid(row=0, column=2, padx=5, pady=2, sticky=tk.W)
        self.recipient_ip_entry = ttk.Entry(send_frame, width=15)
        self.recipient_ip_entry.grid(row=0, column=3, padx=5, pady=2, sticky=tk.W)
        
        ttk.Label(send_frame, text="Порт Получателя:").grid(row=0, column=4, padx=5, pady=2, sticky=tk.W)
        self.recipient_port_entry = ttk.Entry(send_frame, width=7)
        self.recipient_port_entry.grid(row=0, column=5, padx=5, pady=2, sticky=tk.W)

        ttk.Label(send_frame, text="Сообщение:").grid(row=1, column=0, padx=5, pady=2, sticky=tk.NW)
        self.message_to_send_text = scrolledtext.ScrolledText(send_frame, height=4, width=60, wrap=tk.WORD)
        self.message_to_send_text.grid(row=1, column=1, columnspan=5, padx=5, pady=2, sticky=tk.EW)
        
        send_button_frame = ttk.Frame(send_frame)
        send_button_frame.grid(row=2, column=1, columnspan=5, pady=5, sticky=tk.E)
        ttk.Button(send_button_frame, text="Получить сертификат получателя", command=self.fetch_recipient_certificate_action).pack(side=tk.LEFT, padx=5)
        ttk.Button(send_button_frame, text="Отправить", command=self.send_message_action).pack(side=tk.LEFT, padx=5)
        send_frame.columnconfigure(1, weight=1)

        recv_frame = ttk.LabelFrame(frame, text="Полученные сообщения")
        recv_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.received_messages_text = scrolledtext.ScrolledText(recv_frame, height=10, width=80, wrap=tk.WORD, state=tk.DISABLED)
        self.received_messages_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def create_known_certs_tab_widgets(self, parent_tab):
        frame = ttk.Frame(parent_tab, padding="5")
        frame.pack(fill=tk.BOTH, expand=True)

        self.known_certs_listbox = tk.Listbox(frame, width=30, height=15)
        self.known_certs_listbox.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)
        
        certs_scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.known_certs_listbox.yview)
        certs_scrollbar.pack(side=tk.LEFT, fill=tk.Y)
        self.known_certs_listbox.config(yscrollcommand=certs_scrollbar.set)
        
        self.known_certs_listbox.bind('<<ListboxSelect>>', self.on_known_cert_select)

        self.known_cert_details_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, height=15, width=70, state=tk.DISABLED)
        self.known_cert_details_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

    def generate_client_keys_action(self):
        if not self.p or not self.g:
            messagebox.showwarning("Параметры отсутствуют", 
                                   "Параметры p и g не установлены. Они будут получены от LCA. "
                                   "Ключи будут сгенерированы с использованием временных p и g, если они не будут установлены.", parent=self.root)
            if not self.p: self.p = PrimeManager.generate_prime(64, self.get_next_lcg_seed())
            if not self.g: self.g = PrimeManager.find_generator(self.p, self.get_next_lcg_seed())
            if not self.g:
                messagebox.showerror("Ошибка", "Не удалось сгенерировать временные p/g для ключей.", parent=self.root)
                return

        if self.key_pair_signature["private_xs"] or self.key_pair_encryption["private_xe"]:
            if not messagebox.askyesno("Подтверждение", "Ключи клиента уже существуют. Перегенерировать?", parent=self.root):
                return
        try:
            priv_xe, pub_ye = ElGamalCrypto.generate_keys(self.p, self.g, self.get_next_lcg_seed())
            self.key_pair_encryption = {"private_xe": priv_xe, "public_ye": pub_ye}
            
            priv_xs, pub_ys = ElGamalCrypto.generate_keys(self.p, self.g, self.get_next_lcg_seed())
            self.key_pair_signature = {"private_xs": priv_xs, "public_ys": pub_ys}

            logger.info(f"Сгенерированы ключи для клиента '{self.node_id}'. YE: {pub_ye}, YS: {pub_ys}")
            self.update_key_displays()
            messagebox.showinfo("Успех", "Ключи клиента успешно сгенерированы.", parent=self.root)
            self.own_certificate = None 
            self.update_key_displays()

        except Exception as e:
            logger.error(f"Ошибка при генерации ключей клиента: {e}")
            messagebox.showerror("Ошибка", f"Не удалось сгенерировать ключи: {e}", parent=self.root)

    def request_certificate_from_lca_action(self):
        if not self.key_pair_signature["public_ys"] or not self.key_pair_encryption["public_ye"]:
            messagebox.showerror("Ошибка", "Сначала сгенерируйте ключи клиента.", parent=self.root)
            return

        self.lca_host = self.lca_ip_entry.get() # Получаем актуальные значения из GUI
        try:
            self.lca_port = int(self.lca_port_entry.get())
        except ValueError:
            messagebox.showerror("Ошибка", "Порт LCA должен быть числом.", parent=self.root)
            return

        request_payload = {
            "client_id": self.node_id,
            "client_public_key_ye": self.key_pair_encryption["public_ye"],
            "client_public_key_ys": self.key_pair_signature["public_ys"]
        }
        
        lca_sock = None
        try:
            logger.info(f"Подключение к LCA {self.lca_host}:{self.lca_port} для запроса сертификата...")
            lca_sock = connect_to_server(self.lca_host, self.lca_port)
            if not lca_sock:
                messagebox.showerror("Ошибка соединения", f"Не удалось подключиться к LCA по адресу {self.lca_host}:{self.lca_port}", parent=self.root)
                return

            send_json_message(lca_sock, {"command": "request_client_certificate", "payload": request_payload})
            logger.info("Запрос на сертификат клиента отправлен LCA.")

            response = receive_json_message(lca_sock, timeout=30.0)
            if not response:
                messagebox.showerror("Ошибка ответа", "LCA не ответил или ответ некорректен.", parent=self.root)
                return
            logger.info(f"Получен ответ от LCA: {str(response)[:200]}...")

            if response.get("status") == "ok":
                client_cert_data = response.get("client_certificate")
                lca_cert_data = response.get("lca_certificate") # LCA должен прислать свой сертификат

                if not client_cert_data or not lca_cert_data:
                    messagebox.showerror("Ошибка ответа", "Ответ LCA не содержит необходимых сертификатов.", parent=self.root)
                    return
                
                self.lca_certificate = Certificate.from_dict(lca_cert_data)
                self.certificate_store.add_certificate(self.lca_certificate, save_to_file=True)
                logger.info(f"Сертификат LCA '{self.lca_certificate.subject_id}' получен и сохранен.")
                
                self.p = self.lca_certificate.p
                self.g = self.lca_certificate.g
                logger.info(f"Установлены p={self.p}, g={self.g} из сертификата LCA.")

                # Запрос сертификата RCA у LCA
                # Закрываем старое соединение и открываем новое для чистоты, или используем существующее.
                # Здесь для простоты используем существующее, если LCA его не закрыл.
                # Но лучше, если LCA присылает серт. RCA сразу в ответе на get_lca_certificate.
                # В local_ca_app.py команда get_lca_certificate должна возвращать и rca_certificate.
                
                # Давайте предположим, что LCA в ответе на request_client_certificate
                # НЕ присылает сертификат RCA, а клиент запрашивает его отдельно, если нужно.
                # Однако, более логично, если LCA в ответе на request_client_certificate пришлет
                # client_certificate и lca_certificate, а в lca_certificate уже содержится информация об issuer_id (RCA)
                # И клиент потом отдельно запросит у LCA сертификат RCA командой get_rca_certificate_from_lca (если ее реализовать в LCA)
                # ИЛИ команда get_lca_certificate на LCA должна возвращать и сертификат RCA.
                # Текущая реализация LCA.process_command("get_lca_certificate") так и делает.
                
                # Запрашиваем сертификат RCA через LCA (если он его отдает)
                send_json_message(lca_sock, {"command": "get_rca_certificate", "payload": {}})
                rca_response = receive_json_message(lca_sock, timeout=10.0) # Новый receive на том же сокете
                if rca_response and rca_response.get("status") == "ok" and rca_response.get("certificate"):
                    self.rca_certificate = Certificate.from_dict(rca_response.get("certificate"))
                    self.certificate_store.add_certificate(self.rca_certificate, save_to_file=True)
                    logger.info(f"Сертификат RCA '{self.rca_certificate.subject_id}' получен от LCA и сохранен.")
                else:
                    logger.warning(f"Не удалось получить сертификат RCA от LCA. Ответ: {rca_response}")


                self.own_certificate = Certificate.from_dict(client_cert_data)
                
                if self.own_certificate.verify_signature(self.lca_certificate.subject_public_key_ys):
                    self.certificate_store.add_certificate(self.own_certificate, save_to_file=True)
                    logger.info(f"Сертификат для клиента '{self.node_id}' получен, проверен и сохранен.")
                    self.update_key_displays()
                    self.load_known_certificates() 
                    messagebox.showinfo("Успех", "Сертификат от LCA успешно получен и проверен.", parent=self.root)
                else:
                    self.own_certificate = None
                    logger.error("Полученный от LCA сертификат клиента не прошел проверку подписи!")
                    messagebox.showerror("Ошибка проверки", "Подпись полученного сертификата недействительна!", parent=self.root)
            else:
                error_msg = response.get("message", "Неизвестная ошибка от LCA.")
                messagebox.showerror("Ошибка от LCA", f"LCA вернул ошибку: {error_msg}", parent=self.root)

        except (NetworkError, ConnectionClosedError, MessageFormatError, socket.timeout) as e:
            logger.error(f"Сетевая ошибка при запросе сертификата у LCA: {e}")
            messagebox.showerror("Сетевая ошибка", f"Ошибка при обмене данными с LCA: {e}", parent=self.root)
        except Exception as e:
            logger.error(f"Непредвиденная ошибка при запросе сертификата у LCA: {e}")
            import traceback
            logger.debug(traceback.format_exc())
            messagebox.showerror("Ошибка", f"Произошла ошибка: {e}", parent=self.root)
        finally:
            if lca_sock:
                lca_sock.close()
    
    def load_known_certificates(self):
        """Загружает сертификаты из хранилища и обновляет GUI."""
        if not hasattr(self, 'known_certs_listbox'): # Защита, если вызван до создания GUI
            logger.warning("load_known_certificates: known_certs_listbox еще не создан.")
            return

        self.known_certs_listbox.delete(0, tk.END)
        
        # Явно пытаемся загрузить сертификаты своего LCA и RCA из файлов, если они еще не в памяти
        if not self.lca_certificate:
            lca_id_part = self.node_id.split('@')[1] if '@' in self.node_id else None
            if lca_id_part:
                lca_cert_from_file = self.certificate_store.load_certificate_from_file(lca_id_part)
                if lca_cert_from_file: 
                    self.lca_certificate = lca_cert_from_file
                    logger.info(f"Загружен сертификат LCA '{lca_id_part}' из файла.")


        if not self.rca_certificate:
            # Пытаемся загрузить RCA, если он был сохранен ранее
            rca_cert_from_file = self.certificate_store.load_certificate_from_file("RootCA") 
            if rca_cert_from_file: 
                self.rca_certificate = rca_cert_from_file
                logger.info(f"Загружен сертификат RCA 'RootCA' из файла.")
        
        sorted_ids = sorted(list(self.certificate_store.list_subject_ids()))
        for subject_id in sorted_ids:
            self.known_certs_listbox.insert(tk.END, subject_id)
        
        if self.known_certs_listbox.size() > 0:
            try: # Попытка выбрать первый элемент, если он есть
                self.known_certs_listbox.select_set(0)
                self.on_known_cert_select(None)
            except tk.TclError: # Может возникнуть, если listbox пуст или элемент недействителен
                logger.debug("Не удалось выбрать элемент в known_certs_listbox (возможно, он пуст).")


    def on_known_cert_select(self, event):
        if not hasattr(self, 'known_certs_listbox'): return
        selection = self.known_certs_listbox.curselection()
        if not selection: return
        
        selected_subject_id = ""
        try:
            selected_subject_id = self.known_certs_listbox.get(selection[0])
        except tk.TclError: # Если элемент уже удален или не существует
            return

        cert = self.certificate_store.get_certificate(selected_subject_id)
        
        if not hasattr(self, 'known_cert_details_text'): return
        self.known_cert_details_text.config(state=tk.NORMAL)
        self.known_cert_details_text.delete(1.0, tk.END)
        if cert:
            self.known_cert_details_text.insert(tk.END, json.dumps(cert.to_dict(), indent=2, ensure_ascii=False))
            
            # Условия для проверки цепочки: не свой сертификат, не сертификат LCA, не сертификат RCA
            is_other_party_cert = True
            if cert.subject_id == self.node_id: is_other_party_cert = False
            if self.lca_certificate and cert.subject_id == self.lca_certificate.subject_id: is_other_party_cert = False
            if self.rca_certificate and cert.subject_id == self.rca_certificate.subject_id: is_other_party_cert = False
            
            if is_other_party_cert:
                self.known_cert_details_text.insert(tk.END, "\n\n--- Проверка цепочки доверия ---\n")
                is_trusted, chain = self.verify_certificate_chain(cert)
                if is_trusted:
                    self.known_cert_details_text.insert(tk.END, "Цепочка доверия ПОДТВЕРЖДЕНА.\n")
                else:
                    self.known_cert_details_text.insert(tk.END, "Цепочка доверия НЕ ПОДТВЕРЖДЕНА.\n")
                if chain: # Добавляем проверку на None или пустой список
                    self.known_cert_details_text.insert(tk.END, f"Цепочка: {[c.subject_id for c in chain]}\n")
                else:
                    self.known_cert_details_text.insert(tk.END, "Цепочка не построена.\n")
        else:
            self.known_cert_details_text.insert(tk.END, f"Сертификат для {selected_subject_id} не найден.")
        self.known_cert_details_text.config(state=tk.DISABLED)

    def verify_certificate_chain(self, target_cert: Certificate):
        if not target_cert: return False, [] # Добавлена проверка на None
        if not self.rca_certificate:
            logger.warning("Невозможно проверить цепочку: сертификат RCA отсутствует.")
            return False, [target_cert]

        chain = [target_cert]
        current_cert = target_cert

        if not current_cert.is_currently_valid():
            logger.warning(f"Целевой сертификат {current_cert.subject_id} недействителен по дате.")
            return False, chain

        # Максимальная глубина цепочки для предотвращения зацикливания
        max_depth = 10 
        depth = 0

        while current_cert.subject_id != self.rca_certificate.subject_id and depth < max_depth:
            depth += 1
            issuer_id = current_cert.issuer_id
            # Пытаемся загрузить сертификат издателя из хранилища (он мог быть добавлен туда ранее)
            issuer_cert = self.certificate_store.get_certificate(issuer_id)
            
            # Если не нашли, и issuer_id это наш известный LCA или RCA, используем их
            if not issuer_cert and self.lca_certificate and issuer_id == self.lca_certificate.subject_id:
                issuer_cert = self.lca_certificate
            if not issuer_cert and self.rca_certificate and issuer_id == self.rca_certificate.subject_id:
                # Это условие сработает, если current_cert.issuer_id == RCA_ID,
                # и мы должны были выйти из цикла while. Но на всякий случай.
                issuer_cert = self.rca_certificate


            if not issuer_cert:
                logger.warning(f"Сертификат издателя '{issuer_id}' для '{current_cert.subject_id}' не найден в хранилище.")
                # Здесь можно было бы попытаться запросить сертификат issuer_id у current_cert.issuer_id (если это LCA)
                return False, chain
            
            if not issuer_cert.is_currently_valid():
                 logger.warning(f"Сертификат издателя {issuer_cert.subject_id} недействителен по дате.")
                 return False, chain

            if not current_cert.verify_signature(issuer_cert.subject_public_key_ys):
                logger.warning(f"Подпись сертификата '{current_cert.subject_id}' недействительна (издатель '{issuer_id}').")
                return False, chain
            
            if issuer_cert not in chain: # Предотвращаем добавление уже существующего в цепи (хотя это маловероятно при правильной PKI)
                chain.append(issuer_cert)
            current_cert = issuer_cert
        
        if depth >= max_depth:
            logger.error("Достигнута максимальная глубина проверки цепочки, возможно, петля или неверная конфигурация.")
            return False, chain

        if current_cert.subject_id == self.rca_certificate.subject_id and \
           current_cert.verify_signature(current_cert.subject_public_key_ys): 
            logger.info(f"Цепочка сертификатов для '{target_cert.subject_id}' успешно проверена до RCA.")
            return True, chain
        else:
            logger.warning(f"Конечный сертификат в цепочке '{current_cert.subject_id}' не является доверенным RCA или его самоподпись неверна.")
            return False, chain

    def fetch_recipient_certificate_action(self):
        recipient_id = self.recipient_id_entry.get()
        recipient_ip = self.recipient_ip_entry.get()
        recipient_port_str = self.recipient_port_entry.get()

        if not recipient_id or not recipient_ip or not recipient_port_str:
            messagebox.showerror("Ошибка", "Введите ID, IP и порт получателя.", parent=self.root)
            return
        try:
            recipient_port = int(recipient_port_str)
        except ValueError:
            messagebox.showerror("Ошибка", "Порт получателя должен быть числом.", parent=self.root)
            return
            
        recipient_cert = self.certificate_store.get_certificate(recipient_id)
        if recipient_cert:
            is_trusted, _ = self.verify_certificate_chain(recipient_cert)
            if is_trusted:
                messagebox.showinfo("Сертификат найден", f"Сертификат для '{recipient_id}' уже есть в хранилище и он доверенный.", parent=self.root)
                return
            else:
                logger.warning(f"Найден сертификат для '{recipient_id}', но он не прошел проверку доверия. Попытка получить новый.")
        
        sock = None
        try:
            logger.info(f"Попытка получить сертификат от {recipient_id} ({recipient_ip}:{recipient_port})")
            sock = connect_to_server(recipient_ip, recipient_port, timeout=5.0)
            if not sock:
                messagebox.showerror("Ошибка", f"Не удалось подключиться к {recipient_id}.", parent=self.root)
                return

            send_json_message(sock, {"command": "get_own_certificate_chain", "payload": {}})
            response = receive_json_message(sock, timeout=10.0)

            if response and response.get("status") == "ok":
                certs_chain_data = response.get("certificate_chain", []) 
                if not certs_chain_data:
                    messagebox.showerror("Ошибка", f"От {recipient_id} получена пустая цепочка сертификатов.", parent=self.root)
                    return

                parsed_certs = []
                for cert_data in certs_chain_data:
                    try:
                        cert = Certificate.from_dict(cert_data)
                        self.certificate_store.add_certificate(cert, save_to_file=True)
                        parsed_certs.append(cert)
                    except Exception as e_parse:
                        logger.error(f"Ошибка парсинга сертификата из цепочки от {recipient_id}: {e_parse}")
                        messagebox.showerror("Ошибка", "Ошибка при обработке сертификата из цепочки.", parent=self.root)
                        if sock: sock.close() # Закрываем сокет при ошибке
                        return
                
                if not parsed_certs:
                    messagebox.showerror("Ошибка", "Не удалось распарсить сертификаты из цепочки.", parent=self.root)
                    if sock: sock.close()
                    return

                target_recipient_cert = None
                for c in parsed_certs: # Ищем сертификат самого получателя в присланной цепочке
                    if c.subject_id == recipient_id:
                        target_recipient_cert = c
                        break
                
                if not target_recipient_cert:
                    logger.warning(f"В полученной цепочке не найден сертификат для ID '{recipient_id}'. Первый серт: {parsed_certs[0].subject_id if parsed_certs else 'N/A'}")
                    messagebox.showwarning("Внимание", f"В полученной цепочке не найден сертификат для ID '{recipient_id}'.", parent=self.root)
                    # Можно попытаться проверить первый сертификат из цепочки, если он один
                    if len(parsed_certs) == 1 and parsed_certs[0].subject_id != recipient_id:
                        logger.info(f"Цепочка содержит один сертификат для {parsed_certs[0].subject_id}, но ожидали для {recipient_id}.")
                        # Возможно, это сам получатель, но с другим ID? Это странно.
                    elif not parsed_certs: # Если список пуст после цикла (хотя проверка выше должна была это поймать)
                         if sock: sock.close()
                         return

                # Если не нашли по ID, берем первый из списка, как раньше, но с логом
                if not target_recipient_cert and parsed_certs:
                    target_recipient_cert = parsed_certs[0]
                    if target_recipient_cert.subject_id != recipient_id:
                         logger.warning(f"Проверяем сертификат {target_recipient_cert.subject_id}, хотя запрашивали для {recipient_id}.")


                if target_recipient_cert:
                    is_trusted, _ = self.verify_certificate_chain(target_recipient_cert)
                    if is_trusted:
                        messagebox.showinfo("Успех", f"Сертификат для '{target_recipient_cert.subject_id}' и его цепочка получены и проверены.", parent=self.root)
                        self.load_known_certificates() 
                    else:
                        messagebox.showwarning("Внимание", f"Цепочка сертификатов для '{target_recipient_cert.subject_id}' не подтверждена!", parent=self.root)
                else: # Если target_recipient_cert так и не был установлен (parsed_certs пуст)
                    messagebox.showerror("Ошибка", "Не удалось определить целевой сертификат из ответа.", parent=self.root)

            else:
                error_msg = response.get("message", "Не удалось получить сертификат.") if response else "Нет ответа."
                messagebox.showerror("Ошибка", f"Ошибка от {recipient_id}: {error_msg}", parent=self.root)
        
        except (NetworkError, ConnectionClosedError, MessageFormatError, socket.timeout) as e:
            logger.error(f"Сетевая ошибка при получении сертификата {recipient_id}: {e}")
            messagebox.showerror("Сетевая ошибка", f"Ошибка при получении сертификата: {e}", parent=self.root)
        except Exception as e:
            logger.error(f"Ошибка при получении сертификата {recipient_id}: {e}")
            messagebox.showerror("Ошибка", f"Произошла ошибка: {e}", parent=self.root)
        finally:
            if sock: sock.close()


    def send_message_action(self):
        if not self.own_certificate:
            messagebox.showerror("Ошибка", "У вас нет собственного сертификата для подписи сообщения.", parent=self.root)
            return
        if not self.key_pair_signature["private_xs"]:
            messagebox.showerror("Ошибка", "У вас нет закрытого ключа для подписи сообщения.", parent=self.root)
            return

        recipient_id = self.recipient_id_entry.get()
        recipient_ip = self.recipient_ip_entry.get()
        recipient_port_str = self.recipient_port_entry.get()
        message_text = self.message_to_send_text.get(1.0, tk.END).strip()

        if not all([recipient_id, recipient_ip, recipient_port_str, message_text]):
            messagebox.showerror("Ошибка", "Заполните все поля: ID, IP, порт получателя и сообщение.", parent=self.root)
            return
        try:
            recipient_port = int(recipient_port_str)
        except ValueError:
            messagebox.showerror("Ошибка", "Порт получателя должен быть числом.", parent=self.root)
            return

        recipient_cert = self.certificate_store.get_certificate(recipient_id)
        if not recipient_cert:
            messagebox.showerror("Ошибка", f"Сертификат для '{recipient_id}' не найден. Сначала получите его.", parent=self.root)
            return
        
        is_trusted, _ = self.verify_certificate_chain(recipient_cert)
        if not is_trusted:
            if not messagebox.askyesno("Внимание", f"Сертификат получателя '{recipient_id}' не является доверенным. Отправить все равно?", parent=self.root):
                return

        sock = None
        try:
            m_numeric = MessageUtils.message_to_numeric(message_text, self.p) 
            enc_a, enc_b = ElGamalCrypto.encrypt(m_numeric, self.p, self.g, 
                                                 recipient_cert.subject_public_key_ye, 
                                                 self.get_next_lcg_seed())
            logger.info(f"Сообщение для '{recipient_id}' зашифровано: a={enc_a}, b={enc_b}")

            hash_h = MessageUtils.hash_message_for_elgamal(message_text, self.p - 1)
            sig_r, sig_s = ElGamalCrypto.sign(hash_h, self.p, self.g,
                                              self.key_pair_signature["private_xs"],
                                              self.get_next_lcg_seed())
            logger.info(f"Сообщение для '{recipient_id}' подписано: r={sig_r}, s={sig_s}")

            my_chain_to_send_data = []
            # Собираем цепочку: свой сертификат -> LCA -> RCA
            temp_cert = self.own_certificate
            visited_in_chain = set() # Для предотвращения зацикливания при сборке цепочки
            while temp_cert and temp_cert.subject_id not in visited_in_chain:
                my_chain_to_send_data.append(temp_cert.to_dict())
                visited_in_chain.add(temp_cert.subject_id)
                if temp_cert.subject_id == temp_cert.issuer_id: # Самоподписанный (RCA)
                    break 
                temp_cert = self.certificate_store.get_certificate(temp_cert.issuer_id)


            message_payload = {
                "sender_id": self.node_id,
                "encrypted_a": enc_a,
                "encrypted_b": enc_b,
                "signature_r": sig_r,
                "signature_s": sig_s,
                "original_message_hash_h_sender": hash_h, 
                "sender_certificate_chain": my_chain_to_send_data 
            }
            
            logger.info(f"Отправка сообщения для {recipient_id} ({recipient_ip}:{recipient_port})")
            sock = connect_to_server(recipient_ip, recipient_port)
            if not sock:
                messagebox.showerror("Ошибка", f"Не удалось подключиться к {recipient_id}.", parent=self.root)
                return

            send_json_message(sock, {"command": "receive_message", "payload": message_payload})
            
            ack = receive_json_message(sock, timeout=10.0)
            if ack and ack.get("status") == "ok":
                logger.info(f"Сообщение успешно доставлено {recipient_id}: {ack.get('message')}")
                messagebox.showinfo("Успех", f"Сообщение успешно отправлено {recipient_id}.", parent=self.root)
            else:
                error_msg = ack.get("message", "Получатель не подтвердил получение.") if ack else "Нет ответа от получателя."
                logger.warning(f"Ошибка доставки сообщения {recipient_id}: {error_msg}")
                messagebox.showwarning("Доставка", f"Сообщение отправлено, но: {error_msg}", parent=self.root)

        except ValueError as ve: 
            logger.error(f"Ошибка подготовки сообщения: {ve}")
            messagebox.showerror("Ошибка", f"Ошибка подготовки сообщения: {ve}", parent=self.root)
        except (NetworkError, ConnectionClosedError, MessageFormatError, socket.timeout) as e:
            logger.error(f"Сетевая ошибка при отправке сообщения {recipient_id}: {e}")
            messagebox.showerror("Сетевая ошибка", f"Ошибка при отправке сообщения: {e}", parent=self.root)
        except Exception as e:
            logger.error(f"Ошибка при отправке сообщения {recipient_id}: {e}")
            import traceback
            logger.debug(traceback.format_exc())
            messagebox.showerror("Ошибка", f"Произошла ошибка: {e}", parent=self.root)
        finally:
            if sock: sock.close()


    def process_command(self, command: str, payload: dict, addr) -> dict | None:
        logger.debug(f"Клиент '{self.node_id}' process_command: command='{command}' from {addr}")

        if command == "receive_message":
            if not self.own_certificate or not self.key_pair_encryption["private_xe"] or not self.p or not self.g:
                logger.error("Клиент не готов принимать сообщения (нет сертификата, ключей или p,g).")
                return {"status": "error", "message": "Client not ready to receive messages."}
            try:
                sender_id = payload["sender_id"]
                enc_a = int(payload["encrypted_a"])
                enc_b = int(payload["encrypted_b"])
                sig_r = int(payload["signature_r"])
                sig_s = int(payload["signature_s"])
                sender_cert_chain_data = payload.get("sender_certificate_chain", [])

                sender_cert = None
                if sender_cert_chain_data:
                    parsed_sender_certs = [] # Для проверки цепочки
                    for cert_data in sender_cert_chain_data:
                        try:
                            cert = Certificate.from_dict(cert_data)
                            self.certificate_store.add_certificate(cert, save_to_file=True) 
                            parsed_sender_certs.append(cert)
                            if cert.subject_id == sender_id: # Нашли сертификат самого отправителя
                                sender_cert = cert
                        except Exception as e_parse:
                            logger.error(f"Ошибка парсинга сертификата из цепочки от {sender_id}: {e_parse}")
                    
                    if not sender_cert and parsed_sender_certs: # Если не нашли по ID, но что-то пришло
                        logger.warning(f"Сертификат отправителя '{sender_id}' не найден по ID в цепочке, используем первый: {parsed_sender_certs[0].subject_id}")
                        sender_cert = parsed_sender_certs[0] # Берем первый, надеясь, что это он

                if not sender_cert: # Если и после этого не нашли
                    sender_cert = self.certificate_store.get_certificate(sender_id) # Попытка найти в хранилище

                if not sender_cert:
                    logger.error(f"Сертификат отправителя '{sender_id}' не найден или не получен.")
                    return {"status": "error", "message": f"Sender certificate for '{sender_id}' not found."}

                is_sender_trusted, verified_chain = self.verify_certificate_chain(sender_cert)
                trust_status_msg = "ДОВЕРЕННЫЙ" if is_sender_trusted else "НЕДОВЕРЕННЫЙ"
                logger.info(f"Отправитель '{sender_id}' является {trust_status_msg}.")

                if not is_sender_trusted:
                     logger.warning(f"Сообщение от НЕДОВЕРЕННОГО отправителя '{sender_id}'.")
                     # Можно здесь прервать обработку, если политика строгая

                decrypted_numeric = ElGamalCrypto.decrypt(enc_a, enc_b, self.p, self.g, 
                                                          self.key_pair_encryption["private_xe"])
                decrypted_message = MessageUtils.numeric_to_message(decrypted_numeric)
                logger.info(f"Сообщение от '{sender_id}' дешифровано: '{decrypted_message}'")

                local_hash_h = MessageUtils.hash_message_for_elgamal(decrypted_message, self.p - 1)
                
                is_signature_valid = ElGamalCrypto.verify(local_hash_h, sig_r, sig_s, self.p, self.g, 
                                                          sender_cert.subject_public_key_ys)
                
                sig_status_msg = "ВЕРНА" if is_signature_valid else "НЕВЕРНА"
                display_msg = (f"От {sender_id} ({trust_status_msg}): '{decrypted_message}' "
                               f"(Подпись {sig_status_msg})")
                
                if is_signature_valid:
                    logger.info(f"Подпись для сообщения от '{sender_id}' действительна.")
                    status_msg_for_sender = "Message received, decrypted, and signature verified."
                else:
                    logger.warning(f"Подпись для сообщения от '{sender_id}' НЕдействительна!")
                    status_msg_for_sender = "Message received, decrypted, BUT SIGNATURE IS INVALID."
                
                if hasattr(self, 'received_messages_text'):
                    self.received_messages_text.config(state=tk.NORMAL)
                    self.received_messages_text.insert(tk.END, f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {display_msg}\n")
                    self.received_messages_text.see(tk.END)
                    self.received_messages_text.config(state=tk.DISABLED)
                
                self.load_known_certificates()

                return {"status": "ok", "message": status_msg_for_sender}

            except Exception as e:
                logger.error(f"Ошибка при обработке входящего сообщения от {addr}: {e}")
                import traceback
                logger.debug(traceback.format_exc())
                return {"status": "error", "message": f"Error processing incoming message: {str(e)[:100]}"}

        elif command == "get_own_certificate_chain": 
            chain_data = []
            # Собираем цепочку: свой сертификат -> LCA -> RCA
            # Это более надежный способ сбора цепочки, чем был в send_message_action
            current_c = self.own_certificate
            visited_subjects_for_chain = set()
            while current_c and current_c.subject_id not in visited_subjects_for_chain:
                chain_data.append(current_c.to_dict())
                visited_subjects_for_chain.add(current_c.subject_id)
                if current_c.subject_id == current_c.issuer_id: # Дошли до самоподписанного (RCA)
                    break
                current_c = self.certificate_store.get_certificate(current_c.issuer_id)


            if chain_data:
                return {"status": "ok", "certificate_chain": chain_data}
            else:
                return {"status": "error", "message": "Certificate chain not available."}
        
        else:
            return super().process_command(command, payload, addr)

    def load_configuration(self):
        super().load_configuration() # Загружает p, g, ключи, собственный сертификат, порт
        try:
            if os.path.exists(self.config_file_path):
                with open(self.config_file_path, 'r', encoding='utf-8') as f:
                    config_data = json.load(f)
                
                # Загружаем self.lca_host и self.lca_port. GUI поля будут обновлены в __init__
                self.lca_host = config_data.get("lca_host", self.lca_host) 
                self.lca_port = config_data.get("lca_port", self.lca_port)

                lca_cert_data = config_data.get("lca_certificate")
                if lca_cert_data:
                    self.lca_certificate = Certificate.from_dict(lca_cert_data)
                    self.certificate_store.add_certificate(self.lca_certificate, save_to_file=False) 
                
                rca_cert_data = config_data.get("rca_certificate")
                if rca_cert_data:
                    self.rca_certificate = Certificate.from_dict(rca_cert_data)
                    self.certificate_store.add_certificate(self.rca_certificate, save_to_file=False)
        except Exception as e:
            logger.error(f"Ошибка при загрузке специфичной для Клиента конфигурации: {e}")
        
        # self.update_key_displays() вызывается в конце super().load_configuration()
        # self.load_known_certificates() будет вызван в __init__ ПОСЛЕ создания GUI


    def save_configuration(self):
        # Получаем актуальные значения lca_host/port из GUI перед сохранением
        current_lca_host = self.lca_host
        current_lca_port = self.lca_port
        if hasattr(self, 'lca_ip_entry'): current_lca_host = self.lca_ip_entry.get()
        if hasattr(self, 'lca_port_entry'):
            try:
                current_lca_port = int(self.lca_port_entry.get())
            except ValueError: # Если введено не число, сохраняем старое значение
                 logger.warning(f"Неверное значение порта LCA в GUI: {self.lca_port_entry.get()}, сохраняем предыдущее: {self.lca_port}")

        config_data = {
            "node_id": self.node_id,
            "port": self.port,
            "p": self.p,
            "g": self.g,
            "lcg_seed_counter": self.lcg_seed_counter,
            "key_pair_encryption": self.key_pair_encryption,
            "key_pair_signature": self.key_pair_signature,
            "own_certificate": self.own_certificate.to_dict() if self.own_certificate else None,
            "lca_host": current_lca_host,
            "lca_port": current_lca_port,
            "lca_certificate": self.lca_certificate.to_dict() if self.lca_certificate else None,
            "rca_certificate": self.rca_certificate.to_dict() if self.rca_certificate else None
        }
        try:
            with open(self.config_file_path, 'w', encoding='utf-8') as f:
                json.dump(config_data, f, indent=4, ensure_ascii=False)
            logger.info(f"Конфигурация Клиента сохранена в {self.config_file_path}")
            messagebox.showinfo("Сохранение", "Конфигурация Клиента успешно сохранена.", parent=self.root)
        except Exception as e:
            logger.error(f"Ошибка сохранения конфигурации Клиента: {e}")
            messagebox.showerror("Ошибка", f"Не удалось сохранить конфигурацию Клиента: {e}", parent=self.root)


if __name__ == "__main__":
    client_id_input = simpledialog.askstring("ID Клиента", "Введите ID клиента (например, client1@LCA1):", initialvalue="client1@LCA1")
    if not client_id_input:
        print("Запуск отменен.")
        exit()
        
    client_port_input = simpledialog.askstring("Порт Клиента", "Введите порт для этого клиента (например, 11001):", initialvalue="11001")
    if not client_port_input:
        print("Запуск отменен.")
        exit()

    try:
        client_port = int(client_port_input)
    except ValueError:
        print("Неверный порт. Запуск отменен.")
        exit()

    default_lca_port = 10001 
    if "@LCA2" in client_id_input:
        default_lca_port = 10002 

    root_client = tk.Tk()
    app_client = ClientApp(root_client, 
                           node_id=client_id_input, 
                           default_port=client_port,
                           lca_default_port=default_lca_port)
    root_client.mainloop()

# END OF FILE: client_app.py