# START OF FILE: client_app.py
import os
import socket
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, scrolledtext
import logging
import datetime
import json

from base_node_app import BaseNodeApp
from elgamal_utils import ElGamalCrypto, MessageUtils, PrimeManager, LCG
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
        super().__init__(root, node_id, default_port, config_file_name=f"client_{node_id.replace('@','_at_')}_config.json") # Исправлено имя файла конфига
        self.root.title(f"Клиент: {self.node_id}")

        # 3. Создание специфичных для клиента GUI элементов
        self.create_client_specific_gui()

        # 4. Обновление GUI полей lca_host и lca_port значениями,
        # которые могли быть загружены из конфигурации
        if hasattr(self, 'lca_ip_entry'):
            self.lca_ip_entry.delete(0, tk.END)
            self.lca_ip_entry.insert(0, self.lca_host)
        if hasattr(self, 'lca_port_entry'):
            self.lca_port_entry.delete(0, tk.END)
            self.lca_port_entry.insert(0, str(self.lca_port))
            
        # 5. Загрузка и отображение известных сертификатов
        self.load_known_certificates()

        # 6. Финальные проверки и логирование
        if not self.p or not self.g:
             logger.warning(f"Клиент '{self.node_id}' не имеет параметров p и g. Получите их от LCA (кнопка 0).")
        elif not self.key_pair_signature["public_ys"]:
             logger.warning(f"Клиент '{self.node_id}' не имеет ключей. Сгенерируйте их (кнопка 1).")
        elif not self.own_certificate:
             logger.warning(f"Клиент '{self.node_id}' имеет p,g и ключи, но нет собственного сертификата. Запросите у LCA (кнопка 2).")

        logger.info(f"Клиент '{self.node_id}' инициализирован.")

        # 7. Настраиваем начальный размер окна
        self.root.update_idletasks()
        width = max(800, self.root.winfo_reqwidth())
        height = max(600, self.root.winfo_reqheight())
        x = (self.root.winfo_screenwidth() - width) // 2
        y = (self.root.winfo_screenheight() - height) // 2
        self.root.geometry(f"{width}x{height}+{x}+{y}")

    def create_client_specific_gui(self):
        # Панель для параметров подключения к LCA
        lca_conn_panel = ttk.Labelframe(self.control_panel, text="Параметры подключения к LCA")
        lca_conn_panel.pack(side=tk.TOP, fill=tk.X, expand=True, padx=10, pady=5)

        ttk.Label(lca_conn_panel, text="LCA IP:").pack(side=tk.LEFT, padx=5)
        self.lca_ip_entry = ttk.Entry(lca_conn_panel, width=15)
        self.lca_ip_entry.pack(side=tk.LEFT, padx=5)

        ttk.Label(lca_conn_panel, text="LCA Port:").pack(side=tk.LEFT, padx=5)
        self.lca_port_entry = ttk.Entry(lca_conn_panel, width=7)
        self.lca_port_entry.pack(side=tk.LEFT, padx=5)

        # Панель для действий клиента
        client_panel = ttk.Labelframe(self.control_panel, text="Действия клиента")
        client_panel.pack(side=tk.TOP, fill=tk.X, expand=True, padx=10, pady=5)

        buttons_frame = ttk.Frame(client_panel)
        buttons_frame.pack(padx=5, pady=5)

        buttons = [
            ("0. Получить параметры от LCA", self.fetch_lca_params_action_client),
            ("Проверить P на простоту", self.test_prime_p_action),
            ("1. Сгенерировать ключи", self.generate_client_keys_action),
            ("2. Запросить сертификат у LCA", self.request_my_certificate_from_lca_action)
        ]

        for i, (text, command) in enumerate(buttons):
            row = i // 2
            col = i % 2
            ttk.Button(buttons_frame, text=text, command=command).grid(
                row=row, column=col, padx=5, pady=5, sticky="ew"
            )

        buttons_frame.grid_columnconfigure(0, weight=1)
        buttons_frame.grid_columnconfigure(1, weight=1)

        self.messaging_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.messaging_tab, text="Обмен сообщениями")
        self.create_messaging_tab_widgets(self.messaging_tab)

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

        attack_frame = ttk.Frame(frame)
        attack_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        attack_frame.columnconfigure(0, weight=1)
        attack_frame.columnconfigure(1, weight=1)

        attack_msg_frame = ttk.LabelFrame(attack_frame, text="Имитация атаки на зашифрованное сообщение")
        attack_msg_frame.grid(row=0, column=0, padx=5, sticky=tk.NSEW)
        
        ttk.Label(attack_msg_frame, text="Зашифрованное сообщение (a, b), подпись (r,s) и хеш H:").pack(fill=tk.X, padx=5, pady=2) # Обновлен Label
        self.encrypted_message_text = scrolledtext.ScrolledText(attack_msg_frame, height=8, width=40, wrap=tk.WORD)
        self.encrypted_message_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=2)
        
        attack_msg_buttons = ttk.Frame(attack_msg_frame)
        attack_msg_buttons.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(attack_msg_buttons, text="Расшифровать сообщение", command=self.decrypt_message_action).pack(side=tk.LEFT, padx=5)
        ttk.Button(attack_msg_buttons, text="Имитировать атаку на сообщение", command=self.simulate_message_attack_action).pack(side=tk.LEFT, padx=5)

        attack_cert_frame = ttk.LabelFrame(attack_frame, text="Имитация атаки на сертификат")
        attack_cert_frame.grid(row=0, column=1, padx=5, sticky=tk.NSEW)
        
        ttk.Label(attack_cert_frame, text="Цепочка сертификатов отправителя (JSON):").pack(fill=tk.X, padx=5, pady=2) # Обновлен Label
        self.received_cert_text = scrolledtext.ScrolledText(attack_cert_frame, height=8, width=40, wrap=tk.WORD)
        self.received_cert_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=2)
        
        attack_cert_buttons = ttk.Frame(attack_cert_frame)
        attack_cert_buttons.pack(fill=tk.X, padx=5, pady=5)
        ttk.Button(attack_cert_buttons, text="Проверить сертификат(ы)", command=self.verify_received_cert_action).pack(side=tk.LEFT, padx=5) # Обновлен Label кнопки
        ttk.Button(attack_cert_buttons, text="Имитировать атаку на сертификат(ы)", command=self.simulate_cert_attack_action).pack(side=tk.LEFT, padx=5) # Обновлен Label кнопки

        recv_frame = ttk.LabelFrame(frame, text="Результаты проверки и расшифровки")
        recv_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.received_messages_text = scrolledtext.ScrolledText(recv_frame, height=6, width=80, wrap=tk.WORD, state=tk.DISABLED)
        self.received_messages_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.current_message_data = None
        self.current_cert_chain_data = None

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

    def fetch_lca_params_action_client(self):
        if self.p and self.g and self.lca_certificate:
            proceed_msg = "Параметры P, G и сертификат LCA уже существуют."
            if self.rca_certificate:
                proceed_msg = "Параметры P, G и сертификаты LCA/RCA уже существуют."

            if not messagebox.askyesno("Подтверждение",
                                       f"{proceed_msg} Запросить заново?",
                                       parent=self.root):
                return
        
        self.lca_host = self.lca_ip_entry.get()
        try:
            self.lca_port = int(self.lca_port_entry.get())
        except ValueError:
            messagebox.showerror("Ошибка", "Порт LCA должен быть числом.", parent=self.root)
            return
        
        lca_sock = None
        try:
            logger.info(f"Клиент ({self.node_id}) запрашивает цепочку сертификатов у LCA {self.lca_host}:{self.lca_port}...")
            lca_sock = connect_to_server(self.lca_host, self.lca_port)
            if not lca_sock:
                messagebox.showerror("Ошибка соединения", f"Не удалось подключиться к LCA.", parent=self.root)
                return

            send_json_message(lca_sock, {"command": "get_lca_chain", "payload": {}})
            response = receive_json_message(lca_sock, timeout=30.0)

            if not response:
                messagebox.showerror("Ошибка ответа", "LCA не ответил или ответ некорректен.", parent=self.root)
                return
            logger.info(f"Клиент ({self.node_id}) получил ответ от LCA на get_lca_chain: {str(response)[:200]}...")

            if response.get("status") == "ok" or response.get("status") == "ok_partial_chain":
                lca_cert_data = response.get("lca_certificate")
                rca_cert_data = response.get("rca_certificate")

                if not lca_cert_data:
                    messagebox.showerror("Ошибка ответа LCA", "LCA не прислал свой сертификат.", parent=self.root)
                    return
                
                try:
                    parsed_lca_cert = Certificate.from_dict(lca_cert_data)
                except Exception as e_parse_lca:
                     logger.error(f"Ошибка парсинга сертификата LCA: {e_parse_lca}")
                     messagebox.showerror("Ошибка парсинга", f"Не удалось обработать сертификат LCA: {e_parse_lca}", parent=self.root)
                     return
                
                self.lca_certificate = parsed_lca_cert
                self.certificate_store.add_certificate(self.lca_certificate, save_to_file=True)

                new_p = self.lca_certificate.p
                new_g = self.lca_certificate.g
                params_changed_or_unset = (self.p != new_p or self.g != new_g or self.p is None)

                self.p = new_p
                self.g = new_g
                if params_changed_or_unset:
                    logger.info(f"Клиент ({self.node_id}) установил/обновил p и g от LCA: p={self.p}, g={self.g}.")
                
                if rca_cert_data:
                    try:
                        self.rca_certificate = Certificate.from_dict(rca_cert_data)
                        self.certificate_store.add_certificate(self.rca_certificate, save_to_file=True)
                        logger.info(f"Сертификат RCA получен от LCA: {self.rca_certificate.subject_id}")
                    except Exception as e_parse_rca:
                        logger.warning(f"Ошибка парсинга сертификата RCA от LCA: {e_parse_rca}")
                        self.rca_certificate = None
                else:
                    logger.warning("LCA не прислал сертификат RCA.")
                    self.rca_certificate = None

                keys_need_reset = params_changed_or_unset and (self.key_pair_signature["public_ys"] is not None)
                if keys_need_reset or not self.key_pair_signature["public_ys"]:
                    if self.key_pair_signature["public_ys"] or self.own_certificate:
                         logger.warning("Параметры p,g изменились или были установлены. Существующие ключи клиента и сертификат (если были) сброшены.")
                         self.key_pair_encryption = {"private_xe": None, "public_ye": None}
                         self.key_pair_signature = {"private_xs": None, "public_ys": None}
                         self.own_certificate = None
                    self.update_key_displays()
                    messagebox.showinfo("Параметры P,G получены",
                                        f"От LCA получены параметры: P={self.p}, G={self.g} и сертификаты.\n"
                                        f"{'Ваши ключи и сертификат были сброшены, т.к. P,G изменились. ' if keys_need_reset else ''}"
                                        "Теперь сгенерируйте ключи клиента (кнопка 1).",
                                        parent=self.root)
                else:
                     messagebox.showinfo("Параметры P,G актуальны",
                                        f"Параметры P={self.p}, G={self.g} и сертификаты LCA/RCA актуальны.",
                                        parent=self.root)
                self.load_known_certificates()
                self.update_key_displays()
            else:
                error_msg = response.get("message", "Неизвестная ошибка от LCA при получении цепочки.")
                messagebox.showerror("Ошибка от LCA", f"LCA вернул ошибку: {error_msg}", parent=self.root)
        except (NetworkError, ConnectionClosedError, MessageFormatError, socket.timeout) as e:
            logger.error(f"Сетевая ошибка при запросе цепочки у LCA: {e}")
            messagebox.showerror("Сетевая ошибка", f"Ошибка при обмене данными с LCA: {e}", parent=self.root)
        except Exception as e:
            logger.error(f"Непредвиденная ошибка при запросе цепочки у LCA: {e}")
            import traceback
            logger.debug(traceback.format_exc())
            messagebox.showerror("Ошибка", f"Произошла ошибка: {e}", parent=self.root)
        finally:
            if lca_sock:
                lca_sock.close()

    def generate_client_keys_action(self):
        if not self.p or not self.g:
            messagebox.showerror("Ошибка", "Параметры P и G не установлены. Сначала получите их от LCA (кнопка 0).", parent=self.root)
            return

        if self.key_pair_signature["private_xs"] or self.key_pair_encryption["private_xe"]:
            if not messagebox.askyesno("Подтверждение", "Ключи клиента уже существуют. Перегенерировать? "
                                                      "Это сделает недействительным ваш текущий сертификат (если он есть).", parent=self.root):
                return
        try:
            priv_xe, pub_ye = ElGamalCrypto.generate_keys(self.p, self.g, self.get_next_lcg_seed())
            self.key_pair_encryption = {"private_xe": priv_xe, "public_ye": pub_ye}
            
            priv_xs, pub_ys = ElGamalCrypto.generate_keys(self.p, self.g, self.get_next_lcg_seed())
            self.key_pair_signature = {"private_xs": priv_xs, "public_ys": pub_ys}

            logger.info(f"Сгенерированы ключи для клиента '{self.node_id}' с p={self.p}, g={self.g}. YE: {pub_ye}, YS: {pub_ys}")
            self.update_key_displays()
            messagebox.showinfo("Успех", "Ключи клиента успешно сгенерированы.", parent=self.root)
            if self.own_certificate:
                logger.warning("Ключи клиента перегенерированы. Существующий сертификат клиента сброшен.")
                self.own_certificate = None
                self.update_key_displays()
        except Exception as e:
            logger.error(f"Ошибка при генерации ключей клиента: {e}")
            messagebox.showerror("Ошибка", f"Не удалось сгенерировать ключи: {e}", parent=self.root)

    def request_my_certificate_from_lca_action(self):
        if not self.p or not self.g:
            messagebox.showerror("Ошибка", "Параметры P и G не установлены. Сначала получите их от LCA (кнопка 0).", parent=self.root)
            return
        if not self.key_pair_signature["public_ys"] or not self.key_pair_encryption["public_ye"]:
            messagebox.showerror("Ошибка", "Ключи клиента не сгенерированы. Сначала сгенерируйте их (кнопка 1).", parent=self.root)
            return
        if not self.lca_certificate:
            messagebox.showerror("Ошибка", "Сертификат LCA отсутствует. Сначала получите параметры от LCA (кнопка 0).", parent=self.root)
            return

        self.lca_host = self.lca_ip_entry.get()
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
            logger.info(f"Клиент ({self.node_id}) подключается к LCA {self.lca_host}:{self.lca_port} для запроса своего сертификата...")
            lca_sock = connect_to_server(self.lca_host, self.lca_port)
            if not lca_sock:
                messagebox.showerror("Ошибка соединения", f"Не удалось подключиться к LCA.", parent=self.root)
                return

            send_json_message(lca_sock, {"command": "request_client_certificate", "payload": request_payload})
            logger.info(f"Клиент ({self.node_id}) отправил запрос request_client_certificate LCA.")

            response = receive_json_message(lca_sock, timeout=30.0)
            if not response:
                messagebox.showerror("Ошибка ответа", "LCA не ответил или ответ некорректен.", parent=self.root)
                return
            logger.info(f"Клиент ({self.node_id}) получил ответ от LCA: {str(response)[:250]}...")

            if response.get("status") == "ok":
                client_cert_data = response.get("client_certificate")
                lca_cert_data_resp = response.get("lca_certificate")
                rca_cert_data_resp = response.get("rca_certificate")

                if not client_cert_data:
                    messagebox.showerror("Ошибка ответа LCA", "LCA не прислал сертификат клиента.", parent=self.root)
                    return
                
                if lca_cert_data_resp:
                    try:
                        parsed_lca_cert_resp = Certificate.from_dict(lca_cert_data_resp)
                        if not self.lca_certificate or self.lca_certificate.serial_number != parsed_lca_cert_resp.serial_number:
                            logger.info("Сертификат LCA был обновлен от LCA.")
                            self.lca_certificate = parsed_lca_cert_resp
                            self.certificate_store.add_certificate(self.lca_certificate, save_to_file=True)
                            if self.lca_certificate.p != self.p or self.lca_certificate.g != self.g:
                                logger.error("КРИТИЧЕСКАЯ ОШИБКА: P,G в обновленном сертификате LCA не совпадают с ранее установленными!")
                                messagebox.showerror("Ошибка параметров LCA", "P,G в сертификате LCA изменились! Система неконсистентна.",parent=self.root)
                                return
                    except Exception as e_lca_upd:
                        logger.warning(f"Не удалось обновить сертификат LCA из ответа: {e_lca_upd}")
                
                if rca_cert_data_resp:
                    try:
                        parsed_rca_cert_resp = Certificate.from_dict(rca_cert_data_resp)
                        if not self.rca_certificate or self.rca_certificate.serial_number != parsed_rca_cert_resp.serial_number:
                            logger.info("Сертификат RCA был обновлен от LCA.")
                            self.rca_certificate = parsed_rca_cert_resp
                            self.certificate_store.add_certificate(self.rca_certificate, save_to_file=True)
                    except Exception as e_rca_upd:
                        logger.warning(f"Не удалось обновить сертификат RCA из ответа: {e_rca_upd}")


                try:
                    self.own_certificate = Certificate.from_dict(client_cert_data)
                except Exception as e_client_parse:
                    logger.error(f"Ошибка парсинга собственного сертификата клиента: {e_client_parse}")
                    messagebox.showerror("Ошибка парсинга", f"Не удалось обработать собственный сертификат: {e_client_parse}", parent=self.root)
                    return

                logger.debug(f"Клиент ({self.node_id}) получил свой сертификат (subject: {self.own_certificate.subject_id}, issuer: {self.own_certificate.issuer_id}). Подпись R,S: ({self.own_certificate.signature_r}, {self.own_certificate.signature_s})")
                logger.debug(f"Клиент ({self.node_id}) будет проверять свой сертификат ключом YS={self.lca_certificate.subject_public_key_ys} из сертификата LCA.")

                if self.own_certificate.p != self.p or self.own_certificate.g != self.g:
                    logger.error(f"Несоответствие параметров p/g в сертификате клиента! Сертификат клиента p,g: ({self.own_certificate.p},{self.own_certificate.g}), ожидаемые p,g (от LCA): ({self.p},{self.g})")
                    messagebox.showerror("Ошибка параметров", "Параметры p/g в полученном сертификате не соответствуют параметрам УЦ (LCA).", parent=self.root)
                    self.own_certificate = None
                elif self.own_certificate.verify_signature(self.lca_certificate.subject_public_key_ys):
                    self.certificate_store.add_certificate(self.own_certificate, save_to_file=True)
                    logger.info(f"Сертификат для клиента '{self.node_id}' получен, проверен и сохранен.")
                    self.update_key_displays()
                    self.load_known_certificates()
                    messagebox.showinfo("Успех", "Сертификат от LCA успешно получен и проверен.", parent=self.root)
                else:
                    self.own_certificate = None
                    logger.error(f"Полученный от LCA сертификат клиента ({self.node_id}) не прошел проверку подписи!")
                    messagebox.showerror("Ошибка проверки", "Подпись полученного сертификата недействительна!", parent=self.root)
            else:
                error_msg = response.get("message", "Неизвестная ошибка от LCA.")
                logger.error(f"LCA вернул ошибку: {error_msg}")
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
        if not hasattr(self, 'known_certs_listbox'):
            logger.warning("load_known_certificates: known_certs_listbox еще не создан.")
            return
            
        self.known_certs_listbox.delete(0, tk.END)
        
        temp_certs_to_display = {}
        if self.own_certificate: temp_certs_to_display[self.own_certificate.subject_id] = self.own_certificate
        if self.lca_certificate: temp_certs_to_display[self.lca_certificate.subject_id] = self.lca_certificate
        if self.rca_certificate: temp_certs_to_display[self.rca_certificate.subject_id] = self.rca_certificate

        for subject_id in self.certificate_store.list_subject_ids():
            cert_from_store = self.certificate_store.get_certificate(subject_id)
            if cert_from_store:
                temp_certs_to_display[subject_id] = cert_from_store
        
        sorted_ids = sorted(list(temp_certs_to_display.keys()))
        for subject_id in sorted_ids:
            self.known_certs_listbox.insert(tk.END, subject_id)
        
        if self.known_certs_listbox.size() > 0:
            try:
                self.known_certs_listbox.select_set(0)
                self.on_known_cert_select(None)
            except tk.TclError:
                 logger.debug("Не удалось выбрать элемент в known_certs_listbox (возможно, он пуст).")

    def on_known_cert_select(self, event):
        if not hasattr(self, 'known_certs_listbox'): return
        selection = self.known_certs_listbox.curselection()
        if not selection: return
        
        selected_subject_id = ""
        try:
            selected_subject_id = self.known_certs_listbox.get(selection[0])
        except tk.TclError:
            return

        cert_to_display = None
        if self.own_certificate and self.own_certificate.subject_id == selected_subject_id:
            cert_to_display = self.own_certificate
        elif self.lca_certificate and self.lca_certificate.subject_id == selected_subject_id:
            cert_to_display = self.lca_certificate
        elif self.rca_certificate and self.rca_certificate.subject_id == selected_subject_id:
            cert_to_display = self.rca_certificate
        else:
            cert_to_display = self.certificate_store.get_certificate(selected_subject_id)
        
        if not hasattr(self, 'known_cert_details_text'): return
        self.known_cert_details_text.config(state=tk.NORMAL)
        self.known_cert_details_text.delete(1.0, tk.END)

        if cert_to_display:
            self.known_cert_details_text.insert(tk.END, json.dumps(cert_to_display.to_dict(), indent=2, ensure_ascii=False))
            
            is_other_party_cert = True
            if cert_to_display.subject_id == self.node_id: is_other_party_cert = False
            if self.lca_certificate and cert_to_display.subject_id == self.lca_certificate.subject_id: is_other_party_cert = False
            if self.rca_certificate and cert_to_display.subject_id == self.rca_certificate.subject_id: is_other_party_cert = False
            
            if is_other_party_cert:
                self.known_cert_details_text.insert(tk.END, "\n\n--- Проверка цепочки доверия ---\n")
                # ИЗМЕНЕНИЕ: verify_certificate_chain теперь возвращает 3 значения
                is_trusted, chain, verification_detail_msg = self.verify_certificate_chain(cert_to_display)
                if is_trusted:
                    self.known_cert_details_text.insert(tk.END, "Цепочка доверия ПОДТВЕРЖДЕНА.\n")
                else:
                    self.known_cert_details_text.insert(tk.END, "Цепочка доверия НЕ ПОДТВЕРЖДЕНА.\n")
                
                self.known_cert_details_text.insert(tk.END, f"Детали проверки: {verification_detail_msg}\n") # ИЗМЕНЕНИЕ: Добавлены детали
                
                if chain: # Отображаем построенную (или частично построенную) цепочку
                    self.known_cert_details_text.insert(tk.END, f"Проверенный путь: {' -> '.join([c.subject_id for c in chain])}\n")

        else:
            self.known_cert_details_text.insert(tk.END, f"Сертификат для {selected_subject_id} не найден.")
        self.known_cert_details_text.config(state=tk.DISABLED)

    def verify_certificate_chain(self, target_cert: Certificate):
        """
        Проверяет цепочку сертификатов, начиная от target_cert до доверенного RCA.
        Возвращает: (is_trusted: bool, chain: list[Certificate], verification_message: str)
        """
        if not target_cert:
            return False, [], "Целевой сертификат отсутствует."
        if not self.rca_certificate:
            logger.warning("Невозможно проверить цепочку: сертификат RCA отсутствует у клиента.")
            return False, [target_cert], "Сертификат RCA неизвестен клиенту, проверка невозможна."
        
        # Специальный случай: если проверяемый сертификат - это сам RCA
        if target_cert.subject_id == self.rca_certificate.subject_id:
            if target_cert.serial_number == self.rca_certificate.serial_number and \
               target_cert.verify_signature(self.rca_certificate.subject_public_key_ys): # Проверка самоподписи
                return True, [target_cert], f"Сертификат является доверенным RCA ({target_cert.subject_id}), самоподпись верна."
            else:
                return False, [target_cert], f"Представленный сертификат ({target_cert.subject_id}) не совпадает с доверенным RCA или его самоподпись неверна."

        chain = []
        current_cert_obj = target_cert
        visited_subjects_in_chain = set() 
        max_depth = 10
        current_depth = 0

        while current_depth < max_depth:
            current_depth += 1
            if not current_cert_obj: 
                logger.error("Ошибка в verify_certificate_chain: current_cert_obj стал None.")
                return False, chain, "Внутренняя ошибка: обрабатываемый сертификат в цепочке стал None."

            if current_cert_obj.subject_id in visited_subjects_in_chain:
                msg = f"Обнаружен цикл в цепочке сертификатов при проверке {target_cert.subject_id}. Субъект {current_cert_obj.subject_id} уже был в цепочке."
                logger.error(msg)
                return False, chain, msg
            
            visited_subjects_in_chain.add(current_cert_obj.subject_id)
            chain.append(current_cert_obj)

            if not current_cert_obj.is_currently_valid():
                msg = f"Сертификат '{current_cert_obj.subject_id}' (S/N: {current_cert_obj.serial_number}) в цепочке недействителен по сроку."
                logger.warning(msg)
                return False, chain, msg
            
            # Достигли корня доверия (RCA)
            if current_cert_obj.issuer_id == self.rca_certificate.subject_id:
                # Если текущий сертификат и есть RCA (хотя это должно было быть обработано выше, но для полноты)
                if current_cert_obj.subject_id == self.rca_certificate.subject_id:
                    if current_cert_obj.serial_number == self.rca_certificate.serial_number and \
                       current_cert_obj.verify_signature(self.rca_certificate.subject_public_key_ys):
                        return True, chain, f"Цепочка доверена: сертификат '{current_cert_obj.subject_id}' является самоподписанным RCA, подпись верна."
                    else:
                        return False, chain, f"Ошибка: сертификат '{current_cert_obj.subject_id}' заявлен как RCA, но не соответствует доверенному RCA или его самоподпись неверна."
                # Если текущий сертификат выдан RCA
                else:
                    if current_cert_obj.verify_signature(self.rca_certificate.subject_public_key_ys):
                        return True, chain, f"Цепочка доверена: сертификат '{current_cert_obj.subject_id}' подписан доверенным RCA, подпись верна."
                    else:
                        msg = f"Подпись сертификата '{current_cert_obj.subject_id}' (выдан RCA '{self.rca_certificate.subject_id}') неверна."
                        logger.warning(msg)
                        return False, chain, msg
            
            # Ищем сертификат издателя
            issuer_cert_obj = None
            # Сначала проверяем, не является ли издатель известным LCA или RCA (если current_cert_obj.issuer_id != self.rca_certificate.subject_id)
            if self.lca_certificate and current_cert_obj.issuer_id == self.lca_certificate.subject_id:
                issuer_cert_obj = self.lca_certificate
            # Если не LCA, ищем в общем хранилище
            if not issuer_cert_obj:
                issuer_cert_obj = self.certificate_store.get_certificate(current_cert_obj.issuer_id)

            if not issuer_cert_obj:
                msg = f"Сертификат издателя '{current_cert_obj.issuer_id}' для сертификата '{current_cert_obj.subject_id}' не найден."
                logger.warning(msg)
                return False, chain, msg

            # Проверяем подпись текущего сертификата ключом найденного издателя
            if not current_cert_obj.verify_signature(issuer_cert_obj.subject_public_key_ys):
                msg = f"Подпись сертификата '{current_cert_obj.subject_id}' его предполагаемым издателем '{issuer_cert_obj.subject_id}' неверна."
                logger.warning(msg)
                return False, chain, msg
            
            # Переходим к следующему сертификату в цепочке (сертификату издателя)
            current_cert_obj = issuer_cert_obj 
        
        msg = f"Цепочка для '{target_cert.subject_id}' не дошла до доверенного RCA ({self.rca_certificate.subject_id}) за {max_depth} шагов."
        logger.warning(msg)
        return False, chain, msg

    def process_command(self, command: str, payload: dict, addr) -> dict | None:
        logger.debug(f"Клиент ({self.node_id}) process_command: command='{command}', payload='{payload is not None}' from {addr}")

        if command == "receive_message":
            try:
                sender_id = payload.get("sender_id")
                enc_a = int(payload["encrypted_a"])
                enc_b = int(payload["encrypted_b"])
                sig_r = int(payload["signature_r"])
                sig_s = int(payload["signature_s"])
                original_hash_h_sender = int(payload.get("original_message_hash_h_sender")) # Может отсутствовать, если отправитель старой версии
                sender_cert_chain_data = payload.get("sender_certificate_chain", [])

                if not all([sender_id, sender_cert_chain_data]): # Проверяем наличие sender_id и цепочки
                    logger.error(f"Неполное сообщение от {addr}: отсутствует sender_id или sender_certificate_chain.")
                    return {"status": "error", "message": "Incomplete message payload (missing sender_id or chain)."}

                logger.info(f"Получено зашифрованное сообщение от '{sender_id}'.")

                self.current_message_data = payload
                self.current_cert_chain_data = sender_cert_chain_data

                def update_gui():
                    self.encrypted_message_text.delete(1.0, tk.END)
                    message_display_data = {
                        "sender_id": sender_id,
                        "encrypted_a": enc_a,
                        "encrypted_b": enc_b,
                        "signature_r": sig_r,
                        "signature_s": sig_s,
                        "original_message_hash_h_sender": original_hash_h_sender
                    }
                    self.encrypted_message_text.insert(1.0, json.dumps(message_display_data, indent=2, ensure_ascii=False))

                    self.received_cert_text.delete(1.0, tk.END)
                    self.received_cert_text.insert(1.0, json.dumps(sender_cert_chain_data, indent=2, ensure_ascii=False))

                    self.received_messages_text.config(state=tk.NORMAL)
                    self.received_messages_text.insert(tk.END, 
                        f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] "
                        f"Получено новое сообщение от {sender_id}. "
                        f"Используйте кнопки 'Расшифровать сообщение' и 'Проверить сертификат(ы)' для обработки.\n\n")
                    self.received_messages_text.see(tk.END)
                    self.received_messages_text.config(state=tk.DISABLED)
                    self.notebook.select(self.messaging_tab) # Переключиться на вкладку сообщений

                if hasattr(self.root, 'tk') and self.root.winfo_exists():
                    self.root.after(0, update_gui)

                return {"status": "ok", "message": "Message received and ready for processing."}

            except KeyError as e:
                logger.error(f"Неполное сообщение (receive_message) от {addr}: отсутствует {e}")
                return {"status": "error", "message": f"Incomplete message payload, missing: {e}"}
            except ValueError as e: 
                logger.error(f"Ошибка обработки сообщения (receive_message) от {addr}: {e}")
                return {"status": "error", "message": f"Error processing message: {e}"}
            except Exception as e:
                logger.error(f"Непредвиденная ошибка при обработке сообщения (receive_message) от {addr}: {e}")
                import traceback
                logger.debug(traceback.format_exc())
                return {"status": "error", "message": f"Internal server error while processing message: {e}"}
        
        elif command == "get_own_certificate_chain":
            logger.info(f"Клиент ({self.node_id}) получил запрос get_own_certificate_chain от {addr}")
            if not self.own_certificate:
                logger.warning(f"Клиент ({self.node_id}) не может предоставить цепочку: собственный сертификат отсутствует.")
                return {"status": "error", "message": "Own certificate not available."}

            chain_to_send_data = []
            current_cert_obj = self.own_certificate
            visited_subjects_in_chain = set()
            max_depth_chain_build = 5 
            depth_count = 0

            while current_cert_obj and current_cert_obj.subject_id not in visited_subjects_in_chain and depth_count < max_depth_chain_build:
                depth_count += 1
                chain_to_send_data.append(current_cert_obj.to_dict())
                visited_subjects_in_chain.add(current_cert_obj.subject_id)

                if current_cert_obj.issuer_id == current_cert_obj.subject_id: # Дошли до самоподписанного (или просто конец цепочки)
                    break 

                issuer_cert_subject_id = current_cert_obj.issuer_id
                next_cert_in_chain = None

                if self.lca_certificate and issuer_cert_subject_id == self.lca_certificate.subject_id:
                    next_cert_in_chain = self.lca_certificate
                elif self.rca_certificate and issuer_cert_subject_id == self.rca_certificate.subject_id:
                    next_cert_in_chain = self.rca_certificate
                else: # Ищем в общем хранилище
                    next_cert_in_chain = self.certificate_store.get_certificate(issuer_cert_subject_id) 
                
                current_cert_obj = next_cert_in_chain
                if not current_cert_obj and issuer_cert_subject_id not in visited_subjects_in_chain :
                    logger.info(f"Не найден сертификат издателя '{issuer_cert_subject_id}' при построении цепочки для отправки.")
            
            if not chain_to_send_data:
                 logger.error(f"Клиент ({self.node_id}): ошибка, цепочка для отправки пуста, хотя собственный сертификат есть.")
                 return {"status": "error", "message": "Failed to build certificate chain."}

            logger.info(f"Клиент ({self.node_id}) отправляет цепочку из {len(chain_to_send_data)} сертификатов.")
            return {
                "status": "ok",
                "certificate_chain": chain_to_send_data
            }
        
        else: 
            return super().process_command(command, payload, addr)

    def load_configuration(self):
        super().load_configuration()
        try:
            config_file_name_corrected = f"client_{self.node_id.replace('@','_at_')}_config.json"
            config_path_corrected = os.path.join(os.path.dirname(self.config_file_path), config_file_name_corrected)
            
            # Используем исправленный путь, если он отличается от self.config_file_path
            # Это нужно если self.config_file_path был инициализирован с неправильным node_id в имени
            actual_config_path = self.config_file_path 
            if not os.path.exists(actual_config_path) and os.path.exists(config_path_corrected):
                actual_config_path = config_path_corrected
                logger.info(f"Коррекция пути к файлу конфигурации на: {actual_config_path}")


            if os.path.exists(actual_config_path): # Проверяем существование файла
                with open(actual_config_path, 'r', encoding='utf-8') as f:
                    config_data = json.load(f)
                
                self.lca_host = config_data.get("lca_host", self.lca_host)
                self.lca_port = config_data.get("lca_port", self.lca_port)

                lca_cert_data = config_data.get("lca_certificate")
                if lca_cert_data:
                    try:
                        self.lca_certificate = Certificate.from_dict(lca_cert_data)
                        self.certificate_store.add_certificate(self.lca_certificate, save_to_file=False)
                    except Exception as e_lca_load:
                        logger.error(f"Ошибка загрузки сертификата LCA из конфига: {e_lca_load}")
                
                rca_cert_data = config_data.get("rca_certificate")
                if rca_cert_data:
                    try:
                        self.rca_certificate = Certificate.from_dict(rca_cert_data)
                        self.certificate_store.add_certificate(self.rca_certificate, save_to_file=False)
                    except Exception as e_rca_load:
                        logger.error(f"Ошибка загрузки сертификата RCA из конфига: {e_rca_load}")
        except Exception as e:
            logger.error(f"Ошибка при загрузке специфичной для Клиента конфигурации: {e}")
        # finally: # Обновление GUI полей lca_ip_entry и lca_port_entry перенесено в __init__ после super()


    def save_configuration(self):
        current_lca_host = self.lca_host
        current_lca_port = self.lca_port
        if hasattr(self, 'lca_ip_entry'): current_lca_host = self.lca_ip_entry.get()
        if hasattr(self, 'lca_port_entry'):
            try:
                current_lca_port = int(self.lca_port_entry.get())
            except ValueError:
                 logger.warning(f"Неверное значение порта LCA в GUI: {self.lca_port_entry.get()}, сохраняем предыдущее: {self.lca_port}")

        # Убедимся, что self.config_file_path использует актуальный (возможно, исправленный) node_id
        base_config_dir = os.path.dirname(self.config_file_path)
        config_file_name_corrected = f"client_{self.node_id.replace('@','_at_')}_config.json"
        actual_config_path = os.path.join(base_config_dir, config_file_name_corrected)


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
            os.makedirs(os.path.dirname(actual_config_path), exist_ok=True) 
            with open(actual_config_path, 'w', encoding='utf-8') as f:
                json.dump(config_data, f, indent=4, ensure_ascii=False)
            logger.info(f"Конфигурация Клиента сохранена в {actual_config_path}")
            # Обновим self.config_file_path на случай, если он был некорректен
            self.config_file_path = actual_config_path
        except Exception as e:
            logger.error(f"Ошибка сохранения конфигурации Клиента: {e}")

    def send_message_action(self):
        if not self.p or not self.g:
            messagebox.showerror("Ошибка", "Параметры P и G не установлены. Сначала получите их от LCA (кнопка 0).", parent=self.root)
            return
        if not self.own_certificate:
            messagebox.showerror("Ошибка", "У вас нет собственного сертификата для подписи сообщения (кнопка 2).", parent=self.root)
            return
        if not self.key_pair_signature["private_xs"]:
            messagebox.showerror("Ошибка", "У вас нет закрытого ключа для подписи сообщения. Сгенерируйте ключи (кнопка 1).", parent=self.root)
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
            messagebox.showerror("Ошибка", f"Сертификат для '{recipient_id}' не найден. Сначала получите его (кнопка 'Получить сертификат получателя').", parent=self.root)
            return
        
        is_trusted, _, verification_msg_recipient_cert = self.verify_certificate_chain(recipient_cert) # Получаем детали
        if not is_trusted:
            if not messagebox.askyesno("Внимание", 
                                       f"Сертификат получателя '{recipient_id}' не является доверенным или цепочка не проверена.\n"
                                       f"Детали: {verification_msg_recipient_cert}\nОтправить все равно?", 
                                       parent=self.root):
                return

        if not recipient_cert.subject_public_key_ye:
            messagebox.showerror("Ошибка", f"У сертификата получателя '{recipient_id}' отсутствует публичный ключ для шифрования (YE).", parent=self.root)
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
            current_c = self.own_certificate
            visited_subjects_for_chain = set()
            max_depth_chain_send = 5 
            depth_count = 0

            while current_c and current_c.subject_id not in visited_subjects_for_chain and depth_count < max_depth_chain_send:
                depth_count += 1
                my_chain_to_send_data.append(current_c.to_dict())
                visited_subjects_for_chain.add(current_c.subject_id)
                
                if current_c.subject_id == current_c.issuer_id: 
                    break
                
                issuer_cert_obj = None
                issuer_id = current_c.issuer_id
                if self.lca_certificate and issuer_id == self.lca_certificate.subject_id:
                    issuer_cert_obj = self.lca_certificate
                elif self.rca_certificate and issuer_id == self.rca_certificate.subject_id:
                    issuer_cert_obj = self.rca_certificate
                else: 
                    issuer_cert_obj = self.certificate_store.get_certificate(issuer_id)
                
                current_c = issuer_cert_obj
                if not current_c and issuer_id not in visited_subjects_for_chain:
                    logger.info(f"Не удалось найти сертификат издателя '{issuer_id}' при построении цепочки для отправки.")


            if not my_chain_to_send_data: 
                logger.error("Ошибка: не удалось сформировать цепочку сертификатов для отправки.")
                messagebox.showerror("Ошибка", "Не удалось сформировать цепочку сертификатов для отправки.", parent=self.root)
                return

            message_payload = {
                "sender_id": self.node_id,
                "encrypted_a": enc_a,
                "encrypted_b": enc_b,
                "signature_r": sig_r,
                "signature_s": sig_s,
                "original_message_hash_h_sender": hash_h, # Добавляем хеш
                "sender_certificate_chain": my_chain_to_send_data
            }
            
            logger.info(f"Отправка сообщения для {recipient_id} ({recipient_ip}:{recipient_port}) с цепочкой из {len(my_chain_to_send_data)} сертификатов.")
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

    def fetch_recipient_certificate_action(self):
        if not self.p or not self.g:
            messagebox.showerror("Ошибка", "Параметры P и G не установлены. Сначала получите их от LCA (кнопка 0).", parent=self.root)
            return

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
            is_trusted, _, verification_msg_existing = self.verify_certificate_chain(recipient_cert) # Получаем детали
            if is_trusted:
                messagebox.showinfo("Сертификат найден", f"Сертификат для '{recipient_id}' уже есть в хранилище и он доверенный.\nДетали: {verification_msg_existing}", parent=self.root)
                self.load_known_certificates() 
                try:
                    idx = list(self.known_certs_listbox.get(0, tk.END)).index(recipient_id)
                    self.known_certs_listbox.select_clear(0, tk.END)
                    self.known_certs_listbox.select_set(idx)
                    self.known_certs_listbox.activate(idx)
                    self.on_known_cert_select(None)
                except ValueError:
                    pass 
                return
            else:
                logger.warning(f"Найден сертификат для '{recipient_id}', но он не прошел проверку доверия ({verification_msg_existing}). Попытка получить новый.")
        
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
                target_recipient_cert_obj = None
                for cert_data in certs_chain_data:
                    try:
                        cert = Certificate.from_dict(cert_data)
                        self.certificate_store.add_certificate(cert, save_to_file=True) # Сохраняем все сертификаты из цепочки
                        parsed_certs.append(cert)
                        if cert.subject_id == recipient_id: 
                            target_recipient_cert_obj = cert
                    except Exception as e_parse:
                        logger.error(f"Ошибка парсинга сертификата из цепочки от {recipient_id}: {e_parse}")
                
                if not target_recipient_cert_obj and parsed_certs: 
                    if parsed_certs[0].subject_id == recipient_id:
                        target_recipient_cert_obj = parsed_certs[0]
                        logger.info(f"Сертификат получателя '{recipient_id}' взят как первый из цепочки.")
                    else:
                        logger.warning(f"Сертификат получателя '{recipient_id}' не найден по ID в цепочке, и первый сертификат ({parsed_certs[0].subject_id}) не совпадает.")
                elif not parsed_certs: 
                     messagebox.showerror("Ошибка", "Не удалось распарсить сертификаты из цепочки.", parent=self.root)
                     return

                if not target_recipient_cert_obj:
                    messagebox.showerror("Ошибка", f"Сертификат для '{recipient_id}' не найден в полученной цепочке или не удалось его идентифицировать.", parent=self.root)
                    return
                
                is_trusted, _, verification_msg_fetched = self.verify_certificate_chain(target_recipient_cert_obj)
                if is_trusted:
                    messagebox.showinfo("Успех", f"Сертификат для '{target_recipient_cert_obj.subject_id}' и его цепочка получены и проверены.\nДетали: {verification_msg_fetched}", parent=self.root)
                else:
                    messagebox.showwarning("Внимание", f"Цепочка сертификатов для '{target_recipient_cert_obj.subject_id}' не подтверждена!\nДетали: {verification_msg_fetched}", parent=self.root)
                self.load_known_certificates() # Обновить список в любом случае
            else:
                error_msg = response.get("message", "Не удалось получить сертификат.") if response else "Нет ответа."
                messagebox.showerror("Ошибка", f"Ошибка от {recipient_id}: {error_msg}", parent=self.root)
        
        except (NetworkError, ConnectionClosedError, MessageFormatError, socket.timeout) as e:
            logger.error(f"Сетевая ошибка при получении сертификата {recipient_id}: {e}")
            messagebox.showerror("Сетевая ошибка", f"Ошибка при получении сертификата: {e}", parent=self.root)
        except Exception as e:
            logger.error(f"Ошибка при получении сертификата {recipient_id}: {e}")
            import traceback
            logger.debug(traceback.format_exc())
            messagebox.showerror("Ошибка", f"Произошла ошибка: {e}", parent=self.root)
        finally:
            if sock: sock.close()

    def test_prime_p_action(self):
        if not self.p:
            messagebox.showerror("Ошибка", "Параметр P не установлен. Сначала получите P и G от LCA.", parent=self.root)
            return

        logger.info(f"Проверка простоты числа P={self.p}:")
        
        trial_result = PrimeManager._is_prime_trial_division(self.p)
        logger.info(f"1. Trial Division Test: {'ВЕРОЯТНО ПРОСТОЕ' if trial_result else 'СОСТАВНОЕ'}")
        
        lcg = LCG(self.get_next_lcg_seed())
        fermat_result = PrimeManager._is_prime_fermat(self.p, k=5, lcg_instance=lcg)
        logger.info(f"2. Fermat Test (k=5): {'ВЕРОЯТНО ПРОСТОЕ' if fermat_result else 'СОСТАВНОЕ'}")
        
        miller_rabin_result = PrimeManager._is_prime_miller_rabin(self.p, k=64, lcg_instance=lcg)
        logger.info(f"3. Miller-Rabin Test (k=64): {'ВЕРОЯТНО ПРОСТОЕ' if miller_rabin_result else 'СОСТАВНОЕ'}")
        
        if trial_result and fermat_result and miller_rabin_result:
            result_message = "Число P прошло все тесты на простоту:\n\n"
        else:
            result_message = "Число P НЕ прошло некоторые тесты на простоту:\n\n"
            
        result_message += f"1. Trial Division Test: {'ВЕРОЯТНО ПРОСТОЕ' if trial_result else 'СОСТАВНОЕ'}\n"
        result_message += f"2. Fermat Test (k=5): {'ВЕРОЯТНО ПРОСТОЕ' if fermat_result else 'СОСТАВНОЕ'}\n"
        result_message += f"3. Miller-Rabin Test (k=64): {'ВЕРОЯТНО ПРОСТОЕ' if miller_rabin_result else 'СОСТАВНОЕ'}"
        
        messagebox.showinfo("Результаты проверки простоты", result_message, parent=self.root)

    def decrypt_message_action(self):
        if not self.current_message_data: # Проверяем наличие исходных данных
            messagebox.showerror("Ошибка", "Нет данных сообщения для расшифровки (из self.current_message_data).", parent=self.root)
            return

        try:
            # Получаем зашифрованное сообщение из GUI поля (могло быть изменено атакой)
            encrypted_text_from_gui = self.encrypted_message_text.get(1.0, tk.END).strip()
            try:
                gui_data = json.loads(encrypted_text_from_gui)
                enc_a = int(gui_data["encrypted_a"])
                enc_b = int(gui_data["encrypted_b"])
                sig_r = int(gui_data["signature_r"]) # Берем подпись из GUI
                sig_s = int(gui_data["signature_s"]) # Берем подпись из GUI
                sender_id = gui_data["sender_id"]
                # Хеш отправителя берем из исходных (неизмененных) данных, если он там был
                original_hash_h_sender = self.current_message_data.get("original_message_hash_h_sender")
                if original_hash_h_sender is not None:
                    original_hash_h_sender = int(original_hash_h_sender)

            except (json.JSONDecodeError, KeyError, ValueError) as e:
                messagebox.showerror("Ошибка", f"Неверный формат данных в поле зашифрованного сообщения: {e}", parent=self.root)
                return

            if not self.key_pair_encryption["private_xe"]:
                messagebox.showerror("Ошибка", "Отсутствует ваш закрытый ключ для расшифрования (XE).", parent=self.root)
                return

            decrypted_numeric_m = ElGamalCrypto.decrypt(enc_a, enc_b, self.p, self.g, self.key_pair_encryption["private_xe"])
            decrypted_message_text = MessageUtils.numeric_to_message(decrypted_numeric_m)
            
            hash_h_receiver = MessageUtils.hash_message_for_elgamal(decrypted_message_text, self.p - 1)
            hash_match_status = "неизвестно (хеш отправителя отсутствует)"
            if original_hash_h_sender is not None:
                 hash_match_status = 'ДА' if hash_h_receiver == original_hash_h_sender else 'НЕТ'


            # --- Проверка подписи и сертификата ---
            # Получаем цепочку сертификатов из GUI (могла быть изменена атакой)
            cert_chain_text_from_gui = self.received_cert_text.get(1.0, tk.END).strip()
            sender_cert_chain_list_of_dicts = []
            try:
                sender_cert_chain_list_of_dicts = json.loads(cert_chain_text_from_gui)
                if not isinstance(sender_cert_chain_list_of_dicts, list):
                    raise ValueError("Цепочка сертификатов должна быть списком.")
            except (json.JSONDecodeError, ValueError) as e:
                messagebox.showerror("Ошибка", f"Неверный формат JSON для цепочки сертификатов: {e}", parent=self.root)
                # Продолжаем без проверки сертификата, если он не может быть распарсен
            
            sender_cert_obj = None
            parsed_chain_for_verification = []
            if sender_cert_chain_list_of_dicts:
                try:
                    # Пытаемся распарсить всю цепочку из GUI
                    for cert_data_gui in sender_cert_chain_list_of_dicts:
                        # Коррекция ключей перед парсингом (на всякий случай, если атака их изменила)
                        if "subject id" in cert_data_gui: cert_data_gui["subject_id"] = cert_data_gui.pop("subject id")
                        if "issuer id" in cert_data_gui: cert_data_gui["issuer_id"] = cert_data_gui.pop("issuer id")
                        if "valid from" in cert_data_gui: cert_data_gui["valid_from"] = cert_data_gui.pop("valid from")
                        if "valid to" in cert_data_gui: cert_data_gui["valid_to"] = cert_data_gui.pop("valid to")
                        
                        parsed_cert_gui = Certificate.from_dict(cert_data_gui)
                        parsed_chain_for_verification.append(parsed_cert_gui)
                        # Находим сертификат отправителя (первый в цепочке из GUI)
                        if parsed_cert_gui.subject_id == sender_id and sender_cert_obj is None:
                             sender_cert_obj = parsed_cert_gui
                    
                    if not sender_cert_obj and parsed_chain_for_verification: # Если ID не совпал, но есть первый элемент
                        sender_cert_obj = parsed_chain_for_verification[0]
                        logger.warning(f"ID отправителя '{sender_id}' не совпал с ID первого серт. в цепочке из GUI ('{sender_cert_obj.subject_id}'). Используем первый для проверки подписи.")
                except Exception as e_parse_chain_gui:
                    logger.error(f"Ошибка парсинга сертификата(ов) из GUI для проверки подписи: {e_parse_chain_gui}")
                    sender_cert_obj = None # Не удалось распарсить
            
            signature_valid_status = "невозможно проверить (сертификат отправителя не найден/не распарсен из GUI)"
            cert_trust_status = "неизвестно (сертификат отправителя не найден/не распарсен из GUI)"

            if sender_cert_obj:
                if sender_cert_obj.subject_public_key_ys:
                    is_sig_ok = ElGamalCrypto.verify(hash_h_receiver, sig_r, sig_s, 
                                                         self.p, self.g, 
                                                         sender_cert_obj.subject_public_key_ys)
                    signature_valid_status = 'ДА' if is_sig_ok else 'НЕТ'
                else:
                    signature_valid_status = "невозможно проверить (у сертификата отправителя нет ключа YS)"

                # Проверяем доверие к сертификату отправителя (взятому из GUI)
                is_trusted_gui_cert, _, trust_verification_msg_gui = self.verify_certificate_chain(sender_cert_obj)
                cert_trust_status = f"{'ДОВЕРЕННЫЙ' if is_trusted_gui_cert else 'НЕ ДОВЕРЕННЫЙ'}. Детали: {trust_verification_msg_gui}"
            # --- Конец проверки подписи и сертификата ---

            logger.info(f"Результаты расшифровки сообщения от {sender_id}:")
            logger.info(f"  Расшифрованный текст: {decrypted_message_text}")
            logger.info(f"  Совпадение хеша с оригинальным хешем отправителя: {hash_match_status}")
            logger.info(f"  Статус сертификата отправителя (из GUI): {cert_trust_status}")
            logger.info(f"  Подпись (проверена по сертификату из GUI): {signature_valid_status}")

            status_text = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Результат расшифровки сообщения от {sender_id}:\n"
            status_text += f"  Расшифрованный текст: {decrypted_message_text}\n"
            status_text += f"  Совпадение хеша (H_расшифр == H_отправителя_ориг): {hash_match_status}\n"
            status_text += f"  Статус сертификата отправителя (взятого из поля GUI): {cert_trust_status}\n"
            status_text += f"  Подпись сообщения (проверена по ключу YS из сертификата отправителя, взятого из поля GUI): {signature_valid_status}\n\n"

            self.received_messages_text.config(state=tk.NORMAL)
            self.received_messages_text.insert(tk.END, status_text)
            self.received_messages_text.see(tk.END)
            self.received_messages_text.config(state=tk.DISABLED)
            self.load_known_certificates()

        except Exception as e:
            logger.error(f"Ошибка при расшифровке сообщения: {e}")
            import traceback
            logger.debug(traceback.format_exc())
            messagebox.showerror("Ошибка", f"Не удалось расшифровать сообщение: {e}", parent=self.root)

    def simulate_message_attack_action(self):
        if not self.current_message_data:
            messagebox.showerror("Ошибка", "Нет данных сообщения для атаки.", parent=self.root)
            return
        try:
            current_text = self.encrypted_message_text.get(1.0, tk.END).strip()
            current_data = json.loads(current_text)

            dialog = tk.Toplevel(self.root)
            dialog.title("Изменение данных сообщения и подписи")
            dialog.transient(self.root)
            dialog.grab_set()
            
            entries = {}
            fields_to_edit = ["encrypted_a", "encrypted_b", "signature_r", "signature_s"]
            row_idx = 0
            for field in fields_to_edit:
                ttk.Label(dialog, text=f"{field}:").grid(row=row_idx, column=0, padx=5, pady=2, sticky=tk.W)
                entry = ttk.Entry(dialog, width=50)
                entry.insert(0, str(current_data.get(field, "")))
                entry.grid(row=row_idx, column=1, padx=5, pady=2)
                entries[field] = entry
                row_idx +=1
            
            # Добавим оригинальный хеш, если он есть (только для просмотра, не для редактирования здесь)
            original_hash_h = current_data.get("original_message_hash_h_sender")
            if original_hash_h is not None:
                ttk.Label(dialog, text="original_message_hash_h_sender (эталон):").grid(row=row_idx, column=0, padx=5, pady=2, sticky=tk.W)
                ttk.Label(dialog, text=str(original_hash_h)).grid(row=row_idx, column=1, padx=5, pady=2, sticky=tk.W)
                row_idx +=1


            def apply_changes():
                try:
                    for field, entry_widget in entries.items():
                        current_data[field] = int(entry_widget.get()) # Все поля числовые
                    
                    self.encrypted_message_text.delete(1.0, tk.END)
                    self.encrypted_message_text.insert(1.0, json.dumps(current_data, indent=2, ensure_ascii=False))
                    dialog.destroy()
                    messagebox.showinfo("Успех", "Значения успешно изменены.", parent=self.root)
                except ValueError as e:
                    messagebox.showerror("Ошибка", f"Неверный формат чисел: {e}", parent=dialog)

            ttk.Button(dialog, text="Применить", command=apply_changes).grid(row=row_idx, column=0, columnspan=2, pady=10)
            dialog.wait_window()

        except Exception as e:
            logger.error(f"Ошибка при имитации атаки на сообщение: {e}")
            messagebox.showerror("Ошибка", f"Не удалось выполнить атаку: {e}", parent=self.root)

    def verify_received_cert_action(self):
        """Проверяет цепочку сертификатов, отображенную в GUI (возможно, измененную)."""
        cert_text_from_gui = self.received_cert_text.get(1.0, tk.END).strip()
        if not cert_text_from_gui:
            messagebox.showerror("Ошибка", "Нет данных сертификата для проверки в поле GUI.", parent=self.root)
            return

        try:
            cert_chain_data_from_gui = json.loads(cert_text_from_gui)
            if not isinstance(cert_chain_data_from_gui, list) or not cert_chain_data_from_gui:
                messagebox.showerror("Ошибка", "Данные в поле сертификатов должны быть непустым списком JSON объектов.", parent=self.root)
                return
            
            # Пытаемся распарсить сертификат отправителя (первый в цепочке из GUI)
            # Эта часть кода дублируется с decrypt_message_action, можно вынести в хелпер
            parsed_sender_cert_from_gui = None
            try:
                first_cert_data_gui = cert_chain_data_from_gui[0]
                 # Коррекция ключей перед парсингом
                if "subject id" in first_cert_data_gui: first_cert_data_gui["subject_id"] = first_cert_data_gui.pop("subject id")
                if "issuer id" in first_cert_data_gui: first_cert_data_gui["issuer_id"] = first_cert_data_gui.pop("issuer id")
                if "valid from" in first_cert_data_gui: first_cert_data_gui["valid_from"] = first_cert_data_gui.pop("valid from")
                if "valid to" in first_cert_data_gui: first_cert_data_gui["valid_to"] = first_cert_data_gui.pop("valid to")
                parsed_sender_cert_from_gui = Certificate.from_dict(first_cert_data_gui)
            except Exception as e_parse_first_gui:
                messagebox.showerror("Ошибка парсинга", f"Не удалось распарсить первый сертификат из поля GUI: {e_parse_first_gui}", parent=self.root)
                logger.error(f"Ошибка парсинга первого сертификата из GUI: {e_parse_first_gui}")
                # Не сохраняем в хранилище, если не удалось распарсить
            
            # Если первый сертификат успешно распарсен, сохраняем его в хранилище
            # и затем пытаемся сохранить остальные (для полноты, verify_certificate_chain сам их найдет если надо)
            if parsed_sender_cert_from_gui:
                self.certificate_store.add_certificate(parsed_sender_cert_from_gui, save_to_file=True) # Сохраняем (или обновляем)
                
                # Пытаемся сохранить остальные сертификаты из цепочки (если они есть и парсятся)
                if len(cert_chain_data_from_gui) > 1:
                    for cert_data_item_gui in cert_chain_data_from_gui[1:]:
                        try:
                            if "subject id" in cert_data_item_gui: cert_data_item_gui["subject_id"] = cert_data_item_gui.pop("subject id")
                            if "issuer id" in cert_data_item_gui: cert_data_item_gui["issuer_id"] = cert_data_item_gui.pop("issuer id")
                            if "valid from" in cert_data_item_gui: cert_data_item_gui["valid_from"] = cert_data_item_gui.pop("valid from")
                            if "valid to" in cert_data_item_gui: cert_data_item_gui["valid_to"] = cert_data_item_gui.pop("valid to")
                            
                            intermediate_cert_gui = Certificate.from_dict(cert_data_item_gui)
                            self.certificate_store.add_certificate(intermediate_cert_gui, save_to_file=True)
                        except Exception as e_parse_intermediate:
                            logger.warning(f"Не удалось распарсить или сохранить промежуточный сертификат из GUI: {e_parse_intermediate}")
                            # Продолжаем, даже если один из промежуточных не распарсился

            # Проверяем цепочку, начиная с первого сертификата из GUI
            # verify_certificate_chain будет использовать сертификаты из хранилища (включая только что добавленные/обновленные)
            verification_status_text = ""
            if parsed_sender_cert_from_gui:
                is_trusted_gui, chain_gui, verification_detail_msg_gui = self.verify_certificate_chain(parsed_sender_cert_from_gui)
                
                verification_status_text = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Результат проверки цепочки сертификатов (из поля GUI):\n"
                verification_status_text += f"  Целевой сертификат для проверки: '{parsed_sender_cert_from_gui.subject_id}' (S/N: {parsed_sender_cert_from_gui.serial_number})\n"
                verification_status_text += f"  Статус доверия: {'ПОДТВЕРЖДЕНА' if is_trusted_gui else 'НЕ ПОДТВЕРЖДЕНА'}\n"
                verification_status_text += f"  Детали проверки: {verification_detail_msg_gui}\n"
                if chain_gui:
                    verification_status_text += f"  Построенный путь: {' -> '.join([c.subject_id for c in chain_gui])}\n"
            else: # Если даже первый сертификат из GUI не удалось распарсить
                verification_status_text = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] " \
                                           f"Проверка невозможна: не удалось распарсить первый сертификат из предоставленных данных в поле GUI.\n"
            verification_status_text += "\n"

            self.received_messages_text.config(state=tk.NORMAL)
            self.received_messages_text.insert(tk.END, verification_status_text)
            self.received_messages_text.see(tk.END)
            self.received_messages_text.config(state=tk.DISABLED)

            self.load_known_certificates() # Обновить список известных сертификатов

        except json.JSONDecodeError as e:
            messagebox.showerror("Ошибка формата", f"Неверный формат JSON в поле сертификатов: {e}", parent=self.root)
        except Exception as e:
            logger.error(f"Ошибка при проверке сертификата из GUI: {e}")
            import traceback
            logger.debug(traceback.format_exc())
            messagebox.showerror("Ошибка", f"Не удалось проверить сертификат(ы) из поля GUI: {e}", parent=self.root)

    def simulate_cert_attack_action(self):
        current_cert_text_gui = self.received_cert_text.get(1.0, tk.END).strip()
        if not current_cert_text_gui: # Проверка, если поле пустое
             # Если current_cert_chain_data есть (от последнего полученного сообщения), используем его
            if self.current_cert_chain_data:
                current_cert_text_gui = json.dumps(self.current_cert_chain_data, indent=2, ensure_ascii=False)
                self.received_cert_text.insert(1.0, current_cert_text_gui) # Заполняем поле для редактирования
            else:
                messagebox.showerror("Ошибка", "Нет данных сертификата для атаки (ни в поле GUI, ни от последнего сообщения).", parent=self.root)
                return
        try:
            # Данные для редактирования берем из поля GUI
            cert_chain_data_to_edit = json.loads(current_cert_text_gui)

            dialog = tk.Toplevel(self.root)
            dialog.title("Изменение данных цепочки сертификатов (JSON)")
            dialog.transient(self.root)
            dialog.grab_set()

            text_edit = scrolledtext.ScrolledText(dialog, width=80, height=20, wrap=tk.WORD)
            text_edit.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)
            text_edit.insert(1.0, json.dumps(cert_chain_data_to_edit, indent=2, ensure_ascii=False))

            def apply_changes():
                try:
                    new_data_str = text_edit.get(1.0, tk.END)
                    new_data_json = json.loads(new_data_str) # Проверяем, что это валидный JSON
                    
                    self.received_cert_text.delete(1.0, tk.END)
                    self.received_cert_text.insert(1.0, json.dumps(new_data_json, indent=2, ensure_ascii=False))
                    # Важно: self.current_cert_chain_data не обновляем здесь, оно хранит оригинальную цепочку от сообщения
                    dialog.destroy()
                    messagebox.showinfo("Успех", "Данные сертификатов в поле GUI успешно изменены.", parent=self.root)
                except json.JSONDecodeError as e:
                    messagebox.showerror("Ошибка", f"Неверный формат JSON: {e}", parent=dialog)

            ttk.Button(dialog, text="Применить изменения в поле GUI", command=apply_changes).pack(pady=10)
            dialog.wait_window()

        except json.JSONDecodeError as e: # Если исходные данные в GUI были не JSON
            messagebox.showerror("Ошибка формата", f"Неверный формат JSON в поле сертификатов для редактирования: {e}", parent=self.root)
        except Exception as e:
            logger.error(f"Ошибка при имитации атаки на сертификат: {e}")
            messagebox.showerror("Ошибка", f"Не удалось выполнить атаку: {e}", parent=self.root)

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

    default_lca_id_from_client_id = client_id_input.split('@')[-1] if '@' in client_id_input else "LCA1" # Эвристика
    
    # Пытаемся угадать порт LCA по его ID (LCA1 -> 10001, LCA2 -> 10002)
    default_lca_port = 10001 
    if default_lca_id_from_client_id == "LCA1":
        default_lca_port = 10001
    elif default_lca_id_from_client_id == "LCA2":
        default_lca_port = 10002
    # Можно добавить больше LCA или сделать более гибкую настройку

    root_client = tk.Tk()
    app_client = ClientApp(root_client, 
                           node_id=client_id_input, 
                           default_port=client_port,
                           lca_default_port=default_lca_port)
    root_client.mainloop()

# END OF FILE: client_app.py