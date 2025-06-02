# START OF FILE: client_app.py
import os
import socket
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, scrolledtext
import logging
import datetime
import json

from base_node_app import BaseNodeApp
from elgamal_utils import ElGamalCrypto, MessageUtils, PrimeManager
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
        super().__init__(root, node_id, default_port, config_file_name="client_config.json")
        self.root.title(f"Клиент: {self.node_id}")

        # 3. Создание специфичных для клиента GUI элементов
        self.create_client_specific_gui()

        # 4. Обновление GUI полей lca_host и lca_port
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


    def create_client_specific_gui(self):
        client_panel = ttk.Labelframe(self.control_panel, text="Действия клиента")
        client_panel.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10, pady=5)

        ttk.Button(client_panel, text="0. Получить параметры от LCA", command=self.fetch_lca_params_action_client).pack(side=tk.LEFT, padx=5)
        ttk.Button(client_panel, text="1. Сгенерировать ключи", command=self.generate_client_keys_action).pack(side=tk.LEFT, padx=5)
        
        lca_conn_frame = ttk.Frame(client_panel)
        lca_conn_frame.pack(side=tk.LEFT, padx=10)
        ttk.Label(lca_conn_frame, text="LCA IP:").grid(row=0, column=0, sticky=tk.W)
        self.lca_ip_entry = ttk.Entry(lca_conn_frame, width=15)
        self.lca_ip_entry.grid(row=0, column=1, sticky=tk.W)
        # self.lca_ip_entry.insert(0, self.lca_host) # Будет в __init__

        ttk.Label(lca_conn_frame, text="LCA Port:").grid(row=1, column=0, sticky=tk.W)
        self.lca_port_entry = ttk.Entry(lca_conn_frame, width=7)
        self.lca_port_entry.grid(row=1, column=1, sticky=tk.W)
        # self.lca_port_entry.insert(0, str(self.lca_port)) # Будет в __init__

        ttk.Button(client_panel, text="2. Запросить свой сертификат у LCA", command=self.request_my_certificate_from_lca_action).pack(side=tk.LEFT, padx=5)

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

    def fetch_lca_params_action_client(self):
        if self.p and self.g and self.lca_certificate: # Проверяем и LCA сертификат, т.к. p,g из него
            # RCA сертификат может быть None, это допустимо, если LCA его не прислал
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
                
                self.lca_certificate = parsed_lca_cert # Сохраняем объект сертификата
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

                # Если p,g изменились, ИЛИ если ключей еще нет, ИЛИ если ключи были, но p,g изменились
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
                else: # p,g не изменились, и ключи уже были (значит, они для этих p,g)
                     messagebox.showinfo("Параметры P,G актуальны",
                                        f"Параметры P={self.p}, G={self.g} и сертификаты LCA/RCA актуальны.",
                                        parent=self.root)
                self.load_known_certificates()
                self.update_key_displays() # Обновить p,g на дисплее
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
        if not self.lca_certificate: # Нужен сертификат LCA для проверки и информации
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
            # p и g клиента теперь должны совпадать с p и g LCA,
            # LCA будет использовать свои p и g при создании сертификата клиента.
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
                # LCA может снова прислать свой сертификат и RCA, обновим их на всякий случай
                lca_cert_data_resp = response.get("lca_certificate")
                rca_cert_data_resp = response.get("rca_certificate")

                if not client_cert_data:
                    messagebox.showerror("Ошибка ответа LCA", "LCA не прислал сертификат клиента.", parent=self.root)
                    return
                
                if lca_cert_data_resp:
                    try:
                        # Проверяем, не изменился ли сертификат LCA с момента последнего получения
                        parsed_lca_cert_resp = Certificate.from_dict(lca_cert_data_resp)
                        if not self.lca_certificate or self.lca_certificate.serial_number != parsed_lca_cert_resp.serial_number:
                            logger.info("Сертификат LCA был обновлен от LCA.")
                            self.lca_certificate = parsed_lca_cert_resp
                            self.certificate_store.add_certificate(self.lca_certificate, save_to_file=True)
                            # Если p,g LCA изменились, это большая проблема, но LCA не должен их менять просто так
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
                    # ... (дополнительные логи для отладки ошибки проверки, как были ранее) ...
                    messagebox.showerror("Ошибка проверки", "Подпись полученного сертификата недействительна!", parent=self.root)
            else:
                error_msg = response.get("message", "Неизвестная ошибка от LCA.")
                logger.error(f"LCA вернул ошибку: {error_msg}")
                messagebox.showerror("Ошибка от LCA", f"LCA вернул ошибку: {error_msg}", parent=self.root)
        # ... (except и finally) ...
        finally:
            if lca_sock:
                lca_sock.close()

    def load_known_certificates(self):
        if not hasattr(self, 'known_certs_listbox'):
            logger.warning("load_known_certificates: known_certs_listbox еще не создан.")
            return
            
        self.known_certs_listbox.delete(0, tk.END)
        
        # Явное добавление известных важных сертификатов, если они есть в памяти
        # Это поможет им появиться в списке, даже если они еще не были сохранены/загружены из файла
        # в этот конкретный экземпляр certificate_store (хотя они должны добавляться при установке)
        temp_certs_to_display = {}
        if self.own_certificate: temp_certs_to_display[self.own_certificate.subject_id] = self.own_certificate
        if self.lca_certificate: temp_certs_to_display[self.lca_certificate.subject_id] = self.lca_certificate
        if self.rca_certificate: temp_certs_to_display[self.rca_certificate.subject_id] = self.rca_certificate

        # Добавляем все из хранилища, перезаписывая из temp_certs_to_display, если subject_id совпадает,
        # чтобы гарантировать, что в списке самые актуальные объекты из памяти.
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

        # Ищем сертификат сначала среди основных (own, lca, rca), потом в хранилище
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
            
            if is_other_party_cert: # Проверяем только "чужие" сертификаты
                self.known_cert_details_text.insert(tk.END, "\n\n--- Проверка цепочки доверия ---\n")
                is_trusted, chain = self.verify_certificate_chain(cert_to_display)
                if is_trusted:
                    self.known_cert_details_text.insert(tk.END, "Цепочка доверия ПОДТВЕРЖДЕНА.\n")
                else:
                    self.known_cert_details_text.insert(tk.END, "Цепочка доверия НЕ ПОДТВЕРЖДЕНА.\n")
                if chain:
                    self.known_cert_details_text.insert(tk.END, f"Цепочка: {[c.subject_id for c in chain]}\n")
                else:
                    self.known_cert_details_text.insert(tk.END, "Цепочка не построена.\n")
        else:
            self.known_cert_details_text.insert(tk.END, f"Сертификат для {selected_subject_id} не найден.")
        self.known_cert_details_text.config(state=tk.DISABLED)

    def verify_certificate_chain(self, target_cert: Certificate):
        if not target_cert: return False, []
        if not self.rca_certificate:
            logger.warning("Невозможно проверить цепочку: сертификат RCA отсутствует у клиента.")
            return False, [target_cert]
        if not self.lca_certificate and target_cert.issuer_id != self.rca_certificate.subject_id:
             logger.warning(f"Невозможно проверить цепочку для {target_cert.subject_id}: сертификат LCA отсутствует у клиента, а издатель не RCA.")
             return False, [target_cert]


        chain = []
        current_cert_obj = target_cert
        visited_subjects_in_chain = set() # Для предотвращения циклов

        max_depth = 10
        current_depth = 0

        while current_depth < max_depth:
            current_depth += 1
            if not current_cert_obj: # Добавлено для защиты
                logger.error("Ошибка в verify_certificate_chain: current_cert_obj стал None.")
                return False, chain

            if current_cert_obj.subject_id in visited_subjects_in_chain:
                logger.error(f"Обнаружен цикл в цепочке сертификатов при проверке {target_cert.subject_id}. Субъект {current_cert_obj.subject_id} уже был в цепочке.")
                return False, chain
            
            visited_subjects_in_chain.add(current_cert_obj.subject_id)
            chain.append(current_cert_obj)

            if not current_cert_obj.is_currently_valid():
                logger.warning(f"Сертификат {current_cert_obj.subject_id} в цепочке недействителен по дате.")
                return False, chain
            
            # Если текущий сертификат выдан RCA
            if current_cert_obj.issuer_id == self.rca_certificate.subject_id:
                if current_cert_obj.subject_id == self.rca_certificate.subject_id: # Это сам RCA
                    if current_cert_obj.verify_signature(self.rca_certificate.subject_public_key_ys): # Самоподпись
                        logger.info(f"Цепочка для {target_cert.subject_id} дошла до доверенного RCA и самоподпись верна.")
                        return True, chain
                    else:
                        logger.warning(f"Самоподпись сертификата RCA ({self.rca_certificate.subject_id}) неверна.")
                        return False, chain
                else: # Сертификат выдан RCA (например, это LCA)
                    if current_cert_obj.verify_signature(self.rca_certificate.subject_public_key_ys):
                        logger.info(f"Сертификат {current_cert_obj.subject_id} (выдан RCA) проверен. Цепочка для {target_cert.subject_id} доверенная.")
                        return True, chain # Достигли доверенного издателя
                    else:
                        logger.warning(f"Подпись сертификата {current_cert_obj.subject_id}, выданного RCA, неверна.")
                        return False, chain
            
            # Иначе, ищем сертификат издателя в известных
            # Сначала проверяем, не является ли издатель нашим известным LCA
            issuer_cert_obj = None
            if self.lca_certificate and current_cert_obj.issuer_id == self.lca_certificate.subject_id:
                issuer_cert_obj = self.lca_certificate
            else: # Иначе ищем в общем хранилище
                issuer_cert_obj = self.certificate_store.get_certificate(current_cert_obj.issuer_id)

            if not issuer_cert_obj:
                logger.warning(f"Сертификат издателя '{current_cert_obj.issuer_id}' для '{current_cert_obj.subject_id}' не найден.")
                return False, chain

            if not current_cert_obj.verify_signature(issuer_cert_obj.subject_public_key_ys):
                logger.warning(f"Подпись сертификата '{current_cert_obj.subject_id}' издателем '{issuer_cert_obj.subject_id}' неверна.")
                return False, chain
            
            current_cert_obj = issuer_cert_obj # Переходим к следующему сертификату в цепочке
        
        logger.warning(f"Цепочка для {target_cert.subject_id} не дошла до доверенного RCA за {max_depth} шагов.")
        return False, chain
    
    # fetch_recipient_certificate_action, send_message_action, process_command - остаются как в вашем последнем варианте, но с учетом,
    # что p,g теперь должны быть корректно установлены перед их использованием.

    def load_configuration(self):
        super().load_configuration()
        try:
            if os.path.exists(self.config_file_path):
                with open(self.config_file_path, 'r', encoding='utf-8') as f:
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

    def save_configuration(self):
        current_lca_host = self.lca_host
        current_lca_port = self.lca_port
        if hasattr(self, 'lca_ip_entry'): current_lca_host = self.lca_ip_entry.get()
        if hasattr(self, 'lca_port_entry'):
            try:
                current_lca_port = int(self.lca_port_entry.get())
            except ValueError:
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
            os.makedirs(os.path.dirname(self.config_file_path), exist_ok=True) # Убедимся, что директория есть
            with open(self.config_file_path, 'w', encoding='utf-8') as f:
                json.dump(config_data, f, indent=4, ensure_ascii=False)
            logger.info(f"Конфигурация Клиента сохранена в {self.config_file_path}")
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
        
        is_trusted, _ = self.verify_certificate_chain(recipient_cert)
        if not is_trusted:
            if not messagebox.askyesno("Внимание", f"Сертификат получателя '{recipient_id}' не является доверенным или цепочка не проверена. Отправить все равно?", parent=self.root):
                return

        if not recipient_cert.subject_public_key_ye:
            messagebox.showerror("Ошибка", f"У сертификата получателя '{recipient_id}' отсутствует публичный ключ для шифрования (YE).", parent=self.root)
            return

        sock = None
        try:
            # 1. Шифрование сообщения
            # Убедимся, что self.p используется для определения максимальной длины сообщения
            m_numeric = MessageUtils.message_to_numeric(message_text, self.p)
            enc_a, enc_b = ElGamalCrypto.encrypt(m_numeric, self.p, self.g,
                                                 recipient_cert.subject_public_key_ye,
                                                 self.get_next_lcg_seed())
            logger.info(f"Сообщение для '{recipient_id}' зашифровано: a={enc_a}, b={enc_b}")

            # 2. Подпись сообщения (хеша)
            hash_h = MessageUtils.hash_message_for_elgamal(message_text, self.p - 1)
            sig_r, sig_s = ElGamalCrypto.sign(hash_h, self.p, self.g,
                                              self.key_pair_signature["private_xs"],
                                              self.get_next_lcg_seed())
            logger.info(f"Сообщение для '{recipient_id}' подписано: r={sig_r}, s={sig_s}")

            # 3. Формирование пакета и отправка
            my_chain_to_send_data = []
            current_c = self.own_certificate
            visited_subjects_for_chain = set()
            while current_c and current_c.subject_id not in visited_subjects_for_chain:
                my_chain_to_send_data.append(current_c.to_dict())
                visited_subjects_for_chain.add(current_c.subject_id)
                if current_c.subject_id == current_c.issuer_id: # Дошли до самоподписанного (RCA)
                    break
                # Ищем издателя в известных нам сертификатах
                issuer_cert_obj = None
                if self.lca_certificate and current_c.issuer_id == self.lca_certificate.subject_id:
                    issuer_cert_obj = self.lca_certificate
                elif self.rca_certificate and current_c.issuer_id == self.rca_certificate.subject_id:
                    issuer_cert_obj = self.rca_certificate
                else:
                    issuer_cert_obj = self.certificate_store.get_certificate(current_c.issuer_id)
                current_c = issuer_cert_obj


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

    def fetch_recipient_certificate_action(self):
        """ Пытается получить сертификат получателя и его цепочку. """
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
            
        # 0. Проверить, есть ли уже сертификат в локальном хранилище
        recipient_cert = self.certificate_store.get_certificate(recipient_id)
        if recipient_cert:
            is_trusted, _ = self.verify_certificate_chain(recipient_cert)
            if is_trusted:
                messagebox.showinfo("Сертификат найден", f"Сертификат для '{recipient_id}' уже есть в хранилище и он доверенный.", parent=self.root)
                self.load_known_certificates() # Обновить GUI, чтобы выбрать его, если нужно
                # Выбираем сертификат в списке, если он там есть
                try:
                    idx = list(self.known_certs_listbox.get(0, tk.END)).index(recipient_id)
                    self.known_certs_listbox.select_clear(0, tk.END)
                    self.known_certs_listbox.select_set(idx)
                    self.known_certs_listbox.activate(idx)
                    self.on_known_cert_select(None)
                except ValueError:
                    pass # Не найден в списке, ничего страшного
                return
            else:
                logger.warning(f"Найден сертификат для '{recipient_id}', но он не прошел проверку доверия. Попытка получить новый.")
        
        # 1. Подключиться к получателю и запросить его сертификат и цепочку
        sock = None
        try:
            logger.info(f"Попытка получить сертификат от {recipient_id} ({recipient_ip}:{recipient_port})")
            sock = connect_to_server(recipient_ip, recipient_port, timeout=5.0)
            if not sock:
                messagebox.showerror("Ошибка", f"Не удалось подключиться к {recipient_id}.", parent=self.root)
                return

            # Команда "get_own_certificate_chain" должна быть реализована на стороне клиента/узла
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
                        self.certificate_store.add_certificate(cert, save_to_file=True)
                        parsed_certs.append(cert)
                        if cert.subject_id == recipient_id: # Нашли сертификат самого получателя
                            target_recipient_cert_obj = cert
                    except Exception as e_parse:
                        logger.error(f"Ошибка парсинга сертификата из цепочки от {recipient_id}: {e_parse}")
                        # Не прерываем весь процесс, если один из промежуточных сертификатов не распарсился,
                        # но это плохой знак.
                
                if not target_recipient_cert_obj and parsed_certs: # Если по ID не нашли, но что-то есть
                    logger.warning(f"Сертификат получателя '{recipient_id}' не найден по ID в цепочке, используем первый: {parsed_certs[0].subject_id}")
                    target_recipient_cert_obj = parsed_certs[0] # Берем первый, надеясь, что это он
                elif not parsed_certs: # Если ничего не распарсилось
                     messagebox.showerror("Ошибка", "Не удалось распарсить сертификаты из цепочки.", parent=self.root)
                     return


                if not target_recipient_cert_obj:
                    messagebox.showerror("Ошибка", f"Сертификат для '{recipient_id}' не найден в полученной цепочке.", parent=self.root)
                    return
                
                # Проверяем цепочку для полученного сертификата получателя
                is_trusted, _ = self.verify_certificate_chain(target_recipient_cert_obj)
                if is_trusted:
                    messagebox.showinfo("Успех", f"Сертификат для '{target_recipient_cert_obj.subject_id}' и его цепочка получены и проверены.", parent=self.root)
                    self.load_known_certificates() # Обновить список в GUI
                else:
                    messagebox.showwarning("Внимание", f"Цепочка сертификатов для '{target_recipient_cert_obj.subject_id}' не подтверждена!", parent=self.root)
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

if __name__ == "__main__":
    # Пример запуска клиента. ID должен быть в формате "имя@LCA_ID"
    # Например, если LCA1 слушает на 10001, а RCA на 10000
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

    # Определение порта LCA на основе ID клиента (упрощенно)
    default_lca_port = 10001 # Порт для LCA1 по умолчанию
    if "@LCA2" in client_id_input:
        default_lca_port = 10002 # Порт для LCA2 по умолчанию

    root_client = tk.Tk()
    app_client = ClientApp(root_client, 
                           node_id=client_id_input, 
                           default_port=client_port,
                           lca_default_port=default_lca_port)
    root_client.mainloop()

# END OF FILE: client_app.py