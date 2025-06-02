# START OF FILE: client_app.py
import os # <--- ДОБАВЬТЕ ЭТУ СТРОКУ
import socket # <--- УБЕДИТЕСЬ, ЧТО ЭТА СТРОКА ТОЖЕ ЕСТЬ (нужна для network_utils, если он не импортирует сам)
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, scrolledtext
import logging
import datetime # Для работы с датами в сертификатах
import json # Для сериализации/десериализации

from base_node_app import BaseNodeApp
from elgamal_utils import ElGamalCrypto, MessageUtils # LCG, PrimeManager уже в BaseNodeApp
from certificate_manager import Certificate # CertificateStore уже в BaseNodeApp
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
        self.create_client_specific_gui() # Создает self.lca_ip_entry, known_certs_listbox и т.д.

        # 4. Обновление GUI полей lca_host и lca_port значениями,
        # которые могли быть загружены в self.lca_host/port из ClientApp.load_configuration()
        if hasattr(self, 'lca_ip_entry'): # Проверка на всякий случай
            self.lca_ip_entry.delete(0, tk.END)
            self.lca_ip_entry.insert(0, self.lca_host)
        if hasattr(self, 'lca_port_entry'):
            self.lca_port_entry.delete(0, tk.END)
            self.lca_port_entry.insert(0, str(self.lca_port))
            
        # 5. Загрузка и отображение известных сертификатов (теперь GUI полностью готово)
        self.load_known_certificates() # <--- Перенесено сюда

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
        self.lca_ip_entry.insert(0, self.lca_host)
        ttk.Label(lca_conn_frame, text="LCA Port:").grid(row=1, column=0, sticky=tk.W)
        self.lca_port_entry = ttk.Entry(lca_conn_frame, width=7)
        self.lca_port_entry.grid(row=1, column=1, sticky=tk.W)
        self.lca_port_entry.insert(0, str(self.lca_port))

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
        
        # Верхняя часть: отправка сообщения
        send_frame = ttk.LabelFrame(frame, text="Отправить сообщение")
        send_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(send_frame, text="ID Получателя:").grid(row=0, column=0, padx=5, pady=2, sticky=tk.W)
        self.recipient_id_entry = ttk.Entry(send_frame, width=40)
        self.recipient_id_entry.grid(row=0, column=1, padx=5, pady=2, sticky=tk.EW)
        # Пример: client2@LCA1 или client3@LCA2
        
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

        # Нижняя часть: полученные сообщения
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
            # Ключи для шифрования (xe, ye)
            priv_xe, pub_ye = ElGamalCrypto.generate_keys(self.p, self.g, self.get_next_lcg_seed())
            self.key_pair_encryption = {"private_xe": priv_xe, "public_ye": pub_ye}
            
            # Ключи для подписи (xs, ys)
            priv_xs, pub_ys = ElGamalCrypto.generate_keys(self.p, self.g, self.get_next_lcg_seed())
            self.key_pair_signature = {"private_xs": priv_xs, "public_ys": pub_ys}

            logger.info(f"Сгенерированы ключи для клиента '{self.node_id}'. YE: {pub_ye}, YS: {pub_ys}")
            self.update_key_displays()
            messagebox.showinfo("Успех", "Ключи клиента успешно сгенерированы.", parent=self.root)
            self.own_certificate = None # Сброс сертификата, т.к. ключи изменились
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
            logger.info(f"Получен ответ от LCA: {str(response)[:250]}...") # Увеличил длину лога для отладки

            if response.get("status") == "ok":
                client_cert_data = response.get("client_certificate")
                lca_cert_data = response.get("lca_certificate")
                rca_cert_data_from_lca = response.get("rca_certificate") # Ожидаем сертификат RCA здесь

                if not client_cert_data or not lca_cert_data:
                    messagebox.showerror("Ошибка ответа", "Ответ LCA не содержит сертификат клиента и/или сертификат LCA.", parent=self.root)
                    return
                
                # 1. Обработка сертификата LCA
                try:
                    self.lca_certificate = Certificate.from_dict(lca_cert_data)
                    self.certificate_store.add_certificate(self.lca_certificate, save_to_file=True)
                    logger.info(f"Сертификат LCA '{self.lca_certificate.subject_id}' получен и сохранен.")
                except (ValueError, KeyError) as e_lca_parse:
                    logger.error(f"Ошибка парсинга сертификата LCA: {e_lca_parse}. Данные: {lca_cert_data}")
                    messagebox.showerror("Ошибка парсинга", f"Не удалось обработать сертификат LCA: {e_lca_parse}", parent=self.root)
                    return
                
                # Устанавливаем p и g из сертификата LCA (они должны быть глобальными и согласованными)
                self.p = self.lca_certificate.p
                self.g = self.lca_certificate.g
                logger.info(f"Установлены p={self.p}, g={self.g} из сертификата LCA.")

                # 2. Обработка сертификата RCA (если он был прислан)
                if rca_cert_data_from_lca:
                    try:
                        self.rca_certificate = Certificate.from_dict(rca_cert_data_from_lca)
                        self.certificate_store.add_certificate(self.rca_certificate, save_to_file=True)
                        logger.info(f"Сертификат RCA '{self.rca_certificate.subject_id}' получен от LCA и сохранен.")
                    except (ValueError, KeyError) as e_rca_parse:
                        logger.warning(f"Ошибка парсинга сертификата RCA от LCA: {e_rca_parse}. Данные: {rca_cert_data_from_lca}")
                        # Не критично для получения своего сертификата, но важно для цепочек
                else:
                    logger.warning("Сертификат RCA не был получен от LCA в основном ответе.")
                    # Можно добавить логику запроса сертификата RCA отдельно, если он очень нужен и не пришел,
                    # но это усложнит и вернет к предыдущей проблеме, если LCA закрывает соединение.
                    # Лучше, чтобы LCA всегда присылал свой RCA сертификат, если он у него есть.

                # 3. Обработка собственного сертификата клиента
                try:
                    self.own_certificate = Certificate.from_dict(client_cert_data)
                except (ValueError, KeyError) as e_client_parse:
                    logger.error(f"Ошибка парсинга собственного сертификата клиента: {e_client_parse}. Данные: {client_cert_data}")
                    messagebox.showerror("Ошибка парсинга", f"Не удалось обработать собственный сертификат: {e_client_parse}", parent=self.root)
                    return

                # Проверяем, что p и g в нашем сертификате соответствуют p и g от LCA
                if self.own_certificate.p != self.p or self.own_certificate.g != self.g:
                    logger.error(f"Несоответствие параметров p/g в сертификате клиента! Сертификат клиента p,g: ({self.own_certificate.p},{self.own_certificate.g}), LCA p,g: ({self.p},{self.g})")
                    messagebox.showerror("Ошибка параметров", "Параметры p/g в полученном сертификате не соответствуют параметрам УЦ (LCA).", parent=self.root)
                    self.own_certificate = None # Считаем сертификат невалидным
                # Проверяем подпись нашего сертификата, используя публичный ключ LCA
                elif self.own_certificate.verify_signature(self.lca_certificate.subject_public_key_ys):
                    self.certificate_store.add_certificate(self.own_certificate, save_to_file=True)
                    logger.info(f"Сертификат для клиента '{self.node_id}' получен, проверен и сохранен.")
                    self.update_key_displays() # Обновить отображение ключей и сертификата
                    self.load_known_certificates() # Обновить список известных сертификатов в GUI
                    messagebox.showinfo("Успех", "Сертификат от LCA успешно получен и проверен.", parent=self.root)
                else:
                    self.own_certificate = None # Сбрасываем, если проверка не прошла
                    logger.error("Полученный от LCA сертификат клиента не прошел проверку подписи!")
                    messagebox.showerror("Ошибка проверки", "Подпись полученного сертификата недействительна!", parent=self.root)
            else:
                error_msg = response.get("message", "Неизвестная ошибка от LCA.")
                logger.error(f"LCA вернул ошибку: {error_msg}")
                messagebox.showerror("Ошибка от LCA", f"LCA вернул ошибку: {error_msg}", parent=self.root)

        except (NetworkError, ConnectionClosedError, MessageFormatError, socket.timeout) as e:
            logger.error(f"Сетевая ошибка при запросе сертификата у LCA: {e}")
            messagebox.showerror("Сетевая ошибка", f"Ошибка при обмене данными с LCA: {e}", parent=self.root)
        except (ValueError, KeyError) as e_parse: # Общая ошибка парсинга данных, если Certificate.from_dict выдаст ошибку
            logger.error(f"Ошибка обработки данных сертификата от LCA: {e_parse}")
            import traceback
            logger.debug(traceback.format_exc())
            messagebox.showerror("Ошибка данных", f"Некорректные данные сертификата от LCA: {e_parse}", parent=self.root)
        except Exception as e:
            logger.error(f"Непредвиденная ошибка при запросе сертификата у LCA: {e}")
            import traceback
            logger.debug(traceback.format_exc())
            messagebox.showerror("Ошибка", f"Произошла ошибка: {e}", parent=self.root)
        finally:
            if lca_sock:
                lca_sock.close() # Закрываем соединение после одного обмена "запрос-ответ"
    
    def load_known_certificates(self):
        """Загружает сертификаты из хранилища и обновляет GUI."""
        self.known_certs_listbox.delete(0, tk.END)
        # Загружаем все сертификаты из директории хранилища (если есть)
        # CertificateStore.load_certificate_from_file() добавляет в self.certs
        # Нам нужно убедиться, что все файлы из директории загружены, если они не в памяти.
        # Это уже должно делаться при вызове certificate_store.get_certificate или load_certificate_from_file.
        # Здесь мы просто перебираем то, что уже есть в self.certificate_store.certs
        
        # Попытка загрузить сертификаты LCA и RCA, если они еще не загружены из конфига
        if not self.lca_certificate:
            lca_id_part = self.node_id.split('@')[1] if '@' in self.node_id else None
            if lca_id_part:
                lca_cert = self.certificate_store.load_certificate_from_file(lca_id_part)
                if lca_cert: self.lca_certificate = lca_cert

        if not self.rca_certificate and self.lca_certificate: # Если есть LCA, но нет RCA
             # Пытаемся загрузить RCA, если он был сохранен ранее (например, RootCA)
             rca_cert_cand = self.certificate_store.load_certificate_from_file("RootCA") # Стандартное имя
             if rca_cert_cand : self.rca_certificate = rca_cert_cand
        
        # Обновляем список известных сертификатов
        sorted_ids = sorted(list(self.certificate_store.list_subject_ids()))
        for subject_id in sorted_ids:
            self.known_certs_listbox.insert(tk.END, subject_id)
        
        if self.known_certs_listbox.size() > 0:
            self.known_certs_listbox.select_set(0)
            self.on_known_cert_select(None)

    def on_known_cert_select(self, event):
        selection = self.known_certs_listbox.curselection()
        if not selection: return
        selected_subject_id = self.known_certs_listbox.get(selection[0])
        
        cert = self.certificate_store.get_certificate(selected_subject_id)
        self.known_cert_details_text.config(state=tk.NORMAL)
        self.known_cert_details_text.delete(1.0, tk.END)
        if cert:
            self.known_cert_details_text.insert(tk.END, json.dumps(cert.to_dict(), indent=2, ensure_ascii=False))
            # Дополнительно: проверка цепочки доверия для выбранного сертификата
            if cert.subject_id != self.node_id and cert.subject_id != (self.lca_certificate.subject_id if self.lca_certificate else None) \
               and cert.subject_id != (self.rca_certificate.subject_id if self.rca_certificate else None):
                # Это сертификат другого клиента/LCA
                self.known_cert_details_text.insert(tk.END, "\n\n--- Проверка цепочки доверия ---\n")
                is_trusted, chain = self.verify_certificate_chain(cert)
                if is_trusted:
                    self.known_cert_details_text.insert(tk.END, "Цепочка доверия ПОДТВЕРЖДЕНА.\n")
                else:
                    self.known_cert_details_text.insert(tk.END, "Цепочка доверия НЕ ПОДТВЕРЖДЕНА.\n")
                self.known_cert_details_text.insert(tk.END, f"Цепочка: {[c.subject_id for c in chain]}\n")

        else:
            self.known_cert_details_text.insert(tk.END, f"Сертификат для {selected_subject_id} не найден.")
        self.known_cert_details_text.config(state=tk.DISABLED)

    def verify_certificate_chain(self, target_cert: Certificate):
        """
        Проверяет цепочку сертификатов до доверенного RCA.
        Возвращает (bool: is_trusted, list: chain_of_certificates)
        """
        if not self.rca_certificate:
            logger.warning("Невозможно проверить цепочку: сертификат RCA отсутствует.")
            return False, [target_cert]

        chain = [target_cert]
        current_cert = target_cert

        # Проверяем даты самого целевого сертификата
        if not current_cert.is_currently_valid():
            logger.warning(f"Целевой сертификат {current_cert.subject_id} недействителен по дате.")
            return False, chain


        while current_cert.subject_id != self.rca_certificate.subject_id:
            issuer_id = current_cert.issuer_id
            issuer_cert = self.certificate_store.get_certificate(issuer_id)

            if not issuer_cert:
                logger.warning(f"Сертификат издателя '{issuer_id}' для '{current_cert.subject_id}' не найден в хранилище.")
                return False, chain
            
            if not issuer_cert.is_currently_valid():
                 logger.warning(f"Сертификат издателя {issuer_cert.subject_id} недействителен по дате.")
                 return False, chain

            # Проверяем подпись current_cert с помощью issuer_cert.public_key_ys
            if not current_cert.verify_signature(issuer_cert.subject_public_key_ys):
                logger.warning(f"Подпись сертификата '{current_cert.subject_id}' недействительна (издатель '{issuer_id}').")
                return False, chain
            
            chain.append(issuer_cert)
            current_cert = issuer_cert

            if len(chain) > 10: # Защита от зацикливания
                logger.error("Слишком длинная цепочка сертификатов, возможна петля.")
                return False, chain
        
        # Последний сертификат в цепочке должен быть RCA, и он должен быть самоподписанным (проверяется issuer_id == subject_id)
        # и его подпись должна быть верна (проверяется verify_signature с его же ключом)
        if current_cert.subject_id == self.rca_certificate.subject_id and \
           current_cert.verify_signature(current_cert.subject_public_key_ys): # Проверка самоподписи RCA
            logger.info(f"Цепочка сертификатов для '{target_cert.subject_id}' успешно проверена до RCA.")
            return True, chain
        else:
            logger.warning(f"Конечный сертификат в цепочке '{current_cert.subject_id}' не является доверенным RCA или его самоподпись неверна.")
            return False, chain


    def fetch_recipient_certificate_action(self):
        """ Пытается получить сертификат получателя и его цепочку. """
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
                return
            else:
                logger.warning(f"Найден сертификат для '{recipient_id}', но он не прошел проверку доверия. Попытка получить новый.")
        
        # 1. Подключиться к получателю и запросить его сертификат (команда "get_own_certificate")
        # Получатель должен быть онлайн и слушать на указанном IP/порту.
        # Это упрощенный механизм, в реальности мог бы быть центральный каталог.
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
                certs_chain_data = response.get("certificate_chain", []) # Ожидаем список словарей сертификатов
                if not certs_chain_data:
                    messagebox.showerror("Ошибка", f"От {recipient_id} получена пустая цепочка сертификатов.", parent=self.root)
                    return

                # Сохраняем и проверяем всю цепочку
                parsed_certs = []
                for cert_data in certs_chain_data:
                    try:
                        cert = Certificate.from_dict(cert_data)
                        self.certificate_store.add_certificate(cert, save_to_file=True)
                        parsed_certs.append(cert)
                    except Exception as e_parse:
                        logger.error(f"Ошибка парсинга сертификата из цепочки от {recipient_id}: {e_parse}")
                        messagebox.showerror("Ошибка", "Ошибка при обработке сертификата из цепочки.", parent=self.root)
                        return
                
                if not parsed_certs:
                    messagebox.showerror("Ошибка", "Не удалось распарсить сертификаты из цепочки.", parent=self.root)
                    return

                target_recipient_cert = parsed_certs[0] # Первый в цепочке - сертификат самого получателя
                if target_recipient_cert.subject_id != recipient_id:
                     logger.warning(f"Получен сертификат для {target_recipient_cert.subject_id}, ожидали для {recipient_id}")
                     # Можно добавить проверку

                is_trusted, _ = self.verify_certificate_chain(target_recipient_cert)
                if is_trusted:
                    messagebox.showinfo("Успех", f"Сертификат для '{recipient_id}' и его цепочка получены и проверены.", parent=self.root)
                    self.load_known_certificates() # Обновить список в GUI
                else:
                    messagebox.showwarning("Внимание", f"Цепочка сертификатов для '{recipient_id}' не подтверждена!", parent=self.root)
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
            messagebox.showwarning("Внимание", f"Сертификат получателя '{recipient_id}' не является доверенным. Отправка на ваш страх и риск.", parent=self.root)
            # Можно добавить if not messagebox.askyesno(...) return

        sock = None
        try:
            # 1. Шифрование сообщения
            m_numeric = MessageUtils.message_to_numeric(message_text, self.p) # Используем p отправителя/системы
            # Шифруем публичным ключом шифрования получателя (из его сертификата)
            enc_a, enc_b = ElGamalCrypto.encrypt(m_numeric, self.p, self.g, 
                                                 recipient_cert.subject_public_key_ye, 
                                                 self.get_next_lcg_seed())
            logger.info(f"Сообщение для '{recipient_id}' зашифровано: a={enc_a}, b={enc_b}")

            # 2. Подпись сообщения (хеша)
            # Используем тот же p-1 для хеширования, что и при проверке
            hash_h = MessageUtils.hash_message_for_elgamal(message_text, self.p - 1)
            # Подписываем своим закрытым ключом подписи
            sig_r, sig_s = ElGamalCrypto.sign(hash_h, self.p, self.g,
                                              self.key_pair_signature["private_xs"],
                                              self.get_next_lcg_seed())
            logger.info(f"Сообщение для '{recipient_id}' подписано: r={sig_r}, s={sig_s}")

            # 3. Формирование пакета и отправка
            # Отправляем: шифртекст, подпись, и нашу цепочку сертификатов
            # (свой серт + серт LCA + серт RCA)
            # Получатель должен сам собрать цепочку из известных ему сертификатов,
            # но для простоты иногда передают всю цепочку до общего корня.
            # Мы передадим наш сертификат, а получатель уже сам достроит цепочку.
            # Более правильно: передать цепочку [свой_серт, серт_LCA, серт_RCA]
            # или просто [свой_серт, серт_LCA] (т.к. RCA все должны знать)
            
            # Собираем свою цепочку для отправки (если есть)
            my_chain_to_send_data = []
            if self.own_certificate: my_chain_to_send_data.append(self.own_certificate.to_dict())
            if self.lca_certificate: my_chain_to_send_data.append(self.lca_certificate.to_dict())
            # RCA сертификат получатель может запросить у своего LCA или у самого RCA, если нужно.
            # Или мы можем его тоже включить, если он у нас есть.
            if self.rca_certificate and self.rca_certificate not in [self.own_certificate, self.lca_certificate]:
                 # Добавляем RCA, только если он не совпадает с LCA (что маловероятно, но возможно если LCA=RCA)
                 # и не является нашим собственным сертификатом.
                 # Убедимся, что не дублируем, если lca_certificate - это сертификат RCA (для LCA, запрашивающего у RCA)
                 if not any(c["subject_id"] == self.rca_certificate.subject_id for c in my_chain_to_send_data):
                      my_chain_to_send_data.append(self.rca_certificate.to_dict())


            message_payload = {
                "sender_id": self.node_id,
                "encrypted_a": enc_a,
                "encrypted_b": enc_b,
                "signature_r": sig_r,
                "signature_s": sig_s,
                "original_message_hash_h_sender": hash_h, # Для отладки и демонстрации
                "sender_certificate_chain": my_chain_to_send_data # Отправляем нашу цепочку
            }
            
            logger.info(f"Отправка сообщения для {recipient_id} ({recipient_ip}:{recipient_port})")
            sock = connect_to_server(recipient_ip, recipient_port)
            if not sock:
                messagebox.showerror("Ошибка", f"Не удалось подключиться к {recipient_id}.", parent=self.root)
                return

            send_json_message(sock, {"command": "receive_message", "payload": message_payload})
            
            # Ожидаем подтверждение от получателя
            ack = receive_json_message(sock, timeout=10.0)
            if ack and ack.get("status") == "ok":
                logger.info(f"Сообщение успешно доставлено {recipient_id}: {ack.get('message')}")
                messagebox.showinfo("Успех", f"Сообщение успешно отправлено {recipient_id}.", parent=self.root)
            else:
                error_msg = ack.get("message", "Получатель не подтвердил получение.") if ack else "Нет ответа от получателя."
                logger.warning(f"Ошибка доставки сообщения {recipient_id}: {error_msg}")
                messagebox.showwarning("Доставка", f"Сообщение отправлено, но: {error_msg}", parent=self.root)

        except ValueError as ve: # Например, от message_to_numeric
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
                # original_hash_h = int(payload["original_message_hash_h_sender"]) # Можно использовать для сверки
                sender_cert_chain_data = payload.get("sender_certificate_chain", [])

                # 1. Сохранить и проверить цепочку сертификатов отправителя
                sender_cert = None
                if sender_cert_chain_data:
                    parsed_sender_certs = []
                    for cert_data in sender_cert_chain_data:
                        try:
                            cert = Certificate.from_dict(cert_data)
                            self.certificate_store.add_certificate(cert, save_to_file=True) # Сохраняем/обновляем
                            parsed_sender_certs.append(cert)
                        except Exception as e_parse:
                            logger.error(f"Ошибка парсинга сертификата из цепочки от {sender_id}: {e_parse}")
                    
                    if parsed_sender_certs and parsed_sender_certs[0].subject_id == sender_id:
                        sender_cert = parsed_sender_certs[0]
                    else:
                        logger.warning(f"Первый сертификат в цепочке от {sender_id} не соответствует ID отправителя.")
                        # Попробуем найти по ID, если он уже был загружен
                        sender_cert = self.certificate_store.get_certificate(sender_id)

                if not sender_cert:
                    logger.error(f"Сертификат отправителя '{sender_id}' не найден или не получен.")
                    return {"status": "error", "message": f"Sender certificate for '{sender_id}' not found."}

                is_sender_trusted, _ = self.verify_certificate_chain(sender_cert)
                if not is_sender_trusted:
                    logger.warning(f"Сертификат отправителя '{sender_id}' не является доверенным!")
                    # В реальной системе здесь можно было бы отклонить сообщение
                    # Для демо - продолжим, но с предупреждением в логе.
                    # return {"status": "error", "message": f"Sender '{sender_id}' is not trusted."}


                # 2. Дешифрование сообщения
                # Дешифруем нашим закрытым ключом шифрования
                decrypted_numeric = ElGamalCrypto.decrypt(enc_a, enc_b, self.p, self.g, 
                                                          self.key_pair_encryption["private_xe"])
                decrypted_message = MessageUtils.numeric_to_message(decrypted_numeric)
                logger.info(f"Сообщение от '{sender_id}' дешифровано: '{decrypted_message}'")

                # 3. Проверка подписи
                # Пересчитываем хеш полученного (дешифрованного) сообщения
                # Важно: p-1 для хеширования должен быть тем же, что использовал отправитель
                # Предполагаем, что p - это системный параметр
                local_hash_h = MessageUtils.hash_message_for_elgamal(decrypted_message, self.p - 1)
                
                # Проверяем подпись публичным ключом подписи отправителя (из его сертификата)
                is_signature_valid = ElGamalCrypto.verify(local_hash_h, sig_r, sig_s, self.p, self.g, 
                                                          sender_cert.subject_public_key_ys)
                
                log_msg_prefix = f"Сообщение от {sender_id}: '{decrypted_message}'"
                if is_signature_valid:
                    logger.info(f"Подпись для сообщения от '{sender_id}' действительна.")
                    display_msg = f"{log_msg_prefix} (Подпись ВЕРНА)"
                    status_msg = "Message received, decrypted, and signature verified."
                else:
                    logger.warning(f"Подпись для сообщения от '{sender_id}' НЕдействительна!")
                    display_msg = f"{log_msg_prefix} (Подпись НЕВЕРНА!)"
                    status_msg = "Message received, decrypted, BUT SIGNATURE IS INVALID."

                # Отображаем в GUI
                self.received_messages_text.config(state=tk.NORMAL)
                self.received_messages_text.insert(tk.END, f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {display_msg}\n")
                self.received_messages_text.see(tk.END)
                self.received_messages_text.config(state=tk.DISABLED)
                
                self.load_known_certificates() # Обновить список, т.к. могли прийти новые сертификаты

                return {"status": "ok", "message": status_msg}

            except Exception as e:
                logger.error(f"Ошибка при обработке входящего сообщения от {addr}: {e}")
                import traceback
                logger.debug(traceback.format_exc())
                return {"status": "error", "message": f"Error processing incoming message: {e}"}

        elif command == "get_own_certificate_chain": # Запрос нашей цепочки сертификатов
            chain_data = []
            if self.own_certificate: chain_data.append(self.own_certificate.to_dict())
            if self.lca_certificate: chain_data.append(self.lca_certificate.to_dict())
            if self.rca_certificate: chain_data.append(self.rca_certificate.to_dict())
            # Удаление дубликатов по subject_id, если они есть (маловероятно, но возможно)
            unique_chain_data = []
            seen_subjects = set()
            for cert_d in chain_data:
                if cert_d['subject_id'] not in seen_subjects:
                    unique_chain_data.append(cert_d)
                    seen_subjects.add(cert_d['subject_id'])

            if unique_chain_data:
                return {"status": "ok", "certificate_chain": unique_chain_data}
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
            # messagebox.showinfo("Сохранение", "Конфигурация Клиента успешно сохранена.", parent=self.root) # Убрал, чтобы не мешало при автосохранении
        except Exception as e:
            logger.error(f"Ошибка сохранения конфигурации Клиента: {e}")
            # messagebox.showerror("Ошибка", f"Не удалось сохранить конфигурацию Клиента: {e}", parent=self.root)


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