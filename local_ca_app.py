# START OF FILE: local_ca_app.py

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import logging
import datetime # Для работы с датами в сертификатах
import json # Для сериализации/десериализации
import os
import socket

from base_node_app import BaseNodeApp
from elgamal_utils import ElGamalCrypto, PrimeManager # LCG, PrimeManager уже в BaseNodeApp
from certificate_manager import Certificate # CertificateStore уже в BaseNodeApp
from network_utils import connect_to_server, send_json_message, receive_json_message, \
                          ConnectionClosedError, MessageFormatError, NetworkError


logger = logging.getLogger(__name__)

class LocalCAApp(BaseNodeApp):
    def __init__(self, root, node_id, default_port, rca_default_host="127.0.0.1", rca_default_port=10000):
        # 1. Инициализация атрибутов, не зависящих от GUI или super()
        self.rca_host = rca_default_host
        self.rca_port = rca_default_port
        self.rca_certificate = None # Сертификат RCA, полученный от него

        # 2. Вызов super().__init__()
        # Он вызовет BaseNodeApp.setup_gui() и LocalCAApp.load_configuration() (переопределенный)
        super().__init__(root, node_id, default_port, config_file_name=f"lca_{node_id}_config.json")
        self.root.title(f"Локальный УЦ (LCA): {self.node_id}")

        # 3. Создание специфичных для LCA GUI элементов
        self.create_lca_specific_gui() # Создает self.rca_ip_entry и т.д.

        # 4. Обновление GUI полей rca_host и rca_port значениями,
        # которые могли быть загружены в self.rca_host/port из LocalCAApp.load_configuration()
        if hasattr(self, 'rca_ip_entry'): # Проверка на всякий случай
            self.rca_ip_entry.delete(0, tk.END)
            self.rca_ip_entry.insert(0, self.rca_host)
        if hasattr(self, 'rca_port_entry'):
            self.rca_port_entry.delete(0, tk.END)
            self.rca_port_entry.insert(0, str(self.rca_port))

        # 5. Загрузка и отображение выданных сертификатов (теперь GUI полностью готово)
        self.load_issued_client_certificates()
        
        # 6. Финальные проверки и логирование
        if self.p and self.g and not self.own_certificate:
             logger.warning(f"LCA '{self.node_id}' имеет p и g, но нет собственного сертификата. Запросите у RCA.")
        elif not self.p or not self.g:
             logger.warning(f"LCA '{self.node_id}' не имеет параметров p и g. Получите их от RCA (через запрос сертификата).")

        logger.info(f"Локальный УЦ '{self.node_id}' инициализирован.")

        # 7. Настраиваем начальный размер окна
        self.root.update_idletasks()  # Обновляем информацию о размерах виджетов
        width = max(800, self.root.winfo_reqwidth())  # Минимум 800 или требуемая ширина
        height = max(600, self.root.winfo_reqheight())  # Минимум 600 или требуемая высота
        x = (self.root.winfo_screenwidth() - width) // 2
        y = (self.root.winfo_screenheight() - height) // 2
        self.root.geometry(f"{width}x{height}+{x}+{y}")  # Устанавливаем размер и позицию окна

    def create_lca_specific_gui(self):
        """ Добавляет специфичные для LCA элементы в GUI. """
        # Панель для параметров подключения к RCA
        rca_conn_panel = ttk.Labelframe(self.control_panel, text="Параметры подключения к RCA")
        rca_conn_panel.pack(side=tk.TOP, fill=tk.X, expand=True, padx=10, pady=5)

        ttk.Label(rca_conn_panel, text="IP RCA:").pack(side=tk.LEFT, padx=5)
        self.rca_ip_entry = ttk.Entry(rca_conn_panel, width=15)
        self.rca_ip_entry.pack(side=tk.LEFT, padx=5)
        self.rca_ip_entry.insert(0, self.rca_host)

        ttk.Label(rca_conn_panel, text="Порт RCA:").pack(side=tk.LEFT, padx=5)
        self.rca_port_entry = ttk.Entry(rca_conn_panel, width=6)
        self.rca_port_entry.pack(side=tk.LEFT, padx=5)
        self.rca_port_entry.insert(0, str(self.rca_port))

        # Панель для действий LCA
        lca_panel = ttk.Labelframe(self.control_panel, text="Действия LCA")
        lca_panel.pack(side=tk.TOP, fill=tk.X, expand=True, padx=10, pady=5)

        # Создаем фрейм для кнопок внутри панели
        buttons_frame = ttk.Frame(lca_panel)
        buttons_frame.pack(padx=5, pady=5)

        # Список всех кнопок и их команд
        buttons = [
            ("0. Получить параметры от RCA", self.fetch_rca_params_action),
            ("Проверить P на простоту", self.test_prime_p_action),
            ("1. Сгенерировать ключи LCA", self.generate_lca_keys_action),
            ("2. Запросить сертификат LCA у RCA", self.request_lca_certificate_from_rca_action),
            ("Просмотреть выданные сертификаты клиентов", self.view_issued_client_certs_action)
        ]

        # Размещаем кнопки в сетке по 3 в ряд
        for i, (text, command) in enumerate(buttons):
            row = i // 3  # Целочисленное деление для определения строки
            col = i % 3   # Остаток от деления для определения столбца
            ttk.Button(buttons_frame, text=text, command=command).grid(
                row=row, column=col, padx=5, pady=5, sticky="ew"
            )

        # Вкладка для отображения выданных сертификатов клиентов
        self.issued_client_certs_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.issued_client_certs_tab, text="Выданные сертификаты клиентов")
        
        self.issued_client_certs_listbox = tk.Listbox(self.issued_client_certs_tab, width=80, height=15)
        self.issued_client_certs_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        client_certs_scrollbar = ttk.Scrollbar(self.issued_client_certs_tab, orient=tk.VERTICAL, command=self.issued_client_certs_listbox.yview)
        client_certs_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.issued_client_certs_listbox.config(yscrollcommand=client_certs_scrollbar.set)
        
        self.issued_client_certs_listbox.bind('<<ListboxSelect>>', self.on_client_cert_select)

        self.client_cert_details_text = tk.Text(self.issued_client_certs_tab, wrap=tk.WORD, height=10, width=60, state=tk.DISABLED)
        self.client_cert_details_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

    def fetch_rca_params_action(self): # НОВЫЙ МЕТОД
        if self.p and self.g and self.rca_certificate:
            if not messagebox.askyesno("Подтверждение",
                                       "Параметры P, G и сертификат RCA уже существуют. Запросить заново?",
                                       parent=self.root):
                return

        self.rca_host = self.rca_ip_entry.get()
        try:
            self.rca_port = int(self.rca_port_entry.get())
        except ValueError:
            messagebox.showerror("Ошибка", "Порт RCA должен быть числом.", parent=self.root)
            return

        rca_sock = None
        try:
            logger.info(f"LCA ({self.node_id}) запрашивает публичную информацию у RCA {self.rca_host}:{self.rca_port}...")
            rca_sock = connect_to_server(self.rca_host, self.rca_port)
            if not rca_sock:
                messagebox.showerror("Ошибка соединения", f"Не удалось подключиться к RCA по адресу {self.rca_host}:{self.rca_port}", parent=self.root)
                return

            send_json_message(rca_sock, {"command": "get_rca_public_info", "payload": {}}) # Используем новую команду
            logger.info(f"LCA ({self.node_id}) отправил запрос get_rca_public_info к RCA.")

            response = receive_json_message(rca_sock, timeout=30.0)
            if not response:
                messagebox.showerror("Ошибка ответа", "RCA не ответил или ответ некорректен на get_rca_public_info.", parent=self.root)
                return
            logger.info(f"LCA ({self.node_id}) получил ответ от RCA на get_rca_public_info: {str(response)[:200]}...")

            if response.get("status") == "ok":
                rca_cert_data = response.get("rca_certificate")
                if not rca_cert_data:
                    messagebox.showerror("Ошибка ответа RCA", "RCA не прислал свой сертификат в ответе на get_rca_public_info.", parent=self.root)
                    return
                
                try:
                    self.rca_certificate = Certificate.from_dict(rca_cert_data)
                    self.certificate_store.add_certificate(self.rca_certificate, save_to_file=True)
                except Exception as e_parse:
                    logger.error(f"Ошибка парсинга сертификата RCA: {e_parse}")
                    messagebox.showerror("Ошибка парсинга", f"Не удалось обработать сертификат RCA: {e_parse}", parent=self.root)
                    return

                new_p = self.rca_certificate.p
                new_g = self.rca_certificate.g

                if self.p != new_p or self.g != new_g or not self.key_pair_signature["public_ys"]:
                    logger.info(f"LCA ({self.node_id}) установил/обновил p и g от RCA: p={new_p}, g={new_g}.")
                    self.p = new_p
                    self.g = new_g
                    # Сбрасываем ключи и собственный сертификат, т.к. p,g изменились или ключи не были для них
                    if self.key_pair_signature["public_ys"] or self.own_certificate:
                         logger.warning("Параметры p,g изменились или были установлены. Существующие ключи LCA и сертификат (если были) сброшены.")
                         self.key_pair_encryption = {"private_xe": None, "public_ye": None}
                         self.key_pair_signature = {"private_xs": None, "public_ys": None}
                         self.own_certificate = None
                    self.update_key_displays()
                    messagebox.showinfo("Параметры P,G получены",
                                        f"От RCA получены параметры: P={self.p}, G={self.g} и сертификат RCA.\n"
                                        "Теперь сгенерируйте ключи LCA (кнопка 1).",
                                        parent=self.root)
                else:
                    logger.info(f"LCA ({self.node_id}) подтвердил p и g от RCA: p={self.p}, g={self.g}. Изменений нет, ключи существуют.")
                    messagebox.showinfo("Параметры P,G актуальны",
                                        f"Параметры P={self.p}, G={self.g} и сертификат RCA актуальны.",
                                        parent=self.root)
            else:
                error_msg = response.get("message", "Неизвестная ошибка от RCA при получении public_info.")
                messagebox.showerror("Ошибка от RCA", f"RCA вернул ошибку: {error_msg}", parent=self.root)

        except (NetworkError, ConnectionClosedError, MessageFormatError, socket.timeout) as e:
            logger.error(f"Сетевая ошибка при запросе public_info у RCA: {e}")
            messagebox.showerror("Сетевая ошибка", f"Ошибка при обмене данными с RCA: {e}", parent=self.root)
        except Exception as e:
            logger.error(f"Непредвиденная ошибка при запросе public_info у RCA: {e}")
            import traceback
            logger.debug(traceback.format_exc())
            messagebox.showerror("Ошибка", f"Произошла ошибка: {e}", parent=self.root)
        finally:
            if rca_sock:
                rca_sock.close()

    def generate_lca_keys_action(self):
        if not self.p or not self.g:
            messagebox.showwarning("Параметры отсутствуют", 
                                   "Параметры p и g не установлены. Они будут получены от RCA при запросе сертификата. "
                                   "Вы можете сгенерировать ключи сейчас, но они будут основаны на временных p и g, "
                                   "если они не будут установлены вручную или получены от RCA. "
                                   "Пока что разрешим, но с предупреждением. При получении серт. от RCA p,g обновятся.", parent=self.root)
            # Для генерации ключей нужны p и g. Если их нет, можно сгенерировать временные (не рекомендуется)
            # или просто запретить генерацию до получения p,g от RCA.
            # Пока что разрешим, но с предупреждением. При получении серт. от RCA p,g обновятся.
            if not self.p: self.p = PrimeManager.generate_prime(64, self.get_next_lcg_seed()) # Временный p
            if not self.g: self.g = PrimeManager.find_generator(self.p, self.get_next_lcg_seed()) # Временный g
            if not self.g:
                messagebox.showerror("Ошибка", "Не удалось сгенерировать временные p/g для ключей.", parent=self.root)
                return

        if self.key_pair_signature["private_xs"]:
            if not messagebox.askyesno("Подтверждение", "Ключи LCA уже существуют. Перегенерировать?", parent=self.root):
                return
        try:
            priv_xs, pub_ys = ElGamalCrypto.generate_keys(self.p, self.g, self.get_next_lcg_seed())
            self.key_pair_signature = {"private_xs": priv_xs, "public_ys": pub_ys}
            
            # LCA также нужны ключи для шифрования, например, если клиенты будут шифровать что-то для LCA
            # (хотя основное шифрование - между клиентами)
            priv_xe, pub_ye = ElGamalCrypto.generate_keys(self.p, self.g, self.get_next_lcg_seed())
            self.key_pair_encryption = {"private_xe": priv_xe, "public_ye": pub_ye}

            logger.info(f"Сгенерированы ключи для LCA '{self.node_id}'. Public YS: {pub_ys}, Public YE: {pub_ye}")
            self.update_key_displays()
            messagebox.showinfo("Успех", "Ключи LCA успешно сгенерированы.", parent=self.root)
            # Сбрасываем собственный сертификат, так как ключи изменились
            self.own_certificate = None 
            self.update_key_displays() # Обновить GUI, чтобы показать отсутствие сертификата
            
        except Exception as e:
            logger.error(f"Ошибка при генерации ключей LCA: {e}")
            messagebox.showerror("Ошибка", f"Не удалось сгенерировать ключи LCA: {e}", parent=self.root)

    def request_lca_certificate_from_rca_action(self): # Переименовал request_certificate_from_rca_action
        if not self.p or not self.g:
            messagebox.showerror("Ошибка", "Параметры P и G не установлены. Сначала получите их от RCA (кнопка 0).", parent=self.root)
            return
        if not self.key_pair_signature["public_ys"] or not self.key_pair_encryption["public_ye"]:
            messagebox.showerror("Ошибка", "Ключи LCA не сгенерированы. Сначала сгенерируйте их (кнопка 1).", parent=self.root)
            return

        self.rca_host = self.rca_ip_entry.get()
        try:
            self.rca_port = int(self.rca_port_entry.get())
        except ValueError:
            messagebox.showerror("Ошибка", "Порт RCA должен быть числом.", parent=self.root)
            return

        request_payload = { # Теперь мы уверены, что p,g есть и ключи есть
            "lca_id": self.node_id,
            "lca_public_key_ye": self.key_pair_encryption["public_ye"],
            "lca_public_key_ys": self.key_pair_signature["public_ys"],
            "lca_p": self.p,
            "lca_g": self.g
        }
        
        rca_sock = None
        try:
            logger.info(f"LCA ({self.node_id}) подключается к RCA {self.rca_host}:{self.rca_port} для запроса своего сертификата...")
            rca_sock = connect_to_server(self.rca_host, self.rca_port) # <--- ИСПРАВЛЕНИЕ: Добавлено подключение
            if not rca_sock:
                messagebox.showerror("Ошибка соединения", f"Не удалось подключиться к RCA по адресу {self.rca_host}:{self.rca_port}", parent=self.root)
                logger.error(f"LCA ({self.node_id}) не смог подключиться к RCA {self.rca_host}:{self.rca_port} для запроса своего сертификата.")
                return

            send_json_message(rca_sock, {"command": "request_lca_certificate", "payload": request_payload})
            logger.info(f"LCA ({self.node_id}) отправил запрос request_lca_certificate к RCA.")

            response = receive_json_message(rca_sock, timeout=30.0)
            if not response: # <--- ИСПРАВЛЕНИЕ: Обработка случая, если ответ не получен
                messagebox.showerror("Ошибка ответа", "RCA не ответил или ответ некорректен на request_lca_certificate.", parent=self.root)
                logger.error(f"LCA ({self.node_id}) не получил ответ от RCA на request_lca_certificate.")
                return
            logger.info(f"LCA ({self.node_id}) получил ответ от RCA на request_lca_certificate: {str(response)[:200]}...")

            if response.get("status") == "ok":
                lca_cert_data = response.get("lca_certificate")
                rca_cert_data_resp = response.get("rca_certificate") # RCA все равно присылает свой сертификат

                if not lca_cert_data or not rca_cert_data_resp:
                    messagebox.showerror("Ошибка ответа RCA", "RCA не прислал сертификат LCA или свой сертификат.", parent=self.root)
                    return

                # Обновляем/проверяем сертификат RCA
                # Сначала парсим, потом сравниваем, чтобы избежать ошибки если rca_cert_data_resp невалидный
                try:
                    parsed_rca_cert_resp = Certificate.from_dict(rca_cert_data_resp)
                    if not self.rca_certificate or self.rca_certificate.serial_number != parsed_rca_cert_resp.serial_number :
                        self.rca_certificate = parsed_rca_cert_resp
                        self.certificate_store.add_certificate(self.rca_certificate, save_to_file=True)
                        logger.info(f"Сертификат RCA обновлен/подтвержден от RCA: {self.rca_certificate.subject_id}")
                except Exception as e_parse_rca_resp:
                    logger.error(f"Ошибка парсинга сертификата RCA из ответа: {e_parse_rca_resp}")
                    messagebox.showerror("Ошибка парсинга", f"Не удалось обработать сертификат RCA из ответа: {e_parse_rca_resp}", parent=self.root)
                    return


                # Обрабатываем собственный сертификат LCA
                try:
                    temp_lca_cert = Certificate.from_dict(lca_cert_data)
                except Exception as e_parse:
                    logger.error(f"Ошибка парсинга сертификата LCA от RCA: {e_parse}")
                    messagebox.showerror("Ошибка парсинга", f"Не удалось обработать сертификат LCA: {e_parse}", parent=self.root)
                    return

                if temp_lca_cert.p != self.p or temp_lca_cert.g != self.g:
                    logger.error(f"RCA выдал сертификат LCA с p/g ({temp_lca_cert.p},{temp_lca_cert.g}), отличными от текущих p/g ({self.p},{self.g})!")
                    messagebox.showerror("Ошибка параметров", "RCA выдал сертификат с неверными p/g!", parent=self.root)
                    return
                if temp_lca_cert.subject_public_key_ys != self.key_pair_signature["public_ys"]:
                    logger.error(f"RCA выдал сертификат LCA на YS ({temp_lca_cert.subject_public_key_ys}), отличный от текущего YS LCA ({self.key_pair_signature['public_ys']})!")
                    messagebox.showerror("Ошибка ключа", "RCA выдал сертификат на неверный публичный ключ LCA!", parent=self.root)
                    return
                
                self.own_certificate = temp_lca_cert
                if self.own_certificate.verify_signature(self.rca_certificate.subject_public_key_ys):
                    self.certificate_store.add_certificate(self.own_certificate, save_to_file=True)
                    logger.info(f"Сертификат для LCA '{self.node_id}' получен от RCA, проверен и сохранен.")
                    self.update_key_displays()
                    messagebox.showinfo("Успех", "Сертификат LCA от RCA успешно получен и проверен.", parent=self.root)
                else:
                    self.own_certificate = None
                    logger.error(f"Подпись полученного сертификата LCA от RCA недействительна! Проверьте YS RCA ({self.rca_certificate.subject_public_key_ys}).")
                    
                    # Дополнительная отладочная информация
                    data_to_verify = self.own_certificate.get_data_to_sign_or_verify()
                    hash_h = ElGamalCrypto.MessageUtils.hash_message_for_elgamal(data_to_verify, self.own_certificate.p - 1)
                    logger.debug(f"Отладка проверки подписи LCA сертификата:")
                    logger.debug(f"  Данные для проверки (строка): {data_to_verify[:200]}...")
                    logger.debug(f"  Хеш H: {hash_h}")
                    logger.debug(f"  Подпись R: {self.own_certificate.signature_r}, S: {self.own_certificate.signature_s}")
                    logger.debug(f"  Параметры p: {self.own_certificate.p}, g: {self.own_certificate.g}")
                    logger.debug(f"  Публичный ключ издателя (RCA YS): {self.rca_certificate.subject_public_key_ys}")
                    
                    # Проверка компонентов подписи
                    p_val = self.own_certificate.p
                    term1_verify = ElGamalCrypto.ElGamalBaseUtils.custom_pow(self.rca_certificate.subject_public_key_ys, self.own_certificate.signature_r, p_val)
                    term2_verify = ElGamalCrypto.ElGamalBaseUtils.custom_pow(self.own_certificate.signature_r, self.own_certificate.signature_s, p_val)
                    left_side_verify = (term1_verify * term2_verify) % p_val
                    right_side_verify = ElGamalCrypto.ElGamalBaseUtils.custom_pow(self.own_certificate.g, hash_h, p_val)
                    logger.debug(f"  Проверка: (y^r * r^s) mod p = {left_side_verify}")
                    logger.debug(f"  Проверка: g^h mod p = {right_side_verify}")

                    messagebox.showerror("Ошибка проверки", "Подпись сертификата LCA, выданного RCA, недействительна!", parent=self.root)
            elif response.get("status") == "rca_params_provided": # Этот статус здесь не ожидается
                 messagebox.showwarning("Неожиданный ответ RCA", "RCA ответил 'rca_params_provided', хотя ожидался сертификат LCA. Попробуйте сначала '0. Получить параметры'.", parent=self.root)
            else:
                error_msg = response.get("message", "Неизвестная ошибка от RCA при запросе сертификата LCA.")
                messagebox.showerror("Ошибка от RCA", f"RCA вернул ошибку: {error_msg}", parent=self.root)

        except (NetworkError, ConnectionClosedError, MessageFormatError, socket.timeout) as e:
            logger.error(f"Сетевая ошибка при запросе сертификата у RCA: {e}")
            messagebox.showerror("Сетевая ошибка", f"Ошибка при обмене данными с RCA: {e}", parent=self.root)
        except Exception as e:
            logger.error(f"Непредвиденная ошибка при запросе сертификата у RCA: {e}")
            import traceback
            logger.debug(traceback.format_exc())
            messagebox.showerror("Ошибка", f"Произошла ошибка: {e}", parent=self.root)
        finally:
            if rca_sock:
                rca_sock.close()

    def test_prime_p_action(self):
        """Проверяет текущее значение p на простоту всеми тремя методами."""
        if not self.p:
            messagebox.showerror("Ошибка", "Параметр P не установлен. Сначала получите P и G от RCA.", parent=self.root)
            return

        logger.info(f"Проверка простоты числа P={self.p}:")
        
        # 1. Trial Division Test
        trial_result = PrimeManager._is_prime_trial_division(self.p)
        logger.info(f"1. Trial Division Test: {'ВЕРОЯТНО ПРОСТОЕ' if trial_result else 'СОСТАВНОЕ'}")
        
        # 2. Fermat Test
        lcg = LCG(self.get_next_lcg_seed())
        fermat_result = PrimeManager._is_prime_fermat(self.p, k=5, lcg_instance=lcg)
        logger.info(f"2. Fermat Test (k=5): {'ВЕРОЯТНО ПРОСТОЕ' if fermat_result else 'СОСТАВНОЕ'}")
        
        # 3. Miller-Rabin Test
        miller_rabin_result = PrimeManager._is_prime_miller_rabin(self.p, k=64, lcg_instance=lcg)
        logger.info(f"3. Miller-Rabin Test (k=64): {'ВЕРОЯТНО ПРОСТОЕ' if miller_rabin_result else 'СОСТАВНОЕ'}")
        
        # Общий результат
        if trial_result and fermat_result and miller_rabin_result:
            result_message = "Число P прошло все тесты на простоту:\n\n"
        else:
            result_message = "Число P НЕ прошло некоторые тесты на простоту:\n\n"
            
        result_message += f"1. Trial Division Test: {'ВЕРОЯТНО ПРОСТОЕ' if trial_result else 'СОСТАВНОЕ'}\n"
        result_message += f"2. Fermat Test (k=5): {'ВЕРОЯТНО ПРОСТОЕ' if fermat_result else 'СОСТАВНОЕ'}\n"
        result_message += f"3. Miller-Rabin Test (k=64): {'ВЕРОЯТНО ПРОСТОЕ' if miller_rabin_result else 'СОСТАВНОЕ'}"
        
        messagebox.showinfo("Результаты проверки простоты", result_message, parent=self.root)

    def load_issued_client_certificates(self):
        self.issued_client_certs_listbox.delete(0, tk.END)
        for subject_id in self.certificate_store.list_subject_ids():
            cert = self.certificate_store.get_certificate(subject_id)
            # Показываем только сертификаты, выданные этим LCA, и не являющиеся сертификатом самого LCA или RCA
            if cert and cert.issuer_id == self.node_id and \
               subject_id != self.node_id and \
               (not self.rca_certificate or subject_id != self.rca_certificate.subject_id):
                 self.issued_client_certs_listbox.insert(tk.END, cert.subject_id)
        
        if self.issued_client_certs_listbox.size() > 0:
            self.issued_client_certs_listbox.select_set(0)
            self.on_client_cert_select(None)

    def view_issued_client_certs_action(self):
        self.load_issued_client_certificates()
        self.notebook.select(self.issued_client_certs_tab)

    def on_client_cert_select(self, event):
        selection = self.issued_client_certs_listbox.curselection()
        if not selection: return
        selected_subject_id = self.issued_client_certs_listbox.get(selection[0])
        
        cert = self.certificate_store.get_certificate(selected_subject_id)
        self.client_cert_details_text.config(state=tk.NORMAL)
        self.client_cert_details_text.delete(1.0, tk.END)
        if cert:
            self.client_cert_details_text.insert(tk.END, json.dumps(cert.to_dict(), indent=2, ensure_ascii=False))
        else:
            self.client_cert_details_text.insert(tk.END, f"Сертификат для {selected_subject_id} не найден.")
        self.client_cert_details_text.config(state=tk.DISABLED)

    def process_command(self, command: str, payload: dict, addr) -> dict | None:
        logger.debug(f"LCA process_command: command='{command}', payload='{payload is not None}' from {addr}")

        if command == "request_client_certificate":
            # Ожидаемый payload: 
            # { 
            #   "client_id": "client1@LCA1", 
            #   "client_public_key_ye": ..., 
            #   "client_public_key_ys": ...
            # }
            # p и g берутся из LCA
            if not self.own_certificate: # LCA должен иметь собственный сертификат от RCA
                logger.error("LCA не может выдавать сертификаты, т.к. сам не сертифицирован RCA.")
                return {"status": "error", "message": "LCA is not certified by RCA."}
            
            try:
                client_id = payload["client_id"]
                client_pub_ye = int(payload["client_public_key_ye"])
                client_pub_ys = int(payload["client_public_key_ys"])
                
                # ... (проверки ID клиента) ...

                logger.info(f"Получен запрос на сертификат от клиента: {client_id}")

                validity_days = 365
                
                client_cert = Certificate(
                    subject_id=client_id,
                    issuer_id=self.node_id, # LCA является издателем
                    subject_public_key_ye=client_pub_ye,
                    subject_public_key_ys=client_pub_ys,
                    p=self.p, # Используем p и g LCA
                    g=self.g,
                    valid_to_dt = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=validity_days)
                )

                logger.debug(f"LCA ({self.node_id}) подписывает сертификат для {client_id} своим ключом private_xs={self.key_pair_signature['private_xs']}. Публичный ключ YS LCA: {self.key_pair_signature['public_ys']}")
                k_seed_for_client_cert = self.get_next_lcg_seed() 
                logger.debug(f"LCA ({self.node_id}) использует сид {k_seed_for_client_cert} для k_sig при подписи сертификата клиента.")
                # ВАЖНО: передаем k_seed_for_client_cert, а не вызываем get_next_lcg_seed() снова, чтобы сид был тем же, что залогирован
                client_cert.sign(self.key_pair_signature["private_xs"], k_seed_for_client_cert) 
                
                self.certificate_store.add_certificate(client_cert, save_to_file=True)
                # self.load_issued_client_certificates() # <--- ИСПРАВЛЕНИЕ: Убираем прямой вызов GUI-обновления из потока
                
                # Отправляем клиенту его сертификат, сертификат самого LCA и сертификат RCA (если есть)
                response_payload = {
                    "status": "ok",
                    "message": "Client certificate issued.",
                    "client_certificate": client_cert.to_dict(),
                    "lca_certificate": self.own_certificate.to_dict()
                }
                if self.rca_certificate: 
                    response_payload["rca_certificate"] = self.rca_certificate.to_dict()
                
                logger.info(f"Сертификат для клиента '{client_id}' выдан и подписан LCA '{self.node_id}'. Отправляем всю цепочку.")

                if self.own_certificate.subject_public_key_ys != self.key_pair_signature["public_ys"]:
                    logger.error(f"КРИТИЧЕСКАЯ ОШИБКА LCA: YS в собственном сертификате LCA ({self.own_certificate.subject_public_key_ys}) НЕ СОВПАДАЕТ с текущим YS LCA ({self.key_pair_signature['public_ys']})!")
                return response_payload

            except KeyError as e:
                logger.error(f"Неполный запрос на сертификат клиента от {addr}: отсутствует {e}")
                return {"status": "error", "message": f"Incomplete request, missing: {e}"}
            except Exception as e:
                logger.error(f"Ошибка при обработке запроса на сертификат клиента от {addr}: {e}")
                import traceback
                logger.debug(traceback.format_exc()) # Логируем полный traceback
                return {"status": "error", "message": f"Error processing client certificate request: {str(e)}"} # Возвращаем текст ошибки
        
        elif command == "get_lca_certificate": # Запрос сертификата самого LCA
            if self.own_certificate:
                 return {"status": "ok", "lca_certificate": self.own_certificate.to_dict(), 
                                      "rca_certificate": self.rca_certificate.to_dict() if self.rca_certificate else None}
            else:
                 return {"status": "error", "message": "LCA certificate not available."}
        
        elif command == "get_rca_certificate": # Перенаправление запроса или отдача из кэша
            if self.rca_certificate:
                return {"status": "ok", "certificate": self.rca_certificate.to_dict()}
            else: # Попытаться получить у RCA, если не кэширован (более сложная логика)
                logger.warning("Запрошен сертификат RCA, но он отсутствует в кэше LCA.")
                # Можно добавить логику запроса у RCA, если его нет
                return {"status": "error", "message": "RCA certificate not cached by this LCA."}
        
        elif command == "get_lca_chain": # НОВАЯ КОМАНДА для клиента
            logger.info(f"LCA ({self.node_id}) получил запрос get_lca_chain от {addr}")
            if self.own_certificate and self.rca_certificate:
                return {
                    "status": "ok",
                    "lca_certificate": self.own_certificate.to_dict(),
                    "rca_certificate": self.rca_certificate.to_dict()
                }
            elif self.own_certificate: # Если RCA сертификата нет у LCA, отправим хотя бы свой
                 logger.warning(f"LCA ({self.node_id}) отправляет свой сертификат, но сертификат RCA отсутствует.")
                 return {
                    "status": "ok_partial_chain",
                    "lca_certificate": self.own_certificate.to_dict(),
                    "rca_certificate": None
                }
            else:
                logger.error(f"LCA ({self.node_id}) не может предоставить get_lca_chain: отсутствует собственный сертификат.")
                return {"status": "error", "message": "LCA certificate not available."}


        else:
            return super().process_command(command, payload, addr)

    # Переопределяем load_configuration, чтобы загружать rca_host, rca_port и rca_certificate
    def load_configuration(self):
        super().load_configuration() # Вызываем метод базового класса
        
        # Дополнительная загрузка для LCA
        try:
            if os.path.exists(self.config_file_path):
                with open(self.config_file_path, 'r', encoding='utf-8') as f:
                    config_data = json.load(f)
                
                # self.rca_host и self.rca_port уже имеют значения по умолчанию или из аргументов конструктора
                self.rca_host = config_data.get("rca_host", self.rca_host) 
                self.rca_port = config_data.get("rca_port", self.rca_port)
                # Обновление GUI полей rca_ip_entry и rca_port_entry перенесено в __init__

                rca_cert_data = config_data.get("rca_certificate")
                if rca_cert_data:
                    self.rca_certificate = Certificate.from_dict(rca_cert_data)
                    self.certificate_store.add_certificate(self.rca_certificate, save_to_file=False) 
                    logger.info(f"Сертификат RCA загружен из конфигурации LCA: {self.rca_certificate.subject_id}")
                
        except Exception as e: 
            logger.error(f"Ошибка при загрузке специфичной для LCA конфигурации: {e}")
        
        self.update_key_displays()


    # Переопределяем save_configuration
    def save_configuration(self):
        # Сначала получаем данные от базового класса
        # В BaseNodeApp save_configuration уже собирает config_data
        # Мы не можем легко получить этот dict, поэтому лучше переопределить полностью
        # или сделать метод в BaseNodeApp, который возвращает dict для сохранения.
        # Пока что переопределим полностью для простоты.
        
        config_data = {
            "node_id": self.node_id,
            "port": self.port,
            "p": self.p,
            "g": self.g,
            "lcg_seed_counter": self.lcg_seed_counter,
            "key_pair_encryption": self.key_pair_encryption,
            "key_pair_signature": self.key_pair_signature,
            "own_certificate": self.own_certificate.to_dict() if self.own_certificate else None,
            # Специфичные для LCA поля
            "rca_host": self.rca_ip_entry.get(), # Берем актуальные значения из GUI
            "rca_port": int(self.rca_port_entry.get()),
            "rca_certificate": self.rca_certificate.to_dict() if self.rca_certificate else None
        }
        try:
            with open(self.config_file_path, 'w', encoding='utf-8') as f:
                json.dump(config_data, f, indent=4, ensure_ascii=False)
            logger.info(f"Конфигурация LCA сохранена в {self.config_file_path}")
            messagebox.showinfo("Сохранение", "Конфигурация LCA успешно сохранена.", parent=self.root)
        except Exception as e:
            logger.error(f"Ошибка сохранения конфигурации LCA: {e}")
            messagebox.showerror("Ошибка", f"Не удалось сохранить конфигурацию LCA: {e}", parent=self.root)


if __name__ == "__main__":
    # Пример запуска двух LCA, которые будут подключаться к RCA на порту 10000
    # LCA1
    root_lca1 = tk.Tk()
    app_lca1 = LocalCAApp(root_lca1, node_id="LCA1", default_port=10001, rca_default_port=10000)
    
    # LCA2
    root_lca2 = tk.Tk() # Нужно отдельное Tk() для каждого независимого окна
    app_lca2 = LocalCAApp(root_lca2, node_id="LCA2", default_port=10002, rca_default_port=10000)
    
    # Запуск основного цикла для первого LCA. Второй запустится, если этот закроется,
    # или нужно использовать threading/multiprocessing для одновременного запуска из одного скрипта,
    # что усложнит тестовый запуск. Проще запускать каждый LCA в отдельном процессе.
    # Для теста здесь запустим только один.
    root_lca1.mainloop()
    # Если нужно запустить и второй параллельно для ручного теста, придется изменить структуру запуска.
    # Например, создать функцию, принимающую параметры, и вызывать ее в разных потоках.
    # Но для простоты отладки лучше запускать каждый экземпляр приложения отдельно.

# END OF FILE: local_ca_app.py