# START OF FILE: local_ca_app.py

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import logging
import datetime # Для работы с датами в сертификатах
import json # Для сериализации/десериализации
import os

from base_node_app import BaseNodeApp
from elgamal_utils import ElGamalCrypto, PrimeManager # LCG, PrimeManager уже в BaseNodeApp
from certificate_manager import Certificate # CertificateStore уже в BaseNodeApp
from network_utils import connect_to_server, send_json_message, receive_json_message, \
                          ConnectionClosedError, MessageFormatError, NetworkError


logger = logging.getLogger(__name__)

class LocalCAApp(BaseNodeApp):
    def __init__(self, root, node_id, default_port, rca_default_host="127.0.0.1", rca_default_port=10000):
        super().__init__(root, node_id, default_port, config_file_name="lca_config.json")
        self.root.title(f"Локальный УЦ (LCA): {self.node_id}")

        self.rca_host = rca_default_host
        self.rca_port = rca_default_port
        self.rca_certificate = None # Сертификат RCA, полученный от него

        # Дополнительные элементы GUI для LCA
        self.create_lca_specific_gui()

        # Загружаем сертификаты клиентов, если они есть
        self.load_issued_client_certificates()
        
        # При загрузке конфигурации, если есть p и g, но нет своего сертификата,
        # это может означать, что нужно запросить сертификат у RCA
        if self.p and self.g and not self.own_certificate:
             logger.warning(f"LCA '{self.node_id}' имеет p и g, но нет собственного сертификата. Запросите у RCA.")
        elif not self.p or not self.g:
             logger.warning(f"LCA '{self.node_id}' не имеет параметров p и g. Получите их от RCA (через запрос сертификата).")


    def create_lca_specific_gui(self):
        """ Добавляет специфичные для LCA элементы в GUI. """
        lca_panel = ttk.Labelframe(self.control_panel, text="Действия LCA")
        lca_panel.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10, pady=5)

        ttk.Button(lca_panel, text="1. Сгенерировать ключи LCA", command=self.generate_lca_keys_action).pack(side=tk.LEFT, padx=5)
        
        rca_conn_frame = ttk.Frame(lca_panel)
        rca_conn_frame.pack(side=tk.LEFT, padx=10)
        ttk.Label(rca_conn_frame, text="RCA IP:").grid(row=0, column=0, sticky=tk.W)
        self.rca_ip_entry = ttk.Entry(rca_conn_frame, width=15)
        self.rca_ip_entry.grid(row=0, column=1, sticky=tk.W)
        self.rca_ip_entry.insert(0, self.rca_host)
        ttk.Label(rca_conn_frame, text="RCA Port:").grid(row=1, column=0, sticky=tk.W)
        self.rca_port_entry = ttk.Entry(rca_conn_frame, width=7)
        self.rca_port_entry.grid(row=1, column=1, sticky=tk.W)
        self.rca_port_entry.insert(0, str(self.rca_port))

        ttk.Button(lca_panel, text="2. Запросить сертификат у RCA", command=self.request_certificate_from_rca_action).pack(side=tk.LEFT, padx=5)
        ttk.Button(lca_panel, text="Просмотреть выданные сертификаты клиентов", command=self.view_issued_client_certs_action).pack(side=tk.LEFT, padx=5)

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


    def generate_lca_keys_action(self):
        if not self.p or not self.g:
            messagebox.showwarning("Параметры отсутствуют", 
                                   "Параметры p и g не установлены. Они будут получены от RCA при запросе сертификата. "
                                   "Вы можете сгенерировать ключи сейчас, но они будут основаны на временных p и g, "
                                   "если они не будут установлены вручную или получены от RCA.", parent=self.root)
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

    def request_certificate_from_rca_action(self):
        if not self.key_pair_signature["public_ys"] or not self.key_pair_encryption["public_ye"]:
            messagebox.showerror("Ошибка", "Сначала сгенерируйте ключи LCA.", parent=self.root)
            return

        self.rca_host = self.rca_ip_entry.get()
        try:
            self.rca_port = int(self.rca_port_entry.get())
        except ValueError:
            messagebox.showerror("Ошибка", "Порт RCA должен быть числом.", parent=self.root)
            return

        request_payload = {
            "lca_id": self.node_id,
            "lca_public_key_ye": self.key_pair_encryption["public_ye"],
            "lca_public_key_ys": self.key_pair_signature["public_ys"],
            # LCA отправляет свои p и g (если они есть), RCA должен их проверить
            # или установить их из ответа RCA.
            # Если у LCA еще нет p,g, он может отправить None или 0,
            # а RCA пришлет свои p,g в сертификате.
            "lca_p": self.p if self.p else 0, 
            "lca_g": self.g if self.g else 0
        }
        
        rca_sock = None
        try:
            logger.info(f"Подключение к RCA {self.rca_host}:{self.rca_port} для запроса сертификата...")
            rca_sock = connect_to_server(self.rca_host, self.rca_port)
            if not rca_sock:
                messagebox.showerror("Ошибка соединения", f"Не удалось подключиться к RCA по адресу {self.rca_host}:{self.rca_port}", parent=self.root)
                return

            send_json_message(rca_sock, {"command": "request_lca_certificate", "payload": request_payload})
            logger.info("Запрос на сертификат LCA отправлен RCA.")

            response = receive_json_message(rca_sock, timeout=30.0)
            if not response:
                messagebox.showerror("Ошибка ответа", "RCA не ответил или ответ некорректен.", parent=self.root)
                return

            logger.info(f"Получен ответ от RCA: {str(response)[:200]}...")

            if response.get("status") == "ok":
                lca_cert_data = response.get("lca_certificate")
                rca_cert_data = response.get("rca_certificate")

                if not lca_cert_data or not rca_cert_data:
                    messagebox.showerror("Ошибка ответа", "Ответ RCA не содержит необходимых сертификатов.", parent=self.root)
                    return
                
                # Парсим и сохраняем сертификат RCA
                self.rca_certificate = Certificate.from_dict(rca_cert_data)
                self.certificate_store.add_certificate(self.rca_certificate, save_to_file=True) # Сохраняем серт RCA
                logger.info(f"Сертификат RCA получен и сохранен: {self.rca_certificate.subject_id}")

                # Парсим и сохраняем собственный сертификат LCA
                self.own_certificate = Certificate.from_dict(lca_cert_data)
                
                # Важно: Устанавливаем p и g из полученного сертификата (они должны быть от RCA)
                self.p = self.own_certificate.p
                self.g = self.own_certificate.g
                logger.info(f"Установлены p={self.p}, g={self.g} из сертификата, выданного RCA.")

                # Проверяем подпись полученного сертификата LCA, используя публичный ключ RCA (из сертификата RCA)
                if self.own_certificate.verify_signature(self.rca_certificate.subject_public_key_ys):
                    self.certificate_store.add_certificate(self.own_certificate, save_to_file=True) # Сохраняем свой серт
                    logger.info(f"Сертификат для LCA '{self.node_id}' получен, проверен и сохранен.")
                    self.update_key_displays()
                    messagebox.showinfo("Успех", "Сертификат от RCA успешно получен и проверен.", parent=self.root)
                else:
                    self.own_certificate = None # Сертификат невалидный
                    logger.error("Полученный от RCA сертификат LCA не прошел проверку подписи!")
                    messagebox.showerror("Ошибка проверки", "Подпись полученного сертификата LCA недействительна!", parent=self.root)
                
            else:
                error_msg = response.get("message", "Неизвестная ошибка от RCA.")
                logger.error(f"RCA вернул ошибку: {error_msg}")
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
                
                # Проверка, что ID клиента соответствует домену этого LCA (опционально, но логично)
                # Например, если LCA_ID = "LCA1", то клиент "client1@LCA1" подходит.
                if not client_id.endswith(f"@{self.node_id}"):
                     logger.warning(f"Клиент {client_id} запросил сертификат у {self.node_id}, но ID не соответствует домену.")
                     # Можно вернуть ошибку или просто продолжить, если политика позволяет

                logger.info(f"Получен запрос на сертификат от клиента: {client_id}")

                validity_days = int(simpledialog.askstring("Срок действия", 
                                                           f"Введите срок действия сертификата для {client_id} в днях:", 
                                                           initialvalue="180", parent=self.root) or 180)
                
                client_cert = Certificate(
                    subject_id=client_id,
                    issuer_id=self.node_id, # LCA является издателем
                    subject_public_key_ye=client_pub_ye,
                    subject_public_key_ys=client_pub_ys,
                    p=self.p, # Используем p и g LCA
                    g=self.g,
                    valid_to_dt = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=validity_days)
                )
                client_cert.sign(self.key_pair_signature["private_xs"], self.get_next_lcg_seed())
                
                self.certificate_store.add_certificate(client_cert, save_to_file=True)
                self.load_issued_client_certificates() # Обновляем GUI

                logger.info(f"Сертификат для клиента '{client_id}' выдан и подписан LCA '{self.node_id}'.")
                
                # Отправляем клиенту его сертификат и сертификат самого LCA
                return {
                    "status": "ok",
                    "message": "Client certificate issued.",
                    "client_certificate": client_cert.to_dict(),
                    "lca_certificate": self.own_certificate.to_dict() 
                }

            except KeyError as e:
                logger.error(f"Неполный запрос на сертификат клиента от {addr}: отсутствует {e}")
                return {"status": "error", "message": f"Incomplete request, missing: {e}"}
            except Exception as e:
                logger.error(f"Ошибка при обработке запроса на сертификат клиента от {addr}: {e}")
                import traceback
                logger.debug(traceback.format_exc())
                return {"status": "error", "message": f"Error processing client certificate request: {e}"}
        
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
                
                self.rca_host = config_data.get("rca_host", self.rca_host) # self.rca_host уже имеет default
                self.rca_port = config_data.get("rca_port", self.rca_port) # self.rca_port уже имеет default
                self.rca_ip_entry.delete(0, tk.END)
                self.rca_ip_entry.insert(0, self.rca_host)
                self.rca_port_entry.delete(0, tk.END)
                self.rca_port_entry.insert(0, str(self.rca_port))

                rca_cert_data = config_data.get("rca_certificate")
                if rca_cert_data:
                    self.rca_certificate = Certificate.from_dict(rca_cert_data)
                    self.certificate_store.add_certificate(self.rca_certificate, save_to_file=False) # Уже должен быть в файлах, если есть
                    logger.info(f"Сертификат RCA загружен из конфигурации LCA: {self.rca_certificate.subject_id}")
                
        except Exception as e: # Ловим ошибки специфичные для этой части загрузки
            logger.error(f"Ошибка при загрузке специфичной для LCA конфигурации: {e}")
        
        # Обновляем отображение ключей и сертификата (включая p,g которые могли прийти из super().load_configuration())
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