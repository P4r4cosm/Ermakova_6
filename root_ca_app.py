# START OF FILE: root_ca_app.py

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import logging
import datetime # Для работы с датами в сертификатах
import json
from base_node_app import BaseNodeApp
from elgamal_utils import PrimeManager, ElGamalCrypto # LCG уже в BaseNodeApp
from certificate_manager import Certificate # CertificateStore уже в BaseNodeApp

logger = logging.getLogger(__name__)

class RootCAApp(BaseNodeApp):
    def __init__(self, root, node_id="RootCA", default_port=10000):
        super().__init__(root, node_id, default_port, config_file_name="rca_config.json")
        self.root.title(f"Корневой УЦ (RCA): {self.node_id}")
        
        # Дополнительные элементы GUI для RCA
        self.create_rca_specific_gui()

        # Загружаем сертификаты LCA, если они есть
        self.load_issued_lca_certificates()
        
        logger.info(f"Корневой УЦ '{self.node_id}' инициализирован.")
        if not self.p or not self.g:
            logger.warning("Глобальные параметры p и g не установлены. Сгенерируйте их.")
        if not self.key_pair_signature["private_xs"] or not self.own_certificate:
            logger.warning("Ключи RCA или самоподписанный сертификат отсутствуют. Сгенерируйте их.")


    def create_rca_specific_gui(self):
        """ Добавляет специфичные для RCA элементы в GUI. """
        rca_panel = ttk.Labelframe(self.control_panel, text="Действия RCA")
        rca_panel.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10, pady=5)

        ttk.Button(rca_panel, text="1. Сгенерировать P и G", command=self.generate_pg_action).pack(side=tk.LEFT, padx=5)
        ttk.Button(rca_panel, text="2. Сгенерировать ключи RCA и сертификат", command=self.generate_rca_keys_and_cert_action).pack(side=tk.LEFT, padx=5)
        ttk.Button(rca_panel, text="Просмотреть выданные сертификаты LCA", command=self.view_issued_lca_certs_action).pack(side=tk.LEFT, padx=5)

        # Вкладка для отображения выданных сертификатов
        self.issued_lca_certs_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.issued_lca_certs_tab, text="Выданные LCA сертификаты")
        
        self.issued_lca_certs_listbox = tk.Listbox(self.issued_lca_certs_tab, width=80, height=15)
        self.issued_lca_certs_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        lca_certs_scrollbar = ttk.Scrollbar(self.issued_lca_certs_tab, orient=tk.VERTICAL, command=self.issued_lca_certs_listbox.yview)
        lca_certs_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.issued_lca_certs_listbox.config(yscrollcommand=lca_certs_scrollbar.set)
        
        self.issued_lca_certs_listbox.bind('<<ListboxSelect>>', self.on_lca_cert_select)

        self.lca_cert_details_text = tk.Text(self.issued_lca_certs_tab, wrap=tk.WORD, height=10, width=60, state=tk.DISABLED)
        self.lca_cert_details_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)


    def generate_pg_action(self):
        if self.p or self.g:
            if not messagebox.askyesno("Подтверждение", "Параметры P и G уже существуют. Перегенерировать?", parent=self.root):
                return

        bit_length_str = simpledialog.askstring("Разрядность P", "Введите разрядность для P (например, 64-128 для теста):", initialvalue="64", parent=self.root)
        if not bit_length_str: return
        try:
            bit_length = int(bit_length_str)
            if not (64 <= bit_length <= 512): # Ограничение из elgamal_utils
                raise ValueError("Разрядность должна быть между 64 и 512.")
        except ValueError as e:
            messagebox.showerror("Ошибка", f"Некорректная разрядность: {e}", parent=self.root)
            return

        try:
            self.p = PrimeManager.generate_prime(bit_length, self.get_next_lcg_seed())
            self.g = PrimeManager.find_generator(self.p, self.get_next_lcg_seed())
            if self.g is None:
                self.p = None # Сброс, если g не найден
                messagebox.showerror("Ошибка", "Не удалось найти подходящий генератор g для сгенерированного p.", parent=self.root)
                return

            logger.info(f"Сгенерированы глобальные параметры: p={self.p}, g={self.g}")
            self.update_key_displays()
            messagebox.showinfo("Успех", "Параметры P и G успешно сгенерированы.", parent=self.root)
        except Exception as e:
            logger.error(f"Ошибка при генерации P и G: {e}")
            messagebox.showerror("Ошибка", f"Не удалось сгенерировать P и G: {e}", parent=self.root)


    def generate_rca_keys_and_cert_action(self):
        if not self.p or not self.g:
            messagebox.showerror("Ошибка", "Сначала сгенерируйте параметры P и G.", parent=self.root)
            return

        if self.key_pair_signature["private_xs"] or self.own_certificate:
            if not messagebox.askyesno("Подтверждение", "Ключи RCA и/или самоподписанный сертификат уже существуют. Перегенерировать?", parent=self.root):
                return
        try:
            # Генерация ключей для подписи (xs, ys)
            # RCA также может иметь ключи для шифрования (xe, ye), но для выдачи сертификатов нужны ключи подписи.
            # Для простоты, предположим, что ye = ys для RCA.
            priv_xs, pub_ys = ElGamalCrypto.generate_keys(self.p, self.g, self.get_next_lcg_seed())
            self.key_pair_signature = {"private_xs": priv_xs, "public_ys": pub_ys}
            self.key_pair_encryption = {"private_xe": priv_xs, "public_ye": pub_ys} # Используем те же для RCA

            logger.info(f"Сгенерированы ключи RCA: public_ys={pub_ys}")

            # Создание самоподписанного сертификата
            self.own_certificate = Certificate(
                subject_id=self.node_id,
                issuer_id=self.node_id, # Сам себе издатель
                subject_public_key_ye=self.key_pair_encryption["public_ye"],
                subject_public_key_ys=self.key_pair_signature["public_ys"],
                p=self.p,
                g=self.g,
                # valid_from_dt, valid_to_dt - по умолчанию (сейчас, сейчас + 1 год)
                # serial_number - генерируется автоматически
            )
            # Подписываем сертификат собственным закрытым ключом
            self.own_certificate.sign(self.key_pair_signature["private_xs"], self.get_next_lcg_seed())
            
            # Сохраняем свой сертификат в своем же хранилище
            self.certificate_store.add_certificate(self.own_certificate, save_to_file=True)

            logger.info("Самоподписанный сертификат RCA создан и подписан.")
            self.update_key_displays()
            messagebox.showinfo("Успех", "Ключи RCA и самоподписанный сертификат успешно сгенерированы и сохранены.", parent=self.root)

        except Exception as e:
            logger.error(f"Ошибка при генерации ключей/сертификата RCA: {e}")
            messagebox.showerror("Ошибка", f"Не удалось сгенерировать ключи/сертификат RCA: {e}", parent=self.root)

    def load_issued_lca_certificates(self):
        """ Загружает ранее выданные сертификаты LCA из хранилища RCA. """
        self.issued_lca_certs_listbox.delete(0, tk.END)
        # RCA хранит сертификаты, которые он выдал, в своем CertificateStore.
        # Subject_id этих сертификатов - это ID LCA.
        # Issuer_id этих сертификатов - это ID RCA.
        # Мы не хотим показывать собственный сертификат RCA в этом списке.
        for subject_id in self.certificate_store.list_subject_ids():
            if subject_id == self.node_id: # Пропускаем собственный сертификат RCA
                continue
            cert = self.certificate_store.get_certificate(subject_id)
            if cert and cert.issuer_id == self.node_id: # Убедимся, что это сертификат, выданный RCA
                 self.issued_lca_certs_listbox.insert(tk.END, cert.subject_id)
        
        if self.issued_lca_certs_listbox.size() > 0:
            self.issued_lca_certs_listbox.select_set(0)
            self.on_lca_cert_select(None) # Обновить детали для первого элемента


    def view_issued_lca_certs_action(self):
        """ Обновляет список выданных сертификатов LCA. """
        self.load_issued_lca_certificates()
        self.notebook.select(self.issued_lca_certs_tab) # Переключиться на вкладку

    def on_lca_cert_select(self, event):
        """ Отображает детали выбранного сертификата LCA. """
        selection = self.issued_lca_certs_listbox.curselection()
        if not selection:
            return
        selected_subject_id = self.issued_lca_certs_listbox.get(selection[0])
        
        cert = self.certificate_store.get_certificate(selected_subject_id)
        self.lca_cert_details_text.config(state=tk.NORMAL)
        self.lca_cert_details_text.delete(1.0, tk.END)
        if cert:
            self.lca_cert_details_text.insert(tk.END, json.dumps(cert.to_dict(), indent=2, ensure_ascii=False))
        else:
            self.lca_cert_details_text.insert(tk.END, f"Сертификат для {selected_subject_id} не найден.")
        self.lca_cert_details_text.config(state=tk.DISABLED)


    def process_command(self, command: str, payload: dict, addr) -> dict | None:
        """ Обрабатывает команды, специфичные для RCA. """
        logger.debug(f"RCA process_command: command='{command}', payload='{payload is not None}' from {addr}")

        if command == "request_lca_certificate":
            # Ожидаемый payload: 
            # { 
            #   "lca_id": "LCA1", 
            #   "lca_public_key_ye": ..., 
            #   "lca_public_key_ys": ...,
            #   "lca_p": ..., (должен совпадать с p RCA)
            #   "lca_g": ...  (должен совпадать с g RCA)
            # }
            if not all([self.p, self.g, self.key_pair_signature["private_xs"], self.own_certificate]):
                logger.error("RCA не готов выдавать сертификаты (отсутствуют p, g, ключи или собственный сертификат).")
                return {"status": "error", "message": "RCA not ready to issue certificates."}

            try:
                lca_id = payload["lca_id"]
                lca_pub_ye = int(payload["lca_public_key_ye"])
                lca_pub_ys = int(payload["lca_public_key_ys"])
                lca_p = int(payload["lca_p"])
                lca_g = int(payload["lca_g"])

                if lca_p != self.p or lca_g != self.g:
                    logger.warning(f"Запрос сертификата от {lca_id} с неверными p/g. RCA p,g: ({self.p},{self.g}), LCA p,g: ({lca_p},{lca_g})")
                    return {"status": "error", "message": "Mismatch in p/g parameters."}
                
                # В реальной системе здесь была бы проверка LCA (аутентификация, авторизация)
                logger.info(f"Получен запрос на сертификат от LCA: {lca_id}")

                # Создаем сертификат для LCA
                # Срок действия можно сделать настраиваемым
                validity_days = 365

                lca_cert = Certificate(
                    subject_id=lca_id,
                    issuer_id=self.node_id, # RCA является издателем
                    subject_public_key_ye=lca_pub_ye,
                    subject_public_key_ys=lca_pub_ys,
                    p=self.p,
                    g=self.g,
                    valid_to_dt = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=validity_days)
                )
                # Подписываем сертификат LCA закрытым ключом RCA
                lca_cert.sign(self.key_pair_signature["private_xs"], self.get_next_lcg_seed())
                
                # Сохраняем выданный сертификат в хранилище RCA
                self.certificate_store.add_certificate(lca_cert, save_to_file=True)
                self.load_issued_lca_certificates() # Обновляем список в GUI

                logger.info(f"Сертификат для LCA '{lca_id}' выдан и подписан.")
                
                # Отправляем сертификат LCA и сертификат RCA (чтобы LCA мог проверить цепочку)
                return {
                    "status": "ok",
                    "message": "LCA certificate issued.",
                    "lca_certificate": lca_cert.to_dict(),
                    "rca_certificate": self.own_certificate.to_dict() 
                }

            except KeyError as e:
                logger.error(f"Неполный запрос на сертификат LCA от {addr}: отсутствует {e}")
                return {"status": "error", "message": f"Incomplete request, missing: {e}"}
            except Exception as e:
                logger.error(f"Ошибка при обработке запроса на сертификат LCA от {addr}: {e}")
                import traceback
                logger.debug(traceback.format_exc())
                return {"status": "error", "message": f"Error processing LCA certificate request: {e}"}
        
        elif command == "get_rca_certificate":
            if self.own_certificate:
                 return {"status": "ok", "certificate": self.own_certificate.to_dict()}
            else:
                 return {"status": "error", "message": "RCA certificate not available."}

        else:
            # Если команда не распознана, вызываем метод базового класса
            return super().process_command(command, payload, addr)


if __name__ == "__main__":
    root_tk = tk.Tk()
    app = RootCAApp(root_tk)
    root_tk.mainloop()

# END OF FILE: root_ca_app.py