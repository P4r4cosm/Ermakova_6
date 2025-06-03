# START OF FILE: root_ca_app.py

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, scrolledtext
import logging
import datetime # Для работы с датами в сертификатах
import json
from base_node_app import BaseNodeApp
from elgamal_utils import PrimeManager, ElGamalCrypto, LCG # LCG нужен для тестов простоты
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

        # Настраиваем начальный размер окна
        self.root.update_idletasks()  # Обновляем информацию о размерах виджетов
        width = max(600, self.root.winfo_reqwidth())  # Минимум 600 или требуемая ширина
        height = max(400, self.root.winfo_reqheight())  # Минимум 400 или требуемая высота
        x = (self.root.winfo_screenwidth() - width) // 2
        y = (self.root.winfo_screenheight() - height) // 2
        self.root.geometry(f"{width}x{height}+{x}+{y}")  # Устанавливаем размер и позицию окна

    def load_configuration(self):
        """Переопределяем метод для загрузки конфигурации без обновления GUI."""
        import os
        import json

        if os.path.exists(self.config_file_path):
            try:
                with open(self.config_file_path, 'r') as f:
                    config = json.load(f)
                    
                self.p = config.get("p")
                self.g = config.get("g")
                self.key_pair_signature = config.get("key_pair_signature", {"private_xs": None, "public_ys": None})
                self.key_pair_encryption = config.get("key_pair_encryption", {"private_xe": None, "public_ye": None})
                
                # Загружаем собственный сертификат, если он есть
                cert_data = config.get("own_certificate")
                if cert_data:
                    self.own_certificate = Certificate.from_dict(cert_data)
                
                logger.info(f"Конфигурация загружена из {self.config_file_path}")
            except Exception as e:
                logger.error(f"Ошибка при загрузке конфигурации из {self.config_file_path}: {e}")

    def create_rca_specific_gui(self):
        """ Добавляет специфичные для RCA элементы в GUI. """
        rca_panel = ttk.Labelframe(self.control_panel, text="Действия RCA")
        rca_panel.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=10, pady=5)

        # Создаем фрейм для кнопок внутри панели
        buttons_frame = ttk.Frame(rca_panel)
        buttons_frame.pack(padx=5, pady=5)

        # Список всех кнопок и их команд
        buttons = [
            ("1. Сгенерировать P и G", self.generate_pg_action),
            ("Проверить P на простоту", self.test_prime_p_action),
            ("2. Сгенерировать ключи RCA и сертификат", self.generate_rca_keys_and_cert_action),
            ("Просмотреть выданные сертификаты LCA", self.view_issued_lca_certs_action)
        ]

        # Размещаем кнопки в сетке по 2 в ряд
        for i, (text, command) in enumerate(buttons):
            row = i // 2  # Целочисленное деление для определения строки
            col = i % 2   # Остаток от деления для определения столбца
            ttk.Button(buttons_frame, text=text, command=command).grid(
                row=row, column=col, padx=5, pady=5, sticky="ew"
            )

        # Настраиваем одинаковую ширину столбцов
        buttons_frame.grid_columnconfigure(0, weight=1)
        buttons_frame.grid_columnconfigure(1, weight=1)

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

        # После создания всех элементов GUI обновляем отображение
        self.update_key_displays()

    def update_key_displays(self):
        """Переопределяем метод для отображения только ключей подписи в RCA."""
        # Обновляем отображение глобальных параметров
        self.p_display.config(text=str(self.p) if self.p else "Не задано")
        self.g_display.config(text=str(self.g) if self.g else "Не задано")
        
        # Отображаем только ключи подписи
        self.ys_display.config(text=str(self.key_pair_signature.get('public_ys')) if self.key_pair_signature.get('public_ys') else "Не задано")
        # Скрываем или очищаем ye, так как он не используется в RCA
        self.ye_display.config(text="Не используется")

        # Обновляем отображение сертификата
        self.own_cert_text.config(state=tk.NORMAL)
        self.own_cert_text.delete(1.0, tk.END)
        if self.own_certificate:
            self.own_cert_text.insert(tk.END, json.dumps(self.own_certificate.to_dict(), indent=2, ensure_ascii=False))
        else:
            self.own_cert_text.insert(tk.END, "Сертификат отсутствует.")
        self.own_cert_text.config(state=tk.DISABLED)

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
            priv_xs, pub_ys = ElGamalCrypto.generate_keys(self.p, self.g, self.get_next_lcg_seed())
            self.key_pair_signature = {"private_xs": priv_xs, "public_ys": pub_ys}
            
            # RCA не нуждается в ключах шифрования
            self.key_pair_encryption = {"private_xe": None, "public_ye": None}

            logger.info(f"Сгенерированы ключи RCA: public_ys={pub_ys}")

            # Создание самоподписанного сертификата
            self.own_certificate = Certificate(
                subject_id=self.node_id,
                issuer_id=self.node_id, # Сам себе издатель
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

    def test_prime_p_action(self):
        """Проверяет текущее значение p на простоту всеми тремя методами."""
        if not self.p:
            messagebox.showerror("Ошибка", "Параметр P не установлен. Сначала сгенерируйте P и G.", parent=self.root)
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
        elif command == "get_rca_public_info": # НОВАЯ КОМАНДА
            logger.info(f"RCA получил запрос на get_rca_public_info от {addr}")
            if self.own_certificate and self.p and self.g:
                return {
                    "status": "ok",
                    "message": "RCA public information provided.",
                    "rca_certificate": self.own_certificate.to_dict() # Содержит p, g, YS_rca
                }
            else:
                logger.error("RCA не может предоставить public_info: отсутствует собственный сертификат, p или g.")
                return {"status": "error", "message": "RCA not ready to provide public info (missing self-signed certificate, p or g)."}
        # ... (остальные команды) ...
        else:
            # Если команда не распознана, вызываем метод базового класса
            return super().process_command(command, payload, addr)

    def create_keys_certs_tab_widgets(self, parent_tab):
        """ Создает виджеты для вкладки 'Ключи и Сертификат' без отображения ключей шифрования. """
        frame = ttk.Frame(parent_tab, padding="5")
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Параметр p:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.p_display = ttk.Label(frame, text="N/A")
        self.p_display.grid(row=0, column=1, sticky=tk.W, padx=5, pady=2)

        ttk.Label(frame, text="Параметр g:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        self.g_display = ttk.Label(frame, text="N/A")
        self.g_display.grid(row=1, column=1, sticky=tk.W, padx=5, pady=2)

        # Создаем ye_display, но не отображаем его (он нужен для совместимости с базовым классом)
        self.ye_display = ttk.Label(frame, text="N/A")
        
        ttk.Label(frame, text="Открытый ключ подписи (ys):").grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
        self.ys_display = ttk.Label(frame, text="N/A")
        self.ys_display.grid(row=2, column=1, sticky=tk.W, padx=5, pady=2)

        ttk.Label(frame, text="Собственный сертификат:").grid(row=3, column=0, sticky=tk.NW, padx=5, pady=2)
        self.own_cert_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, height=8, width=60, state=tk.DISABLED)
        self.own_cert_text.grid(row=3, column=1, sticky=tk.NSEW, padx=5, pady=2)
        
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(3, weight=1)

if __name__ == "__main__":
    root_tk = tk.Tk()
    app = RootCAApp(root_tk)
    root_tk.mainloop()

# END OF FILE: root_ca_app.py