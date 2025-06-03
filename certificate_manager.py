# START OF FILE: certificate_manager.py

import json
import datetime
from elgamal_utils import ElGamalCrypto, MessageUtils, LCG, PrimeManager  # Предполагается, что elgamal_utils.py находится в том же каталоге

class Certificate:
    def __init__(self, subject_id, issuer_id,
                 subject_public_key_ys,
                 p, g,
                 subject_public_key_ye=None,  # Делаем ye опциональным
                 valid_from_dt=None, valid_to_dt=None,
                 serial_number=None,
                 signature_r=None, signature_s=None):
        """
        Класс для представления цифрового сертификата.

        Args:
            subject_id (str): Идентификатор владельца сертификата.
            issuer_id (str): Идентификатор УЦ, выдавшего сертификат.
            subject_public_key_ys (int): Публичный ключ владельца для проверки подписи (y_s).
            p (int): Простое число p Эль-Гамаля.
            g (int): Генератор g Эль-Гамаля.
            subject_public_key_ye (int, optional): Публичный ключ владельца для шифрования (y_e).
            valid_from_dt (datetime.datetime, optional): Дата начала действия. По умолчанию - сейчас.
            valid_to_dt (datetime.datetime, optional): Дата окончания действия. По умолчанию - через 1 год.
            serial_number (int, optional): Серийный номер. Генерируется, если None.
            signature_r (int, optional): Компонент r подписи УЦ.
            signature_s (int, optional): Компонент s подписи УЦ.
        """
        self.subject_id = str(subject_id)
        self.issuer_id = str(issuer_id)
        self.subject_public_key_ys = int(subject_public_key_ys)
        self.subject_public_key_ye = int(subject_public_key_ye) if subject_public_key_ye is not None else None
        self.p = int(p)
        self.g = int(g)

        now = datetime.datetime.now(datetime.timezone.utc)
        self.valid_from = (valid_from_dt or now).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.valid_to = (valid_to_dt or (now + datetime.timedelta(days=365))).strftime("%Y-%m-%dT%H:%M:%SZ")

        if serial_number is None:
            # Используем LCG для генерации псевдо-уникального серийного номера
            lcg_seed = int(now.timestamp() * 1000) + len(subject_id)
            lcg = LCG(lcg_seed)
            self.serial_number = lcg.randint(10**9, 10**10 -1)
        else:
            self.serial_number = int(serial_number)

        self.signature_r = int(signature_r) if signature_r is not None else None
        self.signature_s = int(signature_s) if signature_s is not None else None

    def get_data_to_sign_or_verify(self):
        """
        Собирает данные сертификата в каноническую строку для подписи или проверки.
        Важно, чтобы порядок и формат полей были строго одинаковыми.
        """
        # Собираем все поля, КРОМЕ самой подписи (signature_r, signature_s)
        data = {
            "subject_id": self.subject_id,
            "issuer_id": self.issuer_id,
            "subject_public_key_ys": self.subject_public_key_ys,
            "p": self.p,
            "g": self.g,
            "valid_from": self.valid_from,
            "valid_to": self.valid_to,
            "serial_number": self.serial_number
        }
        # Добавляем ye только если он есть
        if self.subject_public_key_ye is not None:
            data["subject_public_key_ye"] = self.subject_public_key_ye
            
        # Сериализуем в JSON со строгой сортировкой ключей для консистентности
        return json.dumps(data, sort_keys=True, ensure_ascii=False)

    def sign(self, issuer_private_key_xs, seed_for_k_sig):
        """
        Подписывает сертификат с использованием закрытого ключа подписи издателя (issuer_private_key_xs).
        """
        if self.issuer_id == self.subject_id: # Самоподписанный сертификат
            print(f"INFO: Signing self-signed certificate for {self.subject_id}")

        data_str = self.get_data_to_sign_or_verify()
        # Используем упрощенный хеш из MessageUtils для демонстрации
        # ВАЖНО: p-1 передается в хеш-функцию для корректного взятия по модулю
        hash_h = MessageUtils.hash_message_for_elgamal(data_str, self.p - 1)

        self.signature_r, self.signature_s = ElGamalCrypto.sign(
            hash_h, self.p, self.g, issuer_private_key_xs, seed_for_k_sig
        )
        print(f"INFO: Certificate for {self.subject_id} signed by {self.issuer_id}. R={self.signature_r}, S={self.signature_s}")


    def verify_signature(self, issuer_public_key_ys):
        """
        Проверяет подпись сертификата, используя публичный ключ подписи издателя.
        """
        if self.signature_r is None or self.signature_s is None:
            print(f"ERROR: Certificate for {self.subject_id} is not signed.")
            return False

        data_str = self.get_data_to_sign_or_verify()
        hash_h = MessageUtils.hash_message_for_elgamal(data_str, self.p - 1)

        is_valid = ElGamalCrypto.verify(
            hash_h, self.signature_r, self.signature_s,
            self.p, self.g, issuer_public_key_ys
        )
        return is_valid

    def is_currently_valid(self):
        """
        Проверяет, действителен ли сертификат по датам.
        """
        now_dt = datetime.datetime.now(datetime.timezone.utc)
        try:
            valid_from_dt_obj = datetime.datetime.strptime(self.valid_from, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
            valid_to_dt_obj = datetime.datetime.strptime(self.valid_to, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            print(f"ERROR: Could not parse date strings in certificate for {self.subject_id}")
            return False # Некорректный формат даты

        return valid_from_dt_obj <= now_dt <= valid_to_dt_obj

    def to_dict(self):
        """ Представляет сертификат в виде словаря для сериализации (например, в JSON). """
        data = {
            "subject_id": self.subject_id,
            "issuer_id": self.issuer_id,
            "subject_public_key_ys": self.subject_public_key_ys,
            "p": self.p,
            "g": self.g,
            "valid_from": self.valid_from,
            "valid_to": self.valid_to,
            "serial_number": self.serial_number,
            "signature_r": self.signature_r,
            "signature_s": self.signature_s
        }
        # Добавляем ye только если он есть
        if self.subject_public_key_ye is not None:
            data["subject_public_key_ye"] = self.subject_public_key_ye
        return data

    @classmethod
    def from_dict(cls, cert_data):
        """ Создает объект Certificate из словаря. """
        try:
            return cls(
                subject_id=cert_data["subject_id"],
                issuer_id=cert_data["issuer_id"],
                subject_public_key_ys=cert_data["subject_public_key_ys"],
                subject_public_key_ye=cert_data.get("subject_public_key_ye"),  # Используем .get() для опционального поля
                p=cert_data["p"],
                g=cert_data["g"],
                valid_from_dt=datetime.datetime.strptime(cert_data["valid_from"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc),
                valid_to_dt=datetime.datetime.strptime(cert_data["valid_to"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc),
                serial_number=cert_data["serial_number"],
                signature_r=cert_data.get("signature_r"),
                signature_s=cert_data.get("signature_s")
            )
        except KeyError as e:
            raise ValueError(f"Missing key in certificate data: {e}")
        except ValueError as e:
            raise ValueError(f"Error parsing certificate data: {e}")


    def __str__(self):
        return (f"Certificate(Subject: {self.subject_id}, Issuer: {self.issuer_id}, "
                f"S/N: {self.serial_number}, Valid: {self.valid_from} to {self.valid_to}, "
                f"Signed: {'Yes' if self.signature_r else 'No'})")


class CertificateStore:
    """
    Упрощенное хранилище сертификатов (в памяти или файлах).
    Для демонстрации будем хранить в словаре в памяти и опционально в файлах JSON.
    Ключ словаря - subject_id сертификата.
    """
    def __init__(self, storage_dir="certs_store"):
        self.certs = {} # subject_id -> Certificate object
        self.storage_dir = storage_dir
        # os.makedirs(self.storage_dir, exist_ok=True) # Создадим директорию при необходимости

    def add_certificate(self, cert, save_to_file=False):
        self.certs[cert.subject_id] = cert
        if save_to_file:
            self.save_certificate_to_file(cert)
        print(f"INFO: Certificate for {cert.subject_id} added to store.")

    def get_certificate(self, subject_id):
        return self.certs.get(subject_id)

    def save_certificate_to_file(self, cert):
        import os # Импортируем здесь, чтобы не было зависимости на верхнем уровне файла
        os.makedirs(self.storage_dir, exist_ok=True)
        filename = os.path.join(self.storage_dir, f"{cert.subject_id.replace('@', '_at_')}.json")
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(cert.to_dict(), f, indent=4, ensure_ascii=False)
            print(f"INFO: Certificate for {cert.subject_id} saved to {filename}")
        except IOError as e:
            print(f"ERROR: Could not save certificate for {cert.subject_id} to file: {e}")

    def load_certificate_from_file(self, subject_id):
        import os
        filename = os.path.join(self.storage_dir, f"{subject_id.replace('@', '_at_')}.json")
        if not os.path.exists(filename):
            return None
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                cert_data = json.load(f)
            cert = Certificate.from_dict(cert_data)
            self.certs[subject_id] = cert # Добавляем в кэш памяти
            print(f"INFO: Certificate for {subject_id} loaded from {filename}")
            return cert
        except (IOError, json.JSONDecodeError, ValueError) as e:
            print(f"ERROR: Could not load certificate for {subject_id} from file: {e}")
            return None

    def list_subject_ids(self):
        return list(self.certs.keys())

# --- Тестовый блок ---
if __name__ == "__main__":
    print("--- Testing Certificate Manager ---")

    # Глобальные параметры (должны быть одинаковы для УЦ и субъекта)
    # Для теста сгенерируем их здесь
    lcg_param_seed = 98765
    lcg_for_params = LCG(lcg_param_seed)
    
    test_p = 0
    test_g = 0
    try:
        print("Generating p and g for testing...")
        test_p = PrimeManager.generate_prime(64, lcg_for_params.next_int()) # ИСПРАВЛЕНО
        test_g = PrimeManager.find_generator(test_p, lcg_for_params.next_int()) # ИСПРАВЛЕНО
        print(f"Test p: {test_p}, Test g: {test_g}")
        if test_g is None:
            print("CRITICAL: Could not find generator g for test_p. Aborting test.")
            exit()
    except RuntimeError as e:
        print(f"CRITICAL: Error generating p/g: {e}. Aborting test.")
        exit()


    # Ключи УЦ (Root CA)
    lcg_ca_seed = 112233
    ca_priv_key_xs, ca_pub_key_ys = ElGamalCrypto.generate_keys(test_p, test_g, lcg_ca_seed)
    # Для шифрования ключи могут быть другими, но для простоты УЦ может использовать
    # те же для подписи сертификатов (ys) и для шифрования чего-либо (ye), если потребуется
    ca_pub_key_ye = ca_pub_key_ys 
    print(f"\nCA Keys: private_xs={ca_priv_key_xs}, public_ys={ca_pub_key_ys}")

    # Ключи клиента
    lcg_client_seed = 445566
    client_priv_key_xe, client_pub_key_ye = ElGamalCrypto.generate_keys(test_p, test_g, lcg_client_seed)
    client_priv_key_xs, client_pub_key_ys = ElGamalCrypto.generate_keys(test_p, test_g, lcg_client_seed + 1) # Отдельная пара для подписи
    print(f"Client Keys: pub_ye={client_pub_key_ye}, pub_ys={client_pub_key_ys}")

    # 1. Создание сертификата для клиента
    print("\n1. Creating certificate for Client1...")
    client_cert = Certificate(
        subject_id="client1@example.com",
        issuer_id="RootCA",
        subject_public_key_ys=client_pub_key_ys,
        p=test_p,
        g=test_g
    )
    print(client_cert)

    # 2. УЦ подписывает сертификат клиента
    print("\n2. CA signing Client1's certificate...")
    # Сид для k при подписи сертификата
    k_sig_cert_seed = lcg_for_params.next_int()
    client_cert.sign(ca_priv_key_xs, k_sig_cert_seed)
    print(f"Client1's certificate signed. R={client_cert.signature_r}, S={client_cert.signature_s}")

    # 3. Проверка подписи сертификата клиента
    print("\n3. Verifying Client1's certificate signature...")
    is_verified = client_cert.verify_signature(ca_pub_key_ys)
    print(f"Signature verification result: {'VALID' if is_verified else 'INVALID'}")

    # 4. Проверка срока действия
    print("\n4. Checking certificate validity period...")
    is_current = client_cert.is_currently_valid()
    print(f"Is certificate currently valid by date? {'Yes' if is_current else 'No'}")

    # 5. Испортить данные и проверить снова (ожидаем INVALID)
    print("\n5. Tampering with certificate data and re-verifying (expecting INVALID)...")
    original_subject_id = client_cert.subject_id
    client_cert.subject_id = "hacker@example.com" # Изменяем данные ПОСЛЕ подписи
    is_tampered_verified = client_cert.verify_signature(ca_pub_key_ys)
    print(f"Tampered certificate verification result: {'VALID' if is_tampered_verified else 'INVALID'}")
    client_cert.subject_id = original_subject_id # Восстанавливаем для дальнейших тестов

    # 6. Тест самоподписанного сертификата (для Root CA)
    print("\n6. Testing self-signed certificate for RootCA...")
    root_ca_cert = Certificate(
        subject_id="RootCA",
        issuer_id="RootCA", # Сам себе издатель
        subject_public_key_ys=ca_pub_key_ys, # Публичный ключ УЦ для подписи
        p=test_p,
        g=test_g
    )
    k_sig_self_cert_seed = lcg_for_params.next_int()
    root_ca_cert.sign(ca_priv_key_xs, k_sig_self_cert_seed) # Подписывает своим же закрытым ключом
    print(root_ca_cert)
    is_self_signed_verified = root_ca_cert.verify_signature(ca_pub_key_ys) # Проверяется своим же публичным ключом
    print(f"Self-signed RootCA certificate verification: {'VALID' if is_self_signed_verified else 'INVALID'}")


    # 7. Тестирование CertificateStore
    print("\n7. Testing CertificateStore...")
    store = CertificateStore(storage_dir="test_certs_data") # Используем тестовую директорию
    
    # Удалим старые тестовые файлы, если они есть
    import shutil, os
    if os.path.exists("test_certs_data"):
        shutil.rmtree("test_certs_data")

    store.add_certificate(client_cert, save_to_file=True)
    store.add_certificate(root_ca_cert, save_to_file=True)

    print(f"Subjects in store: {store.list_subject_ids()}")

    loaded_client_cert = store.load_certificate_from_file("client1@example.com")
    if loaded_client_cert:
        print(f"Loaded from file: {loaded_client_cert}")
        is_loaded_verified = loaded_client_cert.verify_signature(ca_pub_key_ys)
        print(f"Loaded client cert signature verification: {'VALID' if is_loaded_verified else 'INVALID'}")
    else:
        print("ERROR: Failed to load client_cert from file.")

    # Проверка неверного subject_id
    non_existent_cert = store.get_certificate("nonexistent@example.com")
    print(f"Certificate for 'nonexistent@example.com': {non_existent_cert}")

    # Попытка загрузить несуществующий
    loaded_non_existent = store.load_certificate_from_file("nonexistent@example.com")
    print(f"Loaded non-existent from file: {loaded_non_existent}")

    print("\n--- Certificate Manager Test Finished ---")

# END OF FILE: certificate_manager.py