import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from config.settings import AES_KEY


def generate_secret_key(secret: str, passphrase: str) -> str:
    """
    Генерирует секретный ключ на основе переданного секрета и кодовой фразы.

    Args:
        secret (str): Секретная информация.
        passphrase (str): Кодовая фраза.

    Returns:
        str: Секретный ключ.
    """
    data = secret + passphrase
    data_bytes = data.encode('utf-8')
    hashed_key = hashlib.sha256(data_bytes).hexdigest()
    return hashed_key


def encrypt(secret: str, password: str) -> tuple:
    """
    Шифрует секрет и кодовую фразу с использованием AES.

    Args:
        secret (str): Секретная информация.
        password (str): Кодовая фраза.

    Returns:
        tuple: Кортеж с зашифрованным IV, секретом и кодовой фразой.
    """
    cipher = AES.new(AES_KEY.encode('utf-8'), AES.MODE_CBC)
    iv = base64.b64encode(cipher.iv).decode('utf-8')

    encrypted_secret = cipher.encrypt(pad(secret.encode('utf-8'), AES.block_size))
    encrypted_secret = base64.b64encode(encrypted_secret).decode('utf-8')

    encrypted_password = cipher.encrypt(pad(password.encode('utf-8'), AES.block_size))
    encrypted_password = base64.b64encode(encrypted_password).decode('utf-8')

    return iv, encrypted_secret, encrypted_password


def decrypt(iv: str, encrypted_secret: str, encrypted_password: str) -> tuple:
    """
    Расшифровывает секрет и кодовую фразу с использованием AES.

    Args:
        iv (str): Зашифрованный IV.
        encrypted_secret (str): Зашифрованный секрет.
        encrypted_password (str): Зашифрованная кодовая фраза.

    Returns:
        tuple: Кортеж с расшифрованным секретом и кодовой фразой.
    """
    cipher = AES.new(AES_KEY.encode('utf-8'), AES.MODE_CBC, base64.b64decode(iv))

    decrypted_secret = unpad(cipher.decrypt(base64.b64decode(encrypted_secret)), AES.block_size).decode('utf-8')
    decrypted_password = unpad(cipher.decrypt(base64.b64decode(encrypted_password)), AES.block_size).decode('utf-8')

    return decrypted_secret, decrypted_password

# def encrypt_passphrase(self, password: str, iv: str):

