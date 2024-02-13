import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from config.settings import AES_KEY


def generate_secret_key(secret: str, passphrase: str) -> str:
    """
    Generate a secret key from a given secret and passphrase.

    Args:
        secret (str): The secret string to be used in the key generation.
        passphrase (str): The passphrase to be used in the key generation.

    Returns:
        str: The generated secret key.

    """
    data = secret + passphrase
    data_bytes = data.encode('utf-8')
    hashed_key = hashlib.sha256(data_bytes).hexdigest()
    return hashed_key


def encrypt(secret: str, password: str) -> tuple:
    """
    This function takes in a secret string and a password as input, and returns a tuple of the initialization vector (IV), the encrypted secret, and the encrypted password.

    Args:
        secret (str): The secret string to be encrypted.
        password (str): The password to be used for encryption.

    Returns:
        tuple: A tuple containing the IV, the encrypted secret, and the encrypted password.

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
    This function takes in the initialization vector (IV), the encrypted secret, and the encrypted password, and returns the decrypted secret and password.

    Args:
        iv (str): The initialization vector used for encryption.
        encrypted_secret (str): The encrypted secret string.
        encrypted_password (str): The encrypted password string.

    Returns:
        tuple: A tuple containing the decrypted secret and password.

    """
    cipher = AES.new(AES_KEY.encode('utf-8'), AES.MODE_CBC, base64.b64decode(iv))

    decrypted_secret = unpad(cipher.decrypt(base64.b64decode(encrypted_secret)), AES.block_size).decode('utf-8')
    decrypted_password = unpad(cipher.decrypt(base64.b64decode(encrypted_password)), AES.block_size).decode('utf-8')

    return decrypted_secret, decrypted_password
