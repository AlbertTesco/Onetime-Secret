import hashlib


from mysecrets.utils import generate_secret_key, encrypt, decrypt


def test_generate_secret_key():
    secret = "my_secret"
    passphrase = "my_passphrase"

    expected_key = hashlib.sha256((secret + passphrase).encode('utf-8')).hexdigest()
    actual_key = generate_secret_key(secret, passphrase)

    assert actual_key == expected_key


def test_encrypt():
    secret = "my_secret"
    password = "my_password"

    iv, encrypted_secret, encrypted_password = encrypt(secret, password)

    # Проверяем, что результаты не пустые
    assert iv
    assert encrypted_secret
    assert encrypted_password

    # Проверяем, что расшифрованный секрет и пароль не совпадают с исходными
    assert secret != encrypted_secret
    assert password != encrypted_password


def test_decrypt():
    secret = "my_secret"
    password = "my_password"

    # Зашифровываем секрет и пароль
    iv, encrypted_secret, encrypted_password = encrypt(secret, password)

    # Расшифровываем секрет и пароль
    decrypted_secret, decrypted_password = decrypt(iv, encrypted_secret, encrypted_password)

    # Проверяем, что расшифрованные данные совпадают с исходными данными
    assert decrypted_secret == secret
    assert decrypted_password == password
