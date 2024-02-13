from django.test import TestCase
from django.utils import timezone
from mysecrets.models import Secret
from mysecrets.utils import generate_secret_key


class SecretModelTestCase(TestCase):
    def test_secret_creation(self):
        # Создание объекта Secret
        secret = Secret.objects.create(
            encrypted_secret="encrypted_secret_data",
            encrypted_passphrase="encrypted_passphrase_data",
            iv="initialization_vector_data"
        )

        # Проверка, что объект успешно создан
        self.assertIsInstance(secret, Secret)

        # Проверка значений атрибутов
        self.assertEqual(secret.encrypted_secret, "encrypted_secret_data")
        self.assertEqual(secret.encrypted_passphrase, "encrypted_passphrase_data")
        self.assertEqual(secret.iv, "initialization_vector_data")
        self.assertTrue(secret.is_active)  # По умолчанию должен быть активен

        # Проверка, что secret_key был сгенерирован
        self.assertTrue(secret.secret_key)

    def test_generate_secret_key(self):
        # Параметры для теста
        secret_data = "my_secret"
        passphrase_data = "my_passphrase"
        expected_key = generate_secret_key(secret_data, passphrase_data)

        # Генерация секретного ключа
        actual_key = generate_secret_key(secret_data, passphrase_data)

        # Проверка, что сгенерированный ключ соответствует ожидаемому
        self.assertEqual(actual_key, expected_key)

    def test_secret_save(self):
        # Создание объекта Secret
        secret = Secret.objects.create(
            encrypted_secret="encrypted_secret_data",
            encrypted_passphrase="encrypted_passphrase_data",
            iv="initialization_vector_data"
        )

        # Сохранение объекта
        secret.save()

        # Проверка, что секретный ключ был сгенерирован после сохранения
        self.assertTrue(secret.secret_key)

        # Проверка, что дата создания была установлена корректно
        self.assertTrue(secret.created_at)
        self.assertIsInstance(secret.created_at, timezone.datetime)

        # Проверка, что секрет активен после сохранения
        self.assertTrue(secret.is_active)
