from django.db import models
from django.utils import timezone

from mysecrets.utils import generate_secret_key


class Secret(models.Model):
    """
    A model that stores secrets.

    Attributes:
        encrypted_secret (TextField): The encrypted secret data.
        encrypted_passphrase (CharField): The encrypted passphrase used to encrypt the secret data.
        secret_key (CharField): The secret key used to encrypt and decrypt the secret data.
        created_at (DateTimeField): The date and time the secret was created.
        iv (CharField): The initialization vector used for encryption.
        is_active (BooleanField): A boolean indicating whether the secret is active or not.
    """

    encrypted_secret = models.TextField(verbose_name='Текст секрета')
    encrypted_passphrase = models.CharField(max_length=255, verbose_name='Секретная фраза')
    secret_key = models.CharField(max_length=255, unique=True, blank=True, verbose_name='Секретный ключ')
    created_at = models.DateTimeField(default=timezone.now, verbose_name='Дата создания')
    iv = models.CharField(max_length=255, verbose_name='Вектор инициализации')
    is_active = models.BooleanField(default=True, verbose_name='Активность')

    def save(self, *args, **kwargs):
        """
        Saves the secret.

        If the secret key is not set, it is generated from the encrypted secret and encrypted passphrase.
        """
        if not self.secret_key:
            self.secret_key = generate_secret_key(self.encrypted_secret, self.encrypted_passphrase)
        super().save(*args, **kwargs)
