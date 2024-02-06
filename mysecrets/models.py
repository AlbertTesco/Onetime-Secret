from django.db import models
from django.utils import timezone

from mysecrets.utils import generate_secret_key


# Create your models here.
class Secret(models.Model):
    """
    A model to store secrets.

    Attributes:
        encrypted_secret (TextField): The encrypted secret.
        encrypted_passphrase (CharField): The encrypted passphrase.
        secret_key (CharField): The secret key.
        created_at (DateTimeField): The date the secret was created.
        iv (CharField): The initialization vector.
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

        If the secret key is not set, it is generated from the encrypted secret and the encrypted passphrase.
        """
        if not self.secret_key:
            self.secret_key = generate_secret_key(self.encrypted_secret, self.encrypted_passphrase)
        super().save(*args, **kwargs)
