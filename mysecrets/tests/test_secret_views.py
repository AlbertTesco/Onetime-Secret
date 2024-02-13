from django.test import TestCase
from rest_framework.test import APIRequestFactory
from rest_framework import status

from mysecrets.api_views.secret import SecretGenerateView, SecretRetrieveView
from mysecrets.models import Secret
from mysecrets.serializers import SecretSerializer


class SecretGenerateViewTest(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()

    def test_generate_secret(self):
        request = self.factory.post('/generate/', {"secret_text": "test_secret", "passphrase": "test_passphrase"})
        view = SecretGenerateView.as_view()
        response = view(request)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        secret_key = response.data.get('secret_key')
        self.assertTrue(Secret.objects.filter(secret_key=secret_key).exists())


class SecretRetrieveViewTest(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()

        # Создаем данные для создания секрета
        secret_data = {"secret_text": "test_secret", "passphrase": "test_passphrase"}

        secret_serializer = SecretSerializer(data=secret_data)

        if secret_serializer.is_valid():
            self.secret = secret_serializer.save()

    def test_retrieve_secret(self):
        request = self.factory.get(f'/secrets/{self.secret.secret_key}/', data={"passphrase": "test_passphrase"})

        # Вызываем представление для обработки запроса
        view = SecretRetrieveView.as_view()
        response = view(request, secret_key=self.secret.secret_key)

        # Проверяем код ответа
        self.assertEqual(response.status_code, status.HTTP_200_OK)  # Успешное получение секрета

    def test_retrieve_inactive_secret(self):
        # Деактивируем секрет
        self.secret.is_active = False
        self.secret.save()

        secret_data = {"passphrase": "test_passphrase"}

        # Создаем запрос с параметром passphrase через URL
        request = self.factory.get(f'/secrets/{self.secret.secret_key}/', data=secret_data)

        # Вызываем представление для обработки запроса
        view = SecretRetrieveView.as_view()
        response = view(request, secret_key=self.secret.secret_key)

        # Проверяем код ответа
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)  # Секрет не найден

    def test_retrieve_invalid_passphrase(self):
        secret_data = {"passphrase": "wrong_passphrase"}

        # Создаем запрос с неправильным passphrase через URL
        request = self.factory.get(f'/secrets/{self.secret.secret_key}/', data=secret_data)

        # Вызываем представление для обработки запроса
        view = SecretRetrieveView.as_view()
        response = view(request, secret_key=self.secret.secret_key)

        # Проверяем код ответа
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)  # Неправильный пароль
