from ..serializers import SecretSerializer
from ..models import Secret
from ..utils import decrypt
from django.shortcuts import get_object_or_404
from django.utils.crypto import constant_time_compare
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi


class SecretGenerateView(APIView):
    """
    This view is responsible for generating a new secret.

    Methods:
        post: This method generates a new secret and saves it to the database.
            It expects the following JSON fields:
            - secret_text (str): The secret data to be stored.
            - passphrase (str): The passphrase to encrypt the secret data.
    """

    @swagger_auto_schema(
        request_body=SecretSerializer,
        responses={201: openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={'secret_key': openapi.Schema(type=openapi.TYPE_STRING)}
        )}
    )
    def post(self, request, format=None):
        """
        This method generates a new secret and saves it to the database.

        Parameters:
            request (HttpRequest): The incoming request.
            format (str): The format of the request.

        Returns:
            Response: A response with the secret key.
        """
        serializer = SecretSerializer(data=request.data)
        if serializer.is_valid():
            secret = serializer.save()
            return Response({"secret_key": secret.secret_key}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SecretRetrieveView(APIView):
    """
    This view is responsible for retrieving a secret based on the secret key and a passphrase.

    Methods:
        get: This method retrieves the secret based on the secret key and the passphrase.
    """

    def get(self, request, secret_key, format=None):
        """
        This method retrieves the secret based on the secret key and the passphrase.

        Parameters:
            request (HttpRequest): The incoming request.
            secret_key (str): The secret key used to retrieve the secret.
            format (str): The format of the request.

        Returns:
            Response: A response with the secret or an error message.
        """
        # Получение секрета по его ключу
        secret = get_object_or_404(Secret, secret_key=secret_key)

        # Проверка активности секрета
        if not secret.is_active:
            return Response({"error": "This secret is not active"}, status=status.HTTP_404_NOT_FOUND)

        # Получение параметра passphrase из URL
        passphrase = request.data.get('passphrase')
        print(passphrase)

        # Проверка наличия пароля
        if not passphrase:
            return Response({"error": "Passphrase is required"}, status=status.HTTP_400_BAD_REQUEST)

        # Дешифровка секрета
        decrypted_secret, decrypted_passphrase = decrypt(secret.iv, secret.encrypted_secret,
                                                         secret.encrypted_passphrase)

        # Проверка правильности пароля
        if constant_time_compare(passphrase, decrypted_passphrase):
            return Response({"secret": decrypted_secret}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid passphrase"}, status=status.HTTP_400_BAD_REQUEST)
