from ..serializers import SecretSerializer, PassphraseSerializer
from ..models import Secret
from ..utils import decrypt
from django.shortcuts import get_object_or_404
from django.utils.crypto import constant_time_compare
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView


class SecretGenerateView(APIView):
    """
    This view generates a new secret and stores it in the database.
    """

    def post(self, request, format=None):
        """
        Generates a new secret and stores it in the database.

        Parameters:
        request (HttpRequest): The incoming request.
        format (str): The format of the request.

        Returns:
        Response: A response containing the secret key.
        """
        serializer = SecretSerializer(data=request.data)
        if serializer.is_valid():
            secret = serializer.save()
            return Response({"secret_key": secret.secret_key}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SecretRetrieveView(APIView):
    """
    Retrieve a secret based on its key and a provided passphrase.

    Parameters:
    secret_key (str): The unique key of the secret to retrieve.
    request (HttpRequest): The incoming request containing the passphrase.

    Returns:
    Response: A response containing the secret or an error.
    """

    def get(self, request, secret_key, format=None):
        secret = get_object_or_404(Secret, secret_key=secret_key)

        if secret.is_active:
            secret.is_active = False
            secret.save()
        else:
            return Response({"error": "This secret is not active"}, status=status.HTTP_200_OK)

        serializer = PassphraseSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        passphrase = serializer.validated_data.get('passphrase', None)

        decrypted_secret, decrypted_passphrase = decrypt(secret.iv, secret.encrypted_secret,
                                                         secret.encrypted_passphrase)

        if constant_time_compare(passphrase, decrypted_passphrase):
            return Response({"secret": decrypted_secret}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid passphrase"}, status=status.HTTP_400_BAD_REQUEST)
