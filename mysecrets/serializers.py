from rest_framework import serializers
from mysecrets.models import Secret
from mysecrets.utils import encrypt


class SecretSerializer(serializers.ModelSerializer):
    secret_text = serializers.CharField(max_length=255)
    passphrase = serializers.CharField(max_length=255)

    class Meta:
        model = Secret
        fields = ['id', 'encrypted_secret', 'iv', 'encrypted_passphrase', 'secret_key', 'secret_text', 'passphrase']
        read_only_fields = ['id', 'iv', 'secret_key', 'encrypted_secret', 'encrypted_passphrase']

    def create(self, validated_data):
        """
        Create a new instance of the Secret model.

        Parameters:
        validated_data (dict):
            The validated data to use to create the instance.
            The expected fields are:
                secret_text (str): The text to be encrypted.
                passphrase (str): The passphrase to use for encryption.

        Returns:
        Secret: The newly created instance.
        """
        secret_text = validated_data.get('secret_text')
        passphrase = validated_data.get('passphrase')

        iv, encrypted_secret, encrypted_passphrase = encrypt(secret_text, passphrase)
        return Secret.objects.create(encrypted_secret=encrypted_secret, encrypted_passphrase=encrypted_passphrase,
                                     iv=iv)


class PassphraseSerializer(serializers.Serializer):
    passphrase = serializers.CharField(max_length=100)

    def validate_passphrase(self, value):
        if not value:
            raise serializers.ValidationError("Passphrase is required")
        return value
