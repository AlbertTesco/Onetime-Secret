from rest_framework import serializers
from mysecrets.models import Secret
from mysecrets.utils import encrypt


class SecretSerializer(serializers.ModelSerializer):
    """
    Serializer for the Secret model.
    """
    secret_text = serializers.CharField(max_length=255)
    passphrase = serializers.CharField(max_length=255)

    class Meta:
        model = Secret
        fields = ['secret_key', 'secret_text', 'passphrase']
        read_only_fields = ['secret_key']

    def create(self, validated_data):
        """
        Create a new Secret instance.
        """
        secret_text = validated_data.get('secret_text')
        passphrase = validated_data.get('passphrase')

        iv, encrypted_secret, encrypted_passphrase = encrypt(secret_text, passphrase)
        return Secret.objects.create(encrypted_secret=encrypted_secret, encrypted_passphrase=encrypted_passphrase,
                                     iv=iv)


