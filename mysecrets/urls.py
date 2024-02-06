from django.urls import path

from mysecrets.api_views.secret import SecretGenerateView, SecretRetrieveView
from mysecrets.apps import MysecretsConfig

app_name = MysecretsConfig.name

urlpatterns = [
    path('generate/', SecretGenerateView.as_view(), name='generate_secret'),
    path('secrets/<str:secret_key>/', SecretRetrieveView.as_view(), name='retrieve_secret'),
]
