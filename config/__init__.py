import os

from dotenv import load_dotenv

from config.settings import BASE_DIR

load_dotenv(BASE_DIR / '.env')

print(os.getenv('DJANGO_SETTINGS_MODULE'))
