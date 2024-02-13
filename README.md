# Онлайн хранилище секретов (Onetime Secret)

Проект "Onetime Secret" представляет собой веб-приложение для генерации одноразовых секретов и безопасного обмена ими.

## Функционал

- **Генерация секретов**: Приложение позволяет создавать одноразовые секреты, содержащие конфиденциальную информацию.
  
- **Шифрование секретов**: Введенный секрет и пароль шифруются перед сохранением в базе данных для обеспечения безопасности.

- **Получение секретов по ссылке**: Каждый секрет получает уникальную ссылку, по которой можно получить доступ к нему только один раз.

- **Автоматическое удаление секретов**: После первого просмотра секрета или по истечении определенного времени он автоматически удаляется.

## Технологии

Проект использует следующие технологии:

- **Python**: Язык программирования, используемый для разработки бэкенда приложения.
  
- **Django**: Фреймворк для создания веб-приложений на Python, используется для реализации серверной части приложения.

- **Django REST Framework**: Библиотека для создания веб-сервисов RESTful API на базе Django.

- **PostgreSQL**: Реляционная база данных, используемая для хранения информации о секретах и пользователях.

- **Docker**: Платформа для разработки, доставки и выполнения приложений в контейнерах.

- **Swagger/OpenAPI**: Инструменты для создания и документирования API.

## Установка

### Без использования Docker

1. Клонируйте репозиторий:

    ```bash
    git clone https://github.com/yourusername/onetime-secret.git
    ```

2. Перейдите в каталог проекта:

    ```bash
    cd onetime-secret
    ```

3. Создайте и активируйте виртуальное окружение:

    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

4. Установите зависимости:

    ```bash
    pip install -r requirements.txt
    ```

5. Примените миграции:

    ```bash
    python manage.py migrate
    ```

6. Запустите сервер:

    ```bash
    python manage.py runserver
    ```

### Используя Docker

1. Установите Docker и Docker Compose, если еще не установлены.

2. Клонируйте репозиторий:

    ```bash
    git clone https://github.com/yourusername/onetime-secret.git
    ```

3. Перейдите в каталог проекта:

    ```bash
    cd onetime-secret
    ```

4. Запустите контейнеры с помощью Docker Compose:

    ```bash
    docker-compose up -d
    ```

## Использование

После установки и запуска сервера вы сможете взаимодействовать с приложением через веб-интерфейс, доступный по адресу [http://127.0.0.1:8000/](http://127.0.0.1:8000/).

## Документация API

Для получения дополнительной информации о доступных API-методах и их использовании можно использовать Swagger-документацию, доступную по адресу [http://127.0.0.1:8000/swagger/](http://127.0.0.1:8000/swagger/).

## Лицензия

Этот проект лицензируется в соответствии с условиями лицензии MIT. Подробности смотрите в файле [LICENSE](LICENSE).
