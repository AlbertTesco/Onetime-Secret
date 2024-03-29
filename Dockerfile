FROM python:3

ENV PYTHONUNBUFFERED 1

WORKDIR /code

COPY . /code/

COPY requirements.txt /code/

RUN pip install --upgrade pip && pip install -r requirements.txt

EXPOSE 8000
