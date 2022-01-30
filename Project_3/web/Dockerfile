FROM python:3.9.5-slim-buster

COPY ./requirements.txt /app/requirements.txt
RUN pip install -r /app/requirements.txt

# set work directory
WORKDIR /app

ENV FLASK_ENV=production
ENV APP_PATH /app/app.py
ENV DOCKER_HOST=tcp://172.17.0.1:2376

COPY static /app/static
COPY templates /app/templates
COPY *.py /app/
COPY entrypoint.sh /

EXPOSE 5000

#RUN useradd -Mr app
#USER app

ENTRYPOINT ["/bin/bash", "/entrypoint.sh"]

