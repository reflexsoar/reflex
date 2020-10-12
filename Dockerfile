FROM python:3.8

LABEL maintainer="Brian Carroll 'netsurge' <bcarroll@zeroonesecurity.com>"

RUN mkdir /opt/reflex
RUN mkdir /opt/reflex/ssl

EXPOSE 80
EXPOSE 443

ADD /reflex-api /opt/reflex/reflex-api
ADD /ui /opt/reflex/ui

RUN pip install --upgrade pip
RUN pip install pipenv
RUN pip install nginx

RUN useradd reflex -m -s /bin/bash
RUN export FLASK_CONFIG="production"

RUN echo "MASTER_PASSWORD = '$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 128 | head -n 1)'" > /opt/reflex/reflex-api/instance/application.conf
RUN echo "SECRET_KEY = '$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 512 | head -n 1)'" >> /opt/reflex/reflex-api/instance/application.conf
RUN echo "SECURITY_PASSWORD_SALT = '$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 512 | head -n 1)'" >> /opt/reflex/reflex-api/instance/application.conf

RUN chown -R reflex:reflex /opt/reflex

ADD /reflex-api.service /etc/systemd/system/reflex-api.service
RUN systemctl daemon-reload
RUN systemctl start reflex-api

ADD /reflex.conf /opt/nginx/sites-enabled/reflex

RUN apt-get update && apt-get install -y nginx
RUN openssl dhparam -dsaparam -out /opt/reflex/ssl/ssl-dhparams.pem 4096
RUN openssl req -new -newkey rsa:4096 -days 3650 -nodes -x509 \
                -subj "/C=US/ST=IL/O=H & A Security Solutions, LLC/CN=reflexsoar" \
                -keyout /opt/reflex/ssl/server.key  -out /opt/reflex/ssl/server.crt

RUN ls /opt/reflex