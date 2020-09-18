#!/bin/bash
export FLASK_CONFIG="production"
cd /opt/reflex/reflex-api
pipenv install --dev
pipenv run python manage.py db init
pipenv run python manage.py db migrate
pipenv run python manage.py db upgrade
pipenv run python manage.py setup