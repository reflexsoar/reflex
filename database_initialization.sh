#!/bin/bash
export FLASK_CONFIG="production"
export PIPENV_PIPFILE=/opt/reflex/reflex-api/Pipfile
cd /opt/reflex/reflex-api
pipenv install --dev
pipenv run python /opt/reflex/reflex-api/manage.py db init
pipenv run python /opt/reflex/reflex-api/manage.py db migrate
pipenv run python /opt/reflex/reflex-api/manage.py db upgrade
pipenv run python /opt/reflex/reflex-api/manage.py setup