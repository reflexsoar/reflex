import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from flask_mail import Mail
from config import app_config

FLASK_BCRYPT = Bcrypt()
db = SQLAlchemy()
cors = CORS()
mail = Mail()

def create_app(environment='development'):

    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(app_config[os.getenv('FLASK_CONFIG', environment)])
    app.config.from_pyfile('application.conf', silent=True)

    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].format(
        app.config['DB_USERNAME'],
        app.config['DB_PASSWORD'],
        app.config['DB_HOST'],
        app.config['DB_PORT'],
        app.config['DB_NAME'],
    )

    db.init_app(app)
    cors.init_app(app)
    mail.init_app(app)

    authorizations = {"Bearer": {"type": "apiKey", "in": "header", "name":"Authorization"}}

    from app.resources import api
    api.authorizations = authorizations
    api.title = app.config['API_TITLE']
    api.version = app.config['API_VERSION']
    api.description = app.config['API_DESCRIPTION']
    api.default_mediatype='application/json'

    from app.resources import api_v1
    app.register_blueprint(api_v1)

    FLASK_BCRYPT.init_app(app)

    return app