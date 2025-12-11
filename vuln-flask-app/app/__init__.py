from flask import Flask

from app.api import register_blueprints


def create_app(env_type: str):
    app = Flask(__name__)

    register_blueprints(app)

    return app
