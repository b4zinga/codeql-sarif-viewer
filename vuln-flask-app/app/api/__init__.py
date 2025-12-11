import importlib
import logging
import os
import traceback
from flask import Blueprint, Flask


logger = logging.getLogger(__name__)


def find_all_blueprints():
    """自动发现当前目录下的blueprint"""
    all_blueprints = []
    current_dir = os.path.dirname(__file__)

    for filename in os.listdir(current_dir):
        if not filename.endswith(".py") or filename.startswith("_"):
            continue
        module_name = filename[:-3]
        try:
            module = importlib.import_module(f"app.api.{module_name}")
            for attr_name in dir(module):
                if not attr_name.endswith("_bp"):
                    continue
                blueprint = getattr(module, attr_name)
                if isinstance(blueprint, Blueprint):
                    logger.debug(f"found blueprint {attr_name} in module {module_name}")
                    all_blueprints.append(blueprint)
        except Exception as e:
            logger.error(f"find_all_blueprints error: {e}, {traceback.format_exc()}")
            continue
    return all_blueprints


def register_blueprints(app: Flask, url_prefix: str = "/api"):
    """注册路由"""

    for blueprint in find_all_blueprints():
        app.register_blueprint(blueprint, url_prefix=url_prefix)
