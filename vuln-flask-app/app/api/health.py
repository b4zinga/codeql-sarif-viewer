from flask import Blueprint, jsonify


health_bp = Blueprint("health", __name__)


@health_bp.route("/status", methods=["GET", "POST"])
def index():
    data = {
        "status": "UP",
    }
    return jsonify(data)
