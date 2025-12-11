import json
from flask import Blueprint, jsonify, request

from app.utils import remote_request, safe_remote_request


ssrf_bp = Blueprint("ssrf", __name__)


@ssrf_bp.get("/ssrf/1")
def ssrf_1():
    url = request.args.get("url")
    try:
        response = remote_request(url)
        json_resp = json.loads(response)
        return jsonify(json_resp)
    except Exception as e:
        return jsonify({"error": str(e)})


@ssrf_bp.get("/ssrf/2")
def ssrf_2():
    url = request.args.get("url")
    try:
        response = safe_remote_request(url)
        json_resp = json.loads(response)
        return jsonify(json_resp)
    except Exception as e:
        return jsonify({"error": str(e)})
