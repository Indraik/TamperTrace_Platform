import datetime
from flask import Blueprint, request, jsonify
from app.database import get_monitored_urls_col
from app.services.restore_service import RestoreService

recovery_bp = Blueprint("recovery", __name__)

@recovery_bp.route("/restore", methods=["POST"])
def restore_site():
    data = request.get_json()
    if not data or "url" not in data:
        return jsonify({
            "success": False,
            "message": "URL parameter is required for disaster recovery restoration."
        }), 400

    url = data["url"]
    result = RestoreService.restore_website(url, restored_by="admin")

    if result.get("success"):
        update_payload = {
            "change_detected": False,
            "status": "✅ Restored to SAFE baseline",
            "last_verified": datetime.datetime.now(),
            "last_change": None
        }
        if result.get("restored_hash"):
            update_payload["html_hash"] = result["restored_hash"]

        get_monitored_urls_col().update_one(
            {"url": url},
            {"$set": update_payload}
        )
        return jsonify(result), 200
    else:
        return jsonify(result), 404
