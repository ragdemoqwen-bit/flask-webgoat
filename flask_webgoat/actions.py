import pickle
import base64
import re
from pathlib import Path
import subprocess

from flask import Blueprint, request, jsonify, session

bp = Blueprint("actions", __name__)


@bp.route("/message", methods=["POST"])
def log_entry():
    user_info = session.get("user_info", None)
    if user_info is None:
        return jsonify({"error": "no user_info found in session"})
    access_level = user_info[2]
    if access_level > 2:
        return jsonify({"error": "access level < 2 is required for this action"})
    filename_param = request.form.get("filename")
    if filename_param is None:
        return jsonify({"error": "filename parameter is required"})
    text_param = request.form.get("text")
    if text_param is None:
        return jsonify({"error": "text parameter is required"})

    user_id = user_info[0]
    user_dir = "data/" + str(user_id)
    user_dir_path = Path(user_dir)
    if not user_dir_path.exists():
        user_dir_path.mkdir()

    filename = filename_param + ".txt"
    path = Path(user_dir + "/" + filename)
    # vulnerability: Directory Traversal
    with path.open("w", encoding="utf-8") as open_file:
        open_file.write(text_param)
    return jsonify({"success": True})


@bp.route("/grep_processes")
def grep_processes():
    name = request.args.get("name")
    if name is None:
        return jsonify({"error": "name parameter is required"}), 400
    # Validate input: only allow alphanumeric characters, hyphens, underscores,
    # dots, and forward slashes to prevent command injection.
    if not re.match(r'^[a-zA-Z0-9_.\-/]+$', name):
        return jsonify({"error": "invalid characters in name parameter"}), 400
    ps_result = subprocess.run(
        ["ps", "aux"],
        capture_output=True,
    )
    grep_result = subprocess.run(
        ["grep", name],
        input=ps_result.stdout,
        capture_output=True,
    )
    awk_result = subprocess.run(
        ["awk", "{print $11}"],
        input=grep_result.stdout,
        capture_output=True,
    )
    if awk_result.stdout is None:
        return jsonify({"error": "no stdout returned"})
    out = awk_result.stdout.decode("utf-8")
    names = out.split("\n")
    return jsonify({"success": True, "names": names})


@bp.route("/deserialized_descr", methods=["POST"])
def deserialized_descr():
    pickled = request.form.get('pickled')
    data = base64.urlsafe_b64decode(pickled)
    # vulnerability: Insecure Deserialization
    deserialized = pickle.loads(data)
    return jsonify({"success": True, "description": str(deserialized)})
