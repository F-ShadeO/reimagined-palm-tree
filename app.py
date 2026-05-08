from flask import Flask, request, jsonify, send_from_directory
import json
import os
import hashlib
from datetime import datetime, timezone

app = Flask(__name__)

FINGERPRINT_ATTRIBUTES = (
    "user_agent", "language", "platform", "screen_resolution",
    "color_depth", "timezone", "hardware_concurrency",
    "pixel_ratio", "touch_points", "canvas_hash",
)

FINGERPRINT_FILE = "fingerprints.json"

def parse_fingerprint(data):
    """This defintion or def is used to define a function, in this case it's to parse(or analyse)
    It validates and sanitises incoming fingerprint payload.
    It expects a dictionary, and will only return a sanitised dictionary with
    the expected attribute keys. Raises TypeError if input is not a dict.
    """
    if not isinstance(data, dict):
        raise TypeError(f"Expected dict, received {type(data).__name__}")
    return {attr: str(data.get(attr) or "unknown") for attr in FINGERPRINT_ATTRIBUTES}

def hash_fingerprint(attributes):
    """This definition or def is used to define a function, in this case it's to hash the fingerprint.
    Hashing converts the fingerprint dictionary into a fixed-length string of characters
    using SHA-256, which is a one-way process meaning the original data cannot be recovered from the hash.
    This satisfies the requirement that no personally identifiable information is stored.
    Keys are sorted before hashing to ensure the same fingerprint always
    produces the same hash regardless of dictionary key order.
    """

    serialised = json.dumps(attributes, sort_keys=True)
    return hashlib.sha256(serialised.encode("utf-8")).hexdigest()

def load_fingerprints(filepath):
    """This definition or def is used to define a function, in this case it's to load fingerprints.
    A fingerprint here refers to the unique combination of browser attributes collected
    from a visitor, i.e a digital fingerprint. This function reads previously stored
    fingerprint records from a JSON file on disk.
    JSON (JavaScript Object Notation) is a lightweight text format for storing structured data.
    It returns an empty list if the file is missing or malformed,
    preventing a corrupted file from crashing the application.
    """
    
    if not os.path.exists(filepath):
        return []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list):
            return []
        return data
    except json.JSONDecodeError:
        return []
    except IOError:
        return []

def save_fingerprints(fingerprints, filepath):
    """This function is used to save fingerprints.
    Saving here means saving the complete list of fingerprint records to a JSON file on disk
    so they persist between sessions. Without this, all data would be lost when the server stops.
    Uses with-open to ensure the file handle is always closed safely,
    even if an error occurs during writing. This is safer than open() without with,
    which risks leaving the file locked if an exception is raised mid-write.
    """
    
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(fingerprints, f, indent=4)

def calculate_uniqueness(fp_hash, all_fingerprints):  
    """This def is used to calculate uniqueness.
    It compares a fingerprint hash against all stored records and returns a uniqueness score.
    Uses a set for O(1) deduplication of hashes rather than a list.
    Returns a dict with total_seen, matching, unique_hashes, and uniqueness_pct.
    """

    total = len(all_fingerprints)
    if total == 0:
        return {"total_seen": 0, "matching": 1, "unique_hashes": 1, "uniqueness_pct": 100.0}
    all_hashes = {r["hash"] for r in all_fingerprints if "hash" in r}
    matching = sum(1 for r in all_fingerprints if r.get("hash") == fp_hash)
    return {
        "total_seen": total,
        "matching": matching,
        "unique_hashes": len(all_hashes),
        "uniqueness_pct": round((matching / total) * 100, 2),
    }

@app.route("/")
def index():
    return send_from_directory("static", "index.html")

@app.route("/fingerprint", methods=["POST"])
def submit_fingerprint():
    raw_data = request.get_json(silent=True)
    if raw_data is None:
        return jsonify({"error": "Request body must be valid JSON"}), 400
    try:
        attributes = parse_fingerprint(raw_data)
    except TypeError as e:
        return jsonify({"error": str(e)}), 400
    fp_hash = hash_fingerprint(attributes)
    all_fingerprints = load_fingerprints(FINGERPRINT_FILE)
    uniqueness = calculate_uniqueness(fp_hash, all_fingerprints)
    record = {
        "hash": fp_hash,
        "attributes": attributes,
        "submitted_at": datetime.now(timezone.utc).isoformat(),
        "uniqueness": uniqueness,
    }
    all_fingerprints.append(record)
    try:
        save_fingerprints(all_fingerprints, FINGERPRINT_FILE)
    except IOError as e:
        return jsonify({"error": f"Storage failure: {e}"}), 500
    return jsonify({"hash": fp_hash, "uniqueness": uniqueness, "attributes": attributes}), 200

@app.route("/stats", methods=["GET"])
def get_stats():
    all_fingerprints = load_fingerprints(FINGERPRINT_FILE)
    if not all_fingerprints:
        return jsonify({"message": "No fingerprints collected yet", "total": 0}), 200
    unique_hashes = {fp["hash"] for fp in all_fingerprints if "hash" in fp}
    return jsonify({
        "total_submissions": len(all_fingerprints),
        "unique_fingerprints": len(unique_hashes),
    }), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
