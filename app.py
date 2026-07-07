from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from analyzer import HeaderAnalyzer

app = Flask(__name__, static_folder="public")
CORS(app)


@app.route("/")
def home():
    return send_from_directory("public", "index.html")


@app.route("/<path:path>")
def serve_static_files(path):
    return send_from_directory("public", path)


@app.route("/analyze", methods=["POST"])
def process_header():
    data = request.get_json()

    if not data:
        return jsonify({"error": "No data received"}), 400

    raw_text = data.get("header", "").strip()

    if not raw_text or "From:" not in raw_text:
        return jsonify({
            "error": "Invalid Header Format. Please paste Gmail original/header details with From:"
        }), 400

    try:
        engine = HeaderAnalyzer(raw_text)
        result = engine.analyze()
        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True, port=5000)