from flask import Flask, request, jsonify
from flask_cors import CORS
from analyzer import HeaderAnalyzer

app = Flask(__name__)
CORS(app)  # Allows Frontend to talk to Backend


@app.route('/analyze', methods=['POST'])
def process_header():
    data = request.get_json()

    if not data:
        return jsonify({"error": "No data received"}), 400

    raw_text = data.get('header', '').strip()

    # Accept normal raw header and Gmail summary format
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


if __name__ == '__main__':
    app.run(debug=True, port=5000)