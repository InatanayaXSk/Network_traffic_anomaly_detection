from flask import Flask, jsonify, send_from_directory, request
from flask_cors import CORS
import json
import os

app = Flask(__name__, static_folder='.')
CORS(app)  # Enable CORS for all routes

# Serve the main page
@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

# Serve the JavaScript file
@app.route('/Script.js')
def script():
    return send_from_directory('.', 'Script.js')

# API: Return anomaly data from JSON file
@app.route('/get-data', methods=['GET'])
def get_data():
    try:
        with open("network_traffic_summary.json", 'r') as f:
            data = json.load(f)
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# API: Return alert instructions in multiple languages
@app.route('/alert', methods=['GET'])
def get_alerts():
    try:
        return jsonify({
            "en": "Potential threat detected in your network. Please review traffic logs.",
            "ku": "هێرشێکی گومانلێکراو دۆزرایەوە. تکایە ترافیکی تۆڕەکەت بپشکنە.",
            "ar": "تم اكتشاف نشاط غير طبيعي. يرجى التحقق من سجلات الشبكة."
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# API: Get all saved email addresses
@app.route('/emails', methods=['GET'])
def get_emails():
    try:
        with open("emails.json", "r") as f:
            emails = json.load(f)
        return jsonify(emails)
    except FileNotFoundError:
        return jsonify([])

# API: Save a new email address
@app.route('/emails', methods=['POST'])
def save_email():
    try:
        email = request.json.get("email")
        with open("emails.json", "r") as f:
            emails = json.load(f)
    except:
        emails = []

    if email and email not in emails:
        emails.append(email)
        with open("emails.json", "w") as f:
            json.dump(emails, f, indent=4)

    return jsonify({"message": "Email saved"}), 200

if __name__ == '__main__':
    app.run(port=8080, debug=True)
