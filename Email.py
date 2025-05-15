import json
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
import time
import re
import os
from dotenv import load_dotenv
from groq import Groq

load_dotenv()

# Configs
network_file_path = "network_traffic_summary.json"
email_file_path = "emails.json"
GROQ_API_KEY = os.getenv('GROQ_API_KEY')  # Add to .env
client = Groq(api_key=GROQ_API_KEY)

# SMTP Config
sender_email = "nads.capstone.2024@gmail.com"
smtp_server = "smtp.gmail.com"
smtp_port = 587
sender_password = "uems ifhn ksca monz"

# Load data
with open(network_file_path, "r") as file:
    data = json.load(file)
with open(email_file_path, "r") as file:
    email_data = json.load(file)

emails = email_data['emails']
total_anomalies = data["total_anomalies"]
anomalies_by_type = data["anomalies_by_type"]

anomalies_timestamped = {}
for key in anomalies_by_type.keys():
    anomalies_timestamped[key] = None

def analyze_with_groq(prompt):
    print("⏳ Sending request to Groq...")
    try:
        chat_completion = client.chat.completions.create(
            model="mixtral-8x7b-32768",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.7,
            max_tokens=2048,
        )
        return chat_completion.choices[0].message.content
    except Exception as e:
        print("❌ Error:", e)
        return None

def get_response(attack_type):
    prompt = f"""
Generate an email to notify a non-technical user about a detected network anomaly of type '{attack_type}'. Respond only with a JSON object containing the email body in three languages: English (en), Kannada (kn), and Telugu (te). The format should be:

{{
    "en": "English text here.",
    "kn": "Kannada translation here.",
    "te": "Telugu translation here."
}}

The content in each language should include:

1. A short and clear explanation of what the anomaly '{attack_type}' means in simple words.
2. A possible reason for why this might have happened, without using technical terms.
3. Easy-to-follow steps that a regular home user can do, like:
   - Restarting the Wi-Fi router.
   - Updating passwords.
   - Checking connected devices.
4. Maintain a polite and friendly tone. Don't create fear. Avoid any technical jargon or advanced solutions.

The instructions should be practical and realistic for a person without any technical background.

Do NOT include any heading or explanation — only output the JSON object.
"""
    return analyze_with_groq(prompt)

def send_email(sender_email, receiver_email, subject, body, smtp_server, smtp_port, sender_password):
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, receiver_email, msg.as_string())
            print(f"✅ Email sent to {receiver_email}")
    except Exception as e:
        print(f"❌ Failed to send email to {receiver_email}: {e}")

def send_all_mails(emails, alert_body):
    for recipient in emails:
        send_email(sender_email, recipient, "📡 Network Attack Alert", alert_body, smtp_server, smtp_port, sender_password)

def create_email_body(json_str):
    match = re.search(r"\{.*\}", json_str, re.DOTALL)
    if not match:
        raise ValueError("No JSON object found in Groq response.")
    data = json.loads(match.group(0).strip())

    return (
        f"📘 Instructions in English:\n{data['en']}\n\n"
        f"📗 ಕನ್ನಡದಲ್ಲಿ ಸೂಚನೆಗಳು:\n{data['kn']}\n\n"
        f"📕 తెలుగులో సూచనలు:\n{data['te']}"
    )

def extract_and_save_json(text, output_filename):
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        raise ValueError("No JSON object found in the input text.")
    data = json.loads(match.group(0).strip())
    with open(output_filename, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)

print("🚀 Monitoring anomalies...")
while True:
    current_time = datetime.now()
    if total_anomalies > 0:
        for key in anomalies_timestamped:
            if key == "1":
                attack_type = "Port Scanning"
            elif key == "2":
                attack_type = "Denial-of-Service (DoS)"
            else:
                attack_type = "Unknown Network Threat"

            last_alert_time = anomalies_timestamped[key]
            if last_alert_time is None or (current_time - last_alert_time > timedelta(minutes=1)):
                print(f"\n🛑 Detected: {attack_type} at {current_time.strftime('%H:%M:%S')}")
                response = get_response(attack_type)
                if response:
                    extract_and_save_json(response, "alert.json")
                    alert_body = create_email_body(response)
                    send_all_mails(emails, alert_body)
                    anomalies_timestamped[key] = current_time
    time.sleep(10)
