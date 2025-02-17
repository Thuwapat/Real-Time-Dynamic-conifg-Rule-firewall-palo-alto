import requests
import json
import os 

# กำหนด Microsoft Teams Webhook URL (เปลี่ยนให้เป็น URL ของคุณเอง)
teams_webhook_url = os.environ.get("WEBHOOK_URL")

def send_teams_alert(title, message, theme_color="0076D7"):
    headers = {"Content-Type": "application/json"}
    payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "summary": title,
        "themeColor": theme_color,
        "title": title,
        "text": message
    }
    response = requests.post(teams_webhook_url, headers=headers, json=payload)
    if response.status_code != 200:
        print(f"ส่ง alert ไปยัง Teams ไม่สำเร็จ: {response.status_code}, {response.text}")