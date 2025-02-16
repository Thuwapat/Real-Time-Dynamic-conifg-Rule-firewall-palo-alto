import requests
import json

# กำหนด Microsoft Teams Webhook URL (เปลี่ยนให้เป็น URL ของคุณเอง)
teams_webhook_url = "https://kkumail.webhook.office.com/webhookb2/5f2cd41f-3e21-4de3-8561-90ca123d40e5@eda31a31-9b97-48a8-8bd8-d0897333bbdb/IncomingWebhook/61b18884d9a44067ae59387eaf4a4dd5/e46d0065-81ce-4b0e-b9e1-273103a1656e/V2TRzDhNmBp-4-9UlJ77wg5eL07cKOAm71DS6l4_2oA-81"

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