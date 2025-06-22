import requests
import json
import time
from datetime import datetime, timedelta
from requests.auth import HTTPBasicAuth
import os
import sys
import secrets_manager

# === CẤU HÌNH ===
ELASTIC_URL = "https://localhost:9200"
INDEX = ".internal.alerts-security.alerts-default-*"
USERNAME = "elastic"
PASSWORD = secrets_manager.get_secret("elastic/user", "password")
VERIFY_CERT_ELASTIC = "/etc/elasticsearch/certs/http_ca.crt"
VERIFY_CERT_WEBHOOK = "/home/nghianguyen/cert/webhook.crt"
WEBHOOK_URL = "http://localhost:8000/alert"

SEEN_FILE = "/tmp/seen_alerts.txt"
CHECK_INTERVAL = 60  

# === KHỞI TẠO ===
if not os.path.exists(SEEN_FILE):
    open(SEEN_FILE, "w").close()

def load_seen_ids():
    """Đọc danh sách các alert đã xử lý."""
    with open(SEEN_FILE, "r") as f:
        return set(line.strip() for line in f.readlines())

def save_seen_id(alert_id):
    """Lưu alert đã xử lý vào file để tránh xử lý lại."""
    with open(SEEN_FILE, "a") as f:
        f.write(alert_id + "\n")

def query_alerts():
    """Truy vấn Elasticsearch để lấy các alert mới."""
    now = datetime.utcnow()
    past = now - timedelta(minutes=6)

    query = {
        "size": 10,
        "sort": [{"kibana.alert.rule.execution.timestamp": "desc"}],
        "query": {
            "range": {
                "kibana.alert.rule.execution.timestamp": {
                    "gte": past.isoformat(),
                    "lte": now.isoformat()
                }
            }
        }
    }

    try:
        res = requests.post(
            f"{ELASTIC_URL}/{INDEX}/_search",
            auth=HTTPBasicAuth(USERNAME, PASSWORD),
            json=query,
            verify=VERIFY_CERT_ELASTIC  
        )
        res.raise_for_status()  
        return res.json().get("hits", {}).get("hits", [])
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Request failed: {e}")
        return []

def send_alert_to_webhook(alert_data):
    """Gửi alert tới webhook server."""
    headers = {
        "Content-Type": "application/json"
    }
    try:
        print(f"Sending data to webhook: {json.dumps(alert_data, indent=4)}")
        response = requests.post(WEBHOOK_URL, json=alert_data, headers=headers, verify=False)
        if response.status_code == 200:
            print(f"[{datetime.utcnow()}] Alert successfully sent to webhook!")
        else:
            print(f"[{datetime.utcnow()}] Failed to send alert to webhook. Status code: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Failed to send alert to webhook: {e}")


# === MAIN LOOP ===
print(f"[{datetime.utcnow()}] Starting alert watcher (every {CHECK_INTERVAL}s)...")


while True:
    seen_ids = load_seen_ids()
    alerts = query_alerts()

    if not alerts:
        print(f"[{datetime.utcnow()}] No alerts found.")
    else:
        alert_printed = False

        for alert in alerts:
            source = alert.get("_source", {})
            alert_id = alert.get("_id", "Unknown")
            ip_address = source.get("source", {}).get("ip", "Unknown IP")  # Lấy IP từ trường source.ip
            rule_name = source.get("kibana.alert.rule.name", "Unknown")
            timestamp = source.get("kibana.alert.rule.execution.timestamp", "unknown")

            if alert_id not in seen_ids:
                print(f"New alert: {rule_name} at {timestamp}")
                save_seen_id(alert_id)
                alert_printed = True

                # Tạo payload để gửi tới webhook
                alert_data = {
                    "ip_address": ip_address,  # chặn IP từ alert1
                    "alert_id": alert_id,
                    "rule_name": rule_name,
                    "timestamp": timestamp
                }

                # In ra dữ liệu để kiểm tra trước khi gửi tới webhook
                print(json.dumps(alert_data, indent=4))
                
                try:
                    send_alert_to_webhook(alert_data)
                except Exception as e:
                    print(f"[ERROR] Failed to send alert to webhook: {e}")
                
                break

        if not alert_printed:
            print(f"[{datetime.utcnow()}] No new alert this round.")

    time.sleep(CHECK_INTERVAL)
