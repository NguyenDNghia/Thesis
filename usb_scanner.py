import sys
import os
import subprocess
import json
from datetime import datetime, timezone
import logging
import re
import requests
from requests.auth import HTTPBasicAuth
import secrets_manager

ELASTIC_URL = os.getenv("ELASTIC_URL", "https://10.11.13.3:9200")
ELASTIC_USER = os.getenv("ELASTIC_USER", "elastic")
ELASTIC_PASS = secrets_manager.get_secret("elastic/user", "password")
ELASTIC_VERIFY_CERT_STR = os.getenv("ELASTIC_VERIFY_CERT", "/home/nghianguyen/http_ca.crt")
ELASTIC_VERIFY_CERT = ELASTIC_VERIFY_CERT_STR if ELASTIC_VERIFY_CERT_STR.lower() != 'false' else False
INDEX_NAME = "usb-malware-alerts"

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    handlers=[logging.FileHandler("/var/log/usb_scanner.log"),
                              logging.StreamHandler()])
logger = logging.getLogger("USBScanner_Final")
def run_command(command):
    """Chạy một lệnh và trả về output, error, và return code."""
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False, shell=True)
        return result.stdout, result.stderr, result.returncode
    except Exception as e:
        logger.error(f"Exception running command '{command}': {e}")
        return None, str(e), -1

def get_usb_device_id(device_path):
    """Lấy ID của USBGuard dựa trên số Serial của thiết bị."""
    parent_device = re.sub(r'\d+$', '', os.path.basename(device_path))
    full_parent_path = f"/dev/{parent_device}"
    
    stdout_udev, _, retcode = run_command(f"udevadm info --query=property --name={full_parent_path}")
    if retcode != 0:
        return None
    serial_line = next((line for line in stdout_udev.splitlines() if 'ID_SERIAL_SHORT=' in line), None)
    if not serial_line:
        logger.warning(f"Could not find ID_SERIAL_SHORT for {full_parent_path}")
        return None

    serial_number = serial_line.split('=')[1]
    
    stdout_usbguard, _, _ = run_command("/usr/bin/usbguard list-devices")
    for line in stdout_usbguard.splitlines():
        if f'serial "{serial_number}"' in line:
            return line.split(' ')[0].strip(':')

    return None

def send_to_elasticsearch(payload):
    """Gửi một document JSON lên Elasticsearch."""
    try:
        url = f"{ELASTIC_URL}/{INDEX_NAME}/_doc"
        response = requests.post(
            url, auth=HTTPBasicAuth(ELASTIC_USER, ELASTIC_PASS),
            json=payload, verify=ELASTIC_VERIFY_CERT, timeout=30
        )
        response.raise_for_status()
        es_doc_id = response.json().get('_id')
        logger.info(f"Successfully sent alert to Elasticsearch. Document ID: {es_doc_id}")
    except requests.exceptions.ConnectionError as e:
        logger.error(f"FATAL: Connection error to Elasticsearch at {ELASTIC_URL}. Check network/firewall. Error: {e}")
    except Exception as e:
        logger.error(f"Failed to send alert to Elasticsearch: {e}")
        if hasattr(e, 'response') and e.response is not None:
            logger.error(f"ES Response: {e.response.text}")

def main():
    if len(sys.argv) < 2:
        logger.error("Script called without device kernel name. Exiting.")
        sys.exit(1)

    kernel_name = sys.argv[1]
    device_path = f"/dev/{kernel_name}"
    mount_path = f"/media/usb_scan_{kernel_name}"
    logger.info(f"--- New event for device: {device_path} ---")

    try:
        os.makedirs(mount_path, exist_ok=True)
        _, stderr, retcode = run_command(f"mount -o ro {device_path} {mount_path}")
        if retcode != 0:
            logger.error(f"Failed to mount {device_path}: {stderr}")
            return

        logger.info(f"Starting optimized scan with clamdscan on {mount_path}...")
        scan_cmd = f"clamdscan --fdpass --infected \"{mount_path}\""
        stdout, stderr, _ = run_command(scan_cmd)
        infected_files = [line for line in stdout.strip().split('\n') if line.endswith("FOUND")]

        if not infected_files:
            logger.info("Scan completed. No malware found.")
            return

        logger.warning(f"MALWARE DETECTED! Found {len(infected_files)} infected file(s).")

        hostname, _, _ = run_command("hostname")
        
        all_ips_str, _, _ = run_command("hostname -I")
        # Xử lý chuỗi thành một danh sách các IP
        list_of_ips = [ip for ip in all_ips_str.strip().split(' ') if ip]
        
        alerts_to_send = []

        for line in infected_files:
            parts = line.split(':', 1)
            file_path = parts[0]
            threat_info = parts[1].strip() if len(parts) > 1 else "Unknown Threat"
            threat_name = threat_info.replace(" FOUND", "").strip()

            hash_out, _, _ = run_command(f"/usr/bin/sha256sum \"{file_path}\"")
            file_hash = hash_out.split(' ')[0].strip()

            if not file_hash:
                logger.error(f"Hash calculation failed for '{file_path}'.")

            alert_id = f"usb-{kernel_name}-{file_hash[:12] if file_hash else str(datetime.now(timezone.utc).timestamp()).replace('.', '')}"

            payload = {
                "@timestamp": datetime.now(timezone.utc).isoformat(),
                "event": {
                    "kind": "alert", "category": "malware", "action": "usb_malware_detection",
                    "type": "detection", "id": alert_id, "dataset": "usb.malware",
                    "reason": f"Malware '{threat_name}' detected on removable media."
                },
                "host": {"name": hostname.strip(), "ip": list_of_ips},
                "malware": {
                    "file_path": file_path, "hash": {"sha256": file_hash if file_hash else None},
                    "threat_name": threat_name
                },
                "usb": {
                    "device_path": device_path,
                    "mount_path": mount_path,
                }
            }
            alerts_to_send.append(payload)

        usb_id = get_usb_device_id(device_path)
        action_taken_status = "block_failed"
        if usb_id:
            logger.info(f"Found USBGuard ID: {usb_id}. All file operations complete. Now blocking device...")
            run_command(f"/usr/bin/usbguard block-device {usb_id}")
            action_taken_status = "blocked"
        else:
            logger.error("Could not determine USBGuard ID to block the device.")
        
        for payload in alerts_to_send:
            payload['usb']['usbguard_id'] = str(usb_id).strip() if usb_id else None
            payload['usb']['action_taken'] = action_taken_status
            send_to_elasticsearch(payload)

    finally:
        logger.info("Cleaning up...")
        if os.path.ismount(mount_path):
            run_command(f"umount {mount_path}")
        if os.path.exists(mount_path):
            run_command(f"rmdir {mount_path}")
        logger.info(f"--- Event processing finished. ---")


if __name__ == "__main__":
    main()
