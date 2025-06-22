import sys
import os
import requests
import json
from datetime import datetime, timedelta, timezone
import logging
from requests.auth import HTTPBasicAuth
import time
import secrets_manager
import ipaddress

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')
logger = logging.getLogger("ContextAware_IOC_Checker")

logger.info("Đang lấy mật khẩu Elastic từ Vault...")
ELASTIC_PASSWORD = secrets_manager.get_secret("elastic/user", "password")
if not ELASTIC_PASSWORD:
    logger.critical("Không thể lấy mật khẩu. Thoát.")
    sys.exit(1)
logger.info("Lấy mật khẩu thành công.")

ELASTIC_URL = "https://10.11.13.3:9200"
ELASTIC_USER = "elastic"
VERIFY_CERT = "/etc/elasticsearch/certs/http_ca.crt"

INDEX_PATTERNS_TO_QUERY = [".ds-logs-zeek.*", ".ds-logs-suricata.eve-*"]
URLHAUS_HOST_API_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/host/"
ALERT_INDEX_NAME = "threat-intel-realtime-alerts"
CHECK_INTERVAL_SECONDS = 60
PROCESSED_CLEAN_IOCS_FILE = "/tmp/processed_clean_iocs.json"

def load_processed_iocs():
    if not os.path.exists(PROCESSED_CLEAN_IOCS_FILE): return {}
    try:
        with open(PROCESSED_CLEAN_IOCS_FILE, "r") as f: return json.load(f)
    except (IOError, json.JSONDecodeError): return {}

def save_processed_iocs(processed_iocs):
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    cleaned_iocs = {ioc: ts for ioc, ts in processed_iocs.items() if ts > cutoff}
    try:
        with open(PROCESSED_CLEAN_IOCS_FILE, "w") as f: json.dump(cleaned_iocs, f)
    except IOError as e:
        logger.error(f"Không thể ghi file processed_iocs: {e}")

def query_elasticsearch(index, query_body, size=10000):
    try:
        response = requests.post(
            f"{ELASTIC_URL}/{index}/_search", auth=HTTPBasicAuth(ELASTIC_USER, ELASTIC_PASSWORD),
            json={"size": size, "query": query_body}, verify=VERIFY_CERT, timeout=30
        )
        response.raise_for_status()
        return response.json().get("hits", {}).get("hits", [])
    except Exception as e:
        logger.error(f"Lỗi khi truy vấn Elasticsearch index {index}: {e}")
        return []

def query_urlhaus_api(host_or_ip):
    logger.info(f"Đang kiểm tra với URLhaus: {host_or_ip}")
    try:
        data = {'host': host_or_ip}
        response = requests.post(URLHAUS_HOST_API_ENDPOINT, data=data, timeout=20)
        if response.status_code == 200:
            return response.json()
    except requests.RequestException as e:
        logger.error(f"Lỗi khi gọi API URLhaus cho {host_or_ip}: {e}")
    return None

def send_alert_to_es(alert):
    logger.info(f"Phát hiện IoC độc hại, đang gửi cảnh báo...")
    try:
        response = requests.post(f"{ELASTIC_URL}/{ALERT_INDEX_NAME}/_doc", auth=HTTPBasicAuth(ELASTIC_USER, ELASTIC_PASSWORD), json=alert, verify=VERIFY_CERT, timeout=30)
        response.raise_for_status()
        logger.info(f"Đã gửi cảnh báo thành công cho IoC: {alert['ioc']['value']}")
    except Exception as e:
        logger.error(f"Lỗi khi gửi cảnh báo lên Elasticsearch: {e}")

def get_recent_iocs_with_context():
    """Lấy các IoC và giữ lại ngữ cảnh, chỉ bao gồm các IP nguồn là IPv4."""
    iocs_with_context = {}
    query = {"range": {"@timestamp": {"gte": f"now-{CHECK_INTERVAL_SECONDS*2}s/s"}}}

    for index_pattern in INDEX_PATTERNS_TO_QUERY:
        hits = query_elasticsearch(index_pattern, query)
        for hit in hits:
            source = hit.get("_source", {})
            indicators = []
            
            dest_ip = source.get("destination", {}).get("ip")
            if dest_ip and not (dest_ip.startswith("10.") or dest_ip.startswith("192.168.") or dest_ip.startswith("172.16.")):
                indicators.append(dest_ip)
            
            domain = (source.get("http", {}).get("hostname") or 
                      source.get("tls", {}).get("server", {}).get("name") or 
                      source.get("dns", {}).get("question", {}).get("name"))
            if domain:
                indicators.append(domain)
            
            source_host_ips_raw = source.get("observer", {}).get("ip", [source.get("source", {}).get("ip")])
            
            ipv4_source_ips = []
            if source_host_ips_raw:
                for ip in source_host_ips_raw:
                    try:
                        if ipaddress.ip_address(ip).version == 4:
                            ipv4_source_ips.append(ip)
                    except ValueError:
                        continue
            

            for ioc in set(indicators):
                if ioc not in iocs_with_context:
                    iocs_with_context[ioc] = {
                        "source_host_ips": ipv4_source_ips, 
                        "initiating_source_ip": source.get("source", {}).get("ip"),
                        "destination_ip": dest_ip,
                        "original_log_timestamp": source.get("@timestamp")
                    }
    return iocs_with_context

def main_loop():
    while True:
        logger.info("="*10 + " Bắt đầu chu trình kiểm tra " + "="*10)
        processed_clean_iocs = load_processed_iocs()
        iocs_to_check = get_recent_iocs_with_context()
        
        if not iocs_to_check:
            logger.info("Không tìm thấy IoC nào mới để kiểm tra.")
        else:
            logger.info(f"Tìm thấy {len(iocs_to_check)} IoC cần kiểm tra: {list(iocs_to_check.keys())}")
        
        for ioc, context in iocs_to_check.items():
            try:
                if ioc in processed_clean_iocs:
                    continue

                time.sleep(1)
                result = query_urlhaus_api(ioc)
                
                if result and result.get("query_status") == "ok" and result.get("urls"):
                    logger.warning(f"!!! CẢNH BÁO MỐI ĐE DỌA: {ioc} !!!")
                    
                    alert_payload = {
                        "@timestamp": datetime.now(timezone.utc).isoformat(),
                        "rule_name": "URLhaus_Malicious_Host_Detected",
                        "ioc": {"value": ioc},
                        "source": {"ip": context.get("source_host_ips")},
                        "destination": {"ip": context.get("destination_ip")},
                        "threat_details": result,
                        "original_log": {"timestamp": context.get("original_log_timestamp")}
                    }
                    send_alert_to_es(alert_payload)
                else:
                    processed_clean_iocs[ioc] = datetime.now(timezone.utc).isoformat()

            except Exception as e:
                logger.error(f"GẶP LỖI KHÔNG XÁC ĐỊNH khi xử lý IoC '{ioc}'. Lỗi: {e}", exc_info=True)
                continue

        save_processed_iocs(processed_clean_iocs)
        logger.info(f"Kết thúc chu trình. Nghỉ {CHECK_INTERVAL_SECONDS} giây.")
        time.sleep(CHECK_INTERVAL_SECONDS)

if __name__ == "__main__":
    main_loop()
