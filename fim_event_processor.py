import requests
import json
import time
from datetime import datetime, timedelta, timezone
from requests.auth import HTTPBasicAuth
import os
import logging
import subprocess
import secrets_manager

# === CẤU HÌNH ===
ELASTIC_URL_FIM = os.getenv("FIM_ELASTIC_URL", "https://localhost:9200")
FIM_INDEX_PATTERN = os.getenv("FIM_INDEX_PATTERN", ".ds-logs-fim.event-default-*")
ELASTIC_USERNAME_FIM = os.getenv("FIM_ELASTIC_USERNAME", "elastic")
ELASTIC_PASSWORD_FIM = secrets_manager.get_secret("elastic/user", "password")
VERIFY_CERT_ELASTIC_FIM_STR = os.getenv("FIM_VERIFY_CERT_ELASTIC", "/etc/elasticsearch/certs/http_ca.crt")
VERIFY_CERT_ELASTIC_FIM = VERIFY_CERT_ELASTIC_FIM_STR if VERIFY_CERT_ELASTIC_FIM_STR.lower() != 'false' else False

VIRUSTOTAL_API_KEY = secrets_manager.get_secret("virustotal/api", "key") 
VT_API_URL_HASH_REPORT = "https://www.virustotal.com/api/v3/files/{file_hash}"

ALERT_WEBHOOK_URL = os.getenv("ALERT_WEBHOOK_URL", "http://localhost:8000/alert") 
VERIFY_CERT_ALERT_WEBHOOK_STR = os.getenv("VERIFY_CERT_ALERT_WEBHOOK", "False")
VERIFY_CERT_ALERT_WEBHOOK = VERIFY_CERT_ALERT_WEBHOOK_STR if VERIFY_CERT_ALERT_WEBHOOK_STR.lower() != 'false' else False

VT_POSITIVE_THRESHOLD = int(os.getenv("VT_POSITIVE_THRESHOLD", "10"))
PROCESSED_FIM_EVENTS_FILE = os.getenv("PROCESSED_FIM_EVENTS_FILE", "/tmp/processed_fim_events.txt")
PROCESS_WINDOW_MINUTES = int(os.getenv("PROCESS_WINDOW_MINUTES", "60"))
FIM_QUERY_INTERVAL_SECONDS = int(os.getenv("FIM_QUERY_INTERVAL_SECONDS", "60"))
DELAY_BEFORE_THREAT_HUNT_SECONDS = int(os.getenv("DELAY_BEFORE_THREAT_HUNT", "10"))

SUSPICIOUS_EXTENSIONS_STR = os.getenv("SUSPICIOUS_EXTENSIONS", "exe,dll,so,elf,sh,py,pl,bat,jar,docm,xlsm,pptm,conf")
SUSPICIOUS_EXTENSIONS = [ext.strip() for ext in SUSPICIOUS_EXTENSIONS_STR.split(',') if ext.strip()] if SUSPICIOUS_EXTENSIONS_STR else []

THREAT_HUNTER_SCRIPT_PATH = os.getenv("THREAT_HUNTER_SCRIPT_PATH",
                                      os.path.join(os.path.dirname(os.path.abspath(__file__)), "threat_hunter.py"))

ELASTIC_URL_TH_REPORT = os.getenv("TH_REPORT_ELASTIC_URL", ELASTIC_URL_FIM)
TH_REPORT_INDEX_NAME = os.getenv("TH_REPORT_INDEX_NAME", "threat_hunt_reports-main")
ELASTIC_USERNAME_TH_REPORT = os.getenv("TH_REPORT_ELASTIC_USERNAME", ELASTIC_USERNAME_FIM)
ELASTIC_PASSWORD_TH_REPORT = os.getenv("TH_REPORT_ELASTIC_PASSWORD", ELASTIC_PASSWORD_FIM)
VERIFY_CERT_ELASTIC_TH_REPORT_STR = os.getenv("TH_REPORT_VERIFY_CERT_ELASTIC", VERIFY_CERT_ELASTIC_FIM_STR)
VERIFY_CERT_ELASTIC_TH_REPORT = VERIFY_CERT_ELASTIC_TH_REPORT_STR if VERIFY_CERT_ELASTIC_TH_REPORT_STR.lower() != 'false' else False

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s [%(module)s.%(funcName)s:%(lineno)d] - %(message)s')
logger = logging.getLogger("FIMProcessor")

if not os.path.exists(PROCESSED_FIM_EVENTS_FILE):
    with open(PROCESSED_FIM_EVENTS_FILE, "w") as f: json.dump({}, f)

def load_processed_fim_events():
    try:
        with open(PROCESSED_FIM_EVENTS_FILE, "r") as f: return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError): return {}

def save_processed_fim_event(event_id, file_path, timestamp_iso):
    processed = load_processed_fim_events()
    processed[event_id] = {"file_path": file_path, "timestamp": timestamp_iso, "processed_at": datetime.utcnow().replace(tzinfo=timezone.utc).isoformat()}
    cutoff_time_obj = datetime.utcnow().replace(tzinfo=timezone.utc) - timedelta(days=7)
    cleaned_processed = { eid: data for eid, data in processed.items() if datetime.fromisoformat(data.get("processed_at", "1970-01-01T00:00:00Z").replace("Z", "")).replace(tzinfo=timezone.utc) > cutoff_time_obj }
    with open(PROCESSED_FIM_EVENTS_FILE, "w") as f: json.dump(cleaned_processed, f)

def query_new_fim_events():
    now = datetime.utcnow().replace(tzinfo=timezone.utc)
    past = now - timedelta(seconds=FIM_QUERY_INTERVAL_SECONDS * 3)
    query_body_conditions = {
        "bool": {
            "must": [
                {"term": {"event.category": "file"}},
                {"terms": {"event.action": ["created", "change", "attributes_modified", "creation"]}}
            ],
            "filter": {
                "range": {
                    "@timestamp": {
                        "gte": past.isoformat(timespec='milliseconds') + "Z",
                        "lte": now.isoformat(timespec='milliseconds') + "Z"
                    }
                }
            }
        }
    }
    if SUSPICIOUS_EXTENSIONS:
        query_body_conditions["bool"]["must"].append({"terms": {"file.extension": SUSPICIOUS_EXTENSIONS}})

    query = {
        "size": 50,
        "sort": [{"@timestamp": "asc"}],
        "query": query_body_conditions
    }
    logger.info(f"Querying FIM events with: {json.dumps(query_body_conditions)}")
    try:
        res = requests.post(
            f"{ELASTIC_URL_FIM}/{FIM_INDEX_PATTERN}/_search",
            auth=HTTPBasicAuth(ELASTIC_USERNAME_FIM, ELASTIC_PASSWORD_FIM) if ELASTIC_USERNAME_FIM else None,
            json=query,
            verify=VERIFY_CERT_ELASTIC_FIM,
            timeout=30
        )
        res.raise_for_status()
        return res.json().get("hits", {}).get("hits", [])
    except requests.exceptions.RequestException as e:
        logger.error(f"FIM Event query failed: {e}")
        if hasattr(e, 'response') and e.response is not None:
            logger.error(f"Response content: {e.response.text}")
        return []

def check_virustotal(file_hash):
    if not VIRUSTOTAL_API_KEY or VIRUSTOTAL_API_KEY == "YOUR_VT_API_KEY_HERE":
        logger.warning("VirusTotal API key not configured or is a placeholder. Skipping VT check.")
        return None
    if not file_hash or len(file_hash) < 32:
        logger.warning(f"Invalid or missing file hash for VT check: {file_hash}")
        return None

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    url = VT_API_URL_HASH_REPORT.format(file_hash=file_hash)
    logger.info(f"Querying VirusTotal for hash: {file_hash}")
    try:
        response = requests.get(url, headers=headers, timeout=20)
        if response.status_code == 200:
            vt_data = response.json()
            attributes = vt_data.get("data", {}).get("attributes", {})
            positives = attributes.get("last_analysis_stats", {}).get("malicious", 0)
            positives = int(positives) if positives is not None else 0
            
            analysis_stats = attributes.get("last_analysis_stats", {})
            total_engines = 0
            if isinstance(analysis_stats, dict):
                total_engines = sum(v for v in analysis_stats.values() if isinstance(v, int))

            scan_date_unix = attributes.get("last_analysis_date")
            scan_date_iso = datetime.fromtimestamp(scan_date_unix, tz=timezone.utc).isoformat() if scan_date_unix else "N/A"
            permalink = f"https://www.virustotal.com/gui/file/{file_hash}/detection"
            
            summary_result = {
                "hash": file_hash,
                "positives": positives,
                "total_engines": total_engines,
                "scan_date": scan_date_iso,
                "permalink": permalink,
                "status": "found"
            }
            logger.info(f"VT Result for {file_hash}: Positives: {positives}/{total_engines}, Scan Date: {scan_date_iso}")
            return summary_result
            
        elif response.status_code == 404:
            logger.info(f"Hash {file_hash} not found on VirusTotal.")
            return {"hash": file_hash, "positives": 0, "total_engines": 0, "status": "not_found"}
        elif response.status_code == 401:
            logger.error(f"VirusTotal API key is invalid or unauthorized for {file_hash}.")
            return {"hash": file_hash, "status": "unauthorized_vt_key"}
        elif response.status_code == 429:
            logger.warning(f"VirusTotal API rate limit exceeded for hash {file_hash}.")
            return {"hash": file_hash, "status": "rate_limited"}
        else:
            logger.error(f"VirusTotal API error for {file_hash}: Status {response.status_code}, Response: {response.text}")
            return {"hash": file_hash, "status": f"api_error_{response.status_code}"}
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to query VirusTotal for {file_hash}: {e}")
        return {"hash": file_hash, "status": "request_exception"}
    except Exception as e_gen:
        logger.error(f"Unexpected error during VirusTotal check for {file_hash}: {e_gen}")
        return {"hash": file_hash, "status": "unexpected_error"}


def send_confirmed_malware_alert(original_event_id, fim_event_source, vt_result):
    host_info = fim_event_source.get("host", {})
    file_info = fim_event_source.get("file", {})
    event_details = fim_event_source.get("event", {})
    
    host_ip_list = host_info.get("ip", [])
    if isinstance(host_ip_list, str): host_ip_list = [host_ip_list]
    if not isinstance(host_ip_list, list): host_ip_list = []

    preferred_ip_str = "Unknown IP"
    for ip_addr in host_ip_list:
        if isinstance(ip_addr, str) and ip_addr.startswith("10.11.13."):
            preferred_ip_str = ip_addr
            break
    if preferred_ip_str == "Unknown IP" and host_ip_list:
        preferred_ip_str = host_ip_list[0]

    alert_payload = {
        "source_event_id": original_event_id,
        "rule_name": "FIM_Malware_Detected_via_VirusTotal",
        "trigger_timestamp": datetime.utcnow().replace(tzinfo=timezone.utc).isoformat(),
        "description": f"Malware detected on host {host_info.get('name', 'N/A')} for file {file_info.get('path', 'N/A')}. VT: {vt_result.get('positives')}/{vt_result.get('total_engines')}",
        "host_name": host_info.get("name"),
        "host_ip": preferred_ip_str,
        "host_all_ips": host_ip_list,
        "file_path": file_info.get("path"),
        "file_hash_sha256": file_info.get("hash", {}).get("sha256"),
        "file_hash_sha1": file_info.get("hash", {}).get("sha1"),
        "virustotal_positives": vt_result.get("positives"),
        "virustotal_total_engines": vt_result.get("total_engines"),
        "virustotal_permalink": vt_result.get("permalink"),
        "original_event_action": event_details.get("action"),
        "original_event_timestamp": fim_event_source.get("@timestamp")
    }
    logger.info(f"Attempting to send confirmed malware alert to webhook: {json.dumps(alert_payload, indent=2)}")
    headers = {"Content-Type": "application/json"}
    try:
        response = requests.post(ALERT_WEBHOOK_URL, json=alert_payload, headers=headers, verify=VERIFY_CERT_ALERT_WEBHOOK, timeout=15)
        if response.status_code == 200:
            logger.info(f" Malware alert successfully sent to webhook for file {file_info.get('path')}")
        else:
            logger.error(f" Failed to send malware alert to webhook. Status: {response.status_code}, Response: {response.text}")
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to send malware alert to webhook (expected if webhook not running for test): {e}")

def send_data_to_elasticsearch(index_name_target, data_payload, es_url, es_user, es_pass, es_verify_cert):
    if "@timestamp" not in data_payload:
        data_payload["@timestamp"] = data_payload.get("hunt_trigger_time_utc", datetime.utcnow().replace(tzinfo=timezone.utc).isoformat())

    logger.info(f"Attempting to send data to Elasticsearch target '{index_name_target}'")
    try:
        doc_id = data_payload.get("threat_hunt_id")
        
        if doc_id:
            full_url = f"{es_url}/{index_name_target}/_create/{doc_id}"
        else:
            full_url = f"{es_url}/{index_name_target}/_doc" 

        res = requests.post(
            full_url,
            auth=HTTPBasicAuth(es_user, es_pass) if es_user else None,
            json=data_payload,
            verify=es_verify_cert,
            timeout=30
        )
        
        if res.status_code == 201:
            logger.info(f" Successfully created document in Elasticsearch target '{index_name_target}'. ID: {res.json().get('_id')}, Result: {res.json().get('result','N/A')}")
        elif res.status_code == 409 and doc_id:
            logger.warning(f"Document with ID '{doc_id}' already exists in '{index_name_target}'. Not overwritten due to _create operation. Response: {res.text}")
        else: 
            res.raise_for_status() 
            logger.info(f"Successfully sent/updated document in Elasticsearch target '{index_name_target}'. Response: {res.json().get('result','N/A')}")
        
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to send data to Elasticsearch target '{index_name_target}': {e}")
        if hasattr(e, 'response') and e.response is not None:
            logger.error(f"Response content: {e.response.text}")
        return False

def main_processor_loop():
    logger.info(f"Starting FIM Event Processor (Interval: {FIM_QUERY_INTERVAL_SECONDS}s, VT Threshold: {VT_POSITIVE_THRESHOLD}, Delay for Hunt: {DELAY_BEFORE_THREAT_HUNT_SECONDS}s)...")
    logger.info(f"Threat Hunt Reports will be sent to ES index: '{TH_REPORT_INDEX_NAME}' at {ELASTIC_URL_TH_REPORT}")
    if not TH_REPORT_INDEX_NAME.startswith(TH_REPORT_INDEX_NAME.split('-')[0] + "-") and "*" not in TH_REPORT_INDEX_NAME:
        logger.warning(f"TH_REPORT_INDEX_NAME ('{TH_REPORT_INDEX_NAME}') may not strictly match common data stream pattern 'basename-namespace-dataset'. Ensure it's correctly set (e.g., 'threat_hunt_reports-main') to match your index template pattern 'threat_hunt_reports-*'.")

    while True:
        processed_events_cache = load_processed_fim_events()
        fim_events = query_new_fim_events()

        if not fim_events:
            logger.debug("No new relevant FIM events found.")
        else:
            logger.info(f"Found {len(fim_events)} FIM events to process.")

        for event_hit in fim_events:
            event_source = event_hit.get("_source", {})
            event_id = event_hit.get("_id")
            file_info = event_source.get("file", {})
            file_path = file_info.get("path")
            event_timestamp_str = event_source.get("@timestamp")

            if not all([file_path, event_id, event_timestamp_str]):
                logger.warning(f"Skipping FIM event due to missing critical data: event_id={event_id}, file_path={file_path}, @timestamp={event_timestamp_str}. Full event: {json.dumps(event_source, indent=2)}")
                continue

            cached_event = processed_events_cache.get(event_id)
            if cached_event:
                try:
                    processed_at_str = cached_event.get("processed_at")
                    if processed_at_str:
                        processed_time_utc = datetime.fromisoformat(processed_at_str.replace("Z", "")).replace(tzinfo=timezone.utc)
                        if datetime.utcnow().replace(tzinfo=timezone.utc) - processed_time_utc < timedelta(minutes=PROCESS_WINDOW_MINUTES):
                            logger.debug(f"Skipping recently processed FIM event ID {event_id} for file {file_path}")
                            continue
                except Exception as e_ts_parse:
                    logger.warning(f"Error parsing processed_at for {event_id} ('{processed_at_str}'): {e_ts_parse}. Will reprocess.")

            file_hash_sha256 = file_info.get("hash", {}).get("sha256")
            file_hash_md5 = file_info.get("hash", {}).get("md5")
            file_hash_sha1 = file_info.get("hash", {}).get("sha1")
            file_hash_to_check = file_hash_sha256 or file_hash_md5 or file_hash_sha1

            if not file_hash_to_check:
                logger.warning(f"No usable hash (SHA256, MD5, SHA1) found for file {file_path}, FIM event ID {event_id}. Skipping VT check.")
                save_processed_fim_event(event_id, file_path, event_timestamp_str)
                continue
            
            if file_hash_to_check == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855":
                logger.info(f"Skipping empty file {file_path} (SHA256: {file_hash_to_check}).")
                save_processed_fim_event(event_id, file_path, event_timestamp_str)
                continue

            logger.info(f"Processing FIM event for file: {file_path}, Hash to check ({'SHA256' if file_hash_to_check == file_hash_sha256 else ('MD5' if file_hash_to_check == file_hash_md5 else 'SHA1')}): {file_hash_to_check}")
            vt_result = check_virustotal(file_hash_to_check)

            if vt_result:
                if vt_result.get("status") == "rate_limited" or vt_result.get("status") == "unauthorized_vt_key":
                    logger.warning(f"VirusTotal API issue ({vt_result.get('status')}). Breaking from current batch processing. Will retry in the next cycle.")
                    time.sleep(60) 
                    break 

                save_processed_fim_event(event_id, file_path, event_timestamp_str)

                if vt_result.get("positives", 0) >= VT_POSITIVE_THRESHOLD:
                    logger.info(f" MALWARE DETECTED for file {file_path} (Hash: {file_hash_to_check}). VT Positives: {vt_result.get('positives')}")
                    send_confirmed_malware_alert(event_id, event_source, vt_result)

                    logger.info(f"Waiting for {DELAY_BEFORE_THREAT_HUNT_SECONDS} seconds before initiating threat hunt...")
                    time.sleep(DELAY_BEFORE_THREAT_HUNT_SECONDS)

                    host_info = event_source.get("host", {})
                    host_ip_list_from_fim = host_info.get("ip", [])
                    if isinstance(host_ip_list_from_fim, str): host_ip_list_from_fim = [host_ip_list_from_fim]
                    if not isinstance(host_ip_list_from_fim, list): host_ip_list_from_fim = []

                    victim_b_primary_ip = "Unknown IP"
                    for ip_addr in host_ip_list_from_fim:
                        if isinstance(ip_addr, str) and ip_addr.startswith("10.11.13."):
                            victim_b_primary_ip = ip_addr; break
                    if victim_b_primary_ip == "Unknown IP" and host_ip_list_from_fim:
                        victim_b_primary_ip = host_ip_list_from_fim[0]
                    
                    if victim_b_primary_ip == "Unknown IP":
                        logger.error(f"Could not determine a valid primary IP for victim host {host_info.get('name')} from FIM event {event_id}. Aborting threat hunt for this event.")
                        continue

                    threat_hunt_input_data = {
                        "victim_primary_ip": victim_b_primary_ip,
                        "victim_all_ips": host_ip_list_from_fim,
                        "victim_host_name": host_info.get("name", f"host_{victim_b_primary_ip}"),
                        "malicious_file_path": file_path,
                        "malicious_file_hash_sha256": file_hash_to_check,
                        "detection_timestamp_str": event_timestamp_str,
                        "vt_result": vt_result,
                        "original_fim_event_id": event_id
                    }
                    logger.info(f"Initiating threat hunt for FIM event {event_id} on host {threat_hunt_input_data['victim_host_name']} ({threat_hunt_input_data['victim_primary_ip']}). Input: {json.dumps(threat_hunt_input_data)}")

                    try:
                        if not os.path.exists(THREAT_HUNTER_SCRIPT_PATH):
                            logger.error(f"Threat hunter script not found at {THREAT_HUNTER_SCRIPT_PATH}")
                        else:
                            process = subprocess.Popen(
                                ['python3', THREAT_HUNTER_SCRIPT_PATH, json.dumps(threat_hunt_input_data)],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors='ignore'
                            )
                            stdout_data, stderr_data = process.communicate(timeout=300)

                            logger.info(f"Threat hunting process (PID: {process.pid}) for {file_path} completed with return code {process.returncode}.")
                            if stderr_data:
                                logger.error(f"Threat hunter stderr for {file_path}:\n{stderr_data}")

                            if stdout_data and process.returncode == 0:
                                try:
                                    report_json_str = None
                                    decoded_stdout = stdout_data
                                    report_start_marker = "--- THREAT HUNT REPORT"
                                    report_end_marker = "--- END OF REPORT ---"
                                    last_report_start_index = decoded_stdout.rfind(report_start_marker)
                                    if last_report_start_index != -1:
                                        actual_json_start = decoded_stdout.find("{", last_report_start_index)
                                        if actual_json_start != -1:
                                            report_end_index = decoded_stdout.find(report_end_marker, actual_json_start)
                                            if report_end_index != -1:
                                                json_candidate_str = decoded_stdout[actual_json_start:report_end_index].strip()
                                                last_brace = json_candidate_str.rfind("}")
                                                if last_brace != -1: report_json_str = json_candidate_str[:last_brace+1]
                                    
                                    if report_json_str:
                                        logger.info(f"Successfully captured threat hunt report JSON from stdout for {file_path}.")
                                        threat_hunt_report = json.loads(report_json_str)
                                        

                                        if "@timestamp" not in threat_hunt_report:
                                            threat_hunt_report["@timestamp"] = threat_hunt_report.get("hunt_trigger_time_utc", datetime.utcnow().replace(tzinfo=timezone.utc).isoformat())
                                        
                                        send_data_to_elasticsearch(TH_REPORT_INDEX_NAME, threat_hunt_report, ELASTIC_URL_TH_REPORT, ELASTIC_USERNAME_TH_REPORT, ELASTIC_PASSWORD_TH_REPORT, VERIFY_CERT_ELASTIC_TH_REPORT)
                                    else:
                                        logger.warning(f"Could not find valid JSON report in threat hunter stdout for {file_path}. Stdout was:\n{decoded_stdout}")
                                except json.JSONDecodeError as je:
                                    logger.error(f"Failed to decode JSON report from threat hunter for {file_path}: {je}. Stdout was:\n{stdout_data}")
                                except Exception as e_parse:
                                    logger.error(f"Error processing threat hunter output for {file_path}: {e_parse}", exc_info=True)
                            elif process.returncode != 0:
                                logger.error(f"Threat hunter for {file_path} exited with error code {process.returncode}. Stdout:\n{stdout_data}\nStderr:\n{stderr_data}")
                    except subprocess.TimeoutExpired:
                        logger.error(f"Threat hunter script for {file_path} timed out after 300 seconds.")
                        if 'process' in locals() and process.poll() is None: process.kill()
                    except Exception as e_subproc:
                        logger.error(f"Failed to launch or process background threat hunter for {file_path}: {e_subproc}", exc_info=True)
                else: 
                    logger.info(f"File {file_path} (Hash: {file_hash_to_check}) likely clean based on VT. VT Positives: {vt_result.get('positives')}")
            else: 
                logger.warning(f"Could not get VT result for file {file_path} (Hash: {file_hash_to_check}). Will retry in the next cycle if not already processed.")
            
            time.sleep(1) 

        logger.info(f"Finished processing FIM events batch. Waiting for {FIM_QUERY_INTERVAL_SECONDS} seconds.")
        time.sleep(FIM_QUERY_INTERVAL_SECONDS)

if __name__ == "__main__":
    logger.info("FIM Processor starting from __main__.")
    main_processor_loop()
