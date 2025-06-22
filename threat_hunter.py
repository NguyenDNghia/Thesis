import requests
import json
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse, unquote
from ipaddress import ip_network, ip_address
from requests.auth import HTTPBasicAuth
import logging
import os
import sys
import secrets_manager

# === CẤU HÌNH CHUNG ===
ELASTIC_URL = os.getenv("TH_ELASTIC_URL", "https://localhost:9200")
ELASTIC_USERNAME = os.getenv("TH_ELASTIC_USERNAME", "elastic")
ELASTIC_PASSWORD = secrets_manager.get_secret("elastic/user", "password")
VERIFY_CERT_ELASTIC_STR = os.getenv("TH_VERIFY_CERT_ELASTIC", "/etc/elasticsearch/certs/http_ca.crt")
VERIFY_CERT_ELASTIC = VERIFY_CERT_ELASTIC_STR if VERIFY_CERT_ELASTIC_STR.lower() != 'false' else False


AUDITD_INDEX_PATTERN = os.getenv("TH_AUDITD_INDEX", ".ds-logs-auditd_manager.auditd-*")
ZEEK_CONN_INDEX_PATTERN = os.getenv("TH_ZEEK_CONN_INDEX", ".ds-logs-zeek.connection-*")
ZEEK_HTTP_INDEX_PATTERN = os.getenv("TH_ZEEK_HTTP_INDEX", ".ds-logs-zeek.http-*")
ZEEK_DNS_INDEX_PATTERN = os.getenv("TH_ZEEK_DNS_INDEX", ".ds-logs-zeek.dns-*")
ZEEK_SSL_INDEX_PATTERN = os.getenv("TH_ZEEK_SSL_INDEX", ".ds-logs-zeek.ssl-*")
ZEEK_FILES_INDEX_PATTERN = os.getenv("TH_ZEEK_FILES_INDEX", ".ds-logs-zeek.files-*")
ZEEK_SSH_INDEX_PATTERN = os.getenv("TH_ZEEK_SSH_INDEX", ".ds-logs-zeek.ssh-*")
SURICATA_INDEX_PATTERN = os.getenv("TH_SURICATA_INDEX", ".ds-logs-suricata.eve-*")
FIM_INDEX_PATTERN_FOR_HOST_INFO = os.getenv("FIM_INDEX_PATTERN", ".ds-logs-fim.event-default-*")


CORRELATION_WINDOW_SECONDS_BEFORE = int(os.getenv("TH_CORRELATION_WINDOW_BEFORE", "300"))
CORRELATION_WINDOW_SECONDS_AFTER = int(os.getenv("TH_CORRELATION_WINDOW_AFTER", "300"))
EXTERNAL_DOWNLOAD_WINDOW_SECONDS_BEFORE = int(os.getenv("TH_EXTERNAL_WINDOW_BEFORE", "7200")) # 2 hours
EXTERNAL_DOWNLOAD_WINDOW_SECONDS_AFTER = int(os.getenv("TH_EXTERNAL_WINDOW_AFTER", "600")) # 10 minutes
HOST_INFO_LOOKUP_WINDOW_HOURS = int(os.getenv("TH_HOST_INFO_WINDOW_HOURS", "24"))
ZEEK_FILE_HASH_WINDOW_SECONDS_BEFORE = int(os.getenv("TH_ZEEK_FILE_HASH_WINDOW_BEFORE", "600"))
ZEEK_FILE_HASH_WINDOW_SECONDS_AFTER = int(os.getenv("TH_ZEEK_FILE_HASH_WINDOW_AFTER", "600"))

INTERNAL_SUBNETS_STR = os.getenv("INTERNAL_SUBNETS", "10.11.13.0/24") # Mặc định cho mạng của Máy B
INTERNAL_SUBNETS = [ip_network(subnet.strip(), strict=False) for subnet in INTERNAL_SUBNETS_STR.split(',') if subnet.strip()]

logger = logging.getLogger("ThreatHunterV3_FullScript_Refined")
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s [%(module)s.%(funcName)s:%(lineno)d] - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

# --- TIỆN ÍCH ---
def is_internal_ip(ip_addr_str):
    if not ip_addr_str: return False
    try:
        addr = ip_address(ip_addr_str)
        if addr.is_loopback or addr.is_link_local or addr.is_multicast: return True
        for subnet in INTERNAL_SUBNETS:
            if addr in subnet: return True
        return False
    except ValueError:
        logger.debug(f"Invalid IP address string for internal check: {ip_addr_str}")
        return False

def query_elasticsearch(index_pattern, query_body, size=10, sort_order=None, timeout=30):
    search_url = f"{ELASTIC_URL}/{index_pattern}/_search"
    headers = {"Content-Type": "application/json"}
    final_query = {"size": size, "query": query_body, "_source": True}
    if sort_order: final_query["sort"] = sort_order

    try:
        query_log_str = json.dumps(final_query)
        if len(query_log_str) > 1000: query_log_str = query_log_str[:1000] + "... (truncated)"
    except Exception: query_log_str = "Could not serialize query for logging"
    logger.debug(f"ES Query URL: {search_url}\nES Query Body (sample): {query_log_str}")

    try:
        response = requests.post(
            search_url,
            auth=HTTPBasicAuth(ELASTIC_USERNAME, ELASTIC_PASSWORD) if ELASTIC_USERNAME else None,
            json=final_query,
            verify=VERIFY_CERT_ELASTIC,
            timeout=timeout
        )
        response.raise_for_status()
        return response.json().get("hits", {}).get("hits", [])
    except requests.exceptions.HTTPError as e:
        logger.error(f"ES HTTPError: {e.response.status_code} - {e.response.text} for index {index_pattern}")
    except requests.exceptions.RequestException as e:
        logger.error(f"ES RequestException: {e} for index {index_pattern}")
    except Exception as e_gen:
        logger.error(f"An unexpected error during ES query for index {index_pattern}: {e_gen}", exc_info=True)
    return []

def parse_url_details(url_string):
    if not url_string or not (isinstance(url_string, str) and (url_string.startswith("http://") or url_string.startswith("https://"))):
        logger.debug(f"Invalid or non-HTTP/S URL provided for parsing: {url_string}")
        return None, None, None, None
    try:
        parsed_url = urlparse(url_string)
        scheme = parsed_url.scheme
        hostname = parsed_url.hostname
        port = parsed_url.port if parsed_url.port else (443 if parsed_url.scheme == 'https' else 80)
        path = parsed_url.path if parsed_url.path else "/"
        if not hostname:
            if parsed_url.netloc:
                hostname_candidate = parsed_url.netloc.split(':')[0]
                try:
                    ip_address(hostname_candidate)
                    hostname = hostname_candidate
                except ValueError:
                    logger.debug(f"Could not parse hostname from URL (netloc not valid IP): {url_string}")
                    return None, None, None, None
            else:
                logger.debug(f"Could not parse hostname from URL: {url_string}")
                return None, None, None, None
        return scheme, hostname, port, path
    except Exception as e:
        logger.error(f"Error parsing URL '{url_string}': {e}")
        return None, None, None, None

def get_field_value(log_source, field_path_list, default=None):
    value = log_source
    if not isinstance(log_source, dict): return default
    for field in field_path_list:
        if isinstance(value, dict):
            value = value.get(field)
        elif isinstance(value, list) and value and isinstance(value[0], dict):
            current_field_value = None
            for item in value:
                if isinstance(item, dict) and item.get(field) is not None:
                    current_field_value = item.get(field)
                    break
            value = current_field_value
        else:
            return default
        if value is None: return default

    if isinstance(value, list) and len(value) == 1:
        return value[0]
    return value

# --- CÁC HÀM TÓM TẮT LOG ---
def summarize_auditd_exec(log_source):
    if not log_source: return None
    args_raw = get_field_value(log_source, ["process", "args"], [])
    args_str_list = [str(arg) for arg in args_raw if arg is not None]
    return {
        "timestamp": get_field_value(log_source, ["@timestamp"]),
        "process_name": get_field_value(log_source, ["process", "name"]),
        "command_line": get_field_value(log_source, ["process", "command_line"]) or " ".join(args_str_list),
        "pid": get_field_value(log_source, ["process", "pid"]),
        "ppid": get_field_value(log_source, ["process", "parent", "pid"]),
        "user": get_field_value(log_source, ["user", "name"]),
        "cwd": get_field_value(log_source, ["process", "working_directory"]),
        "outcome": get_field_value(log_source, ["event", "outcome"])
    }

def summarize_auditd_auth_list(auth_logs_raw):
    if not auth_logs_raw: return []
    summaries = []
    for log_source in auth_logs_raw:
        summary = {
            "timestamp": get_field_value(log_source, ["@timestamp"]),
            "message_type": get_field_value(log_source, ["auditd", "message_type"]),
            "user_acct": get_field_value(log_source, ["auditd", "data", "acct"]) or get_field_value(log_source, ["user", "name"]),
            "source_addr": get_field_value(log_source, ["auditd", "data", "addr"]) or get_field_value(log_source, ["source", "ip"]),
            "terminal": get_field_value(log_source, ["auditd", "data", "terminal"]),
            "sshd_pid": get_field_value(log_source, ["process", "pid"]),
            "session_id": get_field_value(log_source, ["auditd", "session"]),
            "outcome": get_field_value(log_source, ["event", "outcome"])
        }
        summaries.append(summary)
    return summaries

def summarize_zeek_conn(log_source):
    if not log_source: return None
    duration_ns = get_field_value(log_source, ["event", "duration"])
    duration_s_str = "N/A"
    if isinstance(duration_ns, (int, float)) and duration_ns > 0:
        duration_s = duration_ns / 1_000_000_000
        duration_s_str = f"{duration_s:.6f}s"
    return {
        "uid": get_field_value(log_source, ["zeek", "session_id"]),
        "timestamp": get_field_value(log_source, ["@timestamp"]),
        "source_ip": get_field_value(log_source, ["source", "ip"]),
        "source_port": get_field_value(log_source, ["source", "port"]),
        "dest_ip": get_field_value(log_source, ["destination", "ip"]),
        "dest_port": get_field_value(log_source, ["destination", "port"]),
        "protocol": get_field_value(log_source, ["network", "transport"]),
        "state": get_field_value(log_source, ["zeek", "connection", "state"]),
        "duration": duration_s_str,
        "orig_bytes": get_field_value(log_source, ["source", "bytes"]),
        "resp_bytes": get_field_value(log_source, ["destination", "bytes"]),
        "history": get_field_value(log_source, ["zeek", "connection", "history"])
    }

def summarize_zeek_http(log_source):
    if not log_source: return None
    return {
        "uid": get_field_value(log_source, ["zeek", "session_id"]),
        "timestamp": get_field_value(log_source, ["@timestamp"]),
        "method": get_field_value(log_source, ["http", "request", "method"]),
        "host": get_field_value(log_source, ["url", "domain"]) or get_field_value(log_source, ["http","request","host"]),
        "uri": get_field_value(log_source, ["url", "original"]),
        "status_code": get_field_value(log_source, ["http", "response", "status_code"]),
        "user_agent": get_field_value(log_source, ["user_agent", "original"]),
        "resp_fuids": get_field_value(log_source, ["zeek", "http", "resp_fuids"], [])
    }

def summarize_zeek_dns(log_source):
    if not log_source: return None
    return {
        "uid": get_field_value(log_source, ["zeek", "session_id"]),
        "timestamp": get_field_value(log_source, ["@timestamp"]),
        "query": get_field_value(log_source, ["dns","question","name"]) or get_field_value(log_source, ["zeek","dns","query"]),
        "answers": get_field_value(log_source, ["dns","answers","data"], default=[]) or get_field_value(log_source, ["zeek","dns","answers"], default=[]),
        "response_code": get_field_value(log_source, ["dns","response_code"]) or get_field_value(log_source, ["zeek","dns","rcode_name"]),
        "source_ip": get_field_value(log_source, ["source","ip"]),
        "dest_ip": get_field_value(log_source, ["destination","ip"])
    }

def summarize_zeek_ssl(log_source):
    if not log_source: return None
    return {
        "uid": get_field_value(log_source, ["zeek", "session_id"]),
        "timestamp": get_field_value(log_source, ["@timestamp"]),
        "server_name_sni": get_field_value(log_source, ["tls","server","name"]) or get_field_value(log_source, ["zeek","ssl","server_name"]),
        "version": get_field_value(log_source, ["tls","version"]) or get_field_value(log_source, ["zeek","ssl","version"]),
        "cipher": get_field_value(log_source, ["tls","cipher"]) or get_field_value(log_source, ["zeek","ssl","cipher"]),
        "established": get_field_value(log_source, ["tls","established"]) or get_field_value(log_source, ["zeek","ssl","established"]),
    }

def summarize_zeek_file(log_source):
    if not log_source: return None
    return {
        "uid": get_field_value(log_source, ["zeek", "session_id"]) or get_field_value(log_source, ["zeek", "session_ids"]),
        "fuid": get_field_value(log_source, ["zeek", "files", "fuid"]),
        "timestamp": get_field_value(log_source, ["@timestamp"]),
        "source_protocol": get_field_value(log_source, ["zeek", "files", "source"]),
        "mime_type": get_field_value(log_source, ["file", "mime_type"]),
        "filename": get_field_value(log_source, ["file", "name"]),
        "seen_bytes": get_field_value(log_source, ["zeek", "files", "seen_bytes"]),
        "md5": get_field_value(log_source, ["file", "hash", "md5"]),
        "sha1": get_field_value(log_source, ["file", "hash", "sha1"]),
        "sha256": get_field_value(log_source, ["file", "hash", "sha256"])
    }

def summarize_zeek_ssh(log_source):
    if not log_source: return None
    client_sw = get_field_value(log_source, ["zeek", "ssh", "client"]) or get_field_value(log_source, ["ssh", "client", "software","version"])
    if isinstance(client_sw, dict) : client_sw = client_sw.get("version")
    server_sw = get_field_value(log_source, ["zeek", "ssh", "server"]) or get_field_value(log_source, ["ssh", "server", "software","version"])
    if isinstance(server_sw, dict) : server_sw = server_sw.get("version")
    return {
        "uid": get_field_value(log_source, ["zeek", "session_id"]),
        "timestamp": get_field_value(log_source, ["@timestamp"]),
        "client_ip": get_field_value(log_source, ["id.orig_h"]) or get_field_value(log_source, ["source","ip"]),
        "server_ip": get_field_value(log_source, ["id.resp_h"]) or get_field_value(log_source, ["destination","ip"]),
        "client_version": client_sw,
        "server_version": server_sw,
        "direction": get_field_value(log_source, ["network","direction"]) or get_field_value(log_source, ["zeek","ssh","direction"]),
        "auth_success": get_field_value(log_source, ["zeek","ssh","auth_success"]),
        "auth_attempts": get_field_value(log_source, ["zeek","ssh","auth_attempts"])
    }

def summarize_suricata_event(log_source):
    if not log_source: return None
    event_type = get_field_value(log_source, ["suricata", "eve", "event_type"])
    summary = {
        "timestamp": get_field_value(log_source, ["@timestamp"]),
        "event_type": event_type,
        "source_ip": get_field_value(log_source, ["source", "ip"]),
        "source_port": get_field_value(log_source, ["source", "port"]),
        "dest_ip": get_field_value(log_source, ["destination", "ip"]),
        "dest_port": get_field_value(log_source, ["destination", "port"]),
        "protocol": get_field_value(log_source, ["network", "transport"]) or get_field_value(log_source, ["suricata","eve","proto"]),
        "app_protocol": get_field_value(log_source, ["network", "protocol"]) or get_field_value(log_source, ["suricata","eve","app_proto"]),
        "flow_id": get_field_value(log_source, ["suricata","eve","flow_id"])
    }
    if event_type == "alert":
        summary["alert_signature"] = get_field_value(log_source, ["suricata", "eve", "alert", "signature"])
        summary["alert_category"] = get_field_value(log_source, ["suricata", "eve", "alert", "category"])
        summary["alert_severity"] = get_field_value(log_source, ["suricata", "eve", "alert", "severity"])
    elif event_type == "http":
        summary["http_hostname"] = get_field_value(log_source, ["suricata", "eve", "http", "hostname"]) or get_field_value(log_source, ["url", "domain"])
        summary["http_url"] = get_field_value(log_source, ["suricata", "eve", "http", "url"]) or get_field_value(log_source, ["url", "original"])
        summary["http_status"] = get_field_value(log_source, ["suricata", "eve", "http", "status"])
    elif event_type == "dns":
        summary["dns_query"] = get_field_value(log_source, ["dns","question","name"]) or get_field_value(log_source, ["suricata","eve","dns","rrname"])
        summary["dns_type"] = get_field_value(log_source, ["dns","question","type"]) or get_field_value(log_source, ["suricata","eve","dns","rrtype"])
        summary["dns_answers"] = get_field_value(log_source, ["dns","answers","data"], default=[])
        if not summary["dns_answers"] and get_field_value(log_source, ["suricata","eve","dns","answers"]):
            summary["dns_answers"] = [ans.get("rdata") for ans in get_field_value(log_source, ["suricata","eve","dns","answers"], []) if ans.get("rdata")]
        summary["dns_response_code"] = get_field_value(log_source,["dns","response_code"]) or get_field_value(log_source,["suricata","eve","dns","rcode"])
    elif event_type == "tls":
        summary["tls_sni"] = get_field_value(log_source, ["tls","client","server_name"]) or get_field_value(log_source, ["suricata","eve","tls","sni"])
        summary["tls_subject"] = get_field_value(log_source, ["tls","server","x509","subject","common_name"]) or get_field_value(log_source, ["suricata","eve","tls","subject"])
        summary["tls_issuer"] = get_field_value(log_source, ["tls","server","x509","issuer","common_name"]) or get_field_value(log_source, ["suricata","eve","tls","issuerdn"])
        summary["tls_version"] = get_field_value(log_source, ["tls","version"]) or get_field_value(log_source,["suricata","eve","tls","version"])
    elif event_type == "flow":
        summary["flow_state"] = get_field_value(log_source,["suricata","eve","flow","state"])
        summary["flow_reason"] = get_field_value(log_source,["suricata","eve","flow","reason"])
        summary["bytes_toserver"] = get_field_value(log_source,["suricata","eve","flow","bytes_toserver"])
        summary["bytes_toclient"] = get_field_value(log_source,["suricata","eve","flow","bytes_toclient"])
    elif event_type == "fileinfo":
        summary["filename"] = get_field_value(log_source, ["suricata","eve","fileinfo","filename"])
        summary["sha256"] = get_field_value(log_source, ["suricata","eve","fileinfo","sha256"])
        summary["size"] = get_field_value(log_source, ["suricata","eve","fileinfo","size"])
        summary["state"] = get_field_value(log_source, ["suricata","eve","fileinfo","state"])
    return summary


# --- CÁC HÀM Threat Hunt ---

def find_wget_execution_in_auditd(target_host_ip, file_path_on_target, event_ts_obj):
    logger.info(f"AUDITD WGET HUNT (VICTIM): Searching for wget creating '{file_path_on_target}' on host '{target_host_ip}' around {event_ts_obj.isoformat()}")
    start_time_obj = event_ts_obj - timedelta(seconds=CORRELATION_WINDOW_SECONDS_BEFORE)
    end_time_obj = event_ts_obj + timedelta(seconds=CORRELATION_WINDOW_SECONDS_AFTER)
    start_time_iso = start_time_obj.isoformat()
    end_time_iso = end_time_obj.isoformat()

    query_body = {
        "bool": {
            "must": [
                {"term": {"host.ip": target_host_ip}},
                {"term": {"process.name": "wget"}},
                {"term": {"event.action": "executed"}}
            ],
            "filter": [
                {"range": {"@timestamp": {"gte": start_time_iso, "lte": end_time_iso, "format": "strict_date_optional_time_nanos"}}},
                {
                    "bool": {
                        "should": [
                            {"term": {"process.args": file_path_on_target}},
                            {"wildcard": {"process.command_line": f"*{file_path_on_target}*"}},
                            {"wildcard": {"process.title": f"*{file_path_on_target}*"}}
                        ],
                        "minimum_should_match": 1
                    }
                }
            ]
        }
    }
    hits = query_elasticsearch(AUDITD_INDEX_PATTERN, query_body, size=5, sort_order=[{"@timestamp": "desc"}])
    if not hits:
        logger.warning(f"AUDITD WGET HUNT (VICTIM): No 'wget' execution event found outputting to '{file_path_on_target}' on '{target_host_ip}'.")
        return None

    for hit in hits:
        source = hit.get("_source", {})
        args = get_field_value(source, ["process", "args"], [])
        if not isinstance(args, list): args = [str(args)]
        else: args = [str(a) for a in args]

        cmd_line = get_field_value(source, ["process", "command_line"])

        is_output_target = False
        if args:
            try:
                idx = args.index(file_path_on_target)
                if idx > 0 and args[idx-1].upper() == "-O":
                    is_output_target = True
            except ValueError:
                for i, arg_val in enumerate(args):
                    if arg_val == "-O" and i + 1 < len(args) and args[i+1] == file_path_on_target:
                        is_output_target = True; break
                    if arg_val.startswith("-O") and file_path_on_target in arg_val :
                        is_output_target = True; break

        if not is_output_target and cmd_line:
            if f"-O {file_path_on_target}" in cmd_line or \
               f"-O\"{file_path_on_target}\"" in cmd_line or \
               f"-O'{file_path_on_target}'" in cmd_line or \
               f"-O{file_path_on_target}" in cmd_line :
                is_output_target = True

        if is_output_target:
            source_url = None
            for arg_val in args:
                if arg_val.startswith("http://") or arg_val.startswith("https://"):
                    source_url = arg_val
                    break
            if not source_url and cmd_line:
                parts = cmd_line.split()
                for part in parts:
                    if part.startswith("http://") or part.startswith("https://"):
                        source_url = part.strip("'\"")
                        break

            if source_url:
                logger.info(f"AUDITD WGET HUNT (VICTIM): Found wget execution: {cmd_line or ' '.join(args)}")
                return {
                    "type": "wget_execution_on_victim",
                    "log_source_type": "auditd",
                    "timestamp": get_field_value(source, ["@timestamp"]),
                    "source_url": source_url,
                    "target_file_path": file_path_on_target,
                    "_raw_log": source
                }
    logger.warning(f"AUDITD WGET HUNT (VICTIM): 'wget' events found for host {target_host_ip}, but none clearly outputting to '{file_path_on_target}'.")
    return None

def find_wget_on_host_for_url(host_name, host_ips, reference_ts_obj, window_before, window_after):
    logger.info(f"AUDITD WGET HUNT (GENERIC HOST): Searching for any wget with URL on host '{host_name}' (IPs: {host_ips}) around {reference_ts_obj.isoformat()}")
    start_time_obj = reference_ts_obj - timedelta(seconds=window_before)
    end_time_obj = reference_ts_obj + timedelta(seconds=window_after)
    start_time_iso = start_time_obj.isoformat()
    end_time_iso = end_time_obj.isoformat()

    host_clauses = []
    if host_name and host_name != f"host_{host_ips[0] if host_ips else 'unknown'}":
        host_clauses.append({"term": {"host.name": host_name}})
    if host_ips:
        host_clauses.append({"terms": {"host.ip": host_ips}})

    if not host_clauses:
        logger.warning("AUDITD WGET HUNT (GENERIC HOST): No hostname or IPs provided.")
        return None

    query_body = {
        "bool": {
            "must": [
                {"term": {"process.name": "wget"}},
                {"term": {"event.action": "executed"}},
                {"bool": {"should": host_clauses, "minimum_should_match": 1}}
            ],
            "filter": [
                {"range": {"@timestamp": {"gte": start_time_iso, "lte": end_time_iso, "format": "strict_date_optional_time_nanos"}}}
            ]
        }
    }
    hits = query_elasticsearch(AUDITD_INDEX_PATTERN, query_body, size=10, sort_order=[{"@timestamp": "desc"}])

    if not hits:
        logger.warning(f"AUDITD WGET HUNT (GENERIC HOST): No 'wget' execution event found on host '{host_name}' (IPs: {host_ips}).")
        return None

    for hit in hits:
        source = hit.get("_source", {})
        args = get_field_value(source, ["process", "args"], [])
        if not isinstance(args, list): args = [str(args)]
        else: args = [str(a) for a in args]
        cmd_line = get_field_value(source, ["process", "command_line"])

        source_url = None
        for arg_val in args:
            if arg_val.startswith("http://") or arg_val.startswith("https://"):
                source_url = arg_val
                break
        if not source_url and cmd_line:
            parts = cmd_line.split()
            for part in parts:
                if (part.startswith("http://") or part.startswith("https://")) and "." in part:
                    source_url = part.strip("'\"")
                    break

        if source_url:
            logger.info(f"AUDITD WGET HUNT (GENERIC HOST): Found wget execution on '{host_name}': {cmd_line or ' '.join(args)}")
            output_file_path = None
            for i, arg_val in enumerate(args):
                if arg_val == "-O" and i + 1 < len(args):
                    output_file_path = args[i+1]
                    break
                if arg_val.startswith("-O") and len(arg_val) > 2:
                    output_file_path = arg_val[2:]
                    break
            if not output_file_path and cmd_line:
                o_idx = cmd_line.find("-O ")
                if o_idx != -1:
                    parts_after_O = cmd_line[o_idx+3:].split()
                    if parts_after_O:
                        output_file_path = parts_after_O[0].strip("'\"")

            return {
                "type": "wget_execution_on_intermediate",
                "log_source_type": "auditd",
                "timestamp": get_field_value(source, ["@timestamp"]),
                "source_url": source_url,
                "output_file_path_on_host": output_file_path,
                "host_name_reported": get_field_value(source,["host","name"]),
                "host_ip_reported": get_field_value(source,["host","ip"]),
                "_raw_log": source
            }

    logger.warning(f"AUDITD WGET HUNT (GENERIC HOST): 'wget' events found for host '{host_name}' (IPs: {host_ips}), but no HTTP/S URL identified in arguments.")
    return None


def find_scp_server_activity_on_victim(victim_host_ip, malicious_file_path, detection_ts_obj):
    logger.info(f"AUDITD SCP_SERVER HUNT: Searching for sshd activity for '{malicious_file_path}' on victim '{victim_host_ip}' near {detection_ts_obj.isoformat()}")
    start_time_obj = detection_ts_obj - timedelta(seconds=CORRELATION_WINDOW_SECONDS_BEFORE)
    end_time_obj = detection_ts_obj + timedelta(seconds=CORRELATION_WINDOW_SECONDS_AFTER)
    start_time_iso = start_time_obj.isoformat()
    end_time_iso = end_time_obj.isoformat()

    scp_t_cmd_parts = ["scp", "-t", malicious_file_path]
    scp_t_query = {
        "bool": {
            "must": [
                {"term": {"host.ip": victim_host_ip}},
                {"term": {"event.action": "executed"}}
            ],
            "should": [
                {"terms": {"process.args": scp_t_cmd_parts}},
                {"wildcard": {"process.command_line": f"*scp*-t*{malicious_file_path}*"}}
            ],
            "minimum_should_match": 1,
            "filter": {
                "range": {"@timestamp": {"gte": start_time_iso, "lte": end_time_iso, "format": "strict_date_optional_time_nanos"}}
            }
        }
    }
    scp_t_hits = query_elasticsearch(AUDITD_INDEX_PATTERN, scp_t_query, size=5, sort_order=[{"@timestamp":"desc"}])

    if not scp_t_hits:
        logger.warning(f"AUDITD SCP_SERVER HUNT: No 'scp -t {malicious_file_path}' execution found on victim {victim_host_ip}.")
        return None

    for scp_t_hit in scp_t_hits:
        scp_t_source = scp_t_hit.get("_source", {})
        scp_t_pid = get_field_value(scp_t_source, ["process", "pid"])

        sshd_handler_pid = get_field_value(scp_t_source, ["process", "parent", "pid"])
        if get_field_value(scp_t_source,["process","parent","name"]) == "bash" and \
           get_field_value(scp_t_source,["process","parent","parent","name"]) == "sshd":
            sshd_handler_pid = get_field_value(scp_t_source,["process","parent","parent","pid"])

        if not sshd_handler_pid:
            logger.debug(f"AUDITD SCP_SERVER HUNT: Could not determine sshd_handler_pid for scp -t process {scp_t_pid}.")
            continue

        scp_t_timestamp_str = get_field_value(scp_t_source,["@timestamp"],"")
        if not scp_t_timestamp_str:
            logger.warning(f"Missing @timestamp in scp_t_source for PID {scp_t_pid}. Using detection_ts_obj for auth window.")
            scp_t_dt_obj = detection_ts_obj
        else:
            scp_t_timestamp_str = scp_t_timestamp_str.replace("Z","").split('.')[0].split('+')[0]
            try:
                scp_t_dt_obj = datetime.fromisoformat(scp_t_timestamp_str)
            except ValueError:
                logger.warning(f"Could not parse scp_t_timestamp: {get_field_value(scp_t_source,['@timestamp'])}. Using detection_ts_obj for auth window.")
                scp_t_dt_obj = detection_ts_obj

        auth_ts_start_obj = scp_t_dt_obj - timedelta(seconds=120)
        auth_ts_start = auth_ts_start_obj.isoformat()
        auth_ts_end = scp_t_dt_obj.isoformat()

        auth_query = {
            "bool": {
                "must": [
                    {"term": {"host.ip": victim_host_ip}},
                    {"term": {"process.pid": sshd_handler_pid}},
                    {"terms": {"auditd.message_type": ["USER_AUTH", "LOGIN", "CRED_ACQ", "USER_START", "user_auth", "login", "cred_acq", "user_start"]}},
                    {"exists": {"field": "auditd.data.addr"}}
                ],
                "filter": {
                    "range": {"@timestamp": {"gte": auth_ts_start, "lte": auth_ts_end, "format": "strict_date_optional_time_nanos"}}
                }
            }
        }
        auth_hits = query_elasticsearch(AUDITD_INDEX_PATTERN, auth_query, size=10, sort_order=[{"@timestamp":"desc"}])

        source_ip_from_sshd = None
        user_from_sshd = None
        ssh_session_id = None
        raw_auth_logs = []

        if auth_hits:
            for auth_hit in auth_hits:
                auth_s = auth_hit.get("_source",{})
                raw_auth_logs.append(auth_s)
                current_src_ip = get_field_value(auth_s, ["auditd", "data", "addr"]) or get_field_value(auth_s,["source","ip"])
                current_user = get_field_value(auth_s, ["auditd", "data", "acct"]) or get_field_value(auth_s,["user","name"])
                current_session = get_field_value(auth_s, ["auditd","session"])

                if current_src_ip and not is_internal_ip(current_src_ip):
                    logger.debug(f"AUDITD SCP_SERVER HUNT: Auth log for sshd {sshd_handler_pid} shows external source IP {current_src_ip}, skipping for internal hop.")
                    continue

                if not source_ip_from_sshd and current_src_ip: source_ip_from_sshd = current_src_ip
                if not user_from_sshd and current_user: user_from_sshd = current_user
                if not ssh_session_id and current_session : ssh_session_id = current_session

        if source_ip_from_sshd:
            logger.info(f"AUDITD SCP_SERVER HUNT: Correlated 'scp -t' (PID {scp_t_pid}) with sshd (PID {sshd_handler_pid}) auth: SrcIP={source_ip_from_sshd}, User={user_from_sshd}")
            return {
                "type": "scp_server_file_received",
                "log_source_type": "auditd_sshd",
                "timestamp": get_field_value(scp_t_source, ["@timestamp"]),
                "victim_file_path": malicious_file_path,
                "attacker_ip_derived": source_ip_from_sshd,
                "user": user_from_sshd or get_field_value(scp_t_source, ["user","name"]),
                "sshd_pid_victim": sshd_handler_pid,
                "scp_t_pid_victim": scp_t_pid,
                "executed_command_line": get_field_value(scp_t_source, ["process","command_line"]) or " ".join(get_field_value(scp_t_source, ["process","args"],[])),
                "ssh_session_id": ssh_session_id,
                "_raw_scp_t_log": scp_t_source,
                "_raw_auth_logs": raw_auth_logs
            }

    logger.warning(f"AUDITD SCP_SERVER HUNT: Found 'scp -t' like execution(s) for {victim_host_ip}, but could not fully correlate with *internal* auth logs for file '{malicious_file_path}'.")
    if scp_t_hits:
        first_scp_t_source = scp_t_hits[0].get("_source", {})
        return {
            "type": "scp_server_file_received_no_auth_correlation",
            "log_source_type": "auditd_sshd",
            "timestamp": get_field_value(first_scp_t_source, ["@timestamp"]),
            "_raw_scp_t_log": first_scp_t_source
        }
    return None


def find_network_transfer_by_hash(file_hash, target_host_ip, event_ts_obj, transfer_direction="to_target"):
    if not file_hash or file_hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855":
        return {}, {}
    logger.info(f"NETWORK HASH HUNT ({transfer_direction}): Hash '{file_hash}', Host '{target_host_ip}' @ {event_ts_obj.isoformat()}")
    start_time_obj = event_ts_obj - timedelta(seconds=ZEEK_FILE_HASH_WINDOW_SECONDS_BEFORE)
    end_time_obj = event_ts_obj + timedelta(seconds=ZEEK_FILE_HASH_WINDOW_SECONDS_AFTER)
    start_time_iso = start_time_obj.isoformat()
    end_time_iso = end_time_obj.isoformat()

    hash_clauses = [
        {"term": {"file.hash.sha256": file_hash}},
        {"term": {"zeek.files.sha256": file_hash}},
        {"term": {"suricata.eve.fileinfo.sha256": file_hash}}
    ]
    query_body_files = {
        "bool": {
            "should": hash_clauses,
            "minimum_should_match": 1,
            "filter": {"range": {"@timestamp": {"gte": start_time_iso, "lte": end_time_iso, "format": "strict_date_optional_time_nanos"}}}
        }
    }

    zeek_file_hits = query_elasticsearch(ZEEK_FILES_INDEX_PATTERN, query_body_files, size=5)
    suricata_file_hits = query_elasticsearch(
        SURICATA_INDEX_PATTERN,
        {"bool": {
            "must": [{"term":{"suricata.eve.event_type":"fileinfo"}}],
            "should" : hash_clauses,
            "minimum_should_match":1,
            "filter": {"range": {"@timestamp": {"gte": start_time_iso, "lte": end_time_iso, "format": "strict_date_optional_time_nanos"}}}
        }},
        size=5
    )

    collected_evidence_raw = {
        "zeek_file_hash_matches_raw": [h.get("_source") for h in zeek_file_hits if h.get("_source")],
        "suricata_file_hash_matches_raw": [h.get("_source") for h in suricata_file_hits if h.get("_source")]
    }
    derived_info = {}
    all_file_events = collected_evidence_raw["zeek_file_hash_matches_raw"] + collected_evidence_raw["suricata_file_hash_matches_raw"]

    if not all_file_events:
        logger.info(f"NETWORK HASH HUNT: No Zeek or Suricata file logs found for hash {file_hash} related to host {target_host_ip}.")
        return collected_evidence_raw, derived_info

    logger.info(f"NETWORK HASH HUNT: Found {len(all_file_events)} file log entries (Zeek/Suricata) for hash {file_hash}.")

    for file_event_source in all_file_events:
        session_id = get_field_value(file_event_source, ["zeek", "session_id"]) or get_field_value(file_event_source, ["zeek", "session_ids"])
        flow_id = get_field_value(file_event_source, ["suricata", "eve", "flow_id"])
        conn_log_source = None

        if session_id:
            conn_hits = query_elasticsearch(ZEEK_CONN_INDEX_PATTERN, {"bool":{"must":[{"term":{"zeek.session_id": session_id}}]}}, size=1)
            if conn_hits: conn_log_source = conn_hits[0].get("_source", {})
        elif flow_id:
            flow_hits = query_elasticsearch(SURICATA_INDEX_PATTERN, {"bool":{"must":[{"term":{"suricata.eve.flow_id": flow_id}}, {"term":{"suricata.eve.event_type":"flow"}}]}}, size=1)
            if flow_hits:
                conn_log_source = flow_hits[0].get("_source",{})
            else:
                any_event_flow_hits = query_elasticsearch(SURICATA_INDEX_PATTERN, {"bool":{"must":[{"term":{"suricata.eve.flow_id": flow_id}}]}}, size=1, sort_order=[{"@timestamp":"asc"}])
                if any_event_flow_hits: conn_log_source = any_event_flow_hits[0].get("_source",{})

        if conn_log_source:
            src_ip = get_field_value(conn_log_source, ["source", "ip"])
            dst_ip = get_field_value(conn_log_source, ["destination", "ip"])
            conn_matches_direction = False

            if transfer_direction == "to_target" and dst_ip == target_host_ip and is_internal_ip(src_ip):
                conn_matches_direction = True
                derived_info = {
                    "source_ip": src_ip,
                    "source_port": get_field_value(conn_log_source, ["source", "port"]),
                    "destination_port_on_target": get_field_value(conn_log_source, ["destination", "port"]),
                    "protocol": get_field_value(conn_log_source, ["network", "transport"]),
                    "source_method": "NetworkLog_FileHash_TargetIsDest",
                    "_raw_conn_log_for_hash": conn_log_source,
                    "_raw_file_log_for_hash": file_event_source
                }
            elif transfer_direction == "from_target" and src_ip == target_host_ip and is_internal_ip(dst_ip):
                conn_matches_direction = True
                derived_info = {
                    "destination_ip": dst_ip,
                    "destination_port": get_field_value(conn_log_source, ["destination", "port"]),
                    "source_port_on_target": get_field_value(conn_log_source, ["source", "port"]),
                    "protocol": get_field_value(conn_log_source, ["network", "transport"]),
                    "source_method": "NetworkLog_FileHash_TargetIsSource",
                    "_raw_conn_log_for_hash": conn_log_source,
                    "_raw_file_log_for_hash": file_event_source
                }

            if conn_matches_direction:
                if get_field_value(file_event_source,["zeek","files","source"]) == "HTTP" and session_id:
                    http_hits = query_elasticsearch(ZEEK_HTTP_INDEX_PATTERN, {"bool":{"must":[{"term":{"zeek.session_id":session_id}}]}}, size=1)
                    if http_hits:
                        http_s = http_hits[0].get("_source",{})
                        derived_info["uri"] = get_field_value(http_s,["url","original"])
                        derived_info["_raw_http_log_for_hash"] = http_s
                logger.info(f"NETWORK HASH HUNT: Correlated file log with connection: {src_ip} -> {dst_ip}")
                break

    return collected_evidence_raw, derived_info

def find_zeek_ssh_context(target_host_ip, remote_ip, event_ts_obj):
    if not remote_ip: return {}
    logger.info(f"ZEEK SSH HUNT: Target: {target_host_ip}, Remote: {remote_ip} @ {event_ts_obj.isoformat()}")
    start_time_obj = event_ts_obj - timedelta(seconds=CORRELATION_WINDOW_SECONDS_BEFORE)
    end_time_obj = event_ts_obj + timedelta(seconds=CORRELATION_WINDOW_SECONDS_AFTER)
    start_time_iso = start_time_obj.isoformat(); end_time_iso = end_time_obj.isoformat()
    time_filter = {"range": {"@timestamp": {"gte": start_time_iso, "lte": end_time_iso, "format": "strict_date_optional_time_nanos"}}}

    query_ssh_server = {"bool":{"must":[
        {"term":{"source.ip":remote_ip}},
        {"term":{"destination.ip":target_host_ip}},
        {"term":{"destination.port":22}}
    ], "filter": time_filter}}

    query_ssh_client = {"bool":{"must":[
        {"term":{"source.ip":target_host_ip}},
        {"term":{"destination.ip":remote_ip}},
        {"term":{"destination.port":22}}
    ], "filter": time_filter}}

    ssh_hits_raw = [h.get("_source") for h in query_elasticsearch(ZEEK_SSH_INDEX_PATTERN, query_ssh_server, size=5) if h.get("_source")]
    ssh_hits_raw.extend([h.get("_source") for h in query_elasticsearch(ZEEK_SSH_INDEX_PATTERN, query_ssh_client, size=5) if h.get("_source")])

    conn_hits_raw = [h.get("_source") for h in query_elasticsearch(ZEEK_CONN_INDEX_PATTERN, query_ssh_server, size=5) if h.get("_source")]
    conn_hits_raw.extend([h.get("_source") for h in query_elasticsearch(ZEEK_CONN_INDEX_PATTERN, query_ssh_client, size=5) if h.get("_source")])

    evidence = {}
    if ssh_hits_raw: evidence["ssh_sessions_raw"] = ssh_hits_raw
    if conn_hits_raw: evidence["connection_logs_for_ssh_raw"] = conn_hits_raw
    return evidence

def find_network_context_generic(target_host_ip, event_ts_obj, other_ip=None, target_port=None, other_port=None, uri=None):
    logger.info(f"GENERIC NET CONTEXT: TargetHost:{target_host_ip}, PeerIP:{other_ip}, TargetPort:{target_port}, PeerPort:{other_port}, URI:{uri} @ {event_ts_obj.isoformat()}")
    start_time_obj = event_ts_obj - timedelta(seconds=CORRELATION_WINDOW_SECONDS_BEFORE)
    end_time_obj = event_ts_obj + timedelta(seconds=CORRELATION_WINDOW_SECONDS_AFTER)
    start_time_iso = start_time_obj.isoformat(); end_time_iso = end_time_obj.isoformat()
    time_range_filter = {"range":{"@timestamp":{"gte":start_time_iso,"lte":end_time_iso, "format": "strict_date_optional_time_nanos"}}}

    zeek_raw = {}
    suricata_raw_events = []

    base_must_clauses_s = []
    base_must_clauses_z = []

    if other_ip:
        ip_pair_filter = {
            "bool": {
                "should": [
                    {"bool": {"must": [{"term":{"source.ip":target_host_ip}}, {"term":{"destination.ip":other_ip}}]}},
                    {"bool": {"must": [{"term":{"source.ip":other_ip}}, {"term":{"destination.ip":target_host_ip}}]}}
                ],
                "minimum_should_match": 1
            }
        }
        base_must_clauses_s.append(ip_pair_filter)
        base_must_clauses_z.append(ip_pair_filter)

        if target_port:
            port_filter = {"bool": {"should": [{"term":{"source.port":target_port}}, {"term":{"destination.port":target_port}}]}}
            base_must_clauses_s.append(port_filter)
            base_must_clauses_z.append(port_filter)
        if other_port:
            other_port_filter = {"bool": {"should": [{"term":{"source.port":other_port}}, {"term":{"destination.port":other_port}}]}}
            base_must_clauses_s.append(other_port_filter)
            base_must_clauses_z.append(other_port_filter)
    else:
        target_ip_filter = {"bool": {"should": [{"term":{"source.ip":target_host_ip}}, {"term":{"destination.ip":target_host_ip}}], "minimum_should_match": 1}}
        base_must_clauses_s.append(target_ip_filter)
        base_must_clauses_z.append(target_ip_filter)
        if target_port:
            port_filter = {"bool": {"should": [{"term":{"source.port":target_port}}, {"term":{"destination.port":target_port}}]}}
            base_must_clauses_s.append(port_filter)
            base_must_clauses_z.append(port_filter)

    query_conn_z = {"bool":{"must": base_must_clauses_z, "filter":time_range_filter}}
    conn_h = query_elasticsearch(ZEEK_CONN_INDEX_PATTERN,query_conn_z,size=10, sort_order=[{"@timestamp":"asc"}])
    if conn_h: zeek_raw["related_connections_raw"] = [h.get("_source") for h in conn_h if h.get("_source")]

    http_must_z = list(base_must_clauses_z)
    http_ports = [80, 443, 8080, 8000]
    if target_port and target_port in http_ports: current_http_ports = [target_port]
    else: current_http_ports = http_ports
    http_must_z.append({"bool": {"should": [{"terms":{"destination.port":current_http_ports}}, {"terms":{"source.port":current_http_ports}}], "minimum_should_match": 1}})
    if uri: http_must_z.append({"wildcard":{"url.original":f"*{unquote(uri)}*"}})
    query_http_z = {"bool":{"must":http_must_z, "filter":time_range_filter}}
    http_h = query_elasticsearch(ZEEK_HTTP_INDEX_PATTERN, query_http_z, size=5, sort_order=[{"@timestamp":"asc"}])
    if http_h: zeek_raw["related_http_logs_raw"] = [h.get("_source") for h in http_h if h.get("_source")]

    suri_query_must = list(base_must_clauses_s)
    suri_query = {
        "bool":{
            "must": suri_query_must,
            "should": [
                {"term":{"event.kind":"alert"}},
                {"term":{"network.protocol":"http"}}, {"term":{"suricata.eve.event_type":"http"}},
                {"term":{"network.protocol":"tls"}}, {"term":{"suricata.eve.event_type":"tls"}},
                {"term":{"network.protocol":"dns"}}, {"term":{"suricata.eve.event_type":"dns"}}
            ],
            "minimum_should_match":0,
            "filter":time_range_filter
        }
    }
    suri_h = query_elasticsearch(SURICATA_INDEX_PATTERN, suri_query, size=20, sort_order=[{"@timestamp":"asc"}])
    if suri_h: suricata_raw_events = [h.get("_source") for h in suri_h if h.get("_source")]

    return zeek_raw, suricata_raw_events

def get_host_info_from_ip(ip_address_to_find, reference_ts_obj):
    logger.info(f"HOST_INFO_LOOKUP: Attempting to find hostname and all IPs for host owning {ip_address_to_find} around {reference_ts_obj.isoformat()}")

    start_time_obj = reference_ts_obj - timedelta(hours=HOST_INFO_LOOKUP_WINDOW_HOURS)
    end_time_obj = reference_ts_obj + timedelta(minutes=30)
    start_time_iso = start_time_obj.isoformat(); end_time_iso = end_time_obj.isoformat()
    time_filter = {"range": {"@timestamp": {"gte": start_time_iso, "lte": end_time_iso, "format": "strict_date_optional_time_nanos"}}}

    all_related_ips = set()
    try:
        parsed_input_ip = ip_address(ip_address_to_find)
        if is_internal_ip(str(parsed_input_ip)):
            all_related_ips.add(parsed_input_ip.compressed)
    except ValueError:
        logger.error(f"HOST_INFO_LOOKUP: Provided ip_address_to_find '{ip_address_to_find}' is not a valid IP address.")
        return f"invalid_ip_{ip_address_to_find}", []

    potential_hostnames = set()
    primary_hostname_found = None

    ip_involvement_clauses = [
        {"term": {"source.ip": ip_address_to_find}}, {"term": {"destination.ip": ip_address_to_find}},
        {"term": {"host.ip": ip_address_to_find}},
        {"term": {"client.ip": ip_address_to_find}}, {"term": {"server.ip": ip_address_to_find}},
        {"term": {"observer.ip": ip_address_to_find}}
    ]
    query_for_ip_presence = {"bool": {"should": ip_involvement_clauses, "minimum_should_match": 1, "filter": time_filter}}

    indices_to_check = [SURICATA_INDEX_PATTERN, ZEEK_CONN_INDEX_PATTERN, ZEEK_SSL_INDEX_PATTERN, AUDITD_INDEX_PATTERN, FIM_INDEX_PATTERN_FOR_HOST_INFO]

    for index_pat in indices_to_check:
        logger.debug(f"HOST_INFO_LOOKUP: Querying {index_pat} for logs involving IP {ip_address_to_find} to find observer IPs and hostnames.")
        hits = query_elasticsearch(index_pat, query_for_ip_presence, size=50, sort_order=[{"@timestamp":"desc"}])
        for hit in hits:
            s = hit.get("_source", {})

            current_log_hostname = get_field_value(s, ["observer", "hostname"]) or \
                                   get_field_value(s, ["host", "name"]) or \
                                   get_field_value(s, ["agent", "name"])

            if current_log_hostname:
                potential_hostnames.add(current_log_hostname)
                obs_ips_for_hostname_check = get_field_value(s, ["observer", "ip"], [])
                if isinstance(obs_ips_for_hostname_check, str): obs_ips_for_hostname_check = [obs_ips_for_hostname_check]

                if isinstance(obs_ips_for_hostname_check, list):
                    try:
                        normalized_obs_ips = {ip_address(val).compressed for val in obs_ips_for_hostname_check if val}
                        if ip_address(ip_address_to_find).compressed in normalized_obs_ips:
                            if not primary_hostname_found or primary_hostname_found.startswith("host_"):
                                primary_hostname_found = current_log_hostname
                                logger.debug(f"HOST_INFO_LOOKUP: Updated primary_hostname to '{primary_hostname_found}' from log in {index_pat} with matching observer.ip.")
                    except ValueError: pass

            log_ips_to_check_in_current_log = []
            for field_path in [["source","ip"], ["destination","ip"], ["host","ip"], ["client","ip"], ["server","ip"]]:
                ip_val = get_field_value(s, field_path)
                if isinstance(ip_val, list): log_ips_to_check_in_current_log.extend(ip_val)
                elif ip_val: log_ips_to_check_in_current_log.append(ip_val)

            try:
                normalized_log_ips_in_current_log = {ip_address(val).compressed for val in log_ips_to_check_in_current_log if val}
            except ValueError:
                logger.debug(f"HOST_INFO_LOOKUP: Found invalid IP in log fields for {index_pat}, skipping some IPs for this log.")
                normalized_log_ips_in_current_log = set()

            if ip_address(ip_address_to_find).compressed in normalized_log_ips_in_current_log:
                obs_ips_field = get_field_value(s, ["observer", "ip"], [])
                if isinstance(obs_ips_field, str): obs_ips_field = [obs_ips_field]

                if isinstance(obs_ips_field, list) and obs_ips_field:
                    logger.debug(f"HOST_INFO_LOOKUP: Log in {index_pat} (src/dst/host IP matched {ip_address_to_find}). Found observer IPs: {obs_ips_field}")
                    for obs_ip_val in obs_ips_field:
                        if obs_ip_val and isinstance(obs_ip_val, str):
                            try:
                                normalized_ip = ip_address(obs_ip_val).compressed
                                all_related_ips.add(normalized_ip)
                            except ValueError:
                                logger.debug(f"HOST_INFO_LOOKUP: Invalid IP '{obs_ip_val}' in observer.ip, skipping.")

                for r_ip_str in normalized_log_ips_in_current_log:
                    if is_internal_ip(r_ip_str):
                        all_related_ips.add(r_ip_str)

    final_hostname = primary_hostname_found
    if not final_hostname and potential_hostnames:
        non_default_hostnames = [hname for hname in potential_hostnames if not hname.startswith("host_")]
        if non_default_hostnames: final_hostname = non_default_hostnames[0]
        elif potential_hostnames: final_hostname = list(potential_hostnames)[0]

    if not final_hostname:
        final_hostname = f"host_{ip_address_to_find}"

    final_ips = sorted(list(all_related_ips))
    logger.info(f"HOST_INFO_LOOKUP for IP {ip_address_to_find}: Final determined hostname '{final_hostname}', All related IPs: {final_ips}")
    return final_hostname, final_ips

def find_external_download_activity(source_host_name, source_host_all_ips, timeframe_end_obj, search_window_seconds_b, search_window_seconds_a):
    logger.info(f"EXTERNAL_DOWNLOAD_HUNT (NETWORK): Host '{source_host_name}' (All known IPs: {source_host_all_ips}) ref_time: {timeframe_end_obj.isoformat()}")
    potential_downloads = []
    raw_logs_collection = {"dns_zeek_raw": [], "dns_suricata_raw": [], "tls_suricata_raw": [], "http_zeek_raw": [], "conn_zeek_raw": [] }

    start_time_obj = timeframe_end_obj - timedelta(seconds=search_window_seconds_b)
    end_time_obj_query = timeframe_end_obj + timedelta(seconds=search_window_seconds_a)
    start_time_iso = start_time_obj.isoformat(); end_time_iso = end_time_obj_query.isoformat()
    time_filter = {"range": {"@timestamp": {"gte": start_time_iso, "lte": end_time_iso, "format": "strict_date_optional_time_nanos"}}}

    if not source_host_all_ips:
        logger.warning(f"EXTERNAL_DOWNLOAD_HUNT (NETWORK): No source host IPs provided for host {source_host_name}. Skipping.")
        return {"potential_sources": [], "raw_evidence_collection": raw_logs_collection, "dns_map_generated": {}}

    dns_map = {}

    for host_ip_as_source in source_host_all_ips:
        logger.info(f"EXTERNAL_DOWNLOAD_HUNT (NETWORK): Checking for egress traffic FROM IP {host_ip_as_source} (of host {source_host_name}).")

        dns_query_body_zeek = {"bool": {"must": [{"term": {"source.ip": host_ip_as_source}}], "filter": time_filter }}
        zeek_dns_hits = query_elasticsearch(ZEEK_DNS_INDEX_PATTERN, dns_query_body_zeek, size=50, sort_order=[{"@timestamp":"desc"}])
        if zeek_dns_hits : raw_logs_collection["dns_zeek_raw"].extend([h.get("_source") for h in zeek_dns_hits])
        for hit in zeek_dns_hits:
            s = hit.get("_source", {})
            q_name = get_field_value(s, ["dns","question","name"]) or get_field_value(s, ["zeek","dns","query"])
            answers = get_field_value(s, ["dns","answers","data"], []) or get_field_value(s, ["zeek","dns","answers"], [])
            if isinstance(answers,str): answers = [answers]
            if q_name and answers:
                for ans_ip in answers:
                    if ans_ip and not is_internal_ip(ans_ip):
                        dns_map[ans_ip] = {"query": q_name, "timestamp": get_field_value(s,["@timestamp"]), "_raw_log":s, "source_tool": "zeek", "dns_resolver": get_field_value(s,["destination","ip"])}
                        logger.debug(f"EXTERNAL_DOWNLOAD_HUNT (NETWORK): DNS from {host_ip_as_source} to resolver {get_field_value(s,['destination','ip'])} for '{q_name}' -> external_IP '{ans_ip}' (Zeek)")

        dns_query_body_suri = {"bool": {"must": [{"term": {"source.ip": host_ip_as_source}}, {"bool":{"should":[ {"term":{"event.dataset":"suricata.dns"}},{"term":{"suricata.eve.event_type":"dns"}}]}}], "filter": time_filter}}
        suri_dns_hits = query_elasticsearch(SURICATA_INDEX_PATTERN, dns_query_body_suri, size=50, sort_order=[{"@timestamp":"desc"}])
        if suri_dns_hits: raw_logs_collection["dns_suricata_raw"].extend([h.get("_source") for h in suri_dns_hits])
        for hit in suri_dns_hits:
            s = hit.get("_source", {})
            q_name = get_field_value(s, ["dns","question","name"]) or get_field_value(s, ["suricata","eve","dns","rrname"])
            answers_objs = get_field_value(s,["dns","answers"],[])
            if not answers_objs and get_field_value(s,["suricata","eve","dns","answers"]):
                answers_objs = get_field_value(s,["suricata","eve","dns","answers"],[])

            answers_list = []
            if isinstance(answers_objs, list):
                for ans_obj in answers_objs:
                    if isinstance(ans_obj, dict) and ans_obj.get("data"): answers_list.append(ans_obj.get("data"))
                    elif isinstance(ans_obj, dict) and ans_obj.get("rdata"): answers_list.append(ans_obj.get("rdata"))
            elif isinstance(answers_objs, str) : answers_list = [answers_objs]

            if q_name and answers_list:
                for ans_ip in answers_list:
                    if ans_ip and not is_internal_ip(ans_ip) and ans_ip not in dns_map:
                        dns_map[ans_ip] = {"query": q_name, "timestamp": get_field_value(s,["@timestamp"]), "_raw_log":s, "source_tool": "suricata", "dns_resolver": get_field_value(s,["destination","ip"])}
                        logger.debug(f"EXTERNAL_DOWNLOAD_HUNT (NETWORK): DNS from {host_ip_as_source} to resolver {get_field_value(s,['destination','ip'])} for '{q_name}' -> external_IP '{ans_ip}' (Suricata)")

        tls_query_body_suri = {"bool": {"must": [
                                        {"term": {"source.ip": host_ip_as_source}},
                                        {"bool":{"should":[{"term":{"event.dataset":"suricata.tls"}},{"term":{"suricata.eve.event_type":"tls"}}]}}
                                        ],
                                        "must_not": [{"term": {"destination.ip": "127.0.0.1"}}],
                                        "filter": time_filter,
                                        "should": [{"exists":{"field":"tls.client.server_name"}}, {"exists":{"field":"suricata.eve.tls.sni"}}],
                                        "minimum_should_match": 1
                                    }}
        suri_tls_hits = query_elasticsearch(SURICATA_INDEX_PATTERN, tls_query_body_suri, size=20, sort_order=[{"@timestamp":"desc"}])
        if suri_tls_hits: raw_logs_collection["tls_suricata_raw"].extend([h.get("_source") for h in suri_tls_hits])
        for hit in suri_tls_hits:
            s = hit.get("_source", {})
            sni = get_field_value(s, ["tls","client","server_name"]) or get_field_value(s, ["suricata","eve","tls","sni"])
            dest_ip = get_field_value(s, ["destination","ip"])
            if sni and dest_ip and not is_internal_ip(dest_ip):
                full_url = f"https://{sni}"
                scheme, domain, port, path = parse_url_details(full_url)
                if domain:
                    potential_downloads.append({"type": "Suricata_TLS_SNI", "download_actor_ip": host_ip_as_source, "url_domain": domain, "full_url_derived": full_url, "external_dest_ip": dest_ip, "protocol": "https", "port": port or get_field_value(s,["destination","port"]) or 443, "timestamp": get_field_value(s,["@timestamp"]), "_raw_log_tls": s})
                    logger.info(f"EXTERNAL_DOWNLOAD_HUNT (NETWORK): Potential HTTPS source via SNI by {host_ip_as_source}: URL: {full_url}, Dest IP: {dest_ip}")

        http_query_body_zeek = {"bool": {"must": [{"term": {"source.ip": host_ip_as_source}}], "filter": time_filter, "must_not":[{"term":{"destination.ip":"127.0.0.1"}}] }}
        zeek_http_hits = query_elasticsearch(ZEEK_HTTP_INDEX_PATTERN, http_query_body_zeek, size=20, sort_order=[{"@timestamp":"desc"}])
        if zeek_http_hits: raw_logs_collection["http_zeek_raw"].extend([h.get("_source") for h in zeek_http_hits])
        for hit in zeek_http_hits:
            s = hit.get("_source", {})
            dest_ip = get_field_value(s, ["destination","ip"])
            if dest_ip and not is_internal_ip(dest_ip):
                http_host = get_field_value(s, ["url","domain"]) or get_field_value(s,["http","request","host"])
                http_uri_orig = get_field_value(s,["url","original"])
                http_uri_path = get_field_value(s,["url","path"])

                full_url = "Unknown HTTP URL"
                if http_uri_orig and (http_uri_orig.startswith("http://") or http_uri_orig.startswith("https://")): full_url = http_uri_orig
                elif http_host and http_uri_path: full_url = f"http://{http_host}{http_uri_path}"
                elif http_host: full_url = f"http://{http_host}"

                if http_host:
                    potential_downloads.append({"type": "Zeek_HTTP", "download_actor_ip": host_ip_as_source, "url_domain": http_host, "full_url_derived": full_url, "external_dest_ip": dest_ip, "protocol": "http", "port": get_field_value(s,["destination","port"]) or 80, "timestamp": get_field_value(s,["@timestamp"]), "_raw_log_http": s})
                    logger.info(f"EXTERNAL_DOWNLOAD_HUNT (NETWORK): Potential HTTP source by {host_ip_as_source}: URL: {full_url}, Dest IP: {dest_ip}")

        conn_query_body_zeek = {"bool": {"must": [{"term": {"source.ip": host_ip_as_source}}, {"range":{"destination.bytes": {"gt": 100}}}], "filter": time_filter, "must_not":[{"term":{"destination.ip":"127.0.0.1"}}] }}
        zeek_conn_hits = query_elasticsearch(ZEEK_CONN_INDEX_PATTERN, conn_query_body_zeek, size=20, sort_order=[{"destination.bytes":"desc"}])
        if zeek_conn_hits: raw_logs_collection["conn_zeek_raw"].extend([h.get("_source") for h in zeek_conn_hits])
        for hit in zeek_conn_hits:
            s = hit.get("_source",{})
            dest_ip = get_field_value(s,["destination","ip"])
            if dest_ip and not is_internal_ip(dest_ip):
                already_found_by_sni_or_http = False
                for pd in potential_downloads:
                    ts_conn_str = get_field_value(s,["@timestamp"],"").replace("Z","").split('.')[0].split('+')[0]
                    ts_pd_str = pd.get("timestamp","").replace("Z","").split('.')[0].split('+')[0]
                    if pd.get("external_dest_ip") == dest_ip and \
                       pd.get("download_actor_ip") == host_ip_as_source and \
                       ts_conn_str and ts_pd_str:
                        try:
                            time_diff = abs((datetime.fromisoformat(ts_pd_str) - datetime.fromisoformat(ts_conn_str)).total_seconds())
                            if time_diff < 60 :
                                pd["_raw_log_conn"] = s
                                pd["conn_bytes_resp"] = get_field_value(s,["destination","bytes"])
                                already_found_by_sni_or_http = True; break
                        except ValueError: pass

                if not already_found_by_sni_or_http:
                    potential_downloads.append({
                        "type": "Zeek_Conn_LargeDownload",
                        "download_actor_ip": host_ip_as_source,
                        "url_domain": None, "full_url_derived": None,
                        "external_dest_ip": dest_ip,
                        "protocol": get_field_value(s,["network","transport"]),
                        "port": get_field_value(s,["destination","port"]),
                        "timestamp": get_field_value(s,["@timestamp"]),
                        "_raw_log_conn": s,
                        "conn_bytes_resp":get_field_value(s,["destination","bytes"])
                    })
                    logger.info(f"EXTERNAL_DOWNLOAD_HUNT (NETWORK): Potential large download by {host_ip_as_source} from {dest_ip}:{get_field_value(s,['destination','port'])} ({get_field_value(s,['destination','bytes'])} bytes)")

    for dl_event in potential_downloads:
        ext_ip = dl_event.get("external_dest_ip")
        if ext_ip and ext_ip in dns_map:
            dl_event["dns_resolution_evidence"] = dns_map[ext_ip]
            if not dl_event.get("url_domain") and dns_map[ext_ip].get("query"):
                dl_event["url_domain"] = dns_map[ext_ip]["query"]
                if not dl_event.get("full_url_derived") or dl_event.get("full_url_derived") == "Unknown HTTP URL":
                    protocol_guess = dl_event.get('protocol','http')
                    if dl_event.get('port') == 443 and protocol_guess == 'tcp': protocol_guess = 'https'
                    dl_event["full_url_derived"] = f"{protocol_guess}://{dl_event['url_domain']}"

    potential_downloads.sort(key=lambda x: (
        x.get("timestamp", "9999-12-31T23:59:59Z"),
        0 if x.get("type") == "Suricata_TLS_SNI" else 1 if x.get("type") == "Zeek_HTTP" else 2,
        -(int(x.get("conn_bytes_resp", 0) or 0))
    ))
    return {"potential_sources": potential_downloads, "raw_evidence_collection": raw_logs_collection, "dns_map_generated": dns_map}


# --- HÀM TẠO BÁO CÁO ---
def generate_threat_hunt_report(initial_alert_data, determined_scenario,
                                auditd_evidence_collection,
                                network_evidence_on_victim,
                                internal_transfer_details,
                                external_download_details
                                ):
    vt_full_result = initial_alert_data.get("vt_result", {})
    vt_summary = {}
    if vt_full_result:
        for k in ["hash", "positives", "total_engines", "scan_date", "permalink", "status"]:
            if vt_full_result.get(k) is not None:
                vt_summary[k] = vt_full_result.get(k)

    report = {
        "threat_hunt_id": f"ATH-COMP-{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}",
        "hunt_scenario_determined": determined_scenario,
        "hunt_trigger_time_utc": datetime.utcnow().replace(tzinfo=timezone.utc).isoformat(),
        "initial_fim_event_on_victim": {
            "original_fim_event_id": initial_alert_data.get("original_fim_event_id"),
            "detection_timestamp_utc": initial_alert_data.get("detection_timestamp_str"),
            "victim_primary_ip": initial_alert_data.get("victim_primary_ip"),
            "victim_all_ips": initial_alert_data.get("victim_all_ips", []),
            "victim_host_name": initial_alert_data.get("victim_host_name", "N/A"),
            "malware_file_path_on_victim": initial_alert_data.get("malicious_file_path"),
            "malware_hash_sha256_on_victim": initial_alert_data.get("malicious_file_hash_sha256"),
            "virustotal_summary": vt_summary
        },
        "compromise_chain_summary": [],
        "derived_original_source_url": None,
        "derived_original_source_ip": None,
        "evidence_details": {
            "internal_transfer_to_victim": {},
            "external_download_by_intermediate_source": {
                "auditd_wget_evidence_on_intermediate": None,
                "network_derived_sources_summary": []
            },
            "auditd_on_victim": {},
            "network_context_around_victim": {"zeek_summary":{}, "suricata_summary":{}},
            "network_context_around_intermediate_source_download": {"zeek_summary":{}, "suricata_summary":{}}
        },
        "recommendations": [f"Isolate victim host {initial_alert_data.get('victim_host_name', initial_alert_data.get('victim_primary_ip'))} for investigation."]
    }

    if internal_transfer_details:
        report["evidence_details"]["internal_transfer_to_victim"] = {
            "intermediate_source_hostname": internal_transfer_details.get("hostname", "Unknown Hostname"),
            "intermediate_source_all_known_ips": internal_transfer_details.get("all_ips", []),
            "intermediate_source_ip_used_for_transfer": internal_transfer_details.get("transfer_ip"),
            "transfer_method_evidence": internal_transfer_details.get("method", "Unknown Method"),
            "transfer_timestamp_utc": internal_transfer_details.get("timestamp"),
            "raw_logs_supporting_internal_transfer": internal_transfer_details.get("_raw_logs", {})
        }
        actor_A_display = internal_transfer_details.get("hostname") or internal_transfer_details.get("transfer_ip","Unknown Intermediate Host")

        transfer_method_desc = internal_transfer_details.get("method", "transferred file")
        transfer_ip_for_desc = internal_transfer_details.get('transfer_ip', 'unknown IP')
        if "SCP" in transfer_method_desc:
            transfer_action_verb = f"transferred file via SCP (using IP {transfer_ip_for_desc})"
        elif "Network Transfer" in transfer_method_desc:
            transfer_action_verb = f"transferred file via network (hash match, using IP {transfer_ip_for_desc})"
        else:
            transfer_action_verb = f"{transfer_method_desc} (using IP {transfer_ip_for_desc})"

        report["compromise_chain_summary"].append(
            f"Intermediate host {actor_A_display} {transfer_action_verb} "
            f"to victim {report['initial_fim_event_on_victim']['victim_host_name']} ({report['initial_fim_event_on_victim']['victim_primary_ip']}). "
            f"File hash: {initial_alert_data.get('malicious_file_hash_sha256')}."
        )
        report["recommendations"].append(f"Investigate intermediate source host {actor_A_display} (Known IPs: {', '.join(internal_transfer_details.get('all_ips',[]))}).")

    primary_external_source_details = None
    all_potential_sources_from_network_summary = []

    if external_download_details:
        auditd_wget_intermediate_ev = external_download_details.get("auditd_wget_on_intermediate")

        if auditd_wget_intermediate_ev and auditd_wget_intermediate_ev.get("source_url"):
            report["evidence_details"]["external_download_by_intermediate_source"]["auditd_wget_evidence_on_intermediate"] = summarize_auditd_exec(auditd_wget_intermediate_ev.get("_raw_log"))

            primary_external_source_details = {
                "type_from_script": "Auditd_Wget_Intermediate",
                "supporting_evidence_type": "Auditd Wget on Intermediate Host",
                "download_actor_hostname": internal_transfer_details.get("hostname") if internal_transfer_details else auditd_wget_intermediate_ev.get("host_name_reported","Unknown Host"),
                "download_actor_ip": auditd_wget_intermediate_ev.get("host_ip_reported") or (internal_transfer_details.get("all_ips",[None])[0] if internal_transfer_details else None),
                "derived_external_url": auditd_wget_intermediate_ev.get("source_url"),
                "derived_external_ip": "Needs DNS lookup",
                "download_protocol": auditd_wget_intermediate_ev.get("source_url","").split(":")[0],
                "download_timestamp_utc": auditd_wget_intermediate_ev.get("timestamp"),
                "_raw_log_main_external_evidence": auditd_wget_intermediate_ev.get("_raw_log")
            }
            logger.info(f"Primary external source candidate from Auditd (wget on intermediate): {primary_external_source_details.get('derived_external_url')}")

        network_potential_sources_list = external_download_details.get("potential_sources", [])
        if network_potential_sources_list:
            network_potential_sources_list.sort(
                key=lambda x: (
                    x.get("timestamp", "9999-12-31T23:59:59Z"),
                    0 if x.get("type") == "Suricata_TLS_SNI" else 1 if x.get("type") == "Zeek_HTTP" else 2,
                    -(int(x.get("conn_bytes_resp", 0) or 0))
                )
            )
            all_potential_sources_from_network_summary = [
                {k:v for k,v in item.items() if not k.startswith("_raw_log")} for item in network_potential_sources_list[:5]
            ]
            if not primary_external_source_details and network_potential_sources_list:
                best_network_source = network_potential_sources_list[0]
                primary_external_source_details = {
                    "type_from_script": best_network_source.get("type"),
                    "supporting_evidence_type": f"Network Log ({best_network_source.get('type')})",
                    "download_actor_hostname": internal_transfer_details.get("hostname") if internal_transfer_details else "Unknown Host",
                    "download_actor_ip": best_network_source.get("download_actor_ip"),
                    "derived_external_url": best_network_source.get("full_url_derived"),
                    "derived_external_ip": best_network_source.get("external_dest_ip"),
                    "download_protocol": best_network_source.get("protocol"),
                    "download_timestamp_utc": best_network_source.get("timestamp"),
                    "dns_resolution_evidence": best_network_source.get("dns_resolution_evidence", {}),
                    "_raw_log_main_external_evidence": best_network_source.get("_raw_log_tls") or best_network_source.get("_raw_log_http") or best_network_source.get("_raw_log_conn")
                }
                logger.info(f"Primary external source candidate from Network Logs: {primary_external_source_details.get('derived_external_url')} (Type: {primary_external_source_details.get('type_from_script')})")

        if primary_external_source_details and primary_external_source_details.get("type_from_script") == "Auditd_Wget_Intermediate":
            _, wget_domain, _, _ = parse_url_details(primary_external_source_details.get("derived_external_url"))
            if wget_domain and external_download_details.get("dns_map_generated"):
                dns_map_lookup = external_download_details.get("dns_map_generated", {})
                found_ipv4 = None; raw_dns_log_for_ipv4 = None
                found_ipv6 = None; raw_dns_log_for_ipv6 = None

                for ip_addr, dns_data in dns_map_lookup.items():
                    if dns_data.get("query") == wget_domain:
                        try:
                            ip_obj = ip_address(ip_addr)
                            if ip_obj.version == 4:
                                if not found_ipv4: found_ipv4 = ip_addr; raw_dns_log_for_ipv4 = dns_data
                            elif ip_obj.version == 6:
                                if not found_ipv6: found_ipv6 = ip_addr; raw_dns_log_for_ipv6 = dns_data
                        except ValueError: pass

                chosen_ip = found_ipv4 if found_ipv4 else found_ipv6
                chosen_dns_log_data = raw_dns_log_for_ipv4 if found_ipv4 else raw_dns_log_for_ipv6

                if chosen_ip:
                    primary_external_source_details["derived_external_ip"] = chosen_ip
                    if chosen_dns_log_data:
                        primary_external_source_details["dns_resolution_evidence"] = chosen_dns_log_data
                    logger.info(f"Enriched Auditd Wget: domain {wget_domain} resolved to chosen IP {chosen_ip} (IPv4 preferred).")
                else:
                    primary_external_source_details["derived_external_ip"] = None
                    logger.warning(f"Could not find DNS resolution in provided dns_map for domain {wget_domain} from Auditd Wget.")

        if primary_external_source_details:
            target_obj = report["evidence_details"]["external_download_by_intermediate_source"]
            target_obj["download_actor_hostname"] = primary_external_source_details.get("download_actor_hostname")
            target_obj["download_actor_ip"] = primary_external_source_details.get("download_actor_ip")
            target_obj["derived_external_url"] = primary_external_source_details.get("derived_external_url")
            target_obj["derived_external_ip"] = primary_external_source_details.get("derived_external_ip")
            target_obj["download_protocol"] = primary_external_source_details.get("download_protocol")
            target_obj["download_timestamp_utc"] = primary_external_source_details.get("download_timestamp_utc")
            target_obj["dns_resolution_for_external_url"] = primary_external_source_details.get("dns_resolution_evidence", {})
            target_obj["supporting_evidence_type"] = primary_external_source_details.get("supporting_evidence_type")
            target_obj["_raw_log_main_external_evidence"] = primary_external_source_details.get("_raw_log_main_external_evidence")

            report["derived_original_source_url"] = primary_external_source_details.get("derived_external_url")
            report["derived_original_source_ip"] = primary_external_source_details.get("derived_external_ip")

            actor_A_display_dl = primary_external_source_details.get("download_actor_hostname", "Intermediate Host") or \
                                 primary_external_source_details.get("download_actor_ip", "IP N/A")

            if report["derived_original_source_url"]:
                download_action_verb = "downloaded"
                evidence_type_desc_for_summary = primary_external_source_details.get("supporting_evidence_type", "Unknown method")
                if "Auditd Wget" in evidence_type_desc_for_summary:
                    download_action_verb = "executed wget to download"
                elif "TLS" in evidence_type_desc_for_summary or "HTTP" in evidence_type_desc_for_summary or "Network Log" in evidence_type_desc_for_summary :
                    download_action_verb = "downloaded via web (HTTP/S or network log)"

                report["compromise_chain_summary"].insert(0,
                    f"Intermediate host {actor_A_display_dl} {download_action_verb} the original malware from URL: {report['derived_original_source_url']} "
                    f"(resolving to IP: {report['derived_original_source_ip'] if report['derived_original_source_ip'] else 'N/A'}). "
                    f"Evidence: {evidence_type_desc_for_summary}."
                )
            if report["derived_original_source_url"] and report["derived_original_source_url"] not in ["Unknown HTTP URL", None]:
                report["recommendations"].append(f"Block and investigate original source URL: {report['derived_original_source_url']} and its hosting IP: {report.get('derived_original_source_ip', 'N/A')}.")

        report["evidence_details"]["external_download_by_intermediate_source"]["network_derived_sources_summary"] = all_potential_sources_from_network_summary


    elif determined_scenario == "WGET_DOWNLOAD_DIRECTLY_ON_VICTIM":
        wget_ev_victim = auditd_evidence_collection.get("wget_on_victim",{})
        if wget_ev_victim.get("source_url"):
            report["derived_original_source_url"] = wget_ev_victim["source_url"]
            _, wget_domain_victim, _, _ = parse_url_details(wget_ev_victim["source_url"])
            derived_ip_for_victim_wget = None
            if wget_domain_victim and external_download_details and external_download_details.get("dns_map_generated"):
                dns_map_victim = external_download_details.get("dns_map_generated", {})
                found_ipv4_victim = None; found_ipv6_victim = None
                for ip, dns_data in dns_map_victim.items():
                    if dns_data.get("query") == wget_domain_victim:
                        try:
                            ip_obj_victim = ip_address(ip)
                            if ip_obj_victim.version == 4:
                                if not found_ipv4_victim: found_ipv4_victim = ip
                            elif ip_obj_victim.version == 6:
                                if not found_ipv6_victim: found_ipv6_victim = ip
                        except ValueError: pass
                chosen_ip_victim = found_ipv4_victim if found_ipv4_victim else found_ipv6_victim
                if chosen_ip_victim: derived_ip_for_victim_wget = chosen_ip_victim

            report["derived_original_source_ip"] = derived_ip_for_victim_wget

            report["compromise_chain_summary"].insert(0,
                f"Victim host {report['initial_fim_event_on_victim']['victim_host_name']} ({report['initial_fim_event_on_victim']['victim_primary_ip']}) "
                f"executed wget to download the malware directly from URL: {wget_ev_victim['source_url']} (IP: {report['derived_original_source_ip'] if report['derived_original_source_ip'] else 'N/A'})."
            )
            report["recommendations"].append(f"Block and investigate original source URL: {wget_ev_victim['source_url']}.")

    if auditd_evidence_collection.get("wget_on_victim") and determined_scenario == "WGET_DOWNLOAD_DIRECTLY_ON_VICTIM":
        report["evidence_details"]["auditd_on_victim"]["wget_execution_on_victim"] = summarize_auditd_exec(auditd_evidence_collection["wget_on_victim"].get("_raw_log"))
    elif auditd_evidence_collection.get("scp_to_victim"):
        report["evidence_details"]["auditd_on_victim"]["scp_server_activity_on_victim"] = summarize_auditd_exec(auditd_evidence_collection["scp_to_victim"].get("_raw_scp_t_log"))
        if auditd_evidence_collection["scp_to_victim"].get("_raw_auth_logs"):
            report["evidence_details"]["auditd_on_victim"]["scp_server_auth_logs"] = summarize_auditd_auth_list(auditd_evidence_collection["scp_to_victim"]["_raw_auth_logs"])
    elif auditd_evidence_collection.get("direct_external_scp"):
        report["evidence_details"]["auditd_on_victim"]["direct_external_scp_activity"] = summarize_auditd_exec(auditd_evidence_collection["direct_external_scp"].get("_raw_scp_t_log"))
        report["derived_original_source_ip"] = auditd_evidence_collection["direct_external_scp"].get("attacker_ip_derived")
        report["derived_original_source_url"] = f"scp_from_{report['derived_original_source_ip']}"


    zeek_victim_summary = {}; suri_victim_summary = {}
    if network_evidence_on_victim:
        zeek_data_victim = network_evidence_on_victim.get("zeek_raw",{})
        suri_data_victim = network_evidence_on_victim.get("suricata_raw",[])
        if zeek_data_victim.get("related_connections_raw"): zeek_victim_summary["related_connections"] = [summarize_zeek_conn(log) for log in zeek_data_victim["related_connections_raw"][:5]]
        if zeek_data_victim.get("related_http_logs_raw"): zeek_victim_summary["related_http_logs"] = [summarize_zeek_http(log) for log in zeek_data_victim["related_http_logs_raw"][:5]]
        if suri_data_victim: suri_victim_summary["all_related_events_summary"] = [summarize_suricata_event(log) for log in suri_data_victim[:10]]
    report["evidence_details"]["network_context_around_victim"]["zeek_summary"] = zeek_victim_summary
    report["evidence_details"]["network_context_around_victim"]["suricata_summary"] = suri_victim_summary

    if external_download_details and external_download_details.get("raw_evidence_collection"):
        raw_ext_dl_net_evidence = external_download_details["raw_evidence_collection"]
        zeek_s = {}
        if raw_ext_dl_net_evidence.get("dns_zeek_raw"): zeek_s["dns_logs"] = [summarize_zeek_dns(log) for log in raw_ext_dl_net_evidence["dns_zeek_raw"][:3]]
        if raw_ext_dl_net_evidence.get("http_zeek_raw"): zeek_s["http_logs"] = [summarize_zeek_http(log) for log in raw_ext_dl_net_evidence["http_zeek_raw"][:3]]
        if raw_ext_dl_net_evidence.get("conn_zeek_raw"): zeek_s["connection_logs"] = [summarize_zeek_conn(log) for log in raw_ext_dl_net_evidence["conn_zeek_raw"][:3]]
        suri_s = {}
        if raw_ext_dl_net_evidence.get("dns_suricata_raw"): suri_s["dns_logs"] = [summarize_suricata_event(log) for log in raw_ext_dl_net_evidence["dns_suricata_raw"][:3]]
        if raw_ext_dl_net_evidence.get("tls_suricata_raw"): suri_s["tls_logs"] = [summarize_suricata_event(log) for log in raw_ext_dl_net_evidence["tls_suricata_raw"][:3]]
        if zeek_s: report["evidence_details"]["network_context_around_intermediate_source_download"]["zeek_summary"] = zeek_s
        if suri_s: report["evidence_details"]["network_context_around_intermediate_source_download"]["suricata_summary"] = suri_s

    if not report["compromise_chain_summary"]:
        report["compromise_chain_summary"].append(
            f"Malware (SHA256: {initial_alert_data.get('malicious_file_hash_sha256')}) detected on victim "
            f"{report['initial_fim_event_on_victim']['victim_host_name']} ({report['initial_fim_event_on_victim']['victim_primary_ip']}). "
            "The exact delivery path and original internet source could not be fully determined by this automated hunt."
        )
    report["summary_conclusion"] = " -> ".join(report["compromise_chain_summary"])

    if report.get("derived_original_source_url") is None and \
       not any("Block and investigate original source URL" in rec for rec in report["recommendations"]) and \
       not any("wget" in s.lower() for s in report["compromise_chain_summary"]):
        report["recommendations"].append("Perform further manual investigation for the original malware source if automated methods were inconclusive.")

    report["evidence_details"] = {
        k:v for k,v in report["evidence_details"].items()
        if v and (
            isinstance(v, list) and v or
            (isinstance(v,dict) and (
                v.get("zeek_summary") or v.get("suricata_summary") or
                v.get("wget_execution_on_victim") or v.get("scp_server_activity_on_victim") or
                v.get("intermediate_source_hostname") or
                v.get("download_actor_hostname") or
                v.get("auditd_wget_evidence_on_intermediate") or
                v.get("network_derived_sources_summary") or
                v.get("transfer_method_evidence") or v.get("direct_external_scp_activity")
            ))
        )
    }

    final_report_cleaned = {k:v for k,v in report.items() if v is not None}

    logger.info(f"--- THREAT HUNT REPORT (ID: {report['threat_hunt_id']}) ---\n{json.dumps(final_report_cleaned, indent=2, ensure_ascii=False)}\n--- END OF REPORT ---")
    return final_report_cleaned


# === HÀM CHÍNH ĐIỀU PHỐI Threat Hunt ===
def perform_threat_hunt(initial_alert_data):
    logger.info(f"🚀 Comprehensive Threat Hunt V3 (Final Refinements) initiated for FIM event ID: {initial_alert_data.get('original_fim_event_id')} 🚀")

    victim_b_primary_ip = initial_alert_data.get("victim_primary_ip")
    victim_b_all_ips = initial_alert_data.get("victim_all_ips", [])
    if isinstance(victim_b_all_ips, str) and victim_b_all_ips: victim_b_all_ips = [victim_b_all_ips]
    elif not isinstance(victim_b_all_ips, list) or not victim_b_all_ips:
        victim_b_all_ips = [victim_b_primary_ip] if victim_b_primary_ip and victim_b_primary_ip != "Unknown IP" else []

    victim_b_hostname = initial_alert_data.get("victim_host_name")
    malware_file_path_on_victim = initial_alert_data.get("malicious_file_path")
    malware_hash_on_victim = initial_alert_data.get("malicious_file_hash_sha256")
    fim_detection_ts_str = initial_alert_data.get("detection_timestamp_str")

    if not all([victim_b_primary_ip, victim_b_primary_ip != "Unknown IP", malware_file_path_on_victim, malware_hash_on_victim, fim_detection_ts_str]):
        error_msg = f"Critical information (victim primary IP '{victim_b_primary_ip}', file path '{malware_file_path_on_victim}', hash '{malware_hash_on_victim}', or FIM timestamp '{fim_detection_ts_str}') missing."
        logger.error(f"{error_msg} Aborting hunt.")
        return {"error": error_msg, "threat_hunt_id": f"ATH-ERR-{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}", "@timestamp": datetime.utcnow().isoformat()}

    try:
        fim_ts_obj = datetime.fromisoformat(fim_detection_ts_str.replace("Z", "")).replace(tzinfo=timezone.utc)
    except ValueError as e:
        logger.error(f"Invalid FIM timestamp format '{fim_detection_ts_str}': {e}. Aborting.");
        return {"error": f"Invalid FIM timestamp: {e}", "threat_hunt_id": f"ATH-ERR-{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}", "@timestamp": datetime.utcnow().isoformat()}

    auditd_evidence_collection = {}
    network_evidence_victim_context = {}
    internal_transfer_details = {}
    external_download_activity_results = {
        "potential_sources": [],
        "raw_evidence_collection": {},
        "dns_map_generated": {},
        "auditd_wget_on_intermediate": None
    }
    determined_scenario = "INITIAL_DETECTION_ON_VICTIM"
    effective_event_time_for_internal_hunt = fim_ts_obj

    logger.info(f"PHASE 1: Investigating internal transfer to victim {victim_b_hostname} ({victim_b_primary_ip}) for file hash {malware_hash_on_victim}")

    wget_on_victim_evidence = find_wget_execution_in_auditd(victim_b_primary_ip, malware_file_path_on_victim, fim_ts_obj)
    if wget_on_victim_evidence and wget_on_victim_evidence.get("source_url"):
        auditd_evidence_collection["wget_on_victim"] = wget_on_victim_evidence
        determined_scenario = "WGET_DOWNLOAD_DIRECTLY_ON_VICTIM"
        logger.info(f"PHASE 1: Victim {victim_b_hostname} may have downloaded the file directly via wget from {wget_on_victim_evidence['source_url']}")

        external_download_activity_results = find_external_download_activity(
            victim_b_hostname, victim_b_all_ips,
            fim_ts_obj,
            EXTERNAL_DOWNLOAD_WINDOW_SECONDS_BEFORE,
            EXTERNAL_DOWNLOAD_WINDOW_SECONDS_AFTER
        )
        zeek_ctx, suri_ctx = find_network_context_generic(victim_b_primary_ip, fim_ts_obj, uri=wget_on_victim_evidence.get("source_url"))
        network_evidence_victim_context = {"zeek_raw": zeek_ctx, "suricata_raw": suri_ctx}
        return generate_threat_hunt_report(initial_alert_data, determined_scenario,
                                           auditd_evidence_collection, network_evidence_victim_context,
                                           None, external_download_activity_results)

    scp_to_victim_evidence = find_scp_server_activity_on_victim(victim_b_primary_ip, malware_file_path_on_victim, fim_ts_obj)
    if scp_to_victim_evidence:
        intermediate_ip_candidate = scp_to_victim_evidence.get("attacker_ip_derived")

        if intermediate_ip_candidate and is_internal_ip(intermediate_ip_candidate):
            auditd_evidence_collection["scp_to_victim"] = scp_to_victim_evidence
            source_hostname, source_all_ips = get_host_info_from_ip(intermediate_ip_candidate, fim_ts_obj)
            logger.info(f"DEBUG: Intermediate host (from SCP) info for IP {intermediate_ip_candidate}: Hostname='{source_hostname}', All IPs Found='{source_all_ips}'")
            internal_transfer_details = {
                "hostname": source_hostname,
                "all_ips": source_all_ips,
                "transfer_ip": intermediate_ip_candidate,
                "method": "SCP (Victim as Server)",
                "timestamp": get_field_value(scp_to_victim_evidence, ["_raw_scp_t_log","@timestamp"]) or fim_detection_ts_str,
                "_raw_logs": {"auditd_scp_related": scp_to_victim_evidence}
            }
            try:
                effective_event_time_for_internal_hunt = datetime.fromisoformat(internal_transfer_details["timestamp"].replace("Z","").split('.')[0].split('+')[0]).replace(tzinfo=timezone.utc)
            except:
                logger.warning(f"Could not parse internal transfer timestamp '{internal_transfer_details['timestamp']}', using FIM detection time as fallback for next phase window.")
                effective_event_time_for_internal_hunt = fim_ts_obj
            determined_scenario = "SCP_TRANSFER_TO_VICTIM"
            logger.info(f"PHASE 1: Malware likely transferred via SCP from {intermediate_ip_candidate} (Host: {internal_transfer_details.get('hostname','N/A')}) to victim {victim_b_hostname}.")

        elif not intermediate_ip_candidate and scp_to_victim_evidence.get("type") == "scp_server_file_received_no_auth_correlation":
            logger.warning(f"PHASE 1: SCP to victim detected, but source IP could not be correlated to an internal host via Auditd auth logs. Origin of SCP is currently unknown or potentially external.")
            auditd_evidence_collection["scp_to_victim_no_internal_auth"] = scp_to_victim_evidence

    if not (internal_transfer_details and "SCP" in internal_transfer_details.get("method","")):
        net_hash_raw_ev, net_info_from_hash = find_network_transfer_by_hash(malware_hash_on_victim, victim_b_primary_ip, fim_ts_obj, transfer_direction="to_target")
        if net_info_from_hash and net_info_from_hash.get("source_ip"):
            intermediate_ip_candidate_net = net_info_from_hash["source_ip"]
            if is_internal_ip(intermediate_ip_candidate_net):
                source_hostname_net, source_all_ips_net = get_host_info_from_ip(intermediate_ip_candidate_net, fim_ts_obj)
                logger.info(f"DEBUG: Intermediate host (from NetHash) info for IP {intermediate_ip_candidate_net}: Hostname='{source_hostname_net}', All IPs Found='{source_all_ips_net}'")

                if not (internal_transfer_details and "SCP" in internal_transfer_details.get("method","")):
                    internal_transfer_details = {
                        "hostname": source_hostname_net, "all_ips": source_all_ips_net,
                        "transfer_ip": intermediate_ip_candidate_net,
                        "method": f"Network Transfer ({net_info_from_hash.get('protocol','N/A')}, by hash)",
                        "timestamp": get_field_value(net_info_from_hash,["_raw_file_log_for_hash","@timestamp"]) or get_field_value(net_info_from_hash,["_raw_conn_log_for_hash","@timestamp"]) or fim_detection_ts_str,
                        "_raw_logs": {"network_hash_related": net_info_from_hash, "raw_file_events_for_hash": net_hash_raw_ev}
                    }
                    try:
                        effective_event_time_for_internal_hunt = datetime.fromisoformat(internal_transfer_details["timestamp"].replace("Z","").split('.')[0].split('+')[0]).replace(tzinfo=timezone.utc)
                    except:
                        logger.warning(f"Could not parse internal transfer timestamp '{internal_transfer_details['timestamp']}', using FIM detection time as fallback.")
                        effective_event_time_for_internal_hunt = fim_ts_obj
                    determined_scenario = "NETWORK_FILEHASH_TRANSFER_TO_VICTIM"
                    logger.info(f"PHASE 1: Malware likely transferred via network (hash match) from {intermediate_ip_candidate_net} (Host: {internal_transfer_details.get('hostname','N/A')}) to victim {victim_b_hostname}.")
            elif not is_internal_ip(intermediate_ip_candidate_net):
                logger.warning(f"PHASE 1: Network transfer by hash to victim {victim_b_hostname} from presumed external IP {intermediate_ip_candidate_net}.")
                determined_scenario = "DIRECT_EXTERNAL_NETWORK_HASH_TRANSFER_TO_VICTIM"
                external_download_activity_results["potential_sources"].append({
                    "type": "Direct_External_NetHash_Transfer_To_Victim", "download_actor_ip": None,
                    "url_domain": None, "full_url_derived": f"{net_info_from_hash.get('protocol','unknown')}://{intermediate_ip_candidate_net}:{net_info_from_hash.get('source_port','unknown')}",
                    "external_dest_ip": intermediate_ip_candidate_net, "protocol": net_info_from_hash.get('protocol'),
                    "port": net_info_from_hash.get('source_port'),
                    "timestamp": get_field_value(net_info_from_hash,["_raw_file_log_for_hash","@timestamp"]) or get_field_value(net_info_from_hash,["_raw_conn_log_for_hash","@timestamp"]) or fim_detection_ts_str,
                    "_raw_log_file": net_info_from_hash.get("_raw_file_log_for_hash"), "_raw_log_conn": net_info_from_hash.get("_raw_conn_log_for_hash")
                })
                external_download_activity_results["raw_evidence_collection"].update(net_hash_raw_ev)

    if internal_transfer_details and internal_transfer_details.get("all_ips") and \
       determined_scenario not in ["DIRECT_EXTERNAL_SCP_TO_VICTIM", "DIRECT_EXTERNAL_NETWORK_HASH_TRANSFER_TO_VICTIM", "WGET_DOWNLOAD_DIRECTLY_ON_VICTIM"]:

        intermediate_hostname = internal_transfer_details.get("hostname","UnknownHost")
        intermediate_all_ips = internal_transfer_details["all_ips"]
        logger.info(f"PHASE 2: Investigating external download for intermediate source: {intermediate_hostname} (All known IPs: {intermediate_all_ips}) based on internal transfer time: {effective_event_time_for_internal_hunt.isoformat()}")

        wget_on_intermediate_evidence = find_wget_on_host_for_url(
            intermediate_hostname,
            intermediate_all_ips,
            effective_event_time_for_internal_hunt,
            EXTERNAL_DOWNLOAD_WINDOW_SECONDS_BEFORE,
            EXTERNAL_DOWNLOAD_WINDOW_SECONDS_AFTER
        )
        if wget_on_intermediate_evidence and wget_on_intermediate_evidence.get("source_url"):
            logger.info(f"PHASE 2.1: Found Auditd evidence of wget on intermediate host '{intermediate_hostname}' downloading from URL: {wget_on_intermediate_evidence.get('source_url')}")
            external_download_activity_results["auditd_wget_on_intermediate"] = wget_on_intermediate_evidence

        network_download_evidence_intermediate = find_external_download_activity(
            intermediate_hostname,
            intermediate_all_ips,
            effective_event_time_for_internal_hunt,
            EXTERNAL_DOWNLOAD_WINDOW_SECONDS_BEFORE,
            EXTERNAL_DOWNLOAD_WINDOW_SECONDS_AFTER
        )
        if network_download_evidence_intermediate.get("potential_sources"):
            external_download_activity_results["potential_sources"].extend(network_download_evidence_intermediate["potential_sources"])
        if network_download_evidence_intermediate.get("raw_evidence_collection"):
            for key, val_list in network_download_evidence_intermediate["raw_evidence_collection"].items():
                if key not in external_download_activity_results["raw_evidence_collection"]: external_download_activity_results["raw_evidence_collection"][key] = []
                external_download_activity_results["raw_evidence_collection"][key].extend(val_list)
        if network_download_evidence_intermediate.get("dns_map_generated"):
            external_download_activity_results["dns_map_generated"].update(network_download_evidence_intermediate["dns_map_generated"])

        if external_download_activity_results.get("auditd_wget_on_intermediate") or external_download_activity_results.get("potential_sources"):
            determined_scenario = "INTERNET_DOWNLOAD_VIA_INTERNAL_HOP"
            logger.info(f"PHASE 2: Found potential external download evidence for intermediate host {intermediate_hostname}.")
        else:
            logger.info(f"PHASE 2: No clear external download source found for intermediate host {intermediate_hostname}.")
            if determined_scenario.endswith("TO_VICTIM"):
                determined_scenario = f"{determined_scenario}_ORIGIN_UNKNOWN"
            else:
                determined_scenario = "INTERNAL_TRANSFER_ORIGIN_UNKNOWN"

    logger.info(f"PHASE 3: Gathering generic network context around victim {victim_b_hostname} ({victim_b_primary_ip}) at FIM time {fim_ts_obj.isoformat()}")
    peer_ip_for_victim_ctx = internal_transfer_details.get("transfer_ip")
    if not peer_ip_for_victim_ctx:
        if determined_scenario == "DIRECT_EXTERNAL_SCP_TO_VICTIM" and auditd_evidence_collection.get("direct_external_scp"):
            peer_ip_for_victim_ctx = auditd_evidence_collection["direct_external_scp"].get("attacker_ip_derived")
        elif determined_scenario == "DIRECT_EXTERNAL_NETWORK_HASH_TRANSFER_TO_VICTIM":
            if external_download_activity_results.get("potential_sources"):
                for ps in external_download_activity_results["potential_sources"]:
                    if ps.get("type") == "Direct_External_NetHash_Transfer_To_Victim":
                        peer_ip_for_victim_ctx = ps.get("external_dest_ip")
                        break

    zeek_ctx_victim, suri_ctx_victim = find_network_context_generic(
        victim_b_primary_ip, fim_ts_obj, other_ip=peer_ip_for_victim_ctx
    )
    network_evidence_victim_context = { "zeek_raw": zeek_ctx_victim, "suricata_raw": suri_ctx_victim }

    # --- START OF determined_scenario REFINEMENT LOGIC ---
    final_detailed_scenario = determined_scenario

    if determined_scenario == "INTERNET_DOWNLOAD_VIA_INTERNAL_HOP":
        download_method_tag = "UNKNOWN_DL"
        transfer_method_tag = "UNKNOWN_XFER"

        if external_download_activity_results:
            auditd_wget_ev = external_download_activity_results.get("auditd_wget_on_intermediate")
            network_pot_sources = external_download_activity_results.get("potential_sources", [])

            all_evidences_for_scenario = []
            if auditd_wget_ev and auditd_wget_ev.get("source_url"):
                all_evidences_for_scenario.append({
                    "type_from_script": "Auditd_Wget_Intermediate",
                    "type": "Auditd_Wget_Intermediate",
                    "timestamp": auditd_wget_ev.get("timestamp"), "conn_bytes_resp": 0
                })
            all_evidences_for_scenario.extend(network_pot_sources)

            if all_evidences_for_scenario:
                all_evidences_for_scenario.sort(
                    key=lambda x: (
                        x.get("timestamp", "9999-12-31T23:59:59Z"),
                        0 if x.get("type_from_script") == "Auditd_Wget_Intermediate" or x.get("type") == "Auditd_Wget_Intermediate" else \
                        1 if x.get("type") == "Suricata_TLS_SNI" else \
                        2 if x.get("type") == "Zeek_HTTP" else 3,
                        -(int(x.get("conn_bytes_resp", 0) or 0))
                    )
                )
                primary_evidence = all_evidences_for_scenario[0]
                temp_primary_source_type = primary_evidence.get("type_from_script") or primary_evidence.get("type")

                if temp_primary_source_type == "Auditd_Wget_Intermediate":
                    download_method_tag = "WGET"
                elif temp_primary_source_type in ["Suricata_TLS_SNI", "Zeek_HTTP"]:
                    download_method_tag = "WEB_DL"
                elif temp_primary_source_type == "Zeek_Conn_LargeDownload":
                    download_method_tag = "NET_DL"

        if internal_transfer_details and internal_transfer_details.get("method"):
            method_str = internal_transfer_details.get("method", "").upper()
            if "SCP" in method_str:
                transfer_method_tag = "SCP"
            elif "NETWORK TRANSFER" in method_str:
                transfer_method_tag = "NET_XFER"

        if download_method_tag != "UNKNOWN_DL" and transfer_method_tag != "UNKNOWN_XFER":
            final_detailed_scenario = f"{download_method_tag}_INTERMEDIATE_THEN_{transfer_method_tag}_VICTIM"
        elif download_method_tag != "UNKNOWN_DL":
            final_detailed_scenario = f"{download_method_tag}_INTERMEDIATE_THEN_UNKNOWN_XFER_VICTIM"
        elif transfer_method_tag != "UNKNOWN_XFER":
            final_detailed_scenario = f"UNKNOWN_DL_INTERMEDIATE_THEN_{transfer_method_tag}_VICTIM"
        else:
            final_detailed_scenario = "INTERNET_DOWNLOAD_VIA_INTERNAL_HOP_METHODS_UNCLEAR"

        logger.info(f"Refined determined_scenario to: {final_detailed_scenario} from original: {determined_scenario}")
        determined_scenario = final_detailed_scenario

    elif determined_scenario.endswith("_ORIGIN_UNKNOWN"):
        transfer_method_tag = "UNKNOWN_XFER"
        base_scenario_for_origin_unknown = determined_scenario.replace("_ORIGIN_UNKNOWN", "")
        if "SCP_TRANSFER_TO_VICTIM" in base_scenario_for_origin_unknown : transfer_method_tag = "SCP"
        elif "NETWORK_FILEHASH_TRANSFER_TO_VICTIM" in base_scenario_for_origin_unknown : transfer_method_tag = "NET_XFER"
        elif internal_transfer_details and internal_transfer_details.get("method"):
            method_str = internal_transfer_details.get("method", "").upper()
            if "SCP" in method_str: transfer_method_tag = "SCP"
            elif "NETWORK TRANSFER" in method_str: transfer_method_tag = "NET_XFER"

        if transfer_method_tag != "UNKNOWN_XFER":
            final_detailed_scenario = f"{transfer_method_tag}_TO_VICTIM_ORIGIN_UNKNOWN"
            logger.info(f"Refined determined_scenario to: {final_detailed_scenario} from original: {determined_scenario}")
            determined_scenario = final_detailed_scenario
    # --- END OF determined_scenario REFINEMENT LOGIC ---

    final_report = generate_threat_hunt_report(
        initial_alert_data, determined_scenario,
        auditd_evidence_collection,
        network_evidence_victim_context,
        internal_transfer_details,
        external_download_activity_results
    )
    logger.info(f"Comprehensive Threat Hunt (refined scenario & report) process completed.")
    return final_report

# === MAIN EXECUTION ===
if __name__ == "__main__":
    logger.info("Threat Hunter V3 (Final Refinements) script started directly for execution.")
    if len(sys.argv) > 1:
        json_input_str = sys.argv[1]
        logger.info(f"Received JSON input (first 300 chars): {json_input_str[:300]}...")
        try:
            initial_alert_data = json.loads(json_input_str)
            required_keys = ["victim_primary_ip", "victim_host_name", "malicious_file_path", "detection_timestamp_str", "malicious_file_hash_sha256"]
            if not all(k in initial_alert_data for k in required_keys):
                missing_keys = [k for k in required_keys if k not in initial_alert_data]
                logger.error(f"Missing one or more critical fields: {missing_keys}")
                error_report = {"error": f"Missing critical input data: {missing_keys}", "threat_hunt_id": f"ATH-INPERR-{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}", "@timestamp": datetime.utcnow().isoformat()}
                print(f"--- THREAT HUNT REPORT (ERROR) ---\n{json.dumps(error_report, indent=2, ensure_ascii=False)}\n--- END OF REPORT ---")
                sys.exit(1)

            if "victim_all_ips" not in initial_alert_data or not initial_alert_data["victim_all_ips"]:
                initial_alert_data["victim_all_ips"] = [initial_alert_data["victim_primary_ip"]] if initial_alert_data["victim_primary_ip"] and initial_alert_data["victim_primary_ip"] != "Unknown IP" else []
            elif isinstance(initial_alert_data["victim_all_ips"], str):
                initial_alert_data["victim_all_ips"] = [initial_alert_data["victim_all_ips"]]

            hunt_result_dict = perform_threat_hunt(initial_alert_data)
            if hunt_result_dict is None:
                logger.error("perform_threat_hunt returned None, indicating an early exit or unhandled error.")
                error_report = {"error": "Threat hunt aborted unexpectedly, returned None.",
                                "threat_hunt_id": f"ATH-ABORT-{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}",
                                "@timestamp": datetime.utcnow().isoformat(),
                                "initial_alert_data_summary": {k:initial_alert_data.get(k) for k in required_keys}
                               }
                print(f"--- THREAT HUNT REPORT (ABORTED) ---\n{json.dumps(error_report, indent=2, ensure_ascii=False)}\n--- END OF REPORT ---")
                sys.exit(1)

        except json.JSONDecodeError as e:
            logger.error(f"Failed to decode JSON input: {e}\nInput was: {json_input_str}")
            error_report = {"error": f"JSON Decode Error: {e}", "input_received": json_input_str, "threat_hunt_id": f"ATH-JSONERR-{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}", "@timestamp": datetime.utcnow().isoformat()}
            print(f"--- THREAT HUNT REPORT (ERROR) ---\n{json.dumps(error_report, indent=2, ensure_ascii=False)}\n--- END OF REPORT ---")
            sys.exit(1)
        except Exception as e_main:
            logger.error(f"Unexpected error processing CLI input: {e_main}", exc_info=True)
            error_report = {"error": f"Main processing error: {str(e_main)}", "exception_type": type(e_main).__name__, "threat_hunt_id": f"ATH-PROCERR-{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}", "@timestamp": datetime.utcnow().isoformat()}
            print(f"--- THREAT HUNT REPORT (ERROR) ---\n{json.dumps(error_report, indent=2, ensure_ascii=False)}\n--- END OF REPORT ---")
            sys.exit(1)
    else:
        logger.warning("No JSON input provided as command line argument. Script will exit.")
        error_report = {"error": "No JSON input provided.", "threat_hunt_id": f"ATH-NOINPUT-{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}", "@timestamp": datetime.utcnow().isoformat()}
        print(f"--- THREAT HUNT REPORT (ERROR) ---\n{json.dumps(error_report, indent=2, ensure_ascii=False)}\n--- END OF REPORT ---")
        sys.exit(0)
