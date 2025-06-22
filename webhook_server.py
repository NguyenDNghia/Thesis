import subprocess
import os
import sys
from fastapi import FastAPI, HTTPException, Request, BackgroundTasks
import logging
import logging.config
import json

# === CẤU HÌNH ANSIBLE ===
ANSIBLE_PRIVATE_KEY_FILE = os.getenv("ANSIBLE_PRIVATE_KEY_FILE", "/home/nghianguyen/.ssh/id_rsa")
ANSIBLE_INVENTORY_FILE = os.getenv("ANSIBLE_INVENTORY_FILE", "/etc/ansible/hosts")
ISOLATE_HOST_PLAYBOOK = "isolate_host.yml" # Playbook để cô lập host bị nhiễm
BLOCK_IP_PLAYBOOK = "block_ip.yml"         # Playbook để chặn IP (Cho SSH bruteforce)

# === FastAPI App ===
app = FastAPI(title="XDR Webhook Server")

# === Logging Setup ===
logger = logging.getLogger(__name__)


# === Hàm để chạy Ansible Playbook ===
def run_ansible_playbook_generic(playbook_file: str, extra_vars_dict: dict, task_id: str = "N/A"):
    """
    Chạy Ansible playbook chung với extra_vars.
    task_id dùng để logging, giúp theo dõi request nào đã kích hoạt playbook.
    """
    try:

        env = os.environ.copy()

        logger.info(f"[TaskID: {task_id}] Running Ansible playbook '{playbook_file}' with vars: {json.dumps(extra_vars_dict)}")

        extra_vars_json_string = json.dumps(extra_vars_dict)

        ansible_command = [
            "ansible-playbook", playbook_file,
            "--extra-vars", extra_vars_json_string,
            "-i", ANSIBLE_INVENTORY_FILE
        ]
        logger.debug(f"[TaskID: {task_id}] Ansible command: {' '.join(ansible_command)}")


        playbook_result = subprocess.run(
            ansible_command,
            capture_output=True, text=True, env=env, timeout=180 # Tăng timeout lên 3 phút
        )

        if playbook_result.stdout:
            logger.info(f"[TaskID: {task_id}] Ansible stdout for {playbook_file} with {extra_vars_dict}:\n{playbook_result.stdout}")
        if playbook_result.stderr:
            if playbook_result.returncode != 0:
                logger.error(f"[TaskID: {task_id}] Ansible stderr for {playbook_file} with {extra_vars_dict}:\n{playbook_result.stderr}")
            else:
                logger.debug(f"[TaskID: {task_id}] Ansible stderr (non-error) for {playbook_file} with {extra_vars_dict}:\n{playbook_result.stderr}")


        if playbook_result.returncode != 0:
            logger.error(f"[TaskID: {task_id}] Error running {playbook_file}. Ansible return code: {playbook_result.returncode}")
            return False
        else:
            logger.info(f"[TaskID: {task_id}] Playbook {playbook_file} ran successfully (or without critical errors).")
            return True

    except subprocess.TimeoutExpired:
        logger.error(f"[TaskID: {task_id}] Timeout running Ansible playbook {playbook_file}.")
        return False
    except Exception as e:
        logger.error(f"[TaskID: {task_id}] Exception while running Ansible playbook {playbook_file}: {e}", exc_info=True)
        return False

# === Webhook Endpoint ===
@app.post("/alert")
async def alert_handler(request: Request, background_tasks: BackgroundTasks):
    request_id = os.urandom(4).hex()
    try:
        data = await request.json()
        logger.info(f"[RequestID: {request_id}] Webhook received data: {json.dumps(data, indent=2)}")

        rule_name = data.get("rule_name")

        if rule_name == "FIM_Malware_Detected_via_VirusTotal":
            host_to_isolate = data.get("host_ip") 
            file_path_detected = data.get("file_path")
            vt_positives = data.get("virustotal_positives")

            if host_to_isolate and host_to_isolate != "Unknown IP":
                logger.info(f"[RequestID: {request_id}] Malware confirmed for host: {host_to_isolate}, file: {file_path_detected}. VT: {vt_positives}. Initiating isolation.")
                background_tasks.add_task(run_ansible_playbook_generic,
                                          ISOLATE_HOST_PLAYBOOK,
                                          {"host_to_isolate": host_to_isolate},
                                          task_id=f"{request_id}-isolate")
                return {"message": f"Malware alert received for host {host_to_isolate}. Isolation initiated.", "request_id": request_id}
            else:
                logger.warning(f"[RequestID: {request_id}] FIM_Malware_Detected_via_VirusTotal alert received but host_ip is missing or Unknown. Payload: {data}")
                return {"message": "Alert received for FIM/VT but host_ip missing for isolation.", "request_id": request_id}

        elif "Brute Force" in str(rule_name):
            attacker_ip_to_block = data.get("ip_address")
            target_host_bruteforced = data.get("host_ip")

            if attacker_ip_to_block and attacker_ip_to_block != "Unknown IP":
                logger.info(f"[RequestID: {request_id}] SSH Brute force type alert (Rule: {rule_name}) received for attacker IP: {attacker_ip_to_block}. Target: {target_host_bruteforced or 'N/A'}. Initiating block.")
                background_tasks.add_task(run_ansible_playbook_generic,
                                          BLOCK_IP_PLAYBOOK,
                                          {"ip_address": attacker_ip_to_block},
                                          task_id=f"{request_id}-blockip")
                return {"message": f"SSH Brute force alert processed for attacker IP {attacker_ip_to_block}.", "request_id": request_id}
            else:
                logger.warning(f"[RequestID: {request_id}] Brute force type alert (Rule: {rule_name}) received but attacker ip_address missing or Unknown. Payload: {data}")
                return {"message": "Brute force alert received but attacker ip_address missing.", "request_id": request_id}
        else:
            logger.warning(f"[RequestID: {request_id}] Received unhandled alert type or missing critical info: Rule='{rule_name}'. Payload: {data}")
            return {"message": "Alert received but not processed for automatic response based on current rules.", "request_id": request_id}

    except json.JSONDecodeError:
        logger.error(f"[RequestID: {request_id}] Webhook received invalid JSON data.", exc_info=True)
        raise HTTPException(status_code=400, detail="Invalid JSON data")
    except Exception as e:
        logger.error(f"[RequestID: {request_id}] Error processing alert in webhook: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


if __name__ == "__main__":
    LOGGING_CONFIG = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "default": {
                "()": "uvicorn.logging.DefaultFormatter",
                "fmt": "%(levelprefix)s %(asctime)s [%(name)s] [%(threadName)s] %(message)s",
                "datefmt": "%Y-%m-%d %H:%M:%S",
                "use_colors": True,
            },
            "access": {
                "()": "uvicorn.logging.AccessFormatter",
                "fmt": '%(levelprefix)s %(asctime)s [%(name)s] [%(threadName)s] %(client_addr)s - "%(request_line)s" %(status_code)s',
                "datefmt": "%Y-%m-%d %H:%M:%S",
                "use_colors": True,
            },
        },
        "handlers": {
            "default": {
                "formatter": "default",
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stdout",
            },
            "access": {
                "formatter": "access",
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stdout",
            },
        },
        "loggers": {
            "": {"handlers": ["default"], "level": "INFO"},
            "uvicorn": {"handlers": ["default"], "level": "INFO", "propagate": False},
            "uvicorn.error": {"level": "INFO", "propagate": True},
            "uvicorn.access": {"handlers": ["access"], "level": "INFO", "propagate": False},
            __name__: {"handlers": ["default"], "level": "INFO", "propagate": False},
        },
    }
    logging.config.dictConfig(LOGGING_CONFIG)

    logger.info("Starting XDR Webhook Server...")
    logger.info(f"Ansible private key (default): {ANSIBLE_PRIVATE_KEY_FILE}")
    logger.info(f"Ansible inventory (default): {ANSIBLE_INVENTORY_FILE}")
    logger.info(f"Isolate host playbook: {ISOLATE_HOST_PLAYBOOK}")
    logger.info(f"Block IP playbook: {BLOCK_IP_PLAYBOOK}")

    ssh_auth_sock_env = os.getenv("SSH_AUTH_SOCK")
    if ssh_auth_sock_env and os.path.exists(ssh_auth_sock_env):
        logger.info(f"SSH_AUTH_SOCK is set to: {ssh_auth_sock_env} and socket exists. Ansible should use ssh-agent.")
    else:
        logger.warning(f"SSH_AUTH_SOCK is NOT set or socket does not exist ('{ssh_auth_sock_env}'). "
                       "Ansible might fail if SSH keys require a passphrase and no other auth method is configured.")

    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
