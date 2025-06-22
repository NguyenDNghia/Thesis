import hvac
import os
import sys

# Vị trí file token mà Vault Agent sẽ ghi ra
TOKEN_SINK_PATH = "/var/run/vault/token"

def get_token_from_sink():
    """Đọc token từ file sink của Vault Agent."""
    try:
        with open(TOKEN_SINK_PATH, 'r') as f:
            return f.read().strip()
    except FileNotFoundError:
        print(f"CRITICAL: Không tìm thấy file token của Vault Agent tại '{TOKEN_SINK_PATH}'.", file=sys.stderr)
        return None
    except Exception as e:
        print(f"CRITICAL: Lỗi khi đọc file token của Vault Agent: {e}", file=sys.stderr)
        return None

def get_secret(secret_path, key_name="value"):
    vault_addr = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
    vault_token = get_token_from_sink()

    if not vault_token:
        return None
    
    try:
        client = hvac.Client(url=vault_addr, token=vault_token)
        if not client.is_authenticated():
            print(f"CRITICAL: Xác thực với Vault bằng token từ Agent thất bại.", file=sys.stderr)
            return None
        
        response = client.secrets.kv.v2.read_secret_version(path=secret_path)
        secret_value = response.get('data', {}).get('data', {}).get(key_name)
        
        return secret_value
        
    except Exception as e:
        print(f"CRITICAL: Lỗi khi lấy bí mật từ Vault bằng token của Agent: {e}", file=sys.stderr)
        return None
