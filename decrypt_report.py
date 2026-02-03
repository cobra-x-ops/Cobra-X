
import re
import sys
import json
import os

# 1. Read log to find key
try:
    with open('session_log.txt', 'rb') as f:
        log_bytes = f.read()
    # Try decoding as utf-16 (powershell default)
    log_content = log_bytes.decode('utf-16')
except Exception as e:
    # Fallback
    try:
        log_content = log_bytes.decode('utf-8')
    except:
        log_content = log_bytes.decode('cp1252', errors='ignore')

print(f"Log length: {len(log_content)}")

# Regex for key
match = re.search(r"Session Encryption Key: ([a-fA-F0-9]+)", log_content)
if not match:
    print("[-] Key not found in log")
    # print head to debug
    print("--- HEAD ---")
    print(log_content[:500])
    sys.exit(1)

key_hex = match.group(1)
print(f"[+] Found Key: {key_hex}")
key_bytes = bytes.fromhex(key_hex)

# 2. Read encrypted json
if not os.path.exists('cobra_results.json'):
    print("[-] cobra_results.json not found")
    sys.exit(1)

with open('cobra_results.json', 'rb') as f:
    encrypted = f.read()

# 3. Decrypt
decrypted_bytes = bytearray()
for i, b in enumerate(encrypted):
    decrypted_bytes.append(b ^ key_bytes[i % len(key_bytes)])

try:
    json_str = decrypted_bytes.decode('utf-8')
    data = json.loads(json_str)
    print("\n[+] DECRYPTED JSON:")
    print(json.dumps(data, indent=2))
    
    # Generate presentation table text
    print("\n--- SUMMARY TABLE FOR SLIDE ---")
    print("| Metric | Value |")
    print("| :--- | :--- |")
    print(f"| Target | {data.get('target', 'N/A')} |")
    print(f"| Findings Count | {len(data.get('findings', []))} |")
    print(f"| OOB Callbacks | {len(data.get('post_exploitation', {}).get('oob_callbacks', []))} |")
    print(f"| Hijacked Tokens | {len(data.get('post_exploitation', {}).get('hijacked_tokens', {}))} |")
    print(f"| Shell Sessions | {len(data.get('post_exploitation', {}).get('shell_sessions', []))} |")
    print(f"| Scan Score | {data.get('scan_score', 0)} |")
    print("-------------------------------")
    
except Exception as e:
    print(f"[-] Decryption failed: {e}")
    # print(decrypted_bytes)
