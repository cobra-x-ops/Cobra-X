
import json
import os
import sys

# Read key
with open('cobra.key', 'r') as f:
    key_hex = f.read().strip()

key_bytes = bytes.fromhex(key_hex)

# Read encrypted json
with open('cobra_results.json', 'rb') as f:
    encrypted = f.read()

# Decrypt
decrypted_bytes = bytearray()
for i, b in enumerate(encrypted):
    decrypted_bytes.append(b ^ key_bytes[i % len(key_bytes)])

data = json.loads(decrypted_bytes.decode('utf-8'))

# Print raw JSON for artifact
print("```json")
print(json.dumps(data, indent=2))
print("```")

# Print Table for Slide
print("\n### Final Mission Summary Table")
print("| Metric | Value |")
print("| :--- | :--- |")
print(f"| **Target** | `{data.get('target', 'N/A')}` |")
print(f"| **Scan Score** | **{data.get('scan_score', 0)}** |")
print(f"| Findings Count | {len(data.get('findings', []))} |")
print(f"| OOB Callbacks | {len(data.get('post_exploitation', {}).get('oob_callbacks', []))} |")
print(f"| Hijacked Tokens | {len(data.get('post_exploitation', {}).get('hijacked_tokens', {}))} |")
print(f"| Shell Sessions | {len(data.get('post_exploitation', {}).get('shell_sessions', []))} |")
