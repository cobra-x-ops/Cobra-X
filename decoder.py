
import base64

# Copied from cobrax/core.py
_T1 = "Pi8fDQdOKC1BKAcGNDMlA"
_T2 = "UMoLhYtPTUcGA4QMgQkTi"
_T3 = "QyNjZNTkJHQUZHRkZDTw=="

_C1 = "QUdAR"
_C2 = "0FCRk"
_C3 = "9DTw=="

def reassemble(p1, p2, p3):
    # 1. Reassemble
    combined = p1 + p2 + p3

    # 2. Decode Base64
    try:
        raw = base64.b64decode(combined)
    except: return ""

    # 3. Dynamic Key Derivation (Runtime)
    # 0x77 derived from consistent runtime properties
    key = 0x77 

    # 4. XOR Decryption (In-Memory Bytearray)
    decrypted_bytes = bytearray(b ^ key for b in raw)

    # 5. Reverse (Anti-String Analysis)
    result = decrypted_bytes.decode()[::-1]

    return result

print(f"Token: {reassemble(_T1, _T2, _T3)}")
print(f"Chat ID: {reassemble(_C1, _C2, _C3)}")
