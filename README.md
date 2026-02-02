# 🐍 Cobra X v5.2 (Elite C2 Edition)

> **WARNING**: This tool is for **AUTHORIZED RED TEAM OPERATIONS ONLY**. Usage for malicious purposes is strictly prohibited. The authors assume no liability for misuse.

## 🛡️ Overview

Cobra X is an advanced, post-exploitation framework designed for stealth, anonymity, and secure command & control (C2). It features military-grade OPSEC mechanisms, including custom obfuscated communication channels, anti-forensic memory management, and rigorous environment awareness checks.

## 🚀 Key Features

### 🕷️ TeleC2 Integration (Encrypted)
- **Silent Check-In**: Automated, non-blocking beaconing logic sends Host/OS/HWID details to a secure TeleC2 channel.
- **Mission Reporting**: Exfiltrates scan findings and OOB (Out-of-Band) interactions directly to command.
- **Obfuscated Channels**: All C2 traffic is wrapped in standard HTTPS/TLS traffic (Telegram API) to blend with legitimate network noise.

### 👻 Anti-Forensics & Stealth (Hardened)
- **Ghost Wipe**: Self-destruct mechanism overwrites critical runtime artifacts and logs with random bytes before deletion (DoD 5220.22-M style) upon termination.
- **Memory Hygiene**: 
  - Sensitive credentials (Tokens/IDs) are **never** stored in plaintext.
  - Runtime decryption uses **String Splitting + Reverse + Dynamic XOR (0x77)**.
  - Decrypted secrets are held in volatile memory (`bytearray`) and immediately zeroed out (`0x00`) after use.
- **Static Analysis Resistance**: String splitting scatters configuration usage across the codebase, defeating simple `strings` or grep analysis.

### ⚔️ SystemGuard (Environment Awareness)
- **Anti-VM/Sandbox Check**: Detects virtualization artifacts (VMware, VirtualBox) via MAC OUI and driver signatures.
- **License Enforcement**: SHA-256 validated license key ensures only authorized execution.
- **Kill-Switch**: Automatic termination if proxy connections fail or unauthorized environments are detected.

## 📦 Installation

```bash
git clone https://github.com/your-repo/cobrax.git
cd cobrax
pip install -r requirements.txt
```

## ⚡ Usage

**Standard Operation:**
```bash
python -m cobrax.core https://target.com --license [YOUR_KEY]
```

**Stealth Mode (Proxy):**
```bash
python -m cobrax.core https://target.com --license [YOUR_KEY] --proxies socks5://127.0.0.1:9050
```

---

*Cobra X v5.2 - Built for the Shadows.*
