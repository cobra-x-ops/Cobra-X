#!/usr/bin/env python3
"""
Cobra X - Metadata Scrubbing Utility
Cleans all pycache, logs, and temporary artifacts to ensure forensic sterility.
"""
import os
import shutil
import glob

def scrub():
    print("[*] Initiating Forensic Scrub...")
    
    # 1. Clean __pycache__
    for root, dirs, files in os.walk("."):
        for d in dirs:
            if d == "__pycache__":
                path = os.path.join(root, d)
                print(f"    [-] Removing: {path}")
                shutil.rmtree(path)
    
    # 2. Clean .pyc files
    pyc_files = glob.glob("**/*.pyc", recursive=True)
    for f in pyc_files:
        print(f"    [-] Removing: {f}")
        os.remove(f)

    # 3. Clean Logs and Results
    artifacts = ["cobra_results.json", "cobra.log", "*.log"]
    for pattern in artifacts:
        for f in glob.glob(pattern):
            print(f"    [-] Removing Artifact: {f}")
            try:
                os.remove(f)
            except: pass

    print("[+] System Sterile. No forensic traces remain.")

if __name__ == "__main__":
    scrub()
