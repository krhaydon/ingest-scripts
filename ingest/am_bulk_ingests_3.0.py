#!/usr/bin/env python3
import time
import requests
import base64
import os
import urllib3

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load config
config_path = "/Volumes/Library/Archive/Digital Archives/Scripts/config_files/archivematica.conf"
config = {}
with open(config_path) as f:
    for line in f:
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            config[key.strip()] = value.strip().strip('"')

AM_URL = config["AM_URL"]
AM_USER = config["AM_USER"]
AM_KEY = config["AM_KEY"]
AM_TRANSFER_SOURCE = config["AM_TRANSFER_SOURCE"]
AM_PROCESSING_CONFIG = config["AM_PROCESSING_CONFIG"]
DIR_FILE = config["DIR_FILE"]

headers = {
    "Authorization": f"ApiKey {AM_USER}:{AM_KEY}",
    "Content-Type": "application/json"
}

sftp_date = input("Transfer date directory (e.g. 2026-02-18): ").strip()

use_atom = input("Link to AtoM record? (y/n): ").strip().lower() == "y"
atom_slug = None
if use_atom:
    same_id = input("Nest all transfers under the same AtoM ID? (y/n): ").strip().lower() == "y"
    if same_id:
        atom_slug = input("AtoM ID for all transfers (e.g. aa5000): ").strip()
    else:
        atom_slug = None  # will be derived per transfer below

if not os.path.isfile(DIR_FILE):
    print(f"File not found: {DIR_FILE}")
    exit(1)

with open(DIR_FILE) as f:
    directories = [line.strip() for line in f if line.strip()]

print(f"\nLoaded {len(directories)} directories from {DIR_FILE}")

for i, name in enumerate(directories, start=1):
    path_str = f"{AM_TRANSFER_SOURCE}:{sftp_date}/{name}"
    path_b64 = base64.b64encode(path_str.encode()).decode()

    print(f"\n[{i}/{len(directories)}] {name}")
    print(f"  Path decoded:  {path_str}")
    print(f"  Path base64:   {path_b64}")

    payload = {
        "name": name,
        "type": "standard",
        "processing_config": AM_PROCESSING_CONFIG,
        "path": path_b64
    }

    if use_atom:
        access_id = atom_slug if atom_slug else name.lower().replace(".", "-")
        payload["access_system_id"] = access_id
        print(f"  AtoM ID:       {access_id}")

    try:
        response = requests.post(
            f"{AM_URL}/api/v2beta/package/",
            headers=headers,
            json=payload,
            verify=False
        )
        print(f"  Response: {response.text}")
    except Exception as e:
        print(f"  Failed to submit transfer: {e}, skipping...")
        continue

    # Pause between submissions to avoid overwhelming the queue
    time.sleep(10)

print("\nAll transfers submitted.")
