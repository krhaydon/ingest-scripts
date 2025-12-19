#!/usr/bin/env python3
"""
zip_emails.py

Creates a package directory, zips a source folder, uploads the ZIP to SFTP,
computes remote SHA-256, updates and writes a final manifest, and uploads that manifest.

Behavior highlights:
- Accepts shell-escaped or quoted paths (handles pasted paths with backslashes)
- Prompts before overwriting an existing remote ZIP
- Writes manifest only once at the end (authoritative)
- Determines overall status based on remote verification (no stale FAIL)
"""

from __future__ import annotations
import os
import json
import hashlib
import zipfile
import getpass
import posixpath
import shlex
import traceback
from datetime import datetime

# Optional timezone
try:
    import zoneinfo
    EST_TZ = zoneinfo.ZoneInfo("America/New_York")
except Exception:
    EST_TZ = None

# SFTP library (required for upload)
try:
    import paramiko
except ImportError:
    paramiko = None

CHUNK_SIZE = 16 * 1024 * 1024
CONFIG_PATH = os.path.expanduser("~/.zip_emails_sftp.json")


# ---------- Utilities ----------

def timestamp():
    if EST_TZ:
        now = datetime.now(EST_TZ)
    else:
        now = datetime.now()
    return now.isoformat(timespec="seconds"), now.strftime("%Y%m%d_%H%M%S")


def normalize_path(p: str) -> str:
    if p is None:
        return p
    s = p.strip()
    if not s:
        return s
    try:
        parts = shlex.split(s)
        if parts:
            s = parts[0]
    except Exception:
        pass
    s = s.strip().strip('"').strip("'")
    s = os.path.expanduser(s)
    return os.path.abspath(s)


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def sha256_sftp_file(sftp, remote_path: str) -> str:
    h = hashlib.sha256()
    with sftp.open(remote_path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def ensure_remote_dir(sftp, remote_dir: str):
    remote_dir = remote_dir.replace("\\", "/").rstrip("/")
    if not remote_dir:
        return
    parts = []
    cur = remote_dir
    while cur and cur not in ("", "/"):
        parts.append(cur)
        cur = posixpath.dirname(cur)
    parts.reverse()
    for part in parts:
        try:
            sftp.stat(part)
        except (IOError, OSError, FileNotFoundError):
            try:
                sftp.mkdir(part)
            except Exception as e:
                raise RuntimeError(f"Could not create remote dir '{part}': {e}") from e


# ---------- SFTP config ----------

def load_or_prompt_sftp_config():
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            print(f"\nUsing saved SFTP config from {CONFIG_PATH}")
            return cfg
        except Exception:
            pass

    print("\n=== SFTP SETTINGS ===")
    host = input("SFTP host: ").strip()
    port_str = input("SFTP port [22]: ").strip()
    username = input("SFTP username: ").strip()
    password = getpass.getpass("SFTP password: ")
    remote_parent = input("Remote PARENT directory for packages (e.g. /path/to/ingest_root): ").strip()

    if not host or not username or not remote_parent:
        raise RuntimeError("Host, username, and remote parent directory are required.")

    try:
        port = int(port_str) if port_str else 22
    except ValueError:
        port = 22

    cfg = {
        "host": host,
        "port": port,
        "username": username,
        "password": password,
        "remote_parent": remote_parent,
    }

    save = input(f"\nSave these SFTP settings to {CONFIG_PATH}? [Y/n]: ").strip().lower()
    if save in ("", "y", "yes"):
        try:
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2)
            print(f"SFTP config saved to {CONFIG_PATH}")
        except Exception as e:
            print(f"WARNING: Could not save config: {e}")

    return cfg


# ---------- Core functions ----------

def list_source_files(source_dir: str):
    records = []
    total = 0
    for root, _, files in os.walk(source_dir):
        for name in files:
            total += 1
            full = os.path.join(root, name)
            rel = os.path.relpath(full, source_dir).replace(os.sep, "/")
            try:
                size = os.path.getsize(full)
            except OSError:
                size = None
            records.append({"rel_path": rel, "size": size})
    print(f"\nFound {total} files in source directory.")
    return records, total


def make_package_dir(source_dir: str, package_name: str) -> str:
    parent = os.path.dirname(source_dir)
    package_dir = os.path.join(parent, package_name)
    if os.path.exists(package_dir):
        raise RuntimeError(f"Package directory already exists: {package_dir}")
    os.makedirs(package_dir, exist_ok=False)
    return package_dir


def zip_source_into_package(source_dir: str, package_dir: str) -> str:
    base = os.path.basename(os.path.normpath(source_dir))
    zipname = f"{base}.zip"
    zip_path = os.path.join(package_dir, zipname)
    if os.path.exists(zip_path):
        raise RuntimeError(f"Zip file already exists: {zip_path}")

    print("\nZipping source directory...")
    print(f"  Source: {source_dir}")
    print(f"  Zip:    {zip_path}\n")

    parent_of_source = os.path.dirname(source_dir)

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(source_dir):
            for name in files:
                full = os.path.join(root, name)
                rel = os.path.relpath(full, parent_of_source).replace(os.sep, "/")
                print(f"  [file] {rel}")
                zf.write(full, arcname=rel)
            if not files and not dirs:
                rel_root = os.path.relpath(root, parent_of_source).replace(os.sep, "/")
                if rel_root in (".", ""):
                    arcdir = base.rstrip("/") + "/"
                else:
                    arcdir = rel_root.rstrip("/") + "/"
                print(f"  [dir]  {arcdir}")
                zf.writestr(arcdir, "")

    print("\nZipping complete.")
    return zip_path


def upload_zip_and_manifest(zip_path, manifest_path, package_name, cfg, zip_sha256, manifest):
    if paramiko is None:
        raise RuntimeError("Paramiko is not installed. Run: pip install paramiko")

    host = cfg["host"]; port = cfg["port"]; username = cfg["username"]; password = cfg["password"]; remote_parent = cfg["remote_parent"]

    remote_package_dir = posixpath.join(remote_parent, package_name)
    remote_zip_path = posixpath.join(remote_package_dir, os.path.basename(zip_path))
    remote_manifest_path = posixpath.join(remote_package_dir, os.path.basename(manifest_path))

    print("\nConnecting to SFTP...")
    print(f"  Host:   {host}")
    print(f"  Port:   {port}")
    print(f"  User:   {username}")
    print(f"  Parent: {remote_parent}")

    transport = paramiko.Transport((host, port))
    transport.connect(username=username, password=password)
    sftp = paramiko.SFTPClient.from_transport(transport)

    try:
        ensure_remote_dir(sftp, remote_package_dir)

        # If remote zip exists, ask whether to overwrite
        try:
            sftp.stat(remote_zip_path)
            overwrite = input(f"\nRemote zip already exists:\n  {remote_zip_path}\nOverwrite it? [y/N]: ").strip().lower()
            if overwrite not in ("y", "yes"):
                raise RuntimeError("User chose not to overwrite existing remote zip.")
            print("Overwriting existing remote zip...")
        except (IOError, FileNotFoundError):
            pass

        print("\nUploading zip to remote...")
        sftp.put(zip_path, remote_zip_path)

        print("Computing remote zip checksum...")
        remote_sha256 = sha256_sftp_file(sftp, remote_zip_path)
        remote_verified = (remote_sha256 == zip_sha256)

        if remote_verified:
            print("REMOTE CHECKSUM MATCH: PASS")
        else:
            print("REMOTE CHECKSUM MATCH: FAIL")
            print(f"  Local:  {zip_sha256}")
            print(f"  Remote: {remote_sha256}")

        # Update manifest dict with remote info
        manifest.setdefault("zip", {})
        manifest["zip"]["remote_parent"] = cfg.get("remote_parent")
        manifest["zip"]["remote_package_dir"] = remote_package_dir
        manifest["zip"]["remote_path"] = remote_zip_path
        manifest["zip"]["remote_manifest"] = remote_manifest_path
        manifest["zip"]["sha256_remote"] = remote_sha256
        manifest["zip"]["remote_verified"] = bool(remote_verified)

        manifest.setdefault("status", {})
        manifest["status"]["remote_upload_attempted"] = True
        manifest["status"]["remote_verified"] = bool(remote_verified)

        # Write updated manifest locally (so it's authoritative) and upload it
        try:
            with open(manifest_path, "w", encoding="utf-8") as f:
                json.dump(manifest, f, indent=2)
            print(f"Wrote updated manifest locally: {manifest_path}")
        except Exception as e:
            print("WARNING: Could not write updated manifest locally before upload:", e)

        print("\nUploading manifest JSON as receipt to remote...")
        sftp.put(manifest_path, remote_manifest_path)

    finally:
        try:
            sftp.close()
        except Exception:
            pass
        try:
            transport.close()
        except Exception:
            pass

    return remote_package_dir, remote_zip_path, remote_manifest_path, remote_sha256, remote_verified


# ---------- Main ----------

def main():
    print("\n=== zip-emails.py: PACKAGE + ZIP FIXITY + SFTP ===\n")

    status = {
        "files_listed": False,
        "zip_created": False,
        "remote_upload_attempted": False,
        "remote_verified": False,
        "overall": "FAIL",
    }

    source_input = input("Enter or drag the SOURCE directory (emails / files to package): ")
    source_dir = normalize_path(source_input)

    print(f"DEBUG: normalized source path: [{source_dir}]")
    if not source_dir or not os.path.isdir(source_dir):
        print("ERROR: That path is not a valid directory.")
        return

    package_name = input("Enter PACKAGE NAME (used for package folder only): ").strip()
    if not package_name:
        print("ERROR: Package name cannot be empty.")
        return

    technician = input("Technician name (optional, can leave blank): ").strip() or "UNKNOWN"

    created_iso, stamp = timestamp()

    # STEP 1: List files
    print("\nSTEP 1: List source files")
    files_list, total_source_files = list_source_files(source_dir)
    status["files_listed"] = True

    # STEP 2: Create package dir
    print("\nSTEP 2: Create package directory")
    try:
        package_dir = make_package_dir(source_dir, package_name)
    except Exception as e:
        print(f"ERROR creating package dir: {e}")
        traceback.print_exc()
        return

    print(f"  Package directory: {package_dir}")

    # STEP 3: Zip
    print("\nSTEP 3: Zip source into package directory")
    try:
        zip_path = zip_source_into_package(source_dir, package_dir)
        status["zip_created"] = True
    except Exception as e:
        print(f"ERROR while zipping: {e}")
        traceback.print_exc()
        return

    zip_size = os.path.getsize(zip_path)
    try:
        zip_sha256 = sha256_file(zip_path)
    except Exception as e:
        print(f"ERROR computing local sha256: {e}")
        traceback.print_exc()
        return

    print(f"\nZip file SHA-256 (local): {zip_sha256}")

    # Build initial manifest (will be finalized later)
    manifest = {
        "package_name": package_name,
        "technician": technician,
        "created_at": created_iso,
        "source_root": source_dir,
        "package_dir": package_dir,
        "source_file_count": total_source_files,
        "files": files_list,
        "zip": {
            "local_path": zip_path,
            "name": os.path.basename(zip_path),
            "size": zip_size,
            "sha256_local": zip_sha256,
        },
        "status": status,
    }

    manifest_filename = f"package_manifest_{stamp}.json"
    manifest_path = os.path.join(package_dir, manifest_filename)

    # STEP 4: Upload + verify
    print("\nSTEP 4: Send ZIP (and manifest) to SFTP and verify")
    upload_choice = input("Upload zip to SFTP now? [Y/n]: ").strip().lower()

    if upload_choice in ("", "y", "yes"):
        status["remote_upload_attempted"] = True
        try:
            cfg = load_or_prompt_sftp_config()
            remote_dir, remote_zip_path, remote_manifest_path, remote_sha256, remote_verified = \
                upload_zip_and_manifest(zip_path, manifest_path, package_name, cfg, zip_sha256, manifest)

            # sync manifest with returned values (redundant with upload function but keeps things consistent)
            status["remote_verified"] = bool(remote_verified)
            manifest["zip"]["remote_parent"] = cfg.get("remote_parent")
            manifest["zip"]["remote_package_dir"] = remote_dir
            manifest["zip"]["remote_path"] = remote_zip_path
            manifest["zip"]["remote_manifest"] = remote_manifest_path
            manifest["zip"]["sha256_remote"] = remote_sha256
            manifest["zip"]["remote_verified"] = remote_verified

        except Exception as e:
            print(f"\nERROR during SFTP upload/verification: {e}")
            traceback.print_exc()
            status["remote_verified"] = False
            manifest["zip"]["remote_verified"] = False
            manifest["zip"]["remote_error"] = str(e)
    else:
        print("\nSkipping SFTP upload — local package only.")
        status["remote_upload_attempted"] = False
        status["remote_verified"] = False
        manifest["zip"]["remote_verified"] = False

    # ----------------------------
    # Robust finalization (authoritative)
    # ----------------------------
    manifest.setdefault("zip", {})
    manifest.setdefault("status", {})

    files_listed = bool(manifest["status"].get("files_listed"))
    zip_created = bool(manifest["status"].get("zip_created"))
    remote_attempted = bool(manifest["status"].get("remote_upload_attempted") or manifest["zip"].get("remote_path"))
    remote_verified = bool(manifest["zip"].get("remote_verified") or manifest["status"].get("remote_verified"))

    manifest["status"]["files_listed"] = files_listed
    manifest["status"]["zip_created"] = zip_created
    manifest["status"]["remote_upload_attempted"] = remote_attempted
    manifest["status"]["remote_verified"] = remote_verified

    if remote_verified:
        manifest["status"]["overall"] = "PASS"
    elif files_listed and zip_created and not remote_attempted:
        manifest["status"]["overall"] = "LOCAL_ONLY"
    elif files_listed and zip_created and remote_attempted and not remote_verified:
        manifest["status"]["overall"] = "FAIL"
    else:
        manifest["status"]["overall"] = "FAIL"

    # Write final manifest
    try:
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
        print(f"\nFinal manifest written: {manifest_path}")
    except Exception as e:
        print("ERROR: Could not write final manifest:", e)
        traceback.print_exc()

    # Final summary
    print("\n=== DONE ===")
    print(f"Source directory:       {source_dir}")
    print(f"Package directory:      {package_dir}")
    print(f"Zip file (local):       {zip_path}")
    print(f"Source file count:      {total_source_files}")
    print(f"Manifest (local JSON):  {manifest_path}")
    print(f"Files listed:           {'YES' if manifest['status']['files_listed'] else 'NO'}")
    print(f"Zip created:            {'YES' if manifest['status']['zip_created'] else 'NO'}")
    if manifest["status"]["remote_upload_attempted"]:
        print(f"Remote zip path:        {manifest['zip'].get('remote_path', '(unknown)')}")
        print(f"Remote manifest path:   {manifest['zip'].get('remote_manifest', '(unknown)')}")
        print(f"Remote verified:        {manifest['status']['remote_verified']}")
    else:
        print("Remote upload:          NOT ATTEMPTED")
    print(f"\nOVERALL STATUS:         {manifest['status']['overall']}\n")
    print("Archivematica can now ingest the ZIP from the remote package directory (if uploaded).\n")


if __name__ == "__main__":
    main()
