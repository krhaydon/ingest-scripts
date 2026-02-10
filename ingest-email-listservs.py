#!/usr/bin/env python3
"""
ingest-email-listservs.py

- Prompt for SOURCE dir, PACKAGE NAME, optional technician, optional note
- Let user name the ZIP file, or default to source directory name
- Create PACKAGE dir (sibling of SOURCE)
- Create ZIP inside PACKAGE/objects/
- Compute MD5 for ZIP (local)
- List all files in SOURCE (rel path + size)
- Write manifest to: objects/Documentation/aa_logs/package_manifest_*.json
- Optionally upload ZIP + manifest to SFTP
  - SFTP config stored on Desktop: ~/Desktop/.package-email-listservs_sftp.json
  - Remote structure: remote_parent/PACKAGE_NAME/objects/...
  - Creates objects/submissionDocumentation/aa_logs on remote
  - Computes remote MD5, marks PASS if it matches

Manifest status.overall:
- PASS       -> files_listed + zip_created + upload attempted + remote_verified
- LOCAL_ONLY -> files_listed + zip_created + no upload attempted
- FAIL       -> anything else
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

try:
    import paramiko
except ImportError:
    paramiko = None

CHUNK_SIZE = 16 * 1024 * 1024  # 16 MB
CONFIG_PATH = os.path.expanduser("~/Desktop/.package-email-listservs_sftp.json")


# ---------- utilities ----------

def now_iso_stamp():
    now = datetime.now()
    return now.isoformat(timespec="seconds"), now.strftime("%Y%m%d_%H%M%S")


def normalize_path(p: str) -> str:
    if p is None:
        return p
    try:
        parts = shlex.split(p)
        if parts:
            p = parts[0]
    except Exception:
        pass
    p = p.strip().strip('"').strip("'")
    return os.path.abspath(os.path.expanduser(p))


def md5_file(path: str) -> str:
    """Compute MD5 for local file (streamed)."""
    h = hashlib.md5()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def md5_sftp_file(sftp, remote_path: str) -> str:
    """Compute MD5 for remote file over SFTP (streamed)."""
    h = hashlib.md5()
    with sftp.open(remote_path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def ensure_remote_dir(sftp, remote_dir: str):
    """Ensure remote_dir and its parents exist."""
    remote_dir = remote_dir.replace("\\", "/").rstrip("/")
    if not remote_dir:
        return
    parts = []
    d = remote_dir
    while d not in ("", "/"):
        parts.append(d)
        d = posixpath.dirname(d)
    parts.reverse()
    for part in parts:
        try:
            sftp.stat(part)
        except IOError:
            try:
                sftp.mkdir(part)
            except Exception:
                pass


# ---------- SFTP config ----------

def load_or_prompt_sftp_config():
    import socket

    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            print(f"\nUsing saved SFTP config from {CONFIG_PATH}")
            return cfg
        except Exception:
            pass

    print("\n=== SFTP SETTINGS ===")
    raw_host = input("SFTP host (e.g. icahn.archivematica.org): ").strip()
    if raw_host.lower().startswith(("sftp://", "ssh://")):
        raw_host = raw_host.split("://", 1)[1].split("/", 1)[0]

    port_str = input("SFTP port [22]: ").strip()
    username = input("SFTP username: ").strip()
    password = getpass.getpass("SFTP password: ")
    remote_parent = input("Remote parent directory for packages (e.g. /sftp-transfer-source): ").strip()

    if not raw_host or not username or not remote_parent:
        raise RuntimeError("Host, username, and remote parent directory are required.")

    try:
        port = int(port_str) if port_str else 22
    except ValueError:
        port = 22

    # Quick DNS check
    try:
        socket.getaddrinfo(raw_host, port)
    except Exception as e:
        raise RuntimeError(f"Cannot resolve host '{raw_host}': {e}")

    cfg = {
        "host": raw_host,
        "port": port,
        "username": username,
        "password": password,
        "remote_parent": remote_parent,
    }

    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)

    save = input(f"\nSave these SFTP settings to {CONFIG_PATH}? [Y/n]: ").strip().lower()
    if save in ("", "y", "yes"):
        try:
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2)
            print(f"SFTP config saved to {CONFIG_PATH}")
        except Exception as e:
            print(f"WARNING: Could not save config: {e}")

    return cfg


# ---------- core steps ----------

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
    parent_dir = os.path.dirname(source_dir)
    package_dir = os.path.join(parent_dir, package_name)
    if os.path.exists(package_dir):
        raise RuntimeError(f"Package directory already exists: {package_dir}")
    os.makedirs(package_dir, exist_ok=False)
    return package_dir


def zip_source_into_objects(source_dir: str, objects_dir: str, zip_basename: str | None) -> str:
    """Create ZIP of source_dir inside objects_dir, using given basename (no .zip)."""
    source_basename = os.path.basename(os.path.normpath(source_dir))
    if not zip_basename:
        zip_basename = source_basename
    if zip_basename.lower().endswith(".zip"):
        zip_basename = zip_basename[:-4]

    zip_filename = f"{zip_basename}.zip"
    zip_path = os.path.join(objects_dir, zip_filename)

    if os.path.exists(zip_path):
        raise RuntimeError(f"Zip file already exists: {zip_path}")

    print("\nZipping source directory...")
    print(f"  Source: {source_dir}")
    print(f"  Zip:    {zip_path}\n")

    parent_of_source = os.path.dirname(source_dir)

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(source_dir):
            rel_root = os.path.relpath(root, parent_of_source)
            if not files and not dirs:
                arcdir = rel_root.rstrip("/") + "/"
                zf.writestr(arcdir, "")
                print(f"  [dir]  {arcdir}")
                continue

            for name in files:
                full_path = os.path.join(root, name)
                rel_path = os.path.relpath(full_path, parent_of_source)
                print(f"  [file] {rel_path}")
                zf.write(full_path, arcname=rel_path)

    print("\nZipping complete.")
    return zip_path


def upload_zip_and_manifest(zip_path, manifest_path, cfg, local_md5, manifest, package_name):
    """Upload ZIP and manifest to SFTP and verify remote MD5.

    Remote layout:
      remote_parent/package_name/
        objects/
          <zipfile>.zip
          submissionDocumentation/
            aa_logs/
              <manifest>.json
    """
    if paramiko is None:
        raise RuntimeError("Paramiko is not installed. Run: pip install paramiko in this environment.")

    host = cfg["host"]
    port = cfg["port"]
    username = cfg["username"]
    password = cfg["password"]
    remote_parent = cfg["remote_parent"]

    remote_package_dir = posixpath.join(remote_parent, package_name)
    remote_objects_dir = posixpath.join(remote_package_dir, "objects")
    remote_logs_dir = posixpath.join(remote_objects_dir, "submissionDocumentation", "aa_logs")

    remote_zip_path = posixpath.join(remote_objects_dir, os.path.basename(zip_path))
    remote_manifest_path = posixpath.join(remote_logs_dir, os.path.basename(manifest_path))

    print("\nConnecting to SFTP...")
    print(f"  Host:          {host}")
    print(f"  Port:          {port}")
    print(f"  Username:      {username}")
    print(f"  Remote parent: {remote_parent}")
    print(f"  Remote package: {remote_package_dir}")

    transport = paramiko.Transport((host, port))
    transport.connect(username=username, password=password)
    sftp = paramiko.SFTPClient.from_transport(transport)

    try:
        # Ensure base dirs exist
        ensure_remote_dir(sftp, remote_objects_dir)
        ensure_remote_dir(sftp, remote_logs_dir)

        # Ask before overwriting remote zip
        try:
            sftp.stat(remote_zip_path)
            overwrite = input(f"\nRemote zip already exists:\n  {remote_zip_path}\nOverwrite it? [y/N]: ").strip().lower()
            if overwrite not in ("y", "yes"):
                raise RuntimeError("User chose not to overwrite existing remote zip.")
            print("Overwriting existing remote zip...")
        except IOError:
            pass

        print("\nUploading zip to remote...")
        sftp.put(zip_path, remote_zip_path)

        print("Computing remote zip MD5...")
        remote_md5 = md5_sftp_file(sftp, remote_zip_path)
        remote_verified = (remote_md5 == local_md5)

        if remote_verified:
            print("REMOTE MD5 MATCH: PASS")
        else:
            print("REMOTE MD5 MATCH: FAIL")
            print(f"  Local:  {local_md5}")
            print(f"  Remote: {remote_md5}")

        # Update manifest
        manifest.setdefault("zip", {})
        manifest.setdefault("status", {})

        manifest["zip"]["remote_parent"] = remote_parent
        manifest["zip"]["remote_package_dir"] = remote_package_dir
        manifest["zip"]["remote_path"] = remote_zip_path
        manifest["zip"]["remote_manifest"] = remote_manifest_path
        manifest["zip"]["md5_remote"] = remote_md5
        manifest["zip"]["remote_verified"] = bool(remote_verified)

        manifest["status"]["remote_upload_attempted"] = True
        manifest["status"]["remote_verified"] = bool(remote_verified)
        if remote_verified:
            manifest["status"]["overall"] = "PASS"

        # Write manifest locally, then upload
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
        print(f"Wrote updated manifest locally: {manifest_path}")

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

    return remote_package_dir, remote_zip_path, remote_manifest_path, remote_md5, remote_verified


# ---------- main ----------

def main():
    print("\n=== package-email-listservs: PACKAGE + MD5 FIXITY + SFTP ===\n")

    status = {
        "files_listed": False,
        "zip_created": False,
        "remote_upload_attempted": False,
        "remote_verified": False,
        "overall": "FAIL",
    }

    # Source directory
    source_dir = normalize_path(input("Enter or drag the SOURCE directory (emails / files to package): "))
    if not source_dir or not os.path.isdir(source_dir):
        print("ERROR: That path is not a valid directory.")
        return

    # Package name
    package_name = input("Enter PACKAGE NAME (will be the package folder name): ").strip()
    if not package_name:
        print("ERROR: Package name cannot be empty.")
        return

    technician = input("Technician name (optional, can leave blank): ").strip() or "UNKNOWN"
    note = input("Optional note to include in manifest (press Enter to skip): ").strip()

    created_iso, stamp = now_iso_stamp()

    # STEP 1: list files
    print("\nSTEP 1: List source files")
    files_list, total_source_files = list_source_files(source_dir)
    status["files_listed"] = True

    # STEP 2: create package dir and objects dir
    print("\nSTEP 2: Create package directory")
    try:
        package_dir = make_package_dir(source_dir, package_name)
    except Exception as e:
        print(f"ERROR: {e}")
        return
    print(f"  Package directory: {package_dir}")

    objects_dir = os.path.join(package_dir, "objects")
    os.makedirs(objects_dir, exist_ok=True)

    # Ask for zip filename (optional)
    default_zip_base = os.path.basename(os.path.normpath(source_dir))
    zip_base_input = input(f"Zip filename (without .zip) [{default_zip_base}]: ").strip()
    zip_basename = zip_base_input or default_zip_base

    # STEP 3: zip into objects/
    print("\nSTEP 3: Zip source into package/objects/")
    try:
        zip_path = zip_source_into_objects(source_dir, objects_dir, zip_basename)
        status["zip_created"] = True
    except Exception as e:
        print(f"ERROR while zipping: {e}")
        traceback.print_exc()
        return

    # Compute local MD5
    try:
        zip_size = os.path.getsize(zip_path)
        zip_md5 = md5_file(zip_path)
    except Exception as e:
        print(f"ERROR computing local MD5: {e}")
        traceback.print_exc()
        return

    print(f"\nZip file MD5 (local): {zip_md5}")

    # Manifest path: objects/submissionDocumentation/aa_logs
    logs_dir = os.path.join(objects_dir, "submissionDocumentation", "aa_logs")
    os.makedirs(logs_dir, exist_ok=True)
    manifest_filename = f"package_manifest_{stamp}.json"
    manifest_path = os.path.join(logs_dir, manifest_filename)

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
            "md5_local": zip_md5,
        },
        "note": note or None,
        "status": status,
    }

    # STEP 4: SFTP upload (optional)
    print("\nSTEP 4: Send ZIP (and manifest) to SFTP and verify")
    upload_choice = input("Upload zip to SFTP now? [Y/n]: ").strip().lower()

    if upload_choice in ("", "y", "yes"):
        status["remote_upload_attempted"] = True
        try:
            cfg = load_or_prompt_sftp_config()
            remote_dir, remote_zip_path, remote_manifest_path, remote_md5, remote_verified = \
                upload_zip_and_manifest(zip_path, manifest_path, cfg, zip_md5, manifest, package_name)

            status["remote_verified"] = bool(remote_verified)
            manifest["zip"]["remote_parent"] = cfg.get("remote_parent")
            manifest["zip"]["remote_package_dir"] = remote_dir
            manifest["zip"]["remote_path"] = remote_zip_path
            manifest["zip"]["remote_manifest"] = remote_manifest_path
            manifest["zip"]["md5_remote"] = remote_md5
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

    # Final status
    files_listed_flag = bool(status.get("files_listed"))
    zip_created_flag = bool(status.get("zip_created"))
    remote_attempt = bool(status.get("remote_upload_attempted") or manifest["zip"].get("remote_path"))
    remote_verified_flag = bool(manifest["zip"].get("remote_verified") or status.get("remote_verified"))

    status["files_listed"] = files_listed_flag
    status["zip_created"] = zip_created_flag
    status["remote_upload_attempted"] = remote_attempt
    status["remote_verified"] = remote_verified_flag

    if files_listed_flag and zip_created_flag and remote_attempt and remote_verified_flag:
        status["overall"] = "PASS"
    elif files_listed_flag and zip_created_flag and not remote_attempt:
        status["overall"] = "LOCAL_ONLY"
    else:
        status["overall"] = "FAIL"

    # Write final manifest
    try:
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
        print(f"\nFinal manifest written: {manifest_path}")
    except Exception as e:
        print("ERROR: Could not write final manifest:", e)
        traceback.print_exc()

    # Summary
    print("\n=== DONE ===")
    print(f"Source directory:       {source_dir}")
    print(f"Package directory:      {package_dir}")
    print(f"Zip file (local):       {zip_path}")
    print(f"Source file count:      {total_source_files}")
    print(f"Manifest (local JSON):  {manifest_path}")
    print(f"Files listed:           {'YES' if status['files_listed'] else 'NO'}")
    print(f"Zip created:            {'YES' if status['zip_created'] else 'NO'}")
    if status["remote_upload_attempted"]:
        print(f"Remote zip path:        {manifest['zip'].get('remote_path', '(unknown)')}")
        print(f"Remote manifest path:   {manifest['zip'].get('remote_manifest', '(unknown)')}")
        print(f"Remote verified:        {status['remote_verified']}")
    else:
        print("Remote upload:          NOT ATTEMPTED")
    print(f"\nOVERALL STATUS:         {status['overall']}\n")


if __name__ == "__main__":
    main()
