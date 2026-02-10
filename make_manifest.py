#!/usr/bin/env python3
"""
make_manifest.py

- Prompt for PACKAGE directory (which contains objects/)
- Prompt for technician, transfer_agent, optional note
- Discover objects/ folder inside package
- List all files under objects/ (relative path, size, sha256)
- Discover any .zip files under objects/
  - For each zip, list internal files + size + sha256
- Write manifest JSON to:
  objects/submissionDocumentation/aa_logs/package_manifest_YYYYMMDD_HHMMSS.json

Manifest includes (similar to original script but using SHA-256):
- package_name
- technician
- transfer_agent
- created_at
- package_dir
- objects_dir
- files: list of files in objects/ (rel_path, size, sha256)
- zip: summary for first .zip found in objects/ (if any)
- zip_contents: list of entries for all zip files (zip_rel_path, member_path, size, sha256)
- note
- status:
    files_listed
    zip_created
    remote_upload_attempted
    remote_verified
    overall ("LOCAL_ONLY")
"""

import os
import json
import hashlib
import zipfile
from datetime import datetime

CHUNK_SIZE = 16 * 1024 * 1024  # 16 MB


def normalize_path(p: str) -> str:
    """
    Normalize user input path:

    - Strip surrounding whitespace
    - Strip surrounding single/double quotes
    - Convert drag-and-drop escaped spaces (e.g. '\\ ') to real spaces
    - Expand ~ and return an absolute path
    """
    if not p:
        return p

    # Strip whitespace and any wrapping quotes
    p = p.strip().strip('"').strip("'")

    # Handle escaped spaces from drag-and-drop (e.g., /Users/me/My\ Folder)
    p = p.replace("\\ ", " ")

    # Expand ~ and make absolute
    return os.path.abspath(os.path.expanduser(p))


def now_iso_stamp():
    """Return (ISO timestamp, compact stamp) for filenames."""
    now = datetime.now()
    return now.isoformat(timespec="seconds"), now.strftime("%Y%m%d_%H%M%S")


def sha256_file(path: str) -> str:
    """Compute SHA-256 for a local file on disk."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def sha256_zip_entry(zf: zipfile.ZipFile, member_name: str) -> str:
    """Compute SHA-256 for a file *inside* a zip, streaming from the archive."""
    h = hashlib.sha256()
    with zf.open(member_name, "r") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def list_objects_files(objects_dir: str):
    """
    Walk objects_dir and return:
      - files_list: list of dicts {rel_path, size, sha256}
      - count: total number of files
    Paths are relative to objects_dir and use forward slashes.
    """
    records = []
    total = 0
    for root, _, files in os.walk(objects_dir):
        for name in files:
            total += 1
            full = os.path.join(root, name)
            rel = os.path.relpath(full, objects_dir).replace(os.sep, "/")
            try:
                size = os.path.getsize(full)
            except OSError:
                size = None
            try:
                digest = sha256_file(full)
            except Exception:
                digest = None
            records.append({
                "rel_path": rel,
                "size": size,
                "sha256": digest,
            })
    print(f"\nFound {total} files in objects/ directory.")
    return records, total


def find_zip_files(objects_dir: str):
    """Return a list of full paths to .zip files under objects_dir."""
    zips = []
    for root, _, files in os.walk(objects_dir):
        for name in files:
            if name.lower().endswith(".zip"):
                zips.append(os.path.join(root, name))
    return zips


def inspect_zip(zip_path: str, objects_dir: str):
    """
    Inspect a zip file and return:
      - summary: {local_path, rel_path, name, size, sha256_local}
      - entries: list of {zip_rel_path, member_path, size, sha256}
    """
    # Path of the zip relative to objects_dir
    zip_rel = os.path.relpath(zip_path, objects_dir).replace(os.sep, "/")
    size = os.path.getsize(zip_path)
    sha256_local = sha256_file(zip_path)

    summary = {
        "local_path": zip_path,
        "rel_path": zip_rel,
        "name": os.path.basename(zip_path),
        "size": size,
        "sha256_local": sha256_local,
    }

    entries = []
    print(f"\nInspecting ZIP: {zip_rel}")
    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            member_name = info.filename  # always forward slashes
            member_size = info.file_size
            try:
                member_sha256 = sha256_zip_entry(zf, member_name)
            except Exception:
                member_sha256 = None
            entries.append({
                "zip_rel_path": zip_rel,
                "member_path": member_name,
                "size": member_size,
                "sha256": member_sha256,
            })
            print(f"  [zip entry] {member_name} (size={member_size})")

    return summary, entries


def main():
    print("\n=== MAKE MANIFEST (SHA-256, OBJECTS + ZIP CONTENTS) ===\n")

    # PACKAGE directory (contains objects/)
    package_dir_input = input("Enter or drag the PACKAGE directory: ")
    package_dir = normalize_path(package_dir_input)
    if not package_dir or not os.path.isdir(package_dir):
        print("ERROR: That path is not a valid directory.")
        return

    package_name_default = os.path.basename(os.path.normpath(package_dir))
    package_name_in = input(
        f"Package name [{package_name_default}]: "
    ).strip()
    package_name = package_name_in or package_name_default

    # objects/ directory
    objects_dir = os.path.join(package_dir, "objects")
    if not os.path.isdir(objects_dir):
        print(f"ERROR: No 'objects' directory found at:\n  {objects_dir}")
        return

    print(f"\nUsing objects directory:\n  {objects_dir}")

    technician = input("Technician name (optional) [UNKNOWN]: ").strip() or "UNKNOWN"
    transfer_agent = input("Transfer agent (e.g. 'local', 'rsync', 'sftp') [local]: ").strip() or "local"
    note = input("Optional note to include in manifest (press Enter to skip): ").strip()

    created_iso, stamp = now_iso_stamp()

    # STEP 1: List files in objects/
    print("\nSTEP 1: Listing files in objects/ and computing SHA-256...")
    files_list, total_objects_files = list_objects_files(objects_dir)

    # STEP 2: Inspect zip files (if any)
    print("\nSTEP 2: Looking for ZIP files under objects/...")
    zip_paths = find_zip_files(objects_dir)
    zip_created = len(zip_paths) > 0

    zip_summary = None
    zip_contents = []

    if zip_paths:
        print(f"Found {len(zip_paths)} ZIP file(s) under objects/.")
        for idx, zp in enumerate(zip_paths, start=1):
            print(f"\nZIP #{idx}: {os.path.relpath(zp, objects_dir).replace(os.sep, '/')}")
            summary, entries = inspect_zip(zp, objects_dir)
            # Prefer the first ZIP for the top-level summary
            if zip_summary is None:
                zip_summary = summary
            zip_contents.extend(entries)
    else:
        print("No ZIP files found under objects/.")

    # Status similar to original script, but no remote activity yet.
    status = {
        "files_listed": True,
        "zip_created": bool(zip_created),
        "remote_upload_attempted": False,
        "remote_verified": False,
        "overall": "LOCAL_ONLY",
    }

    manifest = {
        "package_name": package_name,
        "technician": technician,
        "transfer_agent": transfer_agent,
        "created_at": created_iso,
        "package_dir": package_dir,
        "objects_dir": objects_dir,
        "objects_file_count": total_objects_files,
        "files": files_list,           # files in objects/
        "zip": zip_summary,            # summary of first zip (if any)
        "zip_contents": zip_contents,  # entries from all zips
        "note": note or None,
        "status": status,
    }

    # Manifest path: objects/submissionDocumentation/aa_logs
    logs_dir = os.path.join(objects_dir, "submissionDocumentation", "aa_logs")
    os.makedirs(logs_dir, exist_ok=True)
    manifest_filename = f"package_manifest_{stamp}.json"
    manifest_path = os.path.join(logs_dir, manifest_filename)

    try:
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
        print(f"\nManifest written:\n  {manifest_path}")
    except Exception as e:
        print("ERROR: Could not write manifest:", e)
        return

    print("\n=== DONE ===")
    print(f"Package directory:      {package_dir}")
    print(f"Objects directory:      {objects_dir}")
    print(f"Objects file count:     {total_objects_files}")
    if zip_summary:
        print(f"Primary ZIP (summary):  {zip_summary['rel_path']}")
    else:
        print("Primary ZIP (summary):  None")
    print(f"Status overall:         {status['overall']}\n")


if __name__ == "__main__":
    main()
