#!/usr/bin/env python3
"""
package_builder.py

Creates a new package, organizes files, and verifies integrity.

Flow:
  1. Ask technician name
  2. Ask source directory
  3. Ask destination directory
  4. Ask package name
  5. Create package structure
  6. Copy files:
     - .mp4, .mov (case-insensitive) -> objects/
     - ALL OTHER FILES (including .jpg/.JPG) -> objects/submissionDocumentation/
  7. Write MD5 checksums and manifest into objects/submissionDocumentation/aa_logs/
"""

from __future__ import annotations
import os
import sys
import shlex
import hashlib
import json
import shutil
from datetime import datetime
from typing import List, Tuple

try:
    from zoneinfo import ZoneInfo
except Exception:
    ZoneInfo = None

# ---------------- CONFIG ----------------
VIDEO_EXTENSIONS = {".mp4", ".mov"}  # CASE-INSENSITIVE
AA_LOGS_DIRNAME = "aa_logs"
CHUNK_SIZE = 16 * 1024 * 1024
TIMEZONE = "America/New_York"
# --------------------------------------


# ---------------- UTILITIES ----------------

def now_stamp() -> Tuple[str, str]:
    if ZoneInfo:
        t = datetime.now(ZoneInfo(TIMEZONE))
    else:
        t = datetime.now()
    return t.strftime("%Y%m%d_%H%M%S"), t.isoformat(timespec="seconds")

def prompt(msg: str) -> str:
    return input(msg).strip()

def normalize_path(raw: str) -> str:
    try:
        token = shlex.split(raw)[0]
    except Exception:
        token = raw
    return os.path.abspath(os.path.expanduser(token))

def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)

def is_video(path: str) -> bool:
    return os.path.splitext(path)[1].lower() in VIDEO_EXTENSIONS

def rel_forward(path: str, start: str) -> str:
    return os.path.relpath(path, start).replace(os.sep, "/")

# ---------------- FILE OPS ----------------

def md5_hex(path: str) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()

def gather_files(root: str) -> List[str]:
    files = []
    for d, _, fs in os.walk(root):
        for f in fs:
            files.append(os.path.join(d, f))
    files.sort()
    return files

def copy_preserve(src: str, dest: str):
    ensure_dir(os.path.dirname(dest))
    shutil.copy2(src, dest)

# ---------------- CHECKSUMS ----------------

def list_object_files(objects_root: str) -> List[str]:
    rels = []
    for d, _, fs in os.walk(objects_root):
        for f in fs:
            full = os.path.join(d, f)
            rel = rel_forward(full, objects_root)
            if rel.startswith(AA_LOGS_DIRNAME + "/"):
                continue
            rels.append(rel)
    rels.sort()
    return rels

def write_md5_checksums(objects_root: str, rels: List[str], out_path: str):
    ensure_dir(os.path.dirname(out_path))
    with open(out_path, "w", encoding="utf-8") as fh:
        for rel in rels:
            full = os.path.join(objects_root, rel.replace("/", os.sep))
            if not os.path.isfile(full):
                continue
            digest = md5_hex(full)
            fh.write(f"{digest}  *{rel}\n")

# ---------------- MANIFEST ----------------

def write_manifest(aa_logs: str, stamp: str, tech: str, pkg_name: str, counts: dict, checksum_file: str):
    path = os.path.join(aa_logs, f"manifest_{stamp}.json")
    manifest = {
        "technician": tech,
        "created_at": now_stamp()[1],
        "package_name": pkg_name,
        "counts": counts,
        "checksums_file": checksum_file
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    print(f"[MANIFEST] {path}")

# ---------------- MAIN ----------------

def main():
    print("\n--- Package Builder ---\n")

    tech = prompt("Technician name: ")
    if not tech:
        sys.exit("Technician name is required.")

    src = normalize_path(prompt("Source directory: "))
    if not os.path.isdir(src):
        sys.exit("Source directory not found.")

    dest = normalize_path(prompt("Destination directory: "))
    if not os.path.isdir(dest):
        sys.exit("Destination directory not found.")

    pkg_name = prompt("Package name: ")
    if not pkg_name:
        sys.exit("Package name is required.")

    # Create package structure
    pkg_root = os.path.join(dest, pkg_name)
    objects_root = os.path.join(pkg_root, "objects")
    submission_root = os.path.join(objects_root, "submissionDocumentation")
    aa_logs = os.path.join(submission_root, AA_LOGS_DIRNAME)

    for p in (objects_root, submission_root, aa_logs):
        ensure_dir(p)

    print(f"\n[INFO] Package created at: {pkg_root}\n")

    src_files = gather_files(src)

    video_count = 0
    doc_count = 0

    for f in src_files:
        rel = rel_forward(f, src)
        if is_video(f):
            target_base = objects_root
            video_count += 1
        else:
            target_base = submission_root
            doc_count += 1

        dest_path = os.path.join(target_base, rel.replace("/", os.sep))
        copy_preserve(f, dest_path)
        print(f"[COPIED] {rel}")

    # Checksums
    stamp = now_stamp()[0]
    checksum_name = f"checksums_{stamp}.txt"
    checksum_path = os.path.join(aa_logs, checksum_name)

    object_rels = list_object_files(objects_root)
    write_md5_checksums(objects_root, object_rels, checksum_path)

    counts = {
        "video_files_in_objects": video_count,
        "files_in_submissionDocumentation": doc_count,
        "total_files": video_count + doc_count
    }

    write_manifest(aa_logs, stamp, tech, pkg_name, counts, checksum_name)

    print("\n[DONE]")
    print(f"Checksums: {checksum_path}")
    print(f"Manifest: {os.path.join(aa_logs, f'manifest_{stamp}.json')}")

if __name__ == "__main__":
    main()
