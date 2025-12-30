#!/usr/bin/env python3
"""
batch_package_builder.py

Interactive batch tool with per-file progress display:
 - Prompts for Technician name, Source parent folder, Destination folder, and Prefix (e.g. AA237.)
 - For each subfolder in Source parent, creates a new package folder in Destination named <prefix><subfolder>
 - Organizes files:
     * video files (.mp4, .mov) => <package>/objects/
     * all other files (including .jpg/.jpeg) => <package>/objects/submissionDocumentation/
 - Writes MD5 checksums and manifest into <package>/objects/submissionDocumentation/aa_logs/
 - Shows per-file progress (bytes / percent) while copying large files
"""
from __future__ import annotations
import os
import sys
import shlex
import hashlib
import json
import shutil
import time
from datetime import datetime
from typing import List, Tuple

# Try zoneinfo for timezone-aware stamps (Python 3.9+)
try:
    from zoneinfo import ZoneInfo
except Exception:
    ZoneInfo = None

# ----- CONFIG -----
VIDEO_EXTENSIONS = {".mp4", ".mov"}      # case-insensitive
AA_LOGS_DIRNAME = "aa_logs"
CHUNK_SIZE = 16 * 1024 * 1024
TIMEZONE = "America/New_York"
PROGRESS_BAR_WIDTH = 40
# ------------------

def now_stamp() -> Tuple[str, str]:
    if ZoneInfo:
        t = datetime.now(ZoneInfo(TIMEZONE))
    else:
        t = datetime.now()
    return t.strftime("%Y%m%d_%H%M%S"), t.isoformat(timespec="seconds")

def prompt(msg: str) -> str:
    return input(msg).strip()

def normalize_path(raw: str) -> str:
    if not raw:
        return ""
    try:
        token = shlex.split(raw)[0]
    except Exception:
        token = raw
    return os.path.abspath(os.path.expanduser(token))

def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)

def is_video_file(path: str) -> bool:
    return os.path.splitext(path)[1].lower() in VIDEO_EXTENSIONS

def rel_forward(path: str, start: str) -> str:
    return os.path.relpath(path, start).replace(os.sep, "/")

def md5_hex(path: str) -> str:
    h = hashlib.md5()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()

def gather_files(root: str) -> List[str]:
    out = []
    for dirpath, _, files in os.walk(root):
        for f in files:
            out.append(os.path.join(dirpath, f))
    out.sort()
    return out

def human_readable(num_bytes: int) -> str:
    # simple human-readable bytes
    for unit in ("B","KB","MB","GB","TB"):
        if num_bytes < 1024 or unit == "TB":
            return f"{num_bytes:.1f}{unit}"
        num_bytes /= 1024
    return f"{num_bytes:.1f}B"

def print_progress_line(prefix: str, copied: int, total: int):
    # builds a bar of fixed width showing percent and bytes
    percent = (copied / total) if total else 1.0
    filled = int(percent * PROGRESS_BAR_WIDTH)
    bar = "[" + "#" * filled + "-" * (PROGRESS_BAR_WIDTH - filled) + "]"
    pct_text = f"{percent*100:6.2f}%"
    bytes_text = f"{human_readable(copied)}/{human_readable(total)}"
    sys.stdout.write(f"\r{prefix} {bar} {pct_text} {bytes_text}")
    sys.stdout.flush()

def copy_with_progress(src: str, dest: str):
    """
    Stream-copy src -> dest chunk-by-chunk, updating per-file progress display.
    Preserves permissions/mtime via copystat at the end.
    """
    ensure_dir(os.path.dirname(dest))
    total = os.path.getsize(src)
    copied = 0
    prefix = f"Copying: {rel_forward(src, os.path.dirname(src))}"
    try:
        with open(src, "rb") as rf, open(dest, "wb") as wf:
            while True:
                chunk = rf.read(CHUNK_SIZE)
                if not chunk:
                    break
                wf.write(chunk)
                copied += len(chunk)
                print_progress_line(prefix, copied, total)
        # finalize metadata
        try:
            shutil.copystat(src, dest)
        except Exception:
            pass
        # ensure final 100% line
        print_progress_line(prefix, total, total)
        sys.stdout.write("\n")
        return True
    except Exception as e:
        sys.stdout.write("\n")
        print(f"[ERROR] copy failed: {src} -> {dest}: {e}", file=sys.stderr)
        return False

def copy_preserve_with_skip(src: str, dest: str) -> bool:
    """
    Check if dest exists and likely identical (size+mtime or md5). If identical, skip (return False).
    Otherwise perform copy_with_progress and return True if copied.
    """
    if os.path.exists(dest) and os.path.isfile(dest):
        try:
            s_stat = os.stat(src)
            d_stat = os.stat(dest)
            if s_stat.st_size == d_stat.st_size and int(s_stat.st_mtime) == int(d_stat.st_mtime):
                # assume identical
                print(f"[SKIP] identical exists: {rel_forward(src, os.path.dirname(src))}")
                return False
            # fallback: md5 compare (slower, but thorough)
            if md5_hex(src) == md5_hex(dest):
                # update dest mtime to match source for future fast checks
                os.utime(dest, (s_stat.st_atime, s_stat.st_mtime))
                print(f"[SKIP] identical (md5) exists: {rel_forward(src, os.path.dirname(src))}")
                return False
        except Exception:
            # on any error, proceed to copy
            pass
    # perform the chunked copy with progress
    return copy_with_progress(src, dest)

def list_object_files(objects_root: str) -> List[str]:
    rels = []
    for dirpath, _, files in os.walk(objects_root):
        for f in files:
            full = os.path.join(dirpath, f)
            rel = rel_forward(full, objects_root)
            if rel == AA_LOGS_DIRNAME or rel.startswith(AA_LOGS_DIRNAME + "/"):
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

def write_manifest(aa_logs_dir: str, stamp: str, technician: str, package_name: str, counts: dict, checksums_filename: str):
    ensure_dir(aa_logs_dir)
    path = os.path.join(aa_logs_dir, f"manifest_{stamp}.json")
    manifest = {
        "technician": technician,
        "created_at": now_stamp()[1],
        "package_name": package_name,
        "counts": counts,
        "checksums_file": checksums_filename
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    print(f"[MANIFEST] {path}")

def process_single_package(src_dir: str, dest_parent: str, technician: str, package_name: str):
    pkg_root = os.path.join(dest_parent, package_name)
    objects_root = os.path.join(pkg_root, "objects")
    submission_root = os.path.join(objects_root, "submissionDocumentation")
    aa_logs = os.path.join(submission_root, AA_LOGS_DIRNAME)

    for p in (objects_root, submission_root, aa_logs):
        ensure_dir(p)

    print(f"[INFO] Processing source: {src_dir}")
    print(f"[INFO] Package created at: {pkg_root}")

    src_files = gather_files(src_dir)
    if not src_files:
        print(f"[WARN] no files found under source {src_dir}; package will remain empty.")
    copied_media = 0
    copied_docs = 0
    skipped = 0
    total_files = len(src_files)

    for idx, full_src in enumerate(src_files, start=1):
        rel = rel_forward(full_src, src_dir)
        # show package-level progress
        print(f"\nFile {idx}/{total_files}: {rel}")
        if is_video_file(full_src):
            target_base = objects_root
            copied_media += 1
        else:
            target_base = submission_root
            copied_docs += 1

        dest_full = os.path.join(target_base, rel.replace("/", os.sep))
        try:
            copied = copy_preserve_with_skip(full_src, dest_full)
            if not copied:
                skipped += 1
        except Exception as e:
            print(f"[ERROR] copying {full_src} -> {dest_full}: {e}", file=sys.stderr)
            skipped += 1

    # checksums & manifest
    stamp = now_stamp()[0]
    checksum_name = f"checksums_{stamp}.txt"
    checksum_path = os.path.join(aa_logs, checksum_name)

    rels = list_object_files(objects_root)
    write_md5_checksums(objects_root, rels, checksum_path)

    counts = {
        "video_files_in_objects": copied_media,
        "files_in_submissionDocumentation": copied_docs,
        "skipped_errors_or_identical": skipped,
        "total_files_processed": total_files
    }

    write_manifest(aa_logs, stamp, technician, package_name, counts, checksum_name)

    print(f"[DONE] package: {package_name} (checksums: {checksum_path})\n")

def main():
    print("\n--- Batch Package Builder (interactive) ---\n")

    technician = prompt("Technician name: ").strip()
    if not technician:
        sys.exit("Technician name required.")

    src_parent = normalize_path(prompt("Source PARENT directory (contains package subfolders): ").strip())
    if not src_parent or not os.path.isdir(src_parent):
        sys.exit("Source parent directory not found or invalid.")

    dest_parent = normalize_path(prompt("Destination directory (will contain created packages): ").strip())
    if not dest_parent or not os.path.isdir(dest_parent):
        sys.exit("Destination directory not found or invalid.")

    prefix = prompt("Prefix to add to package names (e.g. AA237.) — leave blank for none: ").strip()

    subdirs = [d for d in sorted(os.listdir(src_parent)) if os.path.isdir(os.path.join(src_parent, d))]
    if not subdirs:
        sys.exit("No subfolders found in source parent directory — nothing to process.")
    print(f"\nFound {len(subdirs)} subfolders to process (first 10 shown):")
    for d in subdirs[:10]:
        print("  -", d)
    cont = prompt("\nProceed with processing these subfolders? [Y/n]: ").strip().lower()
    if cont == "n":
        print("Aborted by user.")
        return

    # Process each subfolder
    for entry in subdirs:
        src_dir = os.path.join(src_parent, entry)
        pkg_name = f"{prefix}{entry}"
        # Avoid name collision in destination by adding numeric suffix if needed
        target_pkg_path = os.path.join(dest_parent, pkg_name)
        if os.path.exists(target_pkg_path):
            i = 1
            while True:
                alt = os.path.join(dest_parent, f"{pkg_name}_{i}")
                if not os.path.exists(alt):
                    pkg_name = f"{pkg_name}_{i}"
                    break
                i += 1
        print(f"\n=== Processing '{entry}' -> package '{pkg_name}' ===")
        process_single_package(src_dir, dest_parent, technician, pkg_name)

    print("\nBatch complete.")

if __name__ == "__main__":
    main()
