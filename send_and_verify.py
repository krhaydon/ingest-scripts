#!/usr/bin/env python3
"""
send_and_verify.py (batch mode with byte-level diagnostics)

What this script does:
- Processes ONE package or MANY packages (batch mode).
- Transfers either:
  * a ZIP (if manifest["zip"]["local_path"] exists and is a file), OR
  * the objects/ directory (excluding submissionDocumentation/)
- Verifies transfer:
  * ZIP mode: compares SHA-256 of the ZIP file (local vs remote/dest)
  * Directory mode: compares per-file SHA-256 for ALL files under objects/ (excluding submissionDocumentation + junk files)

Manifest behavior:
- If it cannot find a manifest JSON, it will CREATE one in:
  objects/submissionDocumentation/aa_logs/package_manifest_<timestamp>.json
- Prompts for optional free-text fields:
  * transfer_agent (person running the script)
  * source
  * notes
- Method is auto-populated based on the chosen transfer method (sftp or local_copy).

Diagnostics:
- Writes local_hashes_*.txt, remote_hashes_*.txt, differences_*.json when verification is performed.
- If ZIP verification fails, also writes byte_diff_<timestamp>.txt

Input paths:
- Safe for paths with spaces/special characters (paste, drag-and-drop, or quoted)
- Handles macOS drag-and-drop escaping like: /Users/me/My\ Folder/file\(1\).zip
- Preserves UNC paths like: \\server\share\folder
"""

from __future__ import annotations

import os
import json
import hashlib
import getpass
import posixpath
import traceback
import shutil
import subprocess
import re
import shlex
from datetime import datetime

try:
    import paramiko
except Exception:
    paramiko = None

CHUNK_SIZE = 16 * 1024 * 1024
SFTP_CONFIG_PATH = os.path.expanduser("~/Desktop/.package-email-listservs_sftp.json")
MANIFEST_REGEX = re.compile(r"^package_manifest_(\d{8}_\d{6})\.json$", flags=re.IGNORECASE)

# Ignore common OS “junk” files that can appear unexpectedly (esp. on macOS)
IGNORE_BASENAMES = {
    ".DS_Store",
    "Thumbs.db",
    "desktop.ini",
}
IGNORE_PREFIXES = ("._",)  # AppleDouble resource fork files created by macOS on non-HFS volumes

# ----- utilities -----
_MACOS_DRAGDROP_UNESCAPE = re.compile(r"\\([ \(\)\[\]\{\}&;,#@!\+\=\~'])")


def _unescape_macos_dragdrop(p: str) -> str:
    return _MACOS_DRAGDROP_UNESCAPE.sub(r"\1", p)


def normalize_path(p: str) -> str:
    if not p:
        return p

    p = p.strip()
    if (p.startswith('"') and p.endswith('"')) or (p.startswith("'") and p.endswith("'")):
        p = p[1:-1].strip()

    p = _unescape_macos_dragdrop(p)

    # Preserve UNC paths
    if p.startswith("\\\\"):
        return p

    p = os.path.expanduser(p)
    p = os.path.abspath(p)
    return p


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def now_stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def should_ignore(relpath: str) -> bool:
    base = os.path.basename(relpath)
    if base in IGNORE_BASENAMES:
        return True
    if any(base.startswith(p) for p in IGNORE_PREFIXES):
        return True
    return False


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def write_manifest(manifest_path: str, manifest: dict) -> None:
    os.makedirs(os.path.dirname(manifest_path), exist_ok=True)
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)


def compute_objects_checksums(objects_dir: str) -> dict[str, str]:
    """
    Compute SHA-256 checksums for all files in objects/ directory,
    excluding submissionDocumentation and junk files.
    Returns dict: {relative_path: sha256_hash}
    """
    checksums: dict[str, str] = {}

    for root, dirs, files in os.walk(objects_dir):
        if "submissionDocumentation" in dirs:
            dirs.remove("submissionDocumentation")

        for filename in files:
            file_path = os.path.join(root, filename)
            rel_path = os.path.relpath(file_path, objects_dir).replace(os.sep, "/")
            if should_ignore(rel_path):
                continue
            try:
                checksums[rel_path] = sha256_file(file_path)
            except Exception as e:
                print(f"  Warning: Could not hash {rel_path}: {e}")

    return checksums


def compute_objects_file_list(objects_dir: str) -> list[tuple[str, str]]:
    """
    Return sorted list of (relpath, sha256) for all files under objects_dir,
    excluding submissionDocumentation and junk files.
    relpath is relative to objects_dir, using forward slashes.
    """
    items: list[tuple[str, str]] = []
    for root, dirs, files in os.walk(objects_dir):
        if "submissionDocumentation" in dirs:
            dirs.remove("submissionDocumentation")

        for name in files:
            full = os.path.join(root, name)
            rel = os.path.relpath(full, objects_dir).replace(os.sep, "/")
            if should_ignore(rel):
                continue
            items.append((rel, sha256_file(full)))

    items.sort()
    return items


def create_minimal_manifest(package_dir: str, logs_dir: str) -> str:
    os.makedirs(logs_dir, exist_ok=True)
    manifest_path = os.path.join(logs_dir, f"package_manifest_{now_stamp()}.json")
    package_name_guess = os.path.basename(os.path.normpath(package_dir))

    manifest = {
        "package_name": package_name_guess,
        "created": now_iso(),
        "status": {
            "overall": "LOCAL_ONLY",
            "files_listed": False,
            "zip_created": False,
            "remote_upload_attempted": False,
            "remote_verified": False,
        },
        "zip": {},
        "chain_of_custody": [],
    }
    write_manifest(manifest_path, manifest)
    return manifest_path


# ----- manifest discovery -----
def parse_stamp_from_filename(fname: str):
    m = MANIFEST_REGEX.match(fname)
    if not m:
        return None
    stamp = m.group(1)
    try:
        return datetime.strptime(stamp, "%Y%m%d_%H%M%S")
    except Exception:
        return None


def find_manifest_in_logs(logs_dir: str):
    if not os.path.isdir(logs_dir):
        return None
    candidates: list[str] = []
    for name in os.listdir(logs_dir):
        if not name.lower().startswith("package_manifest_") or not name.lower().endswith(".json"):
            continue
        candidates.append(os.path.join(logs_dir, name))
    if not candidates:
        return None

    parsed: list[tuple[datetime, str]] = []
    for path in candidates:
        dt = parse_stamp_from_filename(os.path.basename(path))
        if dt:
            parsed.append((dt, path))

    if parsed:
        parsed.sort(key=lambda x: x[0], reverse=True)
        return parsed[0][1]

    candidates.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    return candidates[0]


def find_all_json_manifests(package_dir: str) -> list[str]:
    candidates: list[str] = []
    for root, _, files in os.walk(package_dir):
        for name in files:
            if name.lower().endswith(".json"):
                candidates.append(os.path.join(root, name))
    return candidates


def find_packages_in_parent(parent_dir: str) -> list[str]:
    packages: list[str] = []
    if not os.path.isdir(parent_dir):
        return packages

    for item in os.listdir(parent_dir):
        item_path = os.path.join(parent_dir, item)
        if os.path.isdir(item_path):
            objects_dir = os.path.join(item_path, "objects")
            if os.path.isdir(objects_dir):
                packages.append(item_path)

    return sorted(packages)


# ----- SFTP helpers -----
def ensure_remote_dir_sftp(sftp, remote_dir: str) -> None:
    remote_dir = remote_dir.replace("\\", "/").rstrip("/")
    if not remote_dir:
        return
    parts: list[str] = []
    d = remote_dir
    while d not in ("", "/"):
        parts.append(d)
        d = posixpath.dirname(d)
    parts.reverse()
    for part in parts:
        try:
            sftp.stat(part)
        except Exception:
            try:
                sftp.mkdir(part)
            except Exception:
                pass
                
def safe_copy_file(src: str, dest: str) -> None:
    """
    Copy a file reliably to network volumes on macOS.
    copy2() may fail trying to apply chflags/copy extended metadata.
    This function falls back to a plain byte copy.
    """
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    try:
        shutil.copy2(src, dest)  # best effort
    except OSError:
        # No metadata preservation; just copy bytes (works on SMB/NFS)
        shutil.copyfile(src, dest)

def sha256_file_remote_sftp(sftp, remote_path: str) -> str:
    h = hashlib.sha256()
    with sftp.open(remote_path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def upload_file_tree_sftp(sftp, local_root: str, remote_root: str) -> None:
    local_root = os.path.normpath(local_root)
    for root, dirs, files in os.walk(local_root):
        if "submissionDocumentation" in dirs:
            dirs.remove("submissionDocumentation")

        rel_root = os.path.relpath(root, local_root)
        remote_dir = remote_root if rel_root in (".",) else posixpath.join(remote_root, rel_root.replace(os.sep, "/"))
        ensure_remote_dir_sftp(sftp, remote_dir)

        for name in files:
            local_file = os.path.join(root, name)
            rel = os.path.relpath(local_file, local_root).replace(os.sep, "/")
            if should_ignore(rel):
                continue
            remote_file = posixpath.join(remote_dir, name)
            print(f"  Uploading: {local_file} -> {remote_file}")
            sftp.put(local_file, remote_file)


def compute_remote_objects_file_list_sftp(sftp, remote_objects_dir: str) -> list[tuple[str, str]]:
    import stat as _stat

    results: list[tuple[str, str]] = []

    def _walk(rpath: str, base: str):
        try:
            entries = sftp.listdir_attr(rpath)
        except IOError:
            return

        for e in entries:
            name = e.filename
            full = posixpath.join(rpath, name)

            if _stat.S_ISDIR(e.st_mode):
                if name == "submissionDocumentation":
                    continue
                _walk(full, base)
            else:
                rel = posixpath.relpath(full, base).replace("\\", "/")
                if should_ignore(rel):
                    continue
                s = sha256_file_remote_sftp(sftp, full)
                results.append((rel, s))

    _walk(remote_objects_dir, remote_objects_dir)
    results.sort()
    return results


# ----- local copy helpers -----
def rsync_copy(src: str, dest: str) -> None:
    src_slash = os.path.join(src, "")
    os.makedirs(dest, exist_ok=True)
    cmd = ["rsync", "-av", "--exclude", "submissionDocumentation", src_slash, dest]
    preview = " ".join(shlex.quote(c) for c in cmd)
    print("\n  Running rsync (preview):")
    print("    ", preview)
    subprocess.run(cmd, check=True)


def copy_tree_shutil(src: str, dest: str) -> None:
    if not os.path.exists(dest):
        os.makedirs(dest, exist_ok=True)
    for item in os.listdir(src):
        if item == "submissionDocumentation":
            continue
        s = os.path.join(src, item)
        d = os.path.join(dest, item)
        if os.path.isdir(s):
            if os.path.exists(d):
                shutil.rmtree(d)
            shutil.copytree(s, d)
        else:
            if should_ignore(item):
                continue
            shutil.copy2(s, d)


# ----- diagnostics helpers -----
def write_hash_list_to_file(path: str, items: list[tuple[str, str]]) -> None:
    items_sorted = sorted(items, key=lambda x: x[0])
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for rel, sha in items_sorted:
            f.write(f"{sha}  {rel}\n")


def write_differences_json(path: str, only_local: list[str], only_remote: list[str], mismatched: list[dict]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    payload = {"only_local": only_local, "only_remote": only_remote, "mismatched": mismatched}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def generate_diagnostics(logs_dir: str, local_items: list[tuple[str, str]], remote_items: list[tuple[str, str]]):
    os.makedirs(logs_dir, exist_ok=True)
    stamp = now_stamp()
    local_path = os.path.join(logs_dir, f"local_hashes_{stamp}.txt")
    remote_path = os.path.join(logs_dir, f"remote_hashes_{stamp}.txt")
    diff_path = os.path.join(logs_dir, f"differences_{stamp}.json")

    write_hash_list_to_file(local_path, local_items)
    write_hash_list_to_file(remote_path, remote_items)

    local_map = {rel: sha for rel, sha in local_items}
    remote_map = {rel: sha for rel, sha in remote_items}

    only_local = sorted([r for r in local_map.keys() if r not in remote_map])
    only_remote = sorted([r for r in remote_map.keys() if r not in local_map])

    mismatched: list[dict] = []
    for rel in sorted(set(local_map.keys()) & set(remote_map.keys())):
        if local_map[rel] != remote_map[rel]:
            mismatched.append({"relpath": rel, "local_sha": local_map[rel], "remote_sha": remote_map[rel]})

    write_differences_json(diff_path, only_local, only_remote, mismatched)
    return local_path, remote_path, diff_path


# ----- byte-level compare helpers -----
def compare_local_and_remote_bytes_local(local_path: str, remote_path: str, logs_dir: str):
    os.makedirs(logs_dir, exist_ok=True)
    local_size = os.path.getsize(local_path)
    remote_size = os.path.getsize(remote_path)
    first_diff = None
    offset = 0

    with open(local_path, "rb") as lf, open(remote_path, "rb") as rf:
        while True:
            lb = lf.read(CHUNK_SIZE)
            rb = rf.read(CHUNK_SIZE)
            if not lb and not rb:
                break
            if lb != rb:
                for i, (a, b) in enumerate(zip(lb, rb)):
                    if a != b:
                        first_diff = {
                            "offset": offset + i,
                            "local_byte": format(a, "02x"),
                            "remote_byte": format(b, "02x"),
                        }
                        break
                if first_diff:
                    break
            offset += len(lb)

    diff_file = os.path.join(logs_dir, f"byte_diff_{now_stamp()}.txt")
    with open(diff_file, "w", encoding="utf-8") as f:
        f.write(f"local_path: {local_path}\n")
        f.write(f"remote_path: {remote_path}\n")
        f.write(f"local_size: {local_size}\n")
        f.write(f"remote_size: {remote_size}\n\n")
        if first_diff:
            f.write("FIRST DIFFERENCE:\n")
            f.write(json.dumps(first_diff, indent=2))
            f.write("\n")
        else:
            f.write("No difference found in streaming compare (unexpected if SHAs differ)\n")

    return first_diff, diff_file


def compare_local_and_remote_bytes_sftp(sftp, local_path: str, remote_path: str, logs_dir: str):
    os.makedirs(logs_dir, exist_ok=True)
    local_size = os.path.getsize(local_path)
    try:
        remote_stat = sftp.stat(remote_path)
        remote_size = remote_stat.st_size
    except Exception:
        remote_size = None

    first_diff = None
    offset = 0
    with open(local_path, "rb") as lf:
        rf = sftp.open(remote_path, "rb")
        try:
            while True:
                lb = lf.read(CHUNK_SIZE)
                rb = rf.read(CHUNK_SIZE)
                if not lb and not rb:
                    break
                if lb != rb:
                    for i, (a, b) in enumerate(zip(lb, rb)):
                        if a != b:
                            first_diff = {
                                "offset": offset + i,
                                "local_byte": format(a, "02x"),
                                "remote_byte": format(b, "02x"),
                            }
                            break
                    if first_diff:
                        break
                offset += len(lb)
        finally:
            try:
                rf.close()
            except Exception:
                pass

    diff_file = os.path.join(logs_dir, f"byte_diff_{now_stamp()}.txt")
    with open(diff_file, "w", encoding="utf-8") as f:
        f.write(f"local_path: {local_path}\n")
        f.write(f"remote_path: {remote_path}\n")
        f.write(f"local_size: {local_size}\n")
        f.write(f"remote_size: {remote_size}\n\n")
        if first_diff:
            f.write("FIRST DIFFERENCE:\n")
            f.write(json.dumps(first_diff, indent=2))
            f.write("\n")
        else:
            f.write("No difference found in streaming compare (unexpected if SHAs differ)\n")

    return first_diff, diff_file


# ----- chain of custody -----
def add_custody_event(
    manifest: dict,
    transfer_agent: str | None,
    source: str | None,
    method: str,
    src: str,
    dest: str,
    verified: bool,
    notes: str | None,
    config_used: str | None = None,
    sha256_local: str | None = None,
    sha256_remote: str | None = None,
    verification: str | None = None,
    file_count_local: int | None = None,
    file_count_remote: int | None = None,
    mismatch_report: str | None = None,
):
    event = {
        "timestamp": now_iso(),
        "transfer_agent": transfer_agent or None,
        "source": source or None,
        "method": method,
        "src_path": src,
        "dest_path": dest,
        "verified": bool(verified),
        "notes": notes or None,
        "config": config_used,
        # hash fields are ONLY hashes now (or None)
        "sha256_local": sha256_local,
        "sha256_remote": sha256_remote,
        # directory verification metadata
        "verification": verification,
        "file_count_local": file_count_local,
        "file_count_remote": file_count_remote,
        "mismatch_report": mismatch_report,
    }
    manifest.setdefault("chain_of_custody", [])
    manifest["chain_of_custody"].append(event)

    # keep a top-level list of agents used (optional)
    if transfer_agent:
        ta = manifest.get("transfer_agent")
        if ta is None:
            manifest["transfer_agent"] = [transfer_agent]
        else:
            if isinstance(ta, list):
                if transfer_agent not in ta:
                    ta.append(transfer_agent)
            else:
                if ta != transfer_agent:
                    manifest["transfer_agent"] = [ta, transfer_agent]

    if source and not manifest.get("source"):
        manifest["source"] = source


# ----- single package processing -----
def process_single_package(
    package_dir: str,
    transfer_agent: str | None,
    source: str | None,
    method_choice: str,
    notes: str | None,
    cfg: dict | None,
    cfg_path_used: str | None,
    dest_base: str | None,
    sftp=None,
):
    print(f"\n{'='*60}")
    print(f"Processing package: {os.path.basename(package_dir)}")
    print(f"{'='*60}")

    objects_dir = os.path.join(package_dir, "objects")
    logs_dir = os.path.join(objects_dir, "submissionDocumentation", "aa_logs")

    if not os.path.isdir(objects_dir):
        return False, f"objects/ directory not found in {package_dir}"

    manifest_auto = find_manifest_in_logs(logs_dir)
    if manifest_auto:
        manifest_path = manifest_auto
        print(f"  Found manifest: {os.path.basename(manifest_path)}")
    else:
        print("  Manifest not found in standard location, searching...")
        all_json = find_all_json_manifests(package_dir)
        if all_json:
            manifest_path = all_json[0]
            print(f"  Using: {os.path.relpath(manifest_path, package_dir)}")
        else:
            manifest_path = create_minimal_manifest(package_dir, logs_dir)
            print(f"  Created new manifest: {os.path.basename(manifest_path)}")

    if not os.path.isfile(manifest_path):
        return False, f"Manifest file not accessible: {manifest_path}"

    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    except Exception as e:
        return False, f"Failed to read manifest: {e}"

    package_name = manifest.get("package_name") or os.path.basename(os.path.normpath(package_dir))

    # Compute and store checksums for manifest (objects only)
    print("  Computing file checksums for manifest...")
    checksums = compute_objects_checksums(objects_dir)
    manifest["file_checksums"] = checksums
    manifest.setdefault("checksum_info", {})
    manifest["checksum_info"]["algorithm"] = "SHA-256"
    manifest["checksum_info"]["timestamp"] = now_iso()
    manifest["checksum_info"]["file_count"] = len(checksums)
    print(f"  Computed checksums for {len(checksums)} file(s)")

    # Choose source: prefer zip if present and exists
    zip_info = manifest.get("zip")
    zip_local_path = None
    if isinstance(zip_info, dict) and zip_info.get("local_path"):
        zip_local_path = normalize_path(str(zip_info.get("local_path")))

    if zip_local_path and os.path.isfile(zip_local_path):
        source_is_zip = True
        local_source_path = zip_local_path
        print(f"  Will transfer ZIP: {os.path.basename(local_source_path)}")
    else:
        source_is_zip = False
        local_source_path = objects_dir
        print("  Will transfer objects/ directory")

    manifest.setdefault("status", manifest.get("status") or {})
    manifest["status"].setdefault("remote_upload_attempted", False)
    manifest["status"].setdefault("remote_verified", False)

    method_str = "sftp" if method_choice == "1" else "local_copy"

    # --- SFTP branch ---
    if method_choice == "1":
        if sftp is None:
            return False, "SFTP connection not available"

        remote_package_dir = posixpath.join(cfg["remote_parent"], package_name)
        remote_objects_dir = posixpath.join(remote_package_dir, "objects")
        remote_logs_dir = posixpath.join(remote_objects_dir, "submissionDocumentation", "aa_logs")
        remote_manifest_path = posixpath.join(remote_logs_dir, os.path.basename(manifest_path))

        try:
            ensure_remote_dir_sftp(sftp, remote_objects_dir)
            ensure_remote_dir_sftp(sftp, remote_logs_dir)

            if source_is_zip:
                remote_zip_path = posixpath.join(remote_objects_dir, os.path.basename(local_source_path))
                print("  Uploading ZIP to remote...")
                sftp.put(local_source_path, remote_zip_path)

                print("  Computing SHAs...")
                local_sha = sha256_file(local_source_path)
                remote_sha = sha256_file_remote_sftp(sftp, remote_zip_path)
                verified = (local_sha == remote_sha)
                print(f"  Local SHA-256:  {local_sha}")
                print(f"  Remote SHA-256: {remote_sha}")
                print(f"  Verified:       {'PASS' if verified else 'FAIL'}")

                add_custody_event(
                    manifest=manifest,
                    transfer_agent=transfer_agent,
                    source=source,
                    method=method_str,
                    src=local_source_path,
                    dest=remote_zip_path,
                    verified=verified,
                    notes=notes,
                    config_used=cfg_path_used,
                    sha256_local=local_sha,
                    sha256_remote=remote_sha,
                    verification="sha256_file",
                )

                manifest["status"]["remote_upload_attempted"] = True
                manifest["status"]["remote_verified"] = bool(verified)
                if verified and manifest["status"].get("files_listed") and manifest["status"].get("zip_created"):
                    manifest["status"]["overall"] = "PASS"

                write_manifest(manifest_path, manifest)

                print("  Uploading manifest to remote...")
                sftp.put(manifest_path, remote_manifest_path)

                local_items = [(os.path.basename(local_source_path), local_sha)]
                remote_items = [(os.path.basename(remote_zip_path), remote_sha)]
                generate_diagnostics(logs_dir, local_items, remote_items)

                if not verified:
                    compare_local_and_remote_bytes_sftp(sftp, local_source_path, remote_zip_path, logs_dir)
                    print("  WARNING: Verification FAILED - diagnostics written to logs")
                    return False, "Verification failed (ZIP SHA mismatch)"

            else:
                print("  Uploading directory tree to remote...")
                upload_file_tree_sftp(sftp, local_source_path, remote_objects_dir)

                print("  Verifying per-file SHA-256 in objects/ (excluding submissionDocumentation + junk files)...")
                local_items = compute_objects_file_list(local_source_path)
                remote_items = compute_remote_objects_file_list_sftp(sftp, remote_objects_dir)
                verified = (dict(local_items) == dict(remote_items))

                print(f"  Verified:           {'PASS' if verified else 'FAIL'}")
                print(f"  Local files hashed:  {len(local_items)}")
                print(f"  Remote files hashed: {len(remote_items)}")

                mismatch_report = None
                if not verified:
                    _, _, mismatch_report = generate_diagnostics(logs_dir, local_items, remote_items)

                add_custody_event(
                    manifest=manifest,
                    transfer_agent=transfer_agent,
                    source=source,
                    method=method_str,
                    src=local_source_path,
                    dest=remote_objects_dir,
                    verified=verified,
                    notes=notes,
                    config_used=cfg_path_used,
                    sha256_local=None,
                    sha256_remote=None,
                    verification="per_file_sha256",
                    file_count_local=len(local_items),
                    file_count_remote=len(remote_items),
                    mismatch_report=mismatch_report,
                )

                manifest["status"]["remote_upload_attempted"] = True
                manifest["status"]["remote_verified"] = bool(verified)
                if verified and manifest["status"].get("files_listed"):
                    manifest["status"]["overall"] = "PASS"

                write_manifest(manifest_path, manifest)

                print("  Uploading manifest to remote...")
                sftp.put(manifest_path, remote_manifest_path)

                if not verified:
                    print("  WARNING: Verification FAILED - diagnostics written to logs")
                    return False, "Verification failed (per-file SHA mismatch)"

        except Exception as e:
            traceback.print_exc()
            add_custody_event(
                manifest=manifest,
                transfer_agent=transfer_agent,
                source=source,
                method=method_str,
                src=local_source_path,
                dest=remote_package_dir,
                verified=False,
                notes=f"{notes} | error: {e}" if notes else f"error: {e}",
                config_used=cfg_path_used,
            )
            write_manifest(manifest_path, manifest)
            return False, f"SFTP transfer error: {e}"

    # --- Local copy branch ---
    else:
        remote_package_dir = os.path.join(dest_base, package_name)
        remote_objects_dir = os.path.join(remote_package_dir, "objects")
        remote_logs_dir = os.path.join(remote_objects_dir, "submissionDocumentation", "aa_logs")
        remote_manifest_path = os.path.join(remote_logs_dir, os.path.basename(manifest_path))

        try:
            os.makedirs(remote_objects_dir, exist_ok=True)
            os.makedirs(remote_logs_dir, exist_ok=True)

            if source_is_zip:
                dest_zip_path = os.path.join(remote_objects_dir, os.path.basename(local_source_path))
                print("  Copying ZIP to destination...")
                shutil.copy2(local_source_path, dest_zip_path)

                local_sha = sha256_file(local_source_path)
                remote_sha = sha256_file(dest_zip_path)
                verified = (local_sha == remote_sha)

                print(f"  Local SHA-256:  {local_sha}")
                print(f"  Dest SHA-256:   {remote_sha}")
                print(f"  Verified:       {'PASS' if verified else 'FAIL'}")

                add_custody_event(
                    manifest=manifest,
                    transfer_agent=transfer_agent,
                    source=source,
                    method=method_str,
                    src=local_source_path,
                    dest=dest_zip_path,
                    verified=verified,
                    notes=notes,
                    config_used=dest_base,
                    sha256_local=local_sha,
                    sha256_remote=remote_sha,
                    verification="sha256_file",
                )

                manifest["status"]["remote_upload_attempted"] = True
                manifest["status"]["remote_verified"] = bool(verified)
                if verified and manifest["status"].get("files_listed") and manifest["status"].get("zip_created"):
                    manifest["status"]["overall"] = "PASS"

                write_manifest(manifest_path, manifest)
                safe_copy_file(manifest_path, remote_manifest_path)

                if not verified:
                    local_items = [(os.path.basename(local_source_path), local_sha)]
                    remote_items = [(os.path.basename(dest_zip_path), remote_sha)]
                    generate_diagnostics(logs_dir, local_items, remote_items)
                    compare_local_and_remote_bytes_local(local_source_path, dest_zip_path, logs_dir)
                    print("  WARNING: Verification FAILED - diagnostics written to logs")
                    return False, "Verification failed (ZIP SHA mismatch)"

            else:
                try:
                    print("  Attempting rsync copy...")
                    rsync_copy(local_source_path, remote_objects_dir)
                except Exception as e:
                    print(f"  rsync failed: {e}, falling back to shutil copy")
                    copy_tree_shutil(local_source_path, remote_objects_dir)

                print("  Verifying per-file SHA-256 in objects/ (excluding submissionDocumentation + junk files)...")
                local_items = compute_objects_file_list(local_source_path)
                remote_items = compute_objects_file_list(remote_objects_dir)
                verified = (dict(local_items) == dict(remote_items))

                print(f"  Verified:           {'PASS' if verified else 'FAIL'}")
                print(f"  Local files hashed: {len(local_items)}")
                print(f"  Dest files hashed:  {len(remote_items)}")

                mismatch_report = None
                if not verified:
                    _, _, mismatch_report = generate_diagnostics(logs_dir, local_items, remote_items)

                add_custody_event(
                    manifest=manifest,
                    transfer_agent=transfer_agent,
                    source=source,
                    method=method_str,
                    src=local_source_path,
                    dest=remote_objects_dir,
                    verified=verified,
                    notes=notes,
                    config_used=dest_base,
                    sha256_local=None,
                    sha256_remote=None,
                    verification="per_file_sha256",
                    file_count_local=len(local_items),
                    file_count_remote=len(remote_items),
                    mismatch_report=mismatch_report,
                )

                manifest["status"]["remote_upload_attempted"] = True
                manifest["status"]["remote_verified"] = bool(verified)
                if verified and manifest["status"].get("files_listed"):
                    manifest["status"]["overall"] = "PASS"

                write_manifest(manifest_path, manifest)
                safe_copy_file(manifest_path, remote_manifest_path)

                if not verified:
                    print("  WARNING: Verification FAILED - diagnostics written to logs")
                    return False, "Verification failed (per-file SHA mismatch)"

        except FileNotFoundError:
            return False, "rsync not found on PATH."
        except subprocess.CalledProcessError as e:
            return False, f"rsync failed with exit code {e.returncode}"
        except Exception as e:
            traceback.print_exc()
            add_custody_event(
                manifest=manifest,
                transfer_agent=transfer_agent,
                source=source,
                method=method_str,
                src=local_source_path,
                dest=remote_objects_dir if "remote_objects_dir" in locals() else "",
                verified=False,
                notes=f"{notes} | error: {e}" if notes else f"error: {e}",
                config_used=dest_base,
            )
            write_manifest(manifest_path, manifest)
            return False, f"Local copy error: {e}"

    print("  ✓ Package processed successfully")
    return True, None


# ----- main flow -----
def main():
    print("\n=== BATCH SEND & VERIFY (per-file SHA verification for directory transfers) ===\n")

    batch_mode = input("Process multiple packages? [Y/n]: ").strip().lower() in ("", "y", "yes")
    packages_to_process: list[str] = []

    if batch_mode:
        parent_dir = normalize_path(input("Enter or drag the PARENT directory containing package folders: ").strip())
        if not parent_dir or not os.path.isdir(parent_dir):
            print("ERROR: invalid parent directory.")
            return

        packages_to_process = find_packages_in_parent(parent_dir)
        if not packages_to_process:
            print("ERROR: No packages found (no subdirectories with objects/ folder)")
            return

        print(f"\nFound {len(packages_to_process)} package(s):")
        for i, pkg in enumerate(packages_to_process, 1):
            print(f"  {i}. {os.path.basename(pkg)}")

        confirm = input(f"\nProcess all {len(packages_to_process)} packages? [Y/n]: ").strip().lower()
        if confirm not in ("", "y", "yes"):
            print("Cancelled.")
            return
    else:
        package_dir = normalize_path(input("Enter or drag the PACKAGE directory (that contains objects/): ").strip())
        if not package_dir or not os.path.isdir(package_dir):
            print("ERROR: invalid package directory.")
            return
        packages_to_process = [package_dir]

    transfer_agent = input("Transfer agent (your name/initials) [optional]: ").strip() or None
    source = input("Source (free text, e.g., workstation/NAS/project) [optional]: ").strip() or None
    notes = input("Notes (free text) [optional]: ").strip() or None

    print("\nTransfer methods:\n  1) SFTP\n  2) Local network copy (mounted or UNC path)")
    method_choice = input("Choose transfer method [1/2] (default 1): ").strip() or "1"

    cfg = None
    cfg_path_used = None
    dest_base = None
    sftp = None
    transport = None

    if method_choice == "1":
        if paramiko is None:
            print("ERROR: paramiko not installed. pip install paramiko and try again.")
            return

        use_config = input(f"Use SFTP config file [{SFTP_CONFIG_PATH}]? [Y/n]: ").strip().lower()
        if use_config in ("", "y", "yes") and os.path.exists(SFTP_CONFIG_PATH):
            try:
                with open(SFTP_CONFIG_PATH, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                cfg_path_used = SFTP_CONFIG_PATH
                print(f"Loaded SFTP config from {SFTP_CONFIG_PATH}")
            except Exception as e:
                print(f"Warning: could not read config: {e}")
                cfg = None

        if cfg is None:
            raw_host = input("SFTP host (hostname or IP): ").strip()
            if raw_host.lower().startswith(("sftp://", "ssh://")):
                raw_host = raw_host.split("://", 1)[1].split("/", 1)[0]
            port_str = input("SFTP port [22]: ").strip()
            username = input("SFTP username: ").strip()
            password = getpass.getpass("SFTP password: ")
            remote_parent = input("Remote parent directory for packages (e.g. /sftp-transfer-source): ").strip()
            try:
                port = int(port_str) if port_str else 22
            except Exception:
                port = 22
            cfg = {
                "host": raw_host,
                "port": port,
                "username": username,
                "password": password,
                "remote_parent": remote_parent,
            }
            cfg_path_used = None

        if not cfg.get("remote_parent"):
            cfg["remote_parent"] = input("Remote parent directory on server (e.g. /sftp-transfer-source): ").strip()

        print("\nConnecting to SFTP...")
        try:
            transport = paramiko.Transport((cfg["host"], int(cfg["port"])))
            transport.connect(username=cfg["username"], password=cfg["password"])
            sftp = paramiko.SFTPClient.from_transport(transport)
            print("SFTP connection established.\n")
        except Exception as e:
            print(f"ERROR connecting to SFTP: {e}")
            traceback.print_exc()
            return

    else:
        dest_base = normalize_path(
            input("Enter destination base directory (mounted path or UNC, e.g. \\\\server\\share\\folder): ").strip()
        )
        if not dest_base:
            print("ERROR: destination required.")
            return

    results = []
    for package_dir in packages_to_process:
        success, error = process_single_package(
            package_dir=package_dir,
            transfer_agent=transfer_agent,
            source=source,
            method_choice=method_choice,
            notes=notes,
            cfg=cfg,
            cfg_path_used=cfg_path_used,
            dest_base=dest_base,
            sftp=sftp,
        )
        results.append({"package": os.path.basename(package_dir), "success": success, "error": error})

    if sftp:
        try:
            sftp.close()
        except Exception:
            pass
    if transport:
        try:
            transport.close()
        except Exception:
            pass

    print("\n" + "=" * 60)
    print("BATCH TRANSFER SUMMARY")
    print("=" * 60)

    successful = [r for r in results if r["success"]]
    failed = [r for r in results if not r["success"]]

    print(f"\nTotal packages: {len(results)}")
    print(f"Successful: {len(successful)}")
    print(f"Failed: {len(failed)}")

    if successful:
        print("\n✓ Successful transfers:")
        for r in successful:
            print(f"  - {r['package']}")

    if failed:
        print("\n✗ Failed transfers:")
        for r in failed:
            print(f"  - {r['package']}: {r['error']}")

    print("\nDone.\n")


if __name__ == "__main__":
    main()
