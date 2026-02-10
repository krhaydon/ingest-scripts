#!/usr/bin/env python3
"""
send_and_record_transfer.py (batch mode with byte-level diagnostics)

- Supports processing multiple packages in a single run
- When a single-file (ZIP) transfer fails verification, the script will:
  * compute and print sizes + SHAs
  * run a byte-by-byte comparison (streamed) between local and remote files
    - for SFTP: stream remote file via paramiko and compare to local bytes
    - for local copy: compare two local files
  * write byte-diff details to objects/submissionDocumentation/aa_logs/byte_diff_<stamp>.txt
  * still produce local_hashes_*, remote_hashes_*, differences_*.json
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


# ----- utilities -----
def normalize_path(p: str) -> str:
    """
    Normalize user input path:
      - strip surrounding whitespace and quotes
      - convert drag-and-drop escaped spaces (e.g. '\ ') to real spaces
      - expand ~ and return absolute path
    """
    if not p:
        return p
    p = p.strip().strip('"').strip("'")
    # Unescape drag-and-drop escaped spaces (e.g., /Users/me/My\ Folder)
    p = p.replace("\\ ", " ")
    return os.path.abspath(os.path.expanduser(p))


def now_iso():
    return datetime.now().isoformat(timespec="seconds")


def now_stamp():
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def write_manifest(manifest_path: str, manifest: dict):
    os.makedirs(os.path.dirname(manifest_path), exist_ok=True)
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)


def compute_objects_checksums(objects_dir: str):
    """
    Compute SHA-256 checksums for all files in objects/ directory,
    excluding submissionDocumentation folder.
    Returns dict: {relative_path: sha256_hash}
    """
    checksums = {}
    
    for root, dirs, files in os.walk(objects_dir):
        # Skip submissionDocumentation folder
        if 'submissionDocumentation' in dirs:
            dirs.remove('submissionDocumentation')
        
        for filename in files:
            file_path = os.path.join(root, filename)
            rel_path = os.path.relpath(file_path, objects_dir).replace(os.sep, "/")
            
            try:
                sha = sha256_file(file_path)
                checksums[rel_path] = sha
            except Exception as e:
                print(f"  Warning: Could not hash {rel_path}: {e}")
    
    return checksums


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
    candidates = []
    for name in os.listdir(logs_dir):
        if not name.lower().startswith("package_manifest_") or not name.lower().endswith(".json"):
            continue
        candidates.append(os.path.join(logs_dir, name))
    if not candidates:
        return None
    parsed = []
    for path in candidates:
        dt = parse_stamp_from_filename(os.path.basename(path))
        if dt:
            parsed.append((dt, path))
    if parsed:
        parsed.sort(key=lambda x: x[0], reverse=True)
        return parsed[0][1]
    candidates.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    return candidates[0]


def find_all_json_manifests(package_dir: str):
    """Recursively search for any .json files that might be manifests."""
    candidates = []
    for root, dirs, files in os.walk(package_dir):
        for name in files:
            if name.lower().endswith(".json"):
                full_path = os.path.join(root, name)
                candidates.append(full_path)
    return candidates


def find_packages_in_parent(parent_dir: str):
    """Find all subdirectories in parent_dir that contain an objects/ folder."""
    packages = []
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
def ensure_remote_dir_sftp(sftp, remote_dir: str):
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
        except Exception:
            try:
                sftp.mkdir(part)
            except Exception:
                pass


def sha256_file_remote_sftp(sftp, remote_path: str) -> str:
    h = hashlib.sha256()
    with sftp.open(remote_path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def upload_file_tree_sftp(sftp, local_root: str, remote_root: str):
    local_root = os.path.normpath(local_root)
    for root, dirs, files in os.walk(local_root):
        rel_root = os.path.relpath(root, local_root)
        if rel_root in (".",):
            remote_dir = remote_root
        else:
            remote_dir = posixpath.join(remote_root, rel_root.replace(os.sep, "/"))
        ensure_remote_dir_sftp(sftp, remote_dir)
        for name in files:
            local_file = os.path.join(root, name)
            remote_file = posixpath.join(remote_dir, name)
            print(f"  Uploading: {local_file} -> {remote_file}")
            sftp.put(local_file, remote_file)


def walk_remote_files_sftp(sftp, remote_root: str):
    """Return list of (relpath, sha256) for files under remote_root using recursion."""
    import stat as _stat

    results = []

    def _walk(rpath, base):
        try:
            entries = sftp.listdir_attr(rpath)
        except IOError:
            return
        for e in entries:
            name = e.filename
            full = posixpath.join(rpath, name)
            if _stat.S_ISDIR(e.st_mode):
                _walk(full, base)
            else:
                rel = posixpath.relpath(full, base).replace("\\", "/")
                s = sha256_file_remote_sftp(sftp, full)
                results.append((rel, s))

    _walk(remote_root, remote_root)
    return results


# ----- local copy helpers -----
def rsync_copy(src: str, dest: str):
    src_slash = os.path.join(src, "")
    os.makedirs(dest, exist_ok=True)
    cmd = ["rsync", "-av", "--exclude", "submissionDocumentation", src_slash, dest]
    preview = " ".join(shlex.quote(c) for c in cmd)
    print("\n  Running rsync (preview):")
    print("    ", preview)
    try:
        subprocess.run(cmd, check=True)
    except FileNotFoundError:
        raise RuntimeError("rsync not found on PATH.")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"rsync failed with exit code {e.returncode}")


def copy_tree_shutil(src: str, dest: str):
    if not os.path.exists(dest):
        os.makedirs(dest, exist_ok=True)
    for item in os.listdir(src):
        s = os.path.join(src, item)
        d = os.path.join(dest, item)
        if os.path.isdir(s):
            if os.path.exists(d):
                shutil.rmtree(d)
            shutil.copytree(s, d)
        else:
            shutil.copy2(s, d)


# ----- tree digest helpers (stable ordering) -----
def compute_local_tree_digest(root: str):
    items = []
    for root_, _, files in os.walk(root):
        for name in files:
            full = os.path.join(root_, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            s = sha256_file(full)
            items.append((rel, s))
    items.sort()
    h = hashlib.sha256()
    for rel, s in items:
        h.update(rel.encode("utf-8") + b"\0" + s.encode("utf-8"))
    return h.hexdigest(), items


def compute_remote_tree_digest_sftp(sftp, remote_root: str):
    items = walk_remote_files_sftp(sftp, remote_root)
    items.sort()
    h = hashlib.sha256()
    for rel, s in items:
        h.update(rel.encode("utf-8") + b"\0" + s.encode("utf-8"))
    return h.hexdigest(), items


# ----- diagnostics helpers (existing) -----
def write_hash_list_to_file(path: str, items: list[tuple[str, str]]):
    items_sorted = sorted(items, key=lambda x: x[0])
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for rel, sha in items_sorted:
            f.write(f"{sha}  {rel}\n")


def write_differences_json(path: str, only_local: list[str], only_remote: list[str], mismatched: list[dict]):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    payload = {"only_local": only_local, "only_remote": only_remote, "mismatched": mismatched}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def generate_diagnostics(logs_dir: str, local_items: list[tuple[str, str]], remote_items: list[tuple[str, str]]):
    os.makedirs(logs_dir, exist_ok=True)
    local_path = os.path.join(logs_dir, f"local_hashes_{now_stamp()}.txt")
    remote_path = os.path.join(logs_dir, f"remote_hashes_{now_stamp()}.txt")
    diff_path = os.path.join(logs_dir, f"differences_{now_stamp()}.json")

    write_hash_list_to_file(local_path, local_items)
    write_hash_list_to_file(remote_path, remote_items)

    local_map = {rel: sha for rel, sha in local_items}
    remote_map = {rel: sha for rel, sha in remote_items}

    only_local = sorted([r for r in local_map.keys() if r not in remote_map])
    only_remote = sorted([r for r in remote_map.keys() if r not in local_map])
    mismatched = []
    for rel in sorted(set(local_map.keys()) & set(remote_map.keys())):
        if local_map[rel] != remote_map[rel]:
            mismatched.append({"relpath": rel, "local_sha": local_map[rel], "remote_sha": remote_map[rel]})

    write_differences_json(diff_path, only_local, only_remote, mismatched)
    return local_path, remote_path, diff_path


# ----- byte-level compare helpers (NEW) -----
def compare_local_and_remote_bytes_local(local_path: str, remote_path: str, logs_dir: str, max_diffs: int = 50):
    """Compare two local files in chunks; return first_diff_info and write byte-diff file."""
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
                # find first differing byte within these blocks
                for i, (a, b) in enumerate(zip(lb, rb)):
                    if a != b:
                        first_diff = {"offset": offset + i, "local_byte": format(a, "02x"), "remote_byte": format(b, "02x")}
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
            f.write("\n\n")
        else:
            f.write("No difference found in streaming compare (unexpected if SHAs differ)\n")
    return first_diff, diff_file


def compare_local_and_remote_bytes_sftp(sftp, local_path: str, remote_path: str, logs_dir: str, max_diffs: int = 50):
    """Stream both local file and remote file over SFTP and compare bytes. Return first_diff and path to diff file."""
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
                            first_diff = {"offset": offset + i, "local_byte": format(a, "02x"), "remote_byte": format(b, "02x")}
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
            f.write("\n\n")
        else:
            f.write("No difference found in streaming compare (unexpected if SHAs differ)\n")
    return first_diff, diff_file


# ----- chain of custody -----
def add_custody_event(manifest: dict,
                      transfer_agent: str,
                      method: str,
                      src: str,
                      dest: str,
                      sha256_local: str | None,
                      sha256_remote: str | None,
                      verified: bool,
                      config_used: str | None,
                      notes: str | None):
    event = {
        "timestamp": now_iso(),
        "transfer_agent": transfer_agent,
        "method": method,
        "src_path": src,
        "dest_path": dest,
        "sha256_local": sha256_local,
        "sha256_remote": sha256_remote,
        "verified": bool(verified),
        "config": config_used,
        "notes": notes or None,
    }
    manifest.setdefault("chain_of_custody", [])
    manifest["chain_of_custody"].append(event)
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


# ----- single package processing -----
def process_single_package(package_dir: str, transfer_agent: str, method_choice: str, 
                          notes: str | None, cfg: dict | None, cfg_path_used: str | None,
                          dest_base: str | None, sftp=None):
    """Process a single package transfer. Returns (success: bool, error_msg: str | None)"""
    
    print(f"\n{'='*60}")
    print(f"Processing package: {os.path.basename(package_dir)}")
    print(f"{'='*60}")
    
    objects_dir = os.path.join(package_dir, "objects")
    logs_dir = os.path.join(objects_dir, "submissionDocumentation", "aa_logs")
    
    if not os.path.isdir(objects_dir):
        return False, f"objects/ directory not found in {package_dir}"

    # Find manifest
    manifest_auto = find_manifest_in_logs(logs_dir)
    
    if manifest_auto:
        manifest_path = manifest_auto
        print(f"  Found manifest: {os.path.basename(manifest_path)}")
    else:
        print(f"  Manifest not found in standard location, searching...")
        all_json = find_all_json_manifests(package_dir)
        
        if all_json:
            # Just use the first one found
            manifest_path = all_json[0]
            print(f"  Using: {os.path.relpath(manifest_path, package_dir)}")
        else:
            return False, "No manifest JSON found in package"
    
    if not os.path.isfile(manifest_path):
        return False, f"Manifest file not accessible: {manifest_path}"

    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    except Exception as e:
        return False, f"Failed to read manifest: {e}"

    package_name = manifest.get("package_name") or os.path.basename(os.path.normpath(package_dir))
    
    # Compute and store checksums for all files in objects/ (excluding submissionDocumentation)
    print("  Computing file checksums...")
    checksums = compute_objects_checksums(objects_dir)
    manifest["file_checksums"] = checksums
    manifest.setdefault("checksum_info", {})
    manifest["checksum_info"]["algorithm"] = "SHA-256"
    manifest["checksum_info"]["timestamp"] = now_iso()
    manifest["checksum_info"]["file_count"] = len(checksums)
    print(f"  Computed checksums for {len(checksums)} file(s)")
    
    # Choose source: prefer zip
    zip_info = manifest.get("zip")
    if zip_info and zip_info.get("local_path") and os.path.isfile(zip_info.get("local_path")):
        source_is_zip = True
        local_source_path = normalize_path(zip_info["local_path"])
        print(f"  Will transfer ZIP: {os.path.basename(local_source_path)}")
    else:
        source_is_zip = False
        local_source_path = objects_dir
        print(f"  Will transfer objects/ directory")

    manifest.setdefault("status", manifest.get("status") or {})
    manifest["status"].setdefault("remote_upload_attempted", False)
    manifest["status"].setdefault("remote_verified", False)

    # --- SFTP branch ---
    if method_choice == "1":
        if sftp is None:
            return False, "SFTP connection not available"

        # Build remote paths (posix)
        remote_package_dir = posixpath.join(cfg["remote_parent"], package_name)
        remote_objects_dir = posixpath.join(remote_package_dir, "objects")
        remote_logs_dir = posixpath.join(remote_objects_dir, "submissionDocumentation", "aa_logs")
        remote_manifest_path = posixpath.join(remote_logs_dir, os.path.basename(manifest_path))

        try:
            ensure_remote_dir_sftp(sftp, remote_objects_dir)
            ensure_remote_dir_sftp(sftp, remote_logs_dir)

            if source_is_zip:
                remote_zip_path = posixpath.join(remote_objects_dir, os.path.basename(local_source_path))
                print(f"  Uploading ZIP to remote...")
                sftp.put(local_source_path, remote_zip_path)

                print("  Computing SHAs...")
                local_sha = sha256_file(local_source_path)
                remote_sha = sha256_file_remote_sftp(sftp, remote_zip_path)
                verified = (local_sha == remote_sha)
                print(f"  Local SHA-256:  {local_sha}")
                print(f"  Remote SHA-256: {remote_sha}")
                print(f"  Verified:       {'PASS' if verified else 'FAIL'}")

                add_custody_event(manifest, transfer_agent, "sftp", local_source_path, remote_zip_path, 
                                local_sha, remote_sha, verified, cfg_path_used, notes)
                manifest["status"]["remote_upload_attempted"] = True
                manifest["status"]["remote_verified"] = bool(verified)
                if verified and manifest["status"].get("files_listed") and manifest["status"].get("zip_created"):
                    manifest["status"]["overall"] = "PASS"
                write_manifest(manifest_path, manifest)

                print(f"  Uploading manifest to remote...")
                sftp.put(manifest_path, remote_manifest_path)

                # Always write checksum files for record-keeping
                local_items = [(os.path.basename(local_source_path), local_sha)]
                remote_items = [(os.path.basename(remote_zip_path), remote_sha)]
                local_file, remote_file, diff_file = generate_diagnostics(logs_dir, local_items, remote_items)
                
                if not verified:
                    first_diff, byte_diff_file = compare_local_and_remote_bytes_sftp(sftp, local_source_path, remote_zip_path, logs_dir)
                    print(f"  WARNING: Verification FAILED - diagnostics written to logs")
                    return False, "Verification failed (ZIP SHA mismatch)"
                else:
                    print(f"  Checksum files written to logs")

            else:
                print(f"  Uploading directory tree to remote...")
                upload_file_tree_sftp(sftp, local_source_path, remote_objects_dir)

                print("  Computing combined tree digests...")
                local_digest, local_items = compute_local_tree_digest(local_source_path)
                remote_digest, remote_items = compute_remote_tree_digest_sftp(sftp, remote_objects_dir)
                verified = (local_digest == remote_digest)
                print(f"  Local tree digest:  {local_digest}")
                print(f"  Remote tree digest: {remote_digest}")
                print(f"  Verified:           {'PASS' if verified else 'FAIL'}")

                add_custody_event(manifest, transfer_agent, "sftp", local_source_path, remote_objects_dir, 
                                local_digest, remote_digest, verified, cfg_path_used, notes)
                manifest["status"]["remote_upload_attempted"] = True
                manifest["status"]["remote_verified"] = bool(verified)
                if verified and manifest["status"].get("files_listed"):
                    manifest["status"]["overall"] = "PASS"

                write_manifest(manifest_path, manifest)
                print(f"  Uploading manifest to remote...")
                sftp.put(manifest_path, remote_manifest_path)

                if not verified:
                    local_file, remote_file, diff_file = generate_diagnostics(logs_dir, local_items, remote_items)
                    print(f"  WARNING: Verification FAILED - diagnostics written to logs")
                    return False, "Verification failed (tree digest mismatch)"

        except Exception as e:
            traceback.print_exc()
            add_custody_event(manifest, transfer_agent, "sftp", local_source_path, remote_package_dir, 
                            None, None, False, cfg_path_used, f"error: {e}")
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
                print(f"  Copying ZIP to destination...")
                shutil.copy2(local_source_path, dest_zip_path)

                local_sha = sha256_file(local_source_path)
                remote_sha = sha256_file(dest_zip_path)
                verified = (local_sha == remote_sha)
                print(f"  Local SHA-256:  {local_sha}")
                print(f"  Dest SHA-256:   {remote_sha}")
                print(f"  Verified:       {'PASS' if verified else 'FAIL'}")

                add_custody_event(manifest, transfer_agent, "local_copy", local_source_path, dest_zip_path, 
                                local_sha, remote_sha, verified, dest_base, notes)
                manifest["status"]["remote_upload_attempted"] = True
                manifest["status"]["remote_verified"] = bool(verified)
                if verified and manifest["status"].get("files_listed") and manifest["status"].get("zip_created"):
                    manifest["status"]["overall"] = "PASS"

                write_manifest(manifest_path, manifest)
                shutil.copy2(manifest_path, remote_manifest_path)

                if not verified:
                    local_items = [(os.path.basename(local_source_path), local_sha)]
                    remote_items = [(os.path.basename(dest_zip_path), remote_sha)]
                    local_file, remote_file, diff_file = generate_diagnostics(logs_dir, local_items, remote_items)
                    first_diff, byte_diff_file = compare_local_and_remote_bytes_local(local_source_path, dest_zip_path, logs_dir)
                    print(f"  WARNING: Verification FAILED - diagnostics written to logs")
                    return False, "Verification failed (ZIP SHA mismatch)"

            else:
                try:
                    print("  Attempting rsync copy...")
                    rsync_copy(local_source_path, remote_objects_dir)
                except Exception as e:
                    print(f"  rsync failed: {e}, falling back to shutil copy")
                    copy_tree_shutil(local_source_path, remote_objects_dir)

                print("  Computing combined tree digests...")
                local_digest, local_items = compute_local_tree_digest(local_source_path)
                remote_digest, remote_items = compute_local_tree_digest(remote_objects_dir)
                verified = (local_digest == remote_digest)
                print(f"  Local tree digest:  {local_digest}")
                print(f"  Dest tree digest:   {remote_digest}")
                print(f"  Verified:           {'PASS' if verified else 'FAIL'}")

                add_custody_event(manifest, transfer_agent, "local_copy", local_source_path, remote_objects_dir, 
                                local_digest, remote_digest, verified, dest_base, notes)
                manifest["status"]["remote_upload_attempted"] = True
                manifest["status"]["remote_verified"] = bool(verified)
                if verified and manifest["status"].get("files_listed"):
                    manifest["status"]["overall"] = "PASS"

                write_manifest(manifest_path, manifest)
                shutil.copy2(manifest_path, remote_manifest_path)

                if not verified:
                    local_file, remote_file, diff_file = generate_diagnostics(logs_dir, local_items, remote_items)
                    print(f"  WARNING: Verification FAILED - diagnostics written to logs")
                    return False, "Verification failed (tree digest mismatch)"

        except Exception as e:
            traceback.print_exc()
            add_custody_event(manifest, transfer_agent, "local_copy", local_source_path, 
                            remote_objects_dir if 'remote_objects_dir' in locals() else None, 
                            None, None, False, dest_base if 'dest_base' in locals() else None, f"error: {e}")
            write_manifest(manifest_path, manifest)
            return False, f"Local copy error: {e}"

    print(f"  ✓ Package processed successfully")
    return True, None


# ----- main flow -----
def main():
    print("\n=== BATCH SEND & RECORD TRANSFER (with byte-level diagnostics) ===\n")

    # Ask if batch mode
    batch_mode = input("Process multiple packages? [Y/n]: ").strip().lower() in ("", "y", "yes")
    
    packages_to_process = []
    
    if batch_mode:
        parent_dir = normalize_path(input("Enter or drag the PARENT directory containing package folders: ").strip())
        if not parent_dir or not os.path.isdir(parent_dir):
            print("ERROR: invalid parent directory.")
            return
        
        # Find all packages
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

    # Collect transfer parameters (same for all packages)
    transfer_agent = input("Transfer agent name (e.g. 'sftp', 'local', 'rsync') [sftp/local]: ").strip() or "sftp"
    notes = input("Optional notes for this transfer (press Enter to skip): ").strip() or None

    # Choose method
    print("\nTransfer methods:\n  1) SFTP\n  2) Local network copy (mounted or UNC path)")
    method_choice = input("Choose transfer method [1/2] (default 1): ").strip() or "1"

    cfg = None
    cfg_path_used = None
    dest_base = None
    sftp = None
    transport = None

    # --- Setup SFTP or local destination ---
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
            cfg = {"host": raw_host, "port": port, "username": username, "password": password, "remote_parent": remote_parent}
            cfg_path_used = None

        if not cfg.get("remote_parent"):
            cfg["remote_parent"] = input("Remote parent directory on server (e.g. /sftp-transfer-source): ").strip()

        print("\nConnecting to SFTP...")
        try:
            transport = paramiko.Transport((cfg["host"], cfg["port"]))
            transport.connect(username=cfg["username"], password=cfg["password"])
            sftp = paramiko.SFTPClient.from_transport(transport)
            print("SFTP connection established.\n")
        except Exception as e:
            print(f"ERROR connecting to SFTP: {e}")
            traceback.print_exc()
            return

    else:
        dest_base = normalize_path(input("Enter destination base directory (mounted path or UNC, e.g. \\\\server\\share\\folder): ").strip())
        if not dest_base:
            print("ERROR: destination required.")
            return

    # --- Process all packages ---
    results = []
    for package_dir in packages_to_process:
        success, error = process_single_package(
            package_dir, transfer_agent, method_choice, notes, 
            cfg, cfg_path_used, dest_base, sftp
        )
        results.append({
            "package": os.path.basename(package_dir),
            "success": success,
            "error": error
        })

    # --- Cleanup SFTP ---
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

    # --- Final summary ---
    print("\n" + "="*60)
    print("BATCH TRANSFER SUMMARY")
    print("="*60)
    
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
