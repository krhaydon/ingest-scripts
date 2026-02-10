#!/usr/bin/env python3
"""
upload_verify_interactive_sha256_fixed.py (updated)

Interactive standalone tool with improved path handling:
- Accepts normal paths with spaces.
- Accepts shell-escaped paths (e.g. /Volumes/.../Pending\ transfer\ to\ Archivematica/...)
- Removes surrounding quotes, expands ~, returns absolute path.
- Echoes resolved paths so user can confirm.

Functionality:
- Prompts user for a manifest file or a package directory (will search aa_logs recursively).
- Computes SHA-256 for the ZIP referenced in the manifest.
- Uploads the ZIP + manifest either via SFTP (paramiko) or by copying into a local "remote" directory.
- Computes streamed SHA-256 on the remote copy, compares to local, and updates manifest in-place.
- Fully interactive.

Save as e.g. upload_verify_interactive_sha256_fixed.py and run:
    python upload_verify_interactive_sha256_fixed.py
"""
from __future__ import annotations
import os
import sys
import json
import hashlib
import posixpath
import traceback
import shutil
import re
from typing import Tuple, Optional, List
from datetime import datetime

CHUNK_SIZE = 16 * 1024 * 1024  # 16 MB


# ----------------- Utilities -----------------

def normalize_path(p: Optional[str]) -> Optional[str]:
    """
    Normalize a filesystem path entered interactively.
    Handles:
      - paths with spaces (literal or shell-escaped as '\ ')
      - surrounding quotes (single or double)
      - ~ expansion
      - returns absolute path

    Examples it will accept:
      /Volumes/My Drive/Some Dir/file.zip
      "/Volumes/My Drive/Some Dir/file.zip"
      /Volumes/My\ Drive/Some\ Dir/file.zip
    """
    if p is None:
        return None
    p = p.strip()
    if not p:
        return p

    # Remove a single matching pair of surrounding quotes if present:
    if len(p) >= 2 and ((p[0] == p[-1]) and p.startswith(("'", '"'))):
        p = p[1:-1]

    # If the user pasted a shell-escaped path (e.g. contains '\ '), unescape common shell escapes.
    # Only unescape backslash-space sequences, and backslash-quote, and double-backslash -> single backslash.
    # This avoids interpreting things like '\n' into newlines.
    if r'\ ' in p or r'\"' in p or r"\'" in p or r'\\' in p:
        # Replace '\ ' -> ' '
        p = p.replace(r'\ ', ' ')
        # Replace '\"' -> '"', "\'" -> "'" (user may have pasted escaped quotes)
        p = p.replace(r'\"', '"').replace(r"\'", "'")
        # Replace '\\' -> '\'
        p = p.replace(r'\\', '\\')

    # Trim again in case replacements introduced leading/trailing space
    p = p.strip()

    # Expand ~ and get absolute path
    p = os.path.abspath(os.path.expanduser(p))
    return p


def sha256_file(path: str) -> str:
    """Compute SHA-256 for local file (streamed)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def now_iso_stamp() -> Tuple[str, str]:
    now = datetime.now()
    return now.isoformat(timespec="seconds"), now.strftime("%Y%m%d_%H%M%S")


# ----------------- Manifest discovery & I/O -----------------

def find_manifests_in_aa_logs(root_dir: str) -> List[str]:
    """
    Walk root_dir recursively, find directories named exactly 'aa_logs' and return
    a list of JSON files found inside them (full paths).
    """
    matches = []
    for dirpath, _, filenames in os.walk(root_dir):
        if os.path.basename(dirpath) == "aa_logs":
            for fn in filenames:
                if fn.lower().endswith(".json"):
                    matches.append(os.path.join(dirpath, fn))
    return matches


def select_newest_file(paths: List[str]) -> Optional[str]:
    if not paths:
        return None
    return sorted(paths, key=lambda p: os.path.getmtime(p), reverse=True)[0]


def load_manifest(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_manifest(path: str, manifest: dict):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)


# ----------------- SFTP helpers -----------------

def ensure_remote_dir_sftp(sftp, remote_dir: str):
    """Ensure remote_dir and its parents exist (SFTP)."""
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
                # ignore races/permissions; will surface on upload if necessary
                pass


def sha256_sftp_file(sftp, remote_path: str) -> str:
    """Compute SHA-256 for remote file over SFTP (streamed)."""
    h = hashlib.sha256()
    with sftp.open(remote_path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


# ----------------- Upload backends -----------------

def upload_to_local_storage(zip_path: str, manifest_path: str, dest_parent: str, package_name: str, allow_overwrite: bool):
    """
    Mirror the remote layout into dest_parent:
      dest_parent/package_name/objects/<zip>
      dest_parent/package_name/objects/submission documentation/aa_logs/<manifest>
    Returns (remote_package_dir, remote_zip_path, remote_manifest_path, sha256_remote)
    """
    dest_parent = os.path.abspath(dest_parent)
    dest_package_dir = os.path.join(dest_parent, package_name)
    dest_objects_dir = os.path.join(dest_package_dir, "objects")
    dest_logs_dir = os.path.join(dest_objects_dir, "submission documentation", "aa_logs")
    os.makedirs(dest_logs_dir, exist_ok=True)

    dest_zip_path = os.path.join(dest_objects_dir, os.path.basename(zip_path))
    dest_manifest_path = os.path.join(dest_logs_dir, os.path.basename(manifest_path))

    if os.path.exists(dest_zip_path) and not allow_overwrite:
        raise RuntimeError(f"Destination zip exists and overwrite not allowed: {dest_zip_path}")

    shutil.copy2(zip_path, dest_zip_path)
    sha256_remote = sha256_file(dest_zip_path)
    shutil.copy2(manifest_path, dest_manifest_path)

    return dest_package_dir, dest_zip_path, dest_manifest_path, sha256_remote


def upload_to_sftp(zip_path: str, manifest_path: str, cfg: dict, package_name: str, allow_overwrite: bool):
    """
    Upload zip and manifest via SFTP (paramiko). Returns:
      (remote_package_dir, remote_zip_path, remote_manifest_path, sha256_remote)
    """
    try:
        import paramiko
    except Exception as e:
        raise RuntimeError("paramiko not installed. Install with: pip install paramiko") from e

    host = cfg["host"]
    port = int(cfg.get("port", 22))
    username = cfg["username"]
    password = cfg.get("password")
    remote_parent = cfg["remote_parent"]

    remote_package_dir = posixpath.join(remote_parent, package_name)
    remote_objects_dir = posixpath.join(remote_package_dir, "objects")
    remote_logs_dir = posixpath.join(remote_objects_dir, "submission documentation", "aa_logs")

    remote_zip_path = posixpath.join(remote_objects_dir, os.path.basename(zip_path))
    remote_manifest_path = posixpath.join(remote_logs_dir, os.path.basename(manifest_path))

    transport = paramiko.Transport((host, port))
    transport.connect(username=username, password=password)
    sftp = paramiko.SFTPClient.from_transport(transport)

    try:
        ensure_remote_dir_sftp(sftp, remote_objects_dir)
        ensure_remote_dir_sftp(sftp, remote_logs_dir)

        # Check if remote exists
        exists = False
        try:
            sftp.stat(remote_zip_path)
            exists = True
        except IOError:
            exists = False

        if exists and not allow_overwrite:
            raise RuntimeError(f"Remote zip exists ({remote_zip_path}) and overwrite not allowed.")

        sftp.put(zip_path, remote_zip_path)
        sha256_remote = sha256_sftp_file(sftp, remote_zip_path)
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

    return remote_package_dir, remote_zip_path, remote_manifest_path, sha256_remote


# ----------------- Interactive helpers -----------------

def prompt_sftp_config() -> dict:
    import getpass, socket
    print("\nEnter SFTP settings (leave host blank to cancel):")
    host = input("  SFTP host (e.g. example.org): ").strip()
    if not host:
        raise RuntimeError("SFTP config entry cancelled.")
    if host.lower().startswith(("sftp://", "ssh://")):
        host = host.split("://", 1)[1].split("/", 1)[0]
    port_str = input("  SFTP port [22]: ").strip()
    username = input("  SFTP username: ").strip()
    password = getpass.getpass("  SFTP password: ")
    remote_parent = input("  Remote parent directory for packages (e.g. /sftp-transfer-source): ").strip()
    if not host or not username or not remote_parent:
        raise RuntimeError("Host, username and remote_parent are required.")
    try:
        port = int(port_str) if port_str else 22
    except Exception:
        port = 22
    # quick DNS check
    try:
        socket.getaddrinfo(host, port)
    except Exception as e:
        raise RuntimeError(f"Cannot resolve host '{host}': {e}")
    return {"host": host, "port": port, "username": username, "password": password, "remote_parent": remote_parent}


def pick_manifest_interactive(manifest_input: str) -> str:
    raw = manifest_input
    inp = normalize_path(raw)
    # Echo resolved input for clarity (good for drag-drop and escaped paths)
    print("Resolved path:", inp)
    if os.path.isdir(inp):
        print(f"\nSearching for manifests under directories named 'aa_logs' in: {inp}")
        candidates = find_manifests_in_aa_logs(inp)
        if not candidates:
            raise RuntimeError("No manifest JSONs found under any aa_logs directory in: " + inp)
        candidates_sorted = sorted(candidates, key=lambda p: os.path.getmtime(p), reverse=True)
        print("\nFound the following manifest files (newest first):")
        for i, p in enumerate(candidates_sorted, start=1):
            mtime = datetime.fromtimestamp(os.path.getmtime(p)).isoformat(sep=" ", timespec="seconds")
            print(f"  [{i}] {p}  (modified: {mtime})")
        pick = input("\nPick a manifest by number (Enter for #1 newest): ").strip()
        if not pick:
            chosen = candidates_sorted[0]
            print("Selected:", chosen)
            return chosen
        try:
            idx = int(pick) - 1
            if idx < 0 or idx >= len(candidates_sorted):
                raise ValueError()
            chosen = candidates_sorted[idx]
            print("Selected:", chosen)
            return chosen
        except Exception:
            raise RuntimeError("Invalid selection.")
    else:
        if not os.path.isfile(inp):
            raise RuntimeError("Manifest file not found: " + inp)
        return inp


# ----------------- Main interactive flow -----------------

def main():
    print("\n=== Upload & verify (interactive, SHA-256) ===\n")
    try:
        manifest_input = input("Enter path to manifest JSON or to package directory (press Enter to cancel): ").strip()
        if not manifest_input:
            print("Cancelled.")
            return
        manifest_path = pick_manifest_interactive(manifest_input)
        # Echo resolved manifest path as final confirmation
        manifest_path = normalize_path(manifest_path)
        print("Resolved manifest path used:", manifest_path)

        manifest = load_manifest(manifest_path)
        zip_info = manifest.get("zip", {})
        zip_path = zip_info.get("local_path")
        if not zip_path:
            raise RuntimeError("Manifest missing zip.local_path")
        zip_path = normalize_path(zip_path)
        print("Resolved zip path:", zip_path)
        if not os.path.isfile(zip_path):
            raise RuntimeError(f"Zip not found at manifest zip.local_path: {zip_path}")

        package_name = manifest.get("package_name") or os.path.basename(manifest.get("package_dir", "package"))

        # Compute local sha256 and update manifest
        print("\nComputing local SHA-256 (this may take a moment)...")
        local_sha256 = sha256_file(zip_path)
        manifest.setdefault("zip", {})
        manifest["zip"]["sha256_local"] = local_sha256

        print(f"\nComputed local SHA-256: {local_sha256}")
        # Choose backend
        print("\nChoose upload destination:")
        print("  [1] SFTP")
        print("  [2] Local directory (mirror as 'remote')")
        choice = input("Enter 1 or 2 (Enter to cancel): ").strip()
        if choice not in ("1", "2"):
            print("Cancelled.")
            return

        if choice == "1":
            # SFTP
            use_cfg = input("\nProvide path to SFTP JSON config file? [y/N]: ").strip().lower() in ("y", "yes")
            if use_cfg:
                cfg_path_raw = input("Path to SFTP config JSON: ").strip()
                cfg_path = normalize_path(cfg_path_raw)
                print("Resolved SFTP config path:", cfg_path)
                if not os.path.isfile(cfg_path):
                    raise RuntimeError("SFTP config not found: " + str(cfg_path))
                with open(cfg_path, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
            else:
                cfg = prompt_sftp_config()

            ov = input("If the remote zip already exists, overwrite? [y/N]: ").strip().lower()
            allow_overwrite = ov in ("y", "yes")

            print(f"\nUploading to SFTP host {cfg.get('host')} under remote parent {cfg.get('remote_parent')} ...")
            manifest["status"] = manifest.get("status", {})
            manifest["status"]["remote_upload_attempted"] = True

            try:
                remote_package_dir, remote_zip_path, remote_manifest_path, remote_sha256 = upload_to_sftp(
                    zip_path, manifest_path, cfg, package_name, allow_overwrite
                )
                verified = (remote_sha256 == local_sha256)
                # Update manifest
                manifest["zip"]["remote_parent"] = cfg.get("remote_parent")
                manifest["zip"]["remote_package_dir"] = remote_package_dir
                manifest["zip"]["remote_path"] = remote_zip_path
                manifest["zip"]["remote_manifest"] = remote_manifest_path
                manifest["zip"]["sha256_remote"] = remote_sha256
                manifest["zip"]["remote_verified"] = bool(verified)

                manifest["status"]["remote_verified"] = bool(verified)
                manifest["status"]["overall"] = "PASS" if verified else "FAIL"

                save_manifest(manifest_path, manifest)
                print("\nSFTP upload complete.")
                print("Local SHA-256: ", local_sha256)
                print("Remote SHA-256:", remote_sha256)
                print("Remote verified:", bool(verified))
                print("Manifest updated at:", manifest_path)
            except Exception as e:
                print("\nERROR during SFTP upload/verify:", e)
                traceback.print_exc()
                manifest["zip"]["remote_error"] = str(e)
                manifest["zip"]["remote_verified"] = False
                manifest["status"]["remote_verified"] = False
                manifest["status"]["overall"] = "FAIL"
                save_manifest(manifest_path, manifest)
                return

        else:
            # local dest
            dest_parent_raw = input("\nEnter local destination directory to act as 'remote' (will be created if needed): ").strip()
            if not dest_parent_raw:
                print("Cancelled.")
                return
            dest_parent = normalize_path(dest_parent_raw)
            print("Resolved destination path:", dest_parent)
            if not os.path.isdir(dest_parent):
                try:
                    os.makedirs(dest_parent, exist_ok=True)
                except Exception as e:
                    raise RuntimeError("Unable to create local destination: " + str(e))

            ov = input("If the destination zip already exists, overwrite? [y/N]: ").strip().lower()
            allow_overwrite = ov in ("y", "yes")

            print(f"\nCopying to local destination: {dest_parent} ...")
            manifest["status"] = manifest.get("status", {})
            manifest["status"]["remote_upload_attempted"] = True

            try:
                remote_package_dir, remote_zip_path, remote_manifest_path, remote_sha256 = upload_to_local_storage(
                    zip_path, manifest_path, dest_parent, package_name, allow_overwrite
                )
                verified = (remote_sha256 == local_sha256)
                manifest["zip"]["remote_parent"] = dest_parent
                manifest["zip"]["remote_package_dir"] = remote_package_dir
                manifest["zip"]["remote_path"] = remote_zip_path
                manifest["zip"]["remote_manifest"] = remote_manifest_path
                manifest["zip"]["sha256_remote"] = remote_sha256
                manifest["zip"]["remote_verified"] = bool(verified)

                manifest["status"]["remote_verified"] = bool(verified)
                manifest["status"]["overall"] = "PASS" if verified else "FAIL"

                save_manifest(manifest_path, manifest)
                print("\nCopy complete.")
                print("Local SHA-256: ", local_sha256)
                print("Remote SHA-256:", remote_sha256)
                print("Remote verified:", bool(verified))
                print("Manifest updated at:", manifest_path)
            except Exception as e:
                print("\nERROR during local copy/verify:", e)
                traceback.print_exc()
                manifest["zip"]["remote_error"] = str(e)
                manifest["zip"]["remote_verified"] = False
                manifest["status"]["remote_verified"] = False
                manifest["status"]["overall"] = "FAIL"
                save_manifest(manifest_path, manifest)
                return

        print("\n=== SUMMARY ===")
        print("Package:", package_name)
        print("Source zip:", zip_path)
        print("Manifest:", manifest_path)
        print("Remote verified:", manifest["status"].get("remote_verified"))
        print("Overall status:", manifest["status"].get("overall"))
        print("\nDone.\n")

    except Exception as e:
        print("ERROR:", e)
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
