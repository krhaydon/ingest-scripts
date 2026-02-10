#!/usr/bin/env python3
"""
rsync_package_and_manifest.py (REFACTORED)

- Local only.
- Copies an entire "package" directory (top level + contents) using rsync -avv.
- SOURCE = package directory (e.g. /path/to/MyPackage)
- DEST_PARENT = parent directory where the package copy will live (e.g. /path/to/destination)

Result:
  rsync -avv SOURCE DEST_PARENT
  -> DEST_PARENT/<PACKAGE_NAME>/...

Then:
- Walk DEST_PARENT/<PACKAGE_NAME> (excluding aa_logs)
- Compute SHA-256 for each file in the destination
- If the corresponding SOURCE file still exists, compute its SHA-256 and mark verified if they match
- Write manifest JSON to:
    DEST_PARENT/<PACKAGE_NAME>/aa_logs/rsync_manifest_YYYYMMDD_HHMMSS.json
"""

import json
import hashlib
import subprocess
from pathlib import Path
from datetime import datetime
import traceback
import shlex

CHUNK_SIZE = 16 * 1024 * 1024  # 16 MB


def normalize_path(p: str) -> Path:
    """
    Normalize user input path:
      - strip surrounding whitespace and quotes
      - convert drag-and-drop escaped spaces (e.g. '\ ') to real spaces
      - expand ~ and return absolute Path object
    """
    if not p:
        return None
    p = p.strip().strip('"').strip("'")
    # Unescape drag-and-drop escaped spaces (e.g., /Users/me/My\ Folder)
    p = p.replace("\\ ", " ")
    return Path(p).expanduser().resolve()


def now_iso_stamp():
    now = datetime.now()
    return now.isoformat(timespec="seconds"), now.strftime("%Y%m%d_%H%M%S")


def sha256_file(path: Path) -> tuple[str, str]:
    """
    Compute SHA-256 of a file.
    Returns: (sha256_hex, error_message)
    If successful, error_message is None.
    """
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest(), None
    except Exception as e:
        return None, str(e)


def run_rsync_package(source_dir: Path, dest_parent: Path):
    """
    Run: rsync -avv source_dir dest_parent
    (no trailing slash on source_dir, so the top-level dir itself is copied)
    Shows real-time verbose output.
    """
    src = str(source_dir)
    dst = str(dest_parent) + "/"

    cmd = ["rsync", "-avv", src, dst]

    # Print a shell-friendly preview
    preview = " ".join(shlex.quote(c) for c in cmd)
    print("\nRunning rsync:")
    print("  ", preview)
    print()

    try:
        # text=True enables real-time output streaming to terminal
        subprocess.run(cmd, check=True, text=True)
    except FileNotFoundError:
        raise RuntimeError("rsync not found on PATH. Please install rsync and try again.")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"rsync failed with exit code {e.returncode}")


def walk_files(root: Path, exclude_dir_name: str = "aa_logs"):
    """
    Yield (abs_path, rel_path_from_root) for all files under root,
    excluding any files under a directory named `exclude_dir_name`.
    rel_path uses forward slashes (POSIX style).
    """
    for item in root.rglob("*"):
        # Skip if any parent directory is the excluded dir
        if exclude_dir_name in item.parts:
            continue
        if item.is_file():
            rel = item.relative_to(root).as_posix()
            yield item, rel


def main():
    print("\n=== RSYNC PACKAGE + MANIFEST (copy top-level dir) ===\n")

    # SOURCE package dir
    src_input = input("Enter or drag SOURCE PACKAGE directory (top-level folder): ")
    source_dir = normalize_path(src_input)
    if not source_dir or not source_dir.is_dir():
        print("ERROR: Source package directory does not exist or is not a directory.")
        return

    package_name = source_dir.name

    # DEST parent dir
    dest_input = input("Enter or drag DESTINATION PARENT directory: ")
    dest_parent = normalize_path(dest_input)
    if not dest_parent:
        print("ERROR: Destination parent path is empty.")
        return
    if not dest_parent.exists():
        create = input("Destination parent does not exist. Create it? [Y/n]: ").strip().lower()
        if create in ("", "y", "yes"):
            dest_parent.mkdir(parents=True, exist_ok=True)
        else:
            print("Aborting.")
            return
    elif not dest_parent.is_dir():
        print("ERROR: Destination parent exists but is not a directory.")
        return

    technician = input("Technician name (optional): ").strip() or "Blank"
    transfer_agent = input("Source: ").strip() or "Blank"
    note = input("Optional note for manifest (press Enter to skip): ").strip() or None

    created_iso, stamp = now_iso_stamp()

    # Run rsync (copy package dir into parent)
    try:
        run_rsync_package(source_dir, dest_parent)
    except Exception as e:
        print(f"\nERROR during rsync: {e}")
        traceback.print_exc()
        return

    # Destination package root
    dest_package_dir = dest_parent / package_name
    if not dest_package_dir.is_dir():
        print(f"\nERROR: Expected destination package dir not found: {dest_package_dir}")
        return

    print(f"\nRsync completed. Building manifest from destination package:\n  {dest_package_dir}")

    files = []
    failures = []

    for abs_dest, rel in walk_files(dest_package_dir, exclude_dir_name="aa_logs"):
        try:
            size_dest = abs_dest.stat().st_size
        except OSError:
            size_dest = None

        sha_dest, err_dest = sha256_file(abs_dest)
        if err_dest:
            failures.append({
                "rel_path": rel,
                "error": f"sha256_dest_error: {err_dest}",
            })

        # Check corresponding source file
        abs_src = source_dir / rel
        if abs_src.exists() and abs_src.is_file():
            sha_src, err_src = sha256_file(abs_src)
            if err_src:
                failures.append({
                    "rel_path": rel,
                    "error": f"sha256_src_error: {err_src}",
                })
        else:
            sha_src = None

        verified = (sha_src is not None and sha_dest is not None and sha_src == sha_dest)

        files.append({
            "rel_path": rel,
            "size": size_dest,
            "sha256_dest": sha_dest,
            "sha256_src": sha_src,
            "verified": verified,
        })

    # Build manifest in DEST_PACKAGE_DIR/aa_logs
    aa_logs_dir = dest_package_dir / "aa_logs"
    aa_logs_dir.mkdir(parents=True, exist_ok=True)
    
    manifest_filename = f"rsync_manifest_{stamp}.json"
    manifest_path = aa_logs_dir / manifest_filename

    # Calculate status
    verified_count = sum(1 for f in files if f.get("verified"))
    if verified_count == len(files):
        overall_status = "PASS"
    elif verified_count > 0:
        overall_status = "PARTIAL"
    else:
        overall_status = "FAIL"

    manifest = {
        "manifest_type": "rsync_local_package",
        "package_name": package_name,
        "created_at": created_iso,
        "technician": technician,
        "transfer_agent": transfer_agent,
        "note": note,
        "source_dir": str(source_dir),
        "dest_parent_dir": str(dest_parent),
        "dest_package_dir": str(dest_package_dir),
        "rsync_command": " ".join(shlex.quote(x) for x in ["rsync", "-avv", str(source_dir), str(dest_parent) + "/"]),
        "file_count": len(files),
        "files": files,
        "failures": failures,
        "status": {
            "overall": overall_status
        },
    }

    try:
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
        print(f"\nManifest written to:\n  {manifest_path}")
    except Exception as e:
        print("ERROR writing manifest:", e)
        traceback.print_exc()
        return

    print("\n=== SUMMARY ===")
    print(f"Source package:  {source_dir}")
    print(f"Dest parent:     {dest_parent}")
    print(f"Dest package:    {dest_package_dir}")
    print(f"File count:      {len(files)}")
    print(f"Status:          {overall_status}")
    print(f"Manifest:        {manifest_path}")
    print("\nDone.\n")


if __name__ == "__main__":
    main()
