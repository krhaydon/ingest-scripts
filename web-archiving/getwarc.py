#!/usr/bin/env python3
"""
Archive-It WASAPI downloader (interactive output dir, safe with spaces).

Features:
- Asks the user where to save WARCs (paths with spaces, ~ expansion).
- Handles missing/invalid starting working directories by falling back to HOME.
- Uses requests.Session with retries and timeouts.
- Flexible extraction of download URL from WASAPI JSON.
- Pagination when a "next" link is present.
- Skips files when local size matches remote Content-Length.
- Streams downloads to .part and renames on success.
"""

from __future__ import annotations

import os
import sys
import time
import getpass
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse, unquote

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# ------------------------ Utilities ----------------------------------------


def fix_cwd_if_invalid() -> None:
    """
    If the current working directory no longer exists (e.g. unmounted volume),
    switch to the user's home directory so relative paths won't crash.
    """
    try:
        os.getcwd()
    except FileNotFoundError:
        home = str(Path.home())
        os.chdir(home)
        print(f"Note: starting directory was invalid — switched to home: {home}")


def safe_filename(name: str) -> str:
    """Produce a filesystem-safe filename from a candidate string."""
    if not name:
        return "download.warc"

    # URL decode and strip path components
    name = unquote(name)
    name = Path(name).name

    # Remove control chars and path separators
    cleaned = []
    for c in name:
        if ord(c) < 32:  # control chars
            continue
        if c in ("/", "\\"):
            continue
        cleaned.append(c)

    result = "".join(cleaned).strip()
    return result or "download.warc"


def make_session(
    username: str,
    password: str,
    retries: int = 4,
    backoff: float = 1.0,
    timeout: int = 30,
) -> requests.Session:
    s = requests.Session()
    s.auth = (username, password)

    retry = Retry(
        total=retries,
        backoff_factor=backoff,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "POST", "HEAD", "OPTIONS"]),
    )

    adapter = HTTPAdapter(max_retries=retry)
    s.mount("https://", adapter)
    s.mount("http://", adapter)

    # stash timeout for convenience
    s.request_timeout = timeout  # type: ignore[attr-defined]
    return s


def extract_url(item: Dict[str, Any]) -> Optional[str]:
    """Try several common shapes to find a usable URL in a WASAPI item."""
    if not isinstance(item, dict):
        return None

    # locations / location
    locs = item.get("locations") or item.get("location") or []
    if isinstance(locs, list) and locs:
        first = locs[0]
        if isinstance(first, str):
            return first
        if isinstance(first, dict):
            for k in ("url", "uri", "link", "href", "download"):
                if first.get(k):
                    return first[k]

    # direct fields
    for k in ("url", "uri", "download", "file_url", "link", "href"):
        if item.get(k):
            return item[k]

    # nested links
    links = item.get("_links") or item.get("links") or {}
    if isinstance(links, dict):
        n = links.get("self") or links.get("download") or links.get("file")
        if isinstance(n, dict):
            return n.get("href")
        if isinstance(n, str):
            return n

    return None


def get_remote_size(session: requests.Session, url: str, timeout: int) -> Optional[int]:
    try:
        head = session.head(url, timeout=timeout, allow_redirects=True)
        if head.ok:
            cl = head.headers.get("Content-Length")
            if cl and cl.isdigit():
                return int(cl)
    except Exception:
        pass
    return None


# ------------------------ Main --------------------------------------------


def main() -> None:
    fix_cwd_if_invalid()

    print("=== Archive-It WASAPI Downloader ===")

    username = input("Archive-It username (usually your email): ").strip()
    password = getpass.getpass("Password: ").strip()
    crawl_id = input("Crawl ID (e.g., 2622263): ").strip()

    # Ask where to save WARCs
    print()
    user_out = input(
        "Output directory for WARCs\n"
        "(press Enter to use the current directory): "
    ).strip()

    if user_out:
        # Don't resolve yet; allow mkdir() to create missing parents.
        out_base = Path(user_out).expanduser()
    else:
        out_base = Path(os.getcwd())

    # Out dir specific to crawl
    out_dir = out_base / f"WARCs_{crawl_id}"

    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        print(f"Failed to create output directory {out_dir}: {e}", file=sys.stderr)
        return

    print(f"\nFiles will be saved in: {out_dir}\n")

    base_api_url = "https://warcs.archive-it.org/wasapi/v1/webdata"
    params = {"crawl": crawl_id}

    session = make_session(username, password, retries=4, backoff=1.0, timeout=30)
    timeout = getattr(session, "request_timeout", 30)

    files_accum = []
    api_url = base_api_url

    # -------- Fetch file list with simple pagination --------
    while True:
        try:
            print(f"Fetching file list from {api_url} (params={params}) ...")
            r = session.get(api_url, params=params, timeout=timeout)
            r.raise_for_status()
        except requests.HTTPError as e:
            print(f"HTTP error while fetching file list: {e}", file=sys.stderr)
            return
        except Exception as e:
            print(f"Error while fetching file list: {e}", file=sys.stderr)
            return

        try:
            data = r.json()
        except Exception:
            snippet = r.text[:800].replace("\n", " ")
            print("Failed to decode JSON from WASAPI response.", file=sys.stderr)
            print("Response snippet:", snippet, file=sys.stderr)
            return

        files = data.get("files") or data.get("items") or data.get("results") or []
        if not isinstance(files, list):
            print("Unexpected 'files' structure in response; expected a list.", file=sys.stderr)
            return

        files_accum.extend(files)

        # pagination: look for "next"
        next_url = None
        if isinstance(data.get("next"), str):
            next_url = data["next"]

        links = data.get("_links") or data.get("links") or {}
        if isinstance(links, dict):
            n = links.get("next") or links.get("Next")
            if isinstance(n, dict):
                next_url = n.get("href") or next_url
            elif isinstance(n, str):
                next_url = n

        if next_url:
            api_url = next_url
            params = {}
            time.sleep(0.1)
            continue
        break

    if not files_accum:
        print("No WARC files found for this crawl.")
        return

    print(f"Found {len(files_accum)} file entries. Starting download...\n")

    # -------- Download loop --------
    for idx, item in enumerate(files_accum, start=1):
        url = None
        tmp_path = None
        try:
            url = extract_url(item)
            if not url:
                print(
                    f"[{idx}/{len(files_accum)}] Skipping entry: no downloadable URL found.",
                    file=sys.stderr,
                )
                continue

            # Determine filename
            filename = None
            for k in ("filename", "file_name", "name"):
                v = item.get(k)
                if isinstance(v, str) and v.strip():
                    filename = v.strip()
                    break

            if not filename:
                parsed = urlparse(url)
                candidate = Path(unquote(parsed.path)).name or parsed.netloc or f"warc_{idx}"
                filename = candidate

            filename = safe_filename(filename)
            dest = out_dir / filename

            # Check remote size
            remote_size = get_remote_size(session, url, timeout)

            if dest.exists():
                local_size = dest.stat().st_size
                if remote_size is not None and local_size == remote_size:
                    print(
                        f"⏭️  [{idx}/{len(files_accum)}] Skipping {filename} "
                        f"(already downloaded, {local_size} bytes)."
                    )
                    continue
                else:
                    print(
                        f"⚠️  [{idx}/{len(files_accum)}] Existing file {filename} present "
                        f"but size differs (local={local_size}, remote={remote_size}). Re-downloading."
                    )

            print(f"⬇️  [{idx}/{len(files_accum)}] Downloading {filename} ...")

            tmp_path = dest.with_suffix(dest.suffix + ".part")
            tmp_path.parent.mkdir(parents=True, exist_ok=True)

            with session.get(url, timeout=timeout, stream=True) as resp:
                resp.raise_for_status()
                with open(tmp_path, "wb") as fh:
                    written = 0
                    for chunk in resp.iter_content(chunk_size=64 * 1024):
                        if not chunk:
                            continue
                        fh.write(chunk)
                        written += len(chunk)

            tmp_path.replace(dest)
            size_mb = dest.stat().st_size / (1024 * 1024)
            print(f"✅  [{idx}/{len(files_accum)}] Saved {filename} ({size_mb:.2f} MB)\n")

        except KeyboardInterrupt:
            print("\nDownload interrupted by user. Exiting.", file=sys.stderr)
            return
        except Exception as e:
            print(
                f"Failed to download entry #{idx} ({url or 'unknown'}): {e}",
                file=sys.stderr,
            )
            # clean up partial
            try:
                if tmp_path and tmp_path.exists():
                    tmp_path.unlink()
            except Exception:
                pass
            continue

    print(f"All done. Files saved in: {out_dir.resolve()}")


if __name__ == "__main__":
    main()
