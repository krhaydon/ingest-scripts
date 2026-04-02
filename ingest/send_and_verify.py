#!/usr/bin/env python3
"""
send_and_verify.py

Records pre-ingest custody and fixity as PREMIS XML before Archivematica
picks up the package from the SFTP staging directory.

VERIFICATION MODES:
1. ZIP Transfer Mode:
   - Transfers a single ZIP file via SFTP or local copy
   - SHA-256 checksum of the ZIP at source vs destination
   - Lists every file inside the ZIP as a PREMIS object (with checksum + MIME + size)

2. Directory Transfer Mode:
   - Transfers the objects/ folder (excluding submissionDocumentation/)
   - SHA-256 checksum of every file, source vs destination
   - Every file becomes a PREMIS object (with checksum + MIME + size)

PREMIS MANIFEST:
- Written to: objects/submissionDocumentation/premis_transfer_<id>_<timestamp>.xml
- Contains: agents, objects (one per file with fixity + MIME + size), events
- Two events recorded: ingestion (transfer) and fixity check
- On failure: eventOutcome is "failure" with a detail note

Input paths:
- Safe for paths with spaces/special characters
- Handles macOS drag-and-drop escaping
- Preserves UNC paths like: \\\\server\\share\\folder
"""

from __future__ import annotations

import os
import hashlib
import getpass
import posixpath
import traceback
import shutil
import subprocess
import re
import shlex
import mimetypes
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime

try:
    import paramiko
except Exception:
    paramiko = None

CHUNK_SIZE        = 16 * 1024 * 1024
SFTP_CONFIG_PATH  = "/Volumes/Shr6/Library/Archive/Digital Archives/Scripts/config_files/archivematica.conf"
SFTP_REMOTE_PARENT = "/sftp-transfer-source"

PREMIS_NS  = "http://www.loc.gov/premis/v3"
XSI_NS     = "http://www.w3.org/2001/XMLSchema-instance"
PREMIS_XSD = "http://www.loc.gov/premis/v3 https://www.loc.gov/standards/premis/premis.xsd"

ET.register_namespace("premis", PREMIS_NS)
ET.register_namespace("xsi",    XSI_NS)

PREMIS_MANIFEST_REGEX = re.compile(
    r"^premis_transfer_.+_(\d{8}_\d{6})\.xml$", flags=re.IGNORECASE
)

IGNORE_BASENAMES = {".DS_Store", "Thumbs.db", "desktop.ini"}
IGNORE_PREFIXES  = ("._",)

_MACOS_DRAGDROP_UNESCAPE = re.compile(r"\\([ \(\)\[\]\{\}&;,#@!\+=\~'])")


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _unescape_macos_dragdrop(p: str) -> str:
    return _MACOS_DRAGDROP_UNESCAPE.sub(r"\1", p)


def normalize_path(p: str) -> str:
    if not p:
        return p
    p = p.strip()
    if (p.startswith('"') and p.endswith('"')) or (p.startswith("'") and p.endswith("'")):
        p = p[1:-1].strip()
    p = _unescape_macos_dragdrop(p)
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


def detect_mime(path: str) -> str:
    mime, _ = mimetypes.guess_type(path)
    return mime or "application/octet-stream"


def format_name_from_mime(mime: str) -> str:
    known = {
        "application/pdf":   "PDF",
        "application/zip":   "ZIP",
        "application/msword": "Microsoft Word",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "DOCX",
        "application/vnd.ms-excel": "Microsoft Excel",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "XLSX",
        "application/vnd.ms-powerpoint": "Microsoft PowerPoint",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation": "PPTX",
        "image/tiff":    "TIFF",
        "image/jpeg":    "JPEG",
        "image/png":     "PNG",
        "image/gif":     "GIF",
        "video/mp4":     "MP4",
        "video/quicktime": "QuickTime",
        "audio/mpeg":    "MP3",
        "audio/wav":     "WAV",
        "text/plain":    "Plain Text",
        "text/csv":      "CSV",
        "text/xml":      "XML",
        "application/xml":  "XML",
        "application/json": "JSON",
    }
    return known.get(mime, mime)


def compute_objects_file_list(objects_dir: str, label: str = "") -> list[tuple[str, str]]:
    """Sorted list of (relative_path, sha256) for all files in objects/."""
    items: list[tuple[str, str]] = []
    for root, dirs, files in os.walk(objects_dir):
        if "submissionDocumentation" in dirs:
            dirs.remove("submissionDocumentation")
        for name in files:
            full = os.path.join(root, name)
            rel  = os.path.relpath(full, objects_dir).replace(os.sep, "/")
            if should_ignore(rel):
                continue
            prefix = f"    [{label}] " if label else "    "
            print(f"{prefix}{rel}")
            items.append((rel, sha256_file(full)))
    items.sort()
    return items


def list_zip_contents(zip_path: str) -> list[dict]:
    """
    Return info for every file inside a ZIP.
    Each entry: {name, sha256, size, mime}
    """
    entries = []
    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            name = info.filename
            if should_ignore(name):
                continue
            print(f"    [zip contents] {name}")
            h = hashlib.sha256()
            with zf.open(info) as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    h.update(chunk)
            entries.append({
                "name":   name,
                "sha256": h.hexdigest(),
                "size":   info.file_size,
                "mime":   detect_mime(name),
            })
    return entries


# ---------------------------------------------------------------------------
# PREMIS XML building
# ---------------------------------------------------------------------------

def _p(tag: str) -> str:
    return f"{{{PREMIS_NS}}}{tag}"


def _sub(parent: ET.Element, tag: str, text: str | None = None) -> ET.Element:
    el = ET.SubElement(parent, _p(tag))
    if text is not None:
        el.text = text
    return el


def _agent_element(agent_id: str, agent_name: str, agent_type: str) -> ET.Element:
    agent = ET.Element(_p("agent"))
    ident = _sub(agent, "agentIdentifier")
    _sub(ident, "agentIdentifierType", "local")
    _sub(ident, "agentIdentifierValue", agent_id)
    _sub(agent, "agentName", agent_name)
    _sub(agent, "agentType", agent_type)
    return agent


def _object_element(
    obj_id: str,
    original_name: str,
    sha256: str,
    size: int,
    mime: str,
    related_ids: list[str] | None = None,
) -> ET.Element:
    obj = ET.Element(_p("object"))
    obj.set(f"{{{XSI_NS}}}type", "premis:file")

    ident = _sub(obj, "objectIdentifier")
    _sub(ident, "objectIdentifierType", "local")
    _sub(ident, "objectIdentifierValue", obj_id)

    chars = _sub(obj, "objectCharacteristics")

    fix = _sub(chars, "fixity")
    _sub(fix, "messageDigestAlgorithm", "SHA-256")
    _sub(fix, "messageDigest", sha256)
    _sub(fix, "messageDigestOriginator", "send_and_verify.py")

    _sub(chars, "size", str(size))

    fmt = _sub(chars, "format")
    fd  = _sub(fmt, "formatDesignation")
    _sub(fd, "formatName", format_name_from_mime(mime))
    fr  = _sub(fmt, "formatRegistry")
    _sub(fr, "formatRegistryName", "MIME")
    _sub(fr, "formatRegistryKey", mime)

    _sub(obj, "originalName", original_name)

    if related_ids:
        rel = _sub(obj, "relationship")
        rt  = _sub(rel, "relationshipType", "structural")
        rt.set("authority", "relationshipType")
        rt.set("authorityURI", "http://id.loc.gov/vocabulary/preservation/relationshipType")
        rt.set("valueURI", "http://id.loc.gov/vocabulary/preservation/relationshipType/str")
        rs  = _sub(rel, "relationshipSubType", "hasPart")
        rs.set("authority", "relationshipSubType")
        rs.set("authorityURI", "http://id.loc.gov/vocabulary/preservation/relationshipSubType")
        rs.set("valueURI", "http://id.loc.gov/vocabulary/preservation/relationshipSubType/hsp")
        for rid in related_ids:
            roi = _sub(rel, "relatedObjectIdentifier")
            _sub(roi, "relatedObjectIdentifierType", "local")
            _sub(roi, "relatedObjectIdentifierValue", rid)

    return obj


def _event_element(
    event_id: str,
    event_type_label: str,
    event_type_uri: str,
    event_dt: str,
    detail: str,
    outcome: str,
    outcome_note: str | None,
    agent_ids: list[tuple[str, str]],
    object_ids: list[str],
) -> ET.Element:
    evt = ET.Element(_p("event"))

    ident = _sub(evt, "eventIdentifier")
    _sub(ident, "eventIdentifierType", "local")
    _sub(ident, "eventIdentifierValue", event_id)

    et_ = _sub(evt, "eventType", event_type_label)
    et_.set("authority", "eventType")
    et_.set("authorityURI", "http://id.loc.gov/vocabulary/preservation/eventType")
    et_.set("valueURI", event_type_uri)

    _sub(evt, "eventDateTime", event_dt)

    edi = _sub(evt, "eventDetailInformation")
    _sub(edi, "eventDetail", detail)

    eoi = _sub(evt, "eventOutcomeInformation")
    _sub(eoi, "eventOutcome", outcome)
    if outcome_note:
        eod = _sub(eoi, "eventOutcomeDetail")
        _sub(eod, "eventOutcomeDetailNote", outcome_note)

    for agent_id, role in agent_ids:
        lai = _sub(evt, "linkingAgentIdentifier")
        _sub(lai, "linkingAgentIdentifierType", "local")
        _sub(lai, "linkingAgentIdentifierValue", agent_id)
        _sub(lai, "linkingAgentRole", role)

    for oid in object_ids:
        loi = _sub(evt, "linkingObjectIdentifier")
        _sub(loi, "linkingObjectIdentifierType", "local")
        _sub(loi, "linkingObjectIdentifierValue", oid)

    return evt


def _append_events(
    premis_root: ET.Element,
    transfer_dt: str,
    transfer_detail: str,
    verified: bool,
    fixity_detail: str,
    fixity_note: str,
    agent_id_person: str,
    agent_id_script: str,
    transfer_obj_ids: list[str],
    fixity_obj_ids: list[str],
) -> None:
    stamp = transfer_dt.replace("-", "").replace(":", "").replace("T", "_")[:15]

    premis_root.append(_event_element(
        event_id         = f"evt-ingestion-{stamp}",
        event_type_label = "ingestion",
        event_type_uri   = "http://id.loc.gov/vocabulary/preservation/eventType/ing",
        event_dt         = transfer_dt,
        detail           = transfer_detail,
        outcome          = "success" if verified else "failure",
        outcome_note     = None,
        agent_ids        = [
            (agent_id_person, "implementer"),
            (agent_id_script, "executing program"),
        ],
        object_ids       = transfer_obj_ids,
    ))

    fixity_dt    = now_iso()
    fixity_stamp = fixity_dt.replace("-", "").replace(":", "").replace("T", "_")[:15]

    premis_root.append(_event_element(
        event_id         = f"evt-fixity-{fixity_stamp}",
        event_type_label = "fixity check",
        event_type_uri   = "http://id.loc.gov/vocabulary/preservation/eventType/fix",
        event_dt         = fixity_dt,
        detail           = fixity_detail,
        outcome          = "success" if verified else "failure",
        outcome_note     = fixity_note,
        agent_ids        = [(agent_id_script, "executing program")],
        object_ids       = fixity_obj_ids,
    ))


def build_premis_root() -> ET.Element:
    root = ET.Element(_p("premis"))
    root.set(f"{{{XSI_NS}}}schemaLocation", PREMIS_XSD)
    root.set("version", "3.0")
    return root


def write_premis_xml(path: str, root: ET.Element) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    ET.indent(ET.ElementTree(root), space="  ")
    tree = ET.ElementTree(root)
    with open(path, "wb") as f:
        f.write(b'<?xml version="1.0" encoding="UTF-8"?>\n')
        tree.write(f, encoding="utf-8", xml_declaration=False)


# ---------------------------------------------------------------------------
# PREMIS manifest discovery
# ---------------------------------------------------------------------------

def find_premis_manifest(submission_doc_dir: str) -> str | None:
    if not os.path.isdir(submission_doc_dir):
        return None
    candidates = [
        os.path.join(submission_doc_dir, n)
        for n in os.listdir(submission_doc_dir)
        if PREMIS_MANIFEST_REGEX.match(n)
    ]
    if not candidates:
        return None
    candidates.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    return candidates[0]


def premis_manifest_path(submission_doc_dir: str, package_id: str) -> str:
    return os.path.join(
        submission_doc_dir,
        f"premis_transfer_{package_id}_{now_stamp()}.xml"
    )


# ---------------------------------------------------------------------------
# SFTP config
# ---------------------------------------------------------------------------

def load_sftp_config(path: str) -> dict | None:
    config = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, _, value = line.partition("=")
                    config[key.strip()] = value.strip().strip('"').strip("'")
    except Exception as e:
        print(f"Warning: could not read config: {e}")
        return None
    return {
        "host":          config.get("SFTP_HOST", ""),
        "port":          int(config.get("SFTP_PORT", 22)),
        "username":      config.get("SFTP_USER", ""),
        "password":      config.get("SFTP_PASS", ""),
        "remote_parent": SFTP_REMOTE_PARENT,
    }


# ---------------------------------------------------------------------------
# SFTP helpers
# ---------------------------------------------------------------------------

def ensure_remote_dir_sftp(sftp, remote_dir: str, base_dir: str = "") -> None:
    remote_dir = remote_dir.replace("\\", "/").rstrip("/")
    base_dir   = base_dir.replace("\\", "/").rstrip("/")
    if not remote_dir:
        return
    parts: list[str] = []
    d = remote_dir
    while d not in ("", "/"):
        parts.append(d)
        d = posixpath.dirname(d)
    parts.reverse()
    for part in parts:
        if base_dir and not part.startswith(base_dir + "/"):
            continue
        try:
            sftp.stat(part)
        except Exception:
            try:
                sftp.mkdir(part)
                print(f"  Created remote directory: {part}")
            except Exception as e:
                raise RuntimeError(f"Could not create remote directory '{part}': {e}") from e


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
        rel_root   = os.path.relpath(root, local_root)
        remote_dir = remote_root if rel_root == "." else posixpath.join(
            remote_root, rel_root.replace(os.sep, "/")
        )
        for name in files:
            local_file  = os.path.join(root, name)
            rel         = os.path.relpath(local_file, local_root).replace(os.sep, "/")
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
                print(f"    [destination] {rel}")
                results.append((rel, sha256_file_remote_sftp(sftp, full)))

    _walk(remote_objects_dir, remote_objects_dir)
    results.sort()
    return results


# ---------------------------------------------------------------------------
# Local copy helpers
# ---------------------------------------------------------------------------

def safe_copy_file(src: str, dest: str) -> None:
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    try:
        shutil.copy2(src, dest)
    except OSError:
        shutil.copyfile(src, dest)


def rsync_copy(src: str, dest: str) -> None:
    src_slash = os.path.join(src, "")
    os.makedirs(dest, exist_ok=True)
    cmd = ["rsync", "-av", "--exclude", "submissionDocumentation", src_slash, dest]
    print("\n  Running rsync:")
    print("    ", " ".join(shlex.quote(c) for c in cmd))
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


# ---------------------------------------------------------------------------
# Diagnostics helpers
# ---------------------------------------------------------------------------

def write_hash_list_to_file(path: str, items: list[tuple[str, str]]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for rel, sha in sorted(items, key=lambda x: x[0]):
            f.write(f"{sha}  {rel}\n")


def write_differences_json(
    path: str,
    only_local: list[str],
    only_remote: list[str],
    mismatched: list[dict],
) -> None:
    import json
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump({
            "verification_failed":           True,
            "files_only_at_source":          only_local,
            "files_only_at_destination":     only_remote,
            "files_with_checksum_mismatch":  mismatched,
        }, f, indent=2)


def generate_diagnostics(
    submission_doc_dir: str,
    local_items: list[tuple[str, str]],
    remote_items: list[tuple[str, str]],
):
    os.makedirs(submission_doc_dir, exist_ok=True)
    stamp       = now_stamp()
    local_path  = os.path.join(submission_doc_dir, f"source_checksums_{stamp}.txt")
    remote_path = os.path.join(submission_doc_dir, f"destination_checksums_{stamp}.txt")
    diff_path   = os.path.join(submission_doc_dir, f"verification_differences_{stamp}.json")

    write_hash_list_to_file(local_path, local_items)
    write_hash_list_to_file(remote_path, remote_items)

    local_map  = dict(local_items)
    remote_map = dict(remote_items)
    only_local  = sorted(r for r in local_map  if r not in remote_map)
    only_remote = sorted(r for r in remote_map if r not in local_map)
    mismatched  = [
        {"filepath": rel, "source_checksum": local_map[rel], "destination_checksum": remote_map[rel]}
        for rel in sorted(set(local_map) & set(remote_map))
        if local_map[rel] != remote_map[rel]
    ]
    write_differences_json(diff_path, only_local, only_remote, mismatched)
    return local_path, remote_path, diff_path


def compare_local_and_remote_bytes_local(local_path, remote_path, submission_doc_dir):
    import json
    os.makedirs(submission_doc_dir, exist_ok=True)
    local_size  = os.path.getsize(local_path)
    remote_size = os.path.getsize(remote_path)
    first_diff  = None
    offset      = 0
    with open(local_path, "rb") as lf, open(remote_path, "rb") as rf:
        while True:
            lb = lf.read(CHUNK_SIZE)
            rb = rf.read(CHUNK_SIZE)
            if not lb and not rb:
                break
            if lb != rb:
                for i, (a, b) in enumerate(zip(lb, rb)):
                    if a != b:
                        first_diff = {"byte_offset": offset + i, "source_byte_hex": format(a, "02x"), "destination_byte_hex": format(b, "02x")}
                        break
                if first_diff:
                    break
            offset += len(lb)
    diff_file = os.path.join(submission_doc_dir, f"byte_difference_analysis_{now_stamp()}.txt")
    with open(diff_file, "w", encoding="utf-8") as f:
        f.write(f"source_path: {local_path}\ndestination_path: {remote_path}\n"
                f"source_size_bytes: {local_size}\ndestination_size_bytes: {remote_size}\n\n")
        f.write("FIRST BYTE DIFFERENCE FOUND:\n" + json.dumps(first_diff, indent=2) + "\n" if first_diff else "No byte difference found\n")
    return first_diff, diff_file


def compare_local_and_remote_bytes_sftp(sftp, local_path, remote_path, submission_doc_dir):
    import json
    os.makedirs(submission_doc_dir, exist_ok=True)
    local_size  = os.path.getsize(local_path)
    try:
        remote_size = sftp.stat(remote_path).st_size
    except Exception:
        remote_size = None
    first_diff = None
    offset     = 0
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
                            first_diff = {"byte_offset": offset + i, "source_byte_hex": format(a, "02x"), "destination_byte_hex": format(b, "02x")}
                            break
                    if first_diff:
                        break
                offset += len(lb)
        finally:
            try:
                rf.close()
            except Exception:
                pass
    diff_file = os.path.join(submission_doc_dir, f"byte_difference_analysis_{now_stamp()}.txt")
    with open(diff_file, "w", encoding="utf-8") as f:
        f.write(f"source_path: {local_path}\ndestination_path: {remote_path}\n"
                f"source_size_bytes: {local_size}\ndestination_size_bytes: {remote_size}\n\n")
        f.write("FIRST BYTE DIFFERENCE FOUND:\n" + json.dumps(first_diff, indent=2) + "\n" if first_diff else "No byte difference found\n")
    return first_diff, diff_file


# ---------------------------------------------------------------------------
# Find packages
# ---------------------------------------------------------------------------

def find_packages_in_parent(parent_dir: str) -> list[str]:
    if not os.path.isdir(parent_dir):
        return []
    return sorted(
        os.path.join(parent_dir, item)
        for item in os.listdir(parent_dir)
        if os.path.isdir(os.path.join(parent_dir, item))
        and os.path.isdir(os.path.join(parent_dir, item, "objects"))
    )


# ---------------------------------------------------------------------------
# Single package processing
# ---------------------------------------------------------------------------

def process_single_package(
    package_dir: str,
    transfer_agent: str | None,
    transfer_agent_id: str | None,
    originating_location: str | None,
    method_choice: str,
    transfer_notes: str | None,
    cfg: dict | None,
    dest_base: str | None,
    sftp=None,
):
    print(f"\n{'='*60}")
    print(f"Processing package: {os.path.basename(package_dir)}")
    print(f"{'='*60}")

    objects_dir        = os.path.join(package_dir, "objects")
    submission_doc_dir = os.path.join(objects_dir, "submissionDocumentation")
    package_id         = os.path.basename(os.path.normpath(package_dir))

    if not os.path.isdir(objects_dir):
        return False, f"objects/ directory not found in {package_dir}"

    os.makedirs(submission_doc_dir, exist_ok=True)

    existing = find_premis_manifest(submission_doc_dir)
    if existing:
        print(f"  Note: prior PREMIS manifest found ({os.path.basename(existing)}), creating a new one for this transfer.")

    manifest_path = premis_manifest_path(submission_doc_dir, package_id)

    # Determine transfer mode — ZIP if one exists directly in objects/
    zip_local_path = None
    for fname in os.listdir(objects_dir):
        if fname.lower().endswith(".zip") and fname not in IGNORE_BASENAMES:
            candidate = os.path.join(objects_dir, fname)
            if os.path.isfile(candidate):
                zip_local_path = candidate
                break

    source_is_zip     = zip_local_path is not None
    local_source_path = zip_local_path if source_is_zip else objects_dir
    transfer_method   = "sftp" if method_choice == "1" else "filesystem_copy"

    if source_is_zip:
        print(f"  Transfer mode: ZIP ({os.path.basename(zip_local_path)})")
    else:
        print(f"  Transfer mode: Directory (objects/)")

    # ------------------------------------------------------------------
    # Build PREMIS skeleton — agents and objects
    # ------------------------------------------------------------------
    print("  Building PREMIS inventory...")

    premis_root     = build_premis_root()
    agent_id_person = transfer_agent_id if transfer_agent_id else "unknown"
    agent_id_script = "send_and_verify.py"

    premis_root.append(_agent_element(agent_id_person, transfer_agent or "Unknown", "archives administrator"))
    premis_root.append(_agent_element(agent_id_script, "send_and_verify.py", "software"))

    if source_is_zip:
        zip_sha  = sha256_file(zip_local_path)
        zip_size = os.path.getsize(zip_local_path)
        zip_name = os.path.basename(zip_local_path)
        print(f"  Enumerating ZIP contents...")
        zip_contents = list_zip_contents(zip_local_path)
        related_ids  = [f"{package_id}/{e['name']}" for e in zip_contents]

        premis_root.append(_object_element(
            obj_id=package_id, original_name=zip_name,
            sha256=zip_sha, size=zip_size, mime="application/zip",
            related_ids=related_ids,
        ))
        for entry in zip_contents:
            premis_root.append(_object_element(
                obj_id=f"{package_id}/{entry['name']}",
                original_name=os.path.basename(entry["name"]),
                sha256=entry["sha256"], size=entry["size"], mime=entry["mime"],
            ))
        print(f"  ✓ ZIP inventoried: {len(zip_contents)} file(s) inside")
        all_object_ids = [package_id]

    else:
        file_entries: list[dict] = []
        for root, dirs, files in os.walk(objects_dir):
            if "submissionDocumentation" in dirs:
                dirs.remove("submissionDocumentation")
            for fname in files:
                fpath = os.path.join(root, fname)
                rel   = os.path.relpath(fpath, objects_dir).replace(os.sep, "/")
                if should_ignore(rel):
                    continue
                print(f"    [inventory] {rel}")
                file_entries.append({
                    "rel": rel, "path": fpath,
                    "sha256": sha256_file(fpath),
                    "size": os.path.getsize(fpath),
                    "mime": detect_mime(fpath),
                })
        file_entries.sort(key=lambda x: x["rel"])
        for entry in file_entries:
            premis_root.append(_object_element(
                obj_id=f"{package_id}/{entry['rel']}",
                original_name=os.path.basename(entry["rel"]),
                sha256=entry["sha256"], size=entry["size"], mime=entry["mime"],
            ))
        print(f"  ✓ Directory inventoried: {len(file_entries)} file(s)")
        all_object_ids = [f"{package_id}/{e['rel']}" for e in file_entries]

    # ------------------------------------------------------------------
    # Transfer + verify
    # ------------------------------------------------------------------
    transfer_dt = now_iso()
    verified    = False

    if method_choice == "1":
        if sftp is None:
            return False, "SFTP connection not available"

        remote_package_dir    = posixpath.join(cfg["remote_parent"], package_id)
        remote_objects_dir    = posixpath.join(remote_package_dir, "objects")
        remote_sub_doc        = posixpath.join(remote_objects_dir, "submissionDocumentation")
        remote_manifest_path  = posixpath.join(remote_sub_doc, os.path.basename(manifest_path))

        try:
            ensure_remote_dir_sftp(sftp, remote_objects_dir, cfg["remote_parent"])
            ensure_remote_dir_sftp(sftp, remote_sub_doc,     cfg["remote_parent"])

            if source_is_zip:
                remote_zip = posixpath.join(remote_objects_dir, zip_name)
                print("  Uploading ZIP...")
                sftp.put(zip_local_path, remote_zip)
                print("  Verifying: SHA-256 source vs destination...")
                remote_sha = sha256_file_remote_sftp(sftp, remote_zip)
                verified   = (zip_sha == remote_sha)
                print(f"  Source:      {zip_sha}")
                print(f"  Destination: {remote_sha}")
                print(f"  Result:      {'✓ PASS' if verified else '✗ FAIL'}")

                transfer_detail = (
                    f"ZIP transferred via SFTP to Archivematica staging. "
                    f"Source: {zip_local_path}. Destination: {remote_zip}. "
                    f"Originating location: {originating_location or 'not specified'}. "
                    f"Notes: {transfer_notes or 'none'}."
                )
                fixity_detail = (
                    f"SHA-256 checksum comparison of ZIP at source and destination. "
                    f"Source: {zip_sha}. Destination: {remote_sha}."
                )
                fixity_note = (
                    "Checksums match. Transfer verified." if verified
                    else f"Checksum mismatch. Source: {zip_sha}. Destination: {remote_sha}."
                )
                if not verified:
                    generate_diagnostics(submission_doc_dir,
                        [(zip_name, zip_sha)], [(zip_name, remote_sha)])
                    compare_local_and_remote_bytes_sftp(sftp, zip_local_path, remote_zip, submission_doc_dir)
                transfer_obj_ids = [package_id]
                fixity_obj_ids   = [package_id]

            else:
                print("  Uploading directory tree...")
                upload_file_tree_sftp(sftp, local_source_path, remote_objects_dir)
                print("  Verifying: SHA-256 per file, source vs destination...")
                print("  Hashing source files:")
                local_items  = compute_objects_file_list(local_source_path, label="source")
                print("  Hashing destination files:")
                remote_items = compute_remote_objects_file_list_sftp(sftp, remote_objects_dir)
                local_dict   = dict(local_items)
                remote_dict  = dict(remote_items)
                verified     = (local_dict == remote_dict)
                files_ok     = len([f for f in local_dict if f in remote_dict and local_dict[f] == remote_dict[f]])
                print(f"  Files at source:      {len(local_items)}")
                print(f"  Files at destination: {len(remote_items)}")
                print(f"  Result:               {'✓ PASS' if verified else '✗ FAIL'}")

                transfer_detail = (
                    f"Directory transferred via SFTP to Archivematica staging. "
                    f"Source: {local_source_path}. Destination: {remote_objects_dir}. "
                    f"Files transferred: {len(local_items)}. submissionDocumentation/ excluded. "
                    f"Originating location: {originating_location or 'not specified'}. "
                    f"Notes: {transfer_notes or 'none'}."
                )
                fixity_detail = (
                    f"SHA-256 per-file comparison, source vs destination. "
                    f"Files at source: {len(local_items)}. Files at destination: {len(remote_items)}. "
                    f"Files verified: {files_ok}."
                )
                fixity_note = (
                    f"All {files_ok} files match. Transfer verified." if verified
                    else f"{files_ok} of {len(local_items)} files match. Verification failed."
                )
                if not verified:
                    generate_diagnostics(submission_doc_dir, local_items, remote_items)
                transfer_obj_ids = all_object_ids
                fixity_obj_ids   = all_object_ids

            _append_events(premis_root, transfer_dt, transfer_detail, verified,
                           fixity_detail, fixity_note, agent_id_person, agent_id_script,
                           transfer_obj_ids, fixity_obj_ids)
            write_premis_xml(manifest_path, premis_root)
            print(f"  PREMIS manifest: {os.path.basename(manifest_path)}")
            print("  Uploading PREMIS manifest to remote...")
            sftp.put(manifest_path, remote_manifest_path)

            if not verified:
                print("  ✗ WARNING: Verification FAILED — diagnostics written to submissionDocumentation/")
                return False, "Verification failed: checksums do not match"

        except Exception as e:
            traceback.print_exc()
            _append_events(premis_root, transfer_dt,
                f"Transfer failed. Error: {e}. Originating location: {originating_location or 'not specified'}. Notes: {transfer_notes or 'none'}.",
                False, "Fixity check not completed due to transfer error.", f"Error: {e}",
                agent_id_person, agent_id_script, all_object_ids, all_object_ids)
            write_premis_xml(manifest_path, premis_root)
            return False, f"SFTP transfer error: {e}"

    else:
        remote_package_dir   = os.path.join(dest_base, package_id)
        remote_objects_dir   = os.path.join(remote_package_dir, "objects")
        remote_sub_doc       = os.path.join(remote_objects_dir, "submissionDocumentation")
        remote_manifest_path = os.path.join(remote_sub_doc, os.path.basename(manifest_path))

        try:
            os.makedirs(remote_objects_dir, exist_ok=True)
            os.makedirs(remote_sub_doc,     exist_ok=True)

            if source_is_zip:
                dest_zip = os.path.join(remote_objects_dir, zip_name)
                print("  Copying ZIP...")
                shutil.copy2(zip_local_path, dest_zip)
                print("  Verifying: SHA-256 source vs destination...")
                remote_sha = sha256_file(dest_zip)
                verified   = (zip_sha == remote_sha)
                print(f"  Source:      {zip_sha}")
                print(f"  Destination: {remote_sha}")
                print(f"  Result:      {'✓ PASS' if verified else '✗ FAIL'}")

                transfer_detail = (
                    f"ZIP copied to destination. Source: {zip_local_path}. Destination: {dest_zip}. "
                    f"Originating location: {originating_location or 'not specified'}. Notes: {transfer_notes or 'none'}."
                )
                fixity_detail = (
                    f"SHA-256 checksum comparison of ZIP at source and destination. "
                    f"Source: {zip_sha}. Destination: {remote_sha}."
                )
                fixity_note = (
                    "Checksums match. Transfer verified." if verified
                    else f"Checksum mismatch. Source: {zip_sha}. Destination: {remote_sha}."
                )
                if not verified:
                    generate_diagnostics(submission_doc_dir, [(zip_name, zip_sha)], [(zip_name, remote_sha)])
                    compare_local_and_remote_bytes_local(zip_local_path, dest_zip, submission_doc_dir)
                transfer_obj_ids = [package_id]
                fixity_obj_ids   = [package_id]

            else:
                try:
                    print("  Attempting rsync copy...")
                    rsync_copy(local_source_path, remote_objects_dir)
                except Exception as e:
                    print(f"  rsync failed ({e}), falling back to shutil")
                    copy_tree_shutil(local_source_path, remote_objects_dir)

                print("  Verifying: SHA-256 per file, source vs destination...")
                print("  Hashing source files:")
                local_items  = compute_objects_file_list(local_source_path, label="source")
                print("  Hashing destination files:")
                remote_items = compute_objects_file_list(remote_objects_dir, label="destination")
                local_dict   = dict(local_items)
                remote_dict  = dict(remote_items)
                verified     = (local_dict == remote_dict)
                files_ok     = len([f for f in local_dict if f in remote_dict and local_dict[f] == remote_dict[f]])
                print(f"  Files at source:      {len(local_items)}")
                print(f"  Files at destination: {len(remote_items)}")
                print(f"  Result:               {'✓ PASS' if verified else '✗ FAIL'}")

                transfer_detail = (
                    f"Directory copied to destination. Source: {local_source_path}. Destination: {remote_objects_dir}. "
                    f"Files transferred: {len(local_items)}. submissionDocumentation/ excluded. "
                    f"Originating location: {originating_location or 'not specified'}. Notes: {transfer_notes or 'none'}."
                )
                fixity_detail = (
                    f"SHA-256 per-file comparison, source vs destination. "
                    f"Files at source: {len(local_items)}. Files at destination: {len(remote_items)}. "
                    f"Files verified: {files_ok}."
                )
                fixity_note = (
                    f"All {files_ok} files match. Transfer verified." if verified
                    else f"{files_ok} of {len(local_items)} files match. Verification failed."
                )
                if not verified:
                    generate_diagnostics(submission_doc_dir, local_items, remote_items)
                transfer_obj_ids = all_object_ids
                fixity_obj_ids   = all_object_ids

            _append_events(premis_root, transfer_dt, transfer_detail, verified,
                           fixity_detail, fixity_note, agent_id_person, agent_id_script,
                           transfer_obj_ids, fixity_obj_ids)
            write_premis_xml(manifest_path, premis_root)
            print(f"  PREMIS manifest: {os.path.basename(manifest_path)}")
            safe_copy_file(manifest_path, remote_manifest_path)

            if not verified:
                print("  ✗ WARNING: Verification FAILED — diagnostics written to submissionDocumentation/")
                return False, "Verification failed: checksums do not match"

        except FileNotFoundError:
            return False, "rsync not found on PATH."
        except subprocess.CalledProcessError as e:
            return False, f"rsync failed with exit code {e.returncode}"
        except Exception as e:
            traceback.print_exc()
            _append_events(premis_root, transfer_dt,
                f"Transfer failed. Error: {e}.",
                False, "Fixity check not completed due to transfer error.", f"Error: {e}",
                agent_id_person, agent_id_script, all_object_ids, all_object_ids)
            write_premis_xml(manifest_path, premis_root)
            return False, f"Local copy error: {e}"

    print("  ✓ Package processed successfully")
    return True, None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("\n" + "="*70)
    print("DIGITAL PRESERVATION PACKAGE TRANSFER & VERIFICATION")
    print("="*70)
    print("\nThis script:")
    print("  • Transfers packages via SFTP or local filesystem")
    print("  • Verifies every file using SHA-256 checksums")
    print("  • Creates a PREMIS XML transfer manifest in submissionDocumentation/")
    print("="*70 + "\n")

    batch_mode = input("Process multiple packages? [Y/n]: ").strip().lower() in ("", "y", "yes")
    packages_to_process: list[str] = []

    if batch_mode:
        parent_dir = normalize_path(input("Enter or drag the PARENT directory containing package folders: ").strip())
        if not parent_dir or not os.path.isdir(parent_dir):
            print("ERROR: invalid parent directory.")
            return
        packages_to_process = find_packages_in_parent(parent_dir)
        if not packages_to_process:
            print("ERROR: no packages found (no subdirectories with an objects/ folder).")
            return
        print(f"\nFound {len(packages_to_process)} package(s):")
        for i, pkg in enumerate(packages_to_process, 1):
            print(f"  {i}. {os.path.basename(pkg)}")
        if input(f"\nProcess all {len(packages_to_process)} packages? [Y/n]: ").strip().lower() not in ("", "y", "yes"):
            print("Cancelled.")
            return
    else:
        package_dir = normalize_path(input("Enter or drag the PACKAGE directory (that contains objects/): ").strip())
        if not package_dir or not os.path.isdir(package_dir):
            print("ERROR: invalid package directory.")
            return
        packages_to_process = [package_dir]

    print("\n" + "-"*70)
    print("TRANSFER METADATA")
    print("-"*70)
    transfer_agent       = input("Your name (for PREMIS agent record): ").strip() or None
    transfer_agent_id    = transfer_agent.lower().replace(" ", "-") if transfer_agent else "unknown"
    originating_location = input("Where are these files from? (e.g. workstation, NAS, project name): ").strip() or None
    transfer_notes       = input("Any notes about this transfer? (optional): ").strip() or None
    print("-"*70 + "\n")

    print("Transfer methods:")
    print("  1) SFTP (to /sftp-transfer-source — Archivematica staging)")
    print("  2) Local filesystem copy (mounted drive or UNC path)")
    method_choice = input("Choose transfer method [1/2] (default 1): ").strip() or "1"

    cfg       = None
    dest_base = None
    sftp      = None
    transport = None

    if method_choice == "1":
        if paramiko is None:
            print("ERROR: paramiko not installed. Run: pip install paramiko")
            return

        use_config = input(f"Use SFTP config file [{SFTP_CONFIG_PATH}]? [Y/n]: ").strip().lower()
        if use_config in ("", "y", "yes") and os.path.exists(SFTP_CONFIG_PATH):
            cfg = load_sftp_config(SFTP_CONFIG_PATH)
            if cfg:
                print(f"Loaded SFTP config from {SFTP_CONFIG_PATH}")

        if cfg is None:
            raw_host = input("SFTP host (hostname or IP): ").strip()
            if raw_host.lower().startswith(("sftp://", "ssh://")):
                raw_host = raw_host.split("://", 1)[1].split("/", 1)[0]
            port_str = input("SFTP port [22]: ").strip()
            username = input("SFTP username: ").strip()
            password = getpass.getpass("SFTP password: ")
            try:
                port = int(port_str) if port_str else 22
            except Exception:
                port = 22
            cfg = {"host": raw_host, "port": port, "username": username,
                   "password": password, "remote_parent": SFTP_REMOTE_PARENT}

        cfg["remote_parent"] = SFTP_REMOTE_PARENT

        print("\nConnecting to SFTP...")
        try:
            transport = paramiko.Transport((cfg["host"], int(cfg["port"])))
            transport.connect(username=cfg["username"], password=cfg["password"])
            sftp = paramiko.SFTPClient.from_transport(transport)
            print("✓ SFTP connection established.\n")
        except Exception as e:
            print(f"ERROR connecting to SFTP: {e}")
            traceback.print_exc()
            return

    else:
        dest_base = normalize_path(input("Enter destination base directory (mounted path or UNC): ").strip())
        if not dest_base:
            print("ERROR: destination required.")
            return

    results = []
    for package_dir in packages_to_process:
        success, error = process_single_package(
            package_dir          = package_dir,
            transfer_agent       = transfer_agent,
            transfer_agent_id    = transfer_agent_id,
            originating_location = originating_location,
            method_choice        = method_choice,
            transfer_notes       = transfer_notes,
            cfg                  = cfg,
            dest_base            = dest_base,
            sftp                 = sftp,
        )
        results.append({"package": os.path.basename(package_dir), "success": success, "error": error})

    for conn in (sftp, transport):
        if conn:
            try:
                conn.close()
            except Exception:
                pass

    print("\n" + "="*70)
    print("TRANSFER SUMMARY")
    print("="*70)
    successful = [r for r in results if r["success"]]
    failed     = [r for r in results if not r["success"]]
    print(f"\nTotal packages: {len(results)}")
    print(f"Successful:     {len(successful)}")
    print(f"Failed:         {len(failed)}")
    if successful:
        print("\n✓ Successful:")
        for r in successful:
            print(f"  • {r['package']}")
    if failed:
        print("\n✗ Failed:")
        for r in failed:
            print(f"  • {r['package']}: {r['error']}")
    print("\n" + "="*70)
    print("Done.")
    print("="*70 + "\n")


if __name__ == "__main__":
    main()