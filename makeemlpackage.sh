#!/usr/bin/env bash
set -euo pipefail

########################################
# Helpers
########################################

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "ERROR: required command '$1' not found in PATH." >&2
    exit 1
  fi
}

clean_input() {
  local p="$1"
  # trim leading/trailing whitespace
  p="${p#"${p%%[![:space:]]*}"}"
  p="${p%"${p##*[![:space:]]}"}"
  # drop trailing slash
  p="${p%/}"
  # strip surrounding quotes
  p="${p%\"}"; p="${p#\"}"
  p="${p%\'}"; p="${p#\'}"
  # turn "\ " into spaces if user typed /Volumes/My\ Drive
  p="${p//\\ / }"
  printf '%s' "$p"
}

print_progress() {
  # label, current, total
  local label="$1"
  local current="$2"
  local total="$3"
  if (( total > 0 )); then
    local percent=$(( current * 100 / total ))
    printf '\r  %s: %d / %d (%d%%)' "$label" "$current" "$total" "$percent"
  fi
}

RED="$(printf '\033[31m')"
GREEN="$(printf '\033[32m')"
YELLOW="$(printf '\033[33m')"
NC="$(printf '\033[0m')"

# Required tools
require_cmd zip
require_cmd unzip
require_cmd shasum
require_cmd find
require_cmd rsync
require_cmd mktemp
require_cmd date

echo "=== Package Builder (zip at source, verify, then package) ==="
echo

########################################
# 1. Collect input (name → source → destination → package name)
########################################

read -rp "Technician username: " TECH_USER
if [[ -z "$TECH_USER" ]]; then
  echo "ERROR: technician username is required." >&2
  exit 1
fi

read -rp "Source directory: " SRC_RAW
SRC_DIR="$(clean_input "$SRC_RAW")"
if [[ ! -d "$SRC_DIR" ]]; then
  echo "ERROR: source directory not found: [$SRC_DIR]" >&2
  exit 1
fi

read -rp "Destination directory (where the package folder will live): " DEST_RAW
DEST_DIR="$(clean_input "$DEST_RAW")"
if [[ ! -d "$DEST_DIR" ]]; then
  echo "ERROR: destination directory does not exist: [$DEST_DIR]" >&2
  exit 1
fi

read -rp "Package name (e.g. AA096): " PKG_NAME
if [[ -z "$PKG_NAME" ]]; then
  echo "ERROR: package name is required." >&2
  exit 1
fi

########################################
# 2. Core paths
########################################

# Timestamp for manifest filename (EDT, 24-hour clock)
EDT_TS="$(TZ='America/New_York' date +%Y%m%d%H%M)EDT"

SRC_PARENT="$(dirname "$SRC_DIR")"
SRC_BASENAME="$(basename "$SRC_DIR")"

PKG_DIR="$DEST_DIR/$PKG_NAME"
PKG_ZIP="$PKG_DIR/${PKG_NAME}.zip"

MANIFEST_FILENAME="${PKG_NAME}-manifest-${EDT_TS}.txt"
MANIFEST_PATH="$PKG_DIR/$MANIFEST_FILENAME"

# Temporary working area (on local disk)
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/pkg_${PKG_NAME}_XXXX")"
SRC_MANIFEST="$WORK_DIR/source_manifest.txt"
VERIFY_RESULTS="$WORK_DIR/verify_results.txt"
TMP_ZIP="$WORK_DIR/${PKG_NAME}.zip"
UNZIP_DIR="$WORK_DIR/unzipped"

echo
echo "Resolved paths:"
echo "  Technician : $TECH_USER"
echo "  Source     : [$SRC_DIR]"
echo "  Source base: [$SRC_BASENAME]"
echo "  Destination: [$DEST_DIR]"
echo "  Package dir: [$PKG_DIR]"
echo "  Final ZIP  : [$PKG_ZIP]"
echo "  Manifest   : [$MANIFEST_FILENAME]"
echo "  Work dir   : [$WORK_DIR]"
echo

########################################
# 3. Ensure package directory doesn't already exist
########################################

if [[ -e "$PKG_DIR" ]]; then
  echo "${RED}ERROR: package directory already exists:${NC}"
  echo "  $PKG_DIR"
  echo "Refusing to overwrite. Move or rename it and try again."
  rm -rf "$WORK_DIR"
  exit 1
fi

mkdir -p "$PKG_DIR"

########################################
# 4. Build source manifest (checksums BEFORE any zipping)
########################################

echo "Step 1/5: Computing source checksums..."

# Total file count for percentages
total_files=$(find "$SRC_DIR" -type f | wc -l | tr -d '[:space:]')
total_files=${total_files:-0}

{
  echo "Source manifest for package: $PKG_NAME"
  echo "Technician: $TECH_USER"
  echo "Created: $(date -Iseconds)"
  echo "Source directory: $SRC_DIR"
  echo "Checksum algorithm: sha256"
  echo
  echo "STATUS|RELATIVE_PATH|SHA256"
} > "$SRC_MANIFEST"

i=0
find "$SRC_DIR" -type f -print0 | while IFS= read -r -d '' f; do
  rel="${f#$SRC_DIR/}"
  hash="$(shasum -a 256 "$f" | awk '{print $1}')"
  echo "OK|$rel|$hash" >> "$SRC_MANIFEST"
  i=$(( i + 1 ))
  print_progress "Checksumming source files" "$i" "$total_files"
done

echo
echo "  Checksums complete."

########################################
# 5. Create ZIP from source directory (on local filesystem)
########################################

echo "Step 2/5: Creating ZIP from source (this may take a while)..."

(
  cd "$SRC_PARENT"
  zip -r "$TMP_ZIP" "$SRC_BASENAME" >/dev/null
)

if [[ ! -f "$TMP_ZIP" ]]; then
  echo "${RED}ERROR: failed to create temporary ZIP at:${NC}"
  echo "  $TMP_ZIP"
  rm -rf "$WORK_DIR"
  exit 1
fi

ZIP_HASH_SRC="$(shasum -a 256 "$TMP_ZIP" | awk '{print $1}')"
echo "  Source ZIP hash: $ZIP_HASH_SRC"

########################################
# 6. Copy ZIP to destination package directory
########################################

echo "Step 3/5: Copying ZIP to destination (rsync with progress)..."

# rsync progress for the single large file
rsync --progress "$TMP_ZIP" "$PKG_ZIP"

if [[ ! -f "$PKG_ZIP" ]]; then
  echo "${RED}ERROR: ZIP file missing at destination after copy:${NC}"
  echo "  $PKG_ZIP"
  rm -rf "$WORK_DIR"
  exit 1
fi

ZIP_HASH_DEST="$(shasum -a 256 "$PKG_ZIP" | awk '{print $1}')"
echo "  Destination ZIP hash: $ZIP_HASH_DEST"

if [[ "$ZIP_HASH_SRC" != "$ZIP_HASH_DEST" ]]; then
  echo "${RED}ERROR: ZIP hash mismatch between source and destination!${NC}"
  echo "Source ZIP:      $TMP_ZIP"
  echo "  SHA256: $ZIP_HASH_SRC"
  echo "Destination ZIP: $PKG_ZIP"
  echo "  SHA256: $ZIP_HASH_DEST"
  rm -rf "$WORK_DIR"
  exit 1
fi

echo "${GREEN}  ZIP copied and hashes match.${NC}"

########################################
# 7. Unzip destination ZIP into temp area and verify file contents
########################################

echo "Step 4/5: Unzipping destination ZIP and verifying files..."

mkdir -p "$UNZIP_DIR"
unzip -q "$PKG_ZIP" -d "$UNZIP_DIR"

DEST_ROOT="$UNZIP_DIR/$SRC_BASENAME"
if [[ ! -d "$DEST_ROOT" ]]; then
  echo "${RED}ERROR: After unzip, expected directory not found:${NC}"
  echo "  $DEST_ROOT"
  rm -rf "$WORK_DIR"
  exit 1
fi

ok=0
missing=0
mismatch=0
: > "$VERIFY_RESULTS"

total_manifest_lines=$(grep -c '^OK|' "$SRC_MANIFEST" || true)
total_manifest_lines=${total_manifest_lines:-0}
processed=0

while IFS='|' read -r status rel src_hash; do
  [[ "$status" != "OK" ]] && continue
  processed=$(( processed + 1 ))

  dest_file="$DEST_ROOT/$rel"

  if [[ ! -f "$dest_file" ]]; then
    ((missing++))
    {
      echo "MISSING | $rel"
      echo "  source checksum: $src_hash"
      echo "  dest   checksum: (missing - file not found in unzipped tree)"
      echo
    } >> "$VERIFY_RESULTS"
  else
    dest_hash="$(shasum -a 256 "$dest_file" | awk '{print $1}')"
    if [[ "$dest_hash" == "$src_hash" ]]; then
      ((ok++))
      {
        echo "OK | $rel"
        echo "  source checksum: $src_hash"
        echo "  dest   checksum: $dest_hash"
        echo
      } >> "$VERIFY_RESULTS"
    else
      ((mismatch++))
      {
        echo "MISMATCH | $rel"
        echo "  source checksum: $src_hash"
        echo "  dest   checksum: $dest_hash"
        echo
      } >> "$VERIFY_RESULTS"
    fi
  fi

  print_progress "Verifying unzipped files" "$processed" "$total_manifest_lines"
done < "$SRC_MANIFEST"

echo

overall_status="OK"
if (( missing > 0 || mismatch > 0 )); then
  overall_status="FAIL"
fi

########################################
# 8. Write final manifest/receipt in package directory
########################################

echo "Step 5/5: Writing manifest/receipt: $MANIFEST_FILENAME"

{
  echo "Package Manifest & Verification Report"
  echo "Package: $PKG_NAME"
  echo "Technician: $TECH_USER"
  echo "Timestamp (EDT): $EDT_TS"
  echo
  echo "Source directory: $SRC_DIR"
  echo "Destination package directory: $PKG_DIR"
  echo
  echo "ZIP file:"
  echo "  Name:   $(basename "$PKG_ZIP")"
  echo "  SHA256: $ZIP_HASH_DEST"
  echo
  echo "[SUMMARY]"
  echo "Files verified OK:    $ok"
  echo "Missing files:        $missing"
  echo "Mismatched files:     $mismatch"
  echo "Overall verification: $overall_status"
  echo
  echo "[DETAILS]"
  echo "FORMAT:"
  echo "  STATUS | relative/path"
  echo "    source checksum: <sha256>"
  echo "    dest   checksum: <sha256 or explanation>"
  echo
  cat "$VERIFY_RESULTS"
} > "$MANIFEST_PATH"

if [[ ! -f "$MANIFEST_PATH" ]]; then
  echo "${RED}ERROR: manifest file was not created:${NC}"
  echo "  $MANIFEST_PATH"
  rm -rf "$WORK_DIR"
  exit 1
fi

if [[ "$overall_status" != "OK" ]]; then
  echo
  echo "${RED}❗ VERIFICATION FAILED ❗${NC}"
  echo "${YELLOW}Missing files : $missing${NC}"
  echo "${YELLOW}Mismatched    : $mismatch${NC}"
  echo "See manifest for full details:"
  echo "  $MANIFEST_PATH"
  rm -rf "$WORK_DIR"
  exit 1
fi

echo
echo "${GREEN}All checksums match after unzip. Preservation package is VALID.${NC}"

########################################
# 9. Cleanup temp work directory
########################################

rm -rf "$WORK_DIR"

echo
echo "=== DONE ==="
echo "Package directory:"
echo "  $PKG_DIR"
echo
echo "Contents:"
ls -l "$PKG_DIR"
echo
echo "${GREEN}Original source was never modified. Destination stores ZIP + manifest only.${NC}"
