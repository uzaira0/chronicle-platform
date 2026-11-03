#!/bin/bash
# Chronicle Key Ceremony Script
# Splits TDE principal key and backup encryption key into Shamir shares (3-of-5).
#
# Usage:
#   ./key-ceremony.sh [--tde-key <hex>] [--backup-key-file <path>] [--output-dir <dir>]
#
# If keys are not provided, new ones are generated.
# Produces share-{1..5}.txt for each key in the output directory.
#
# Requires: ssss-split (from ssss package) OR Python 3

set -euo pipefail

# shellcheck source=docker/backup-format.sh
source "$(dirname "${BASH_SOURCE[0]}")/backup-format.sh"

# ── Defaults ──────────────────────────────────────────────────────────────────
OUTPUT_DIR="./key-ceremony-output"
TDE_KEY=""
BACKUP_KEY_FILE=""
SHARES_TOTAL=5
SHARES_THRESHOLD=3

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

log()      { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
log_ok()   { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${GREEN}OK${NC} $*"; }
log_err()  { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${RED}ERROR${NC} $*" >&2; }
log_warn() { echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] ${YELLOW}WARN${NC} $*"; }

usage() {
    echo "Usage: $0 [--tde-key <hex>] [--backup-key-file <path>] [--output-dir <dir>]"
    echo ""
    echo "Options:"
    echo "  --tde-key <hex>           TDE principal key as hex string (generated if omitted)"
    echo "  --backup-key-file <path>  Path to backup encryption key file (generated if omitted)"
    echo "  --output-dir <dir>        Output directory for shares (default: ./key-ceremony-output)"
    exit 1
}

# ── Parse arguments ───────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --tde-key)        TDE_KEY="$2"; shift 2 ;;
        --backup-key-file) BACKUP_KEY_FILE="$2"; shift 2 ;;
        --output-dir)     OUTPUT_DIR="$2"; shift 2 ;;
        --help|-h)        usage ;;
        *)                log_err "Unknown option: $1"; usage ;;
    esac
done

# ── Detect Shamir tool ────────────────────────────────────────────────────────
SHAMIR_TOOL=""
if command -v ssss-split >/dev/null 2>&1; then
    SHAMIR_TOOL="ssss"
    log "Using ssss-split for Shamir secret sharing"
elif command -v python3 >/dev/null 2>&1; then
    SHAMIR_TOOL="python"
    log "Using Python 3 for Shamir secret sharing"
else
    log_err "Neither ssss-split nor python3 found. Install ssss or python3."
    exit 1
fi

# ── Python-based Shamir implementation (GF(256)) ─────────────────────────────
python_split() {
    python3 "$(dirname "${BASH_SOURCE[0]}")/shamir.py" split "$@"
}

# ── ssss-based split ──────────────────────────────────────────────────────────
ssss_split_key() {
    local secret_hex="$1"
    local threshold="$2"
    local share_count="$3"

    echo "$secret_hex" | ssss-split -t "$threshold" -n "$share_count" -x -Q 2>/dev/null
}

# ── Generate or read keys ─────────────────────────────────────────────────────
if [ -z "$TDE_KEY" ]; then
    log "Generating new TDE principal key..."
    TDE_KEY=$(openssl rand -hex 32)
    log_ok "TDE principal key generated (256-bit)"
else
    log "Using provided TDE principal key"
fi

if [ -n "$BACKUP_KEY_FILE" ] && [ -f "$BACKUP_KEY_FILE" ]; then
    BACKUP_KEY_HEX=$(xxd -p -c 256 "$BACKUP_KEY_FILE" | tr -d '\n')
    log "Read backup encryption key from $BACKUP_KEY_FILE"
else
    log "Generating new backup encryption key..."
    BACKUP_KEY_HEX=$(openssl rand -base64 64 | xxd -p -c 256 | tr -d '\n')
    log_ok "Backup encryption key generated (512-bit)"
fi

# ── Create output directory ───────────────────────────────────────────────────
mkdir -p "$OUTPUT_DIR"
chmod 700 "$OUTPUT_DIR"

TDE_SHARE_DIR="${OUTPUT_DIR}/tde-shares"
BACKUP_SHARE_DIR="${OUTPUT_DIR}/backup-shares"
mkdir -p "$TDE_SHARE_DIR" "$BACKUP_SHARE_DIR"
chmod 700 "$TDE_SHARE_DIR" "$BACKUP_SHARE_DIR"

# ── Split TDE key ─────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}=== Splitting TDE Principal Key (${SHARES_THRESHOLD}-of-${SHARES_TOTAL}) ===${NC}"

if [ "$SHAMIR_TOOL" = "ssss" ]; then
    SHARES_OUTPUT=$(ssss_split_key "$TDE_KEY" "$SHARES_THRESHOLD" "$SHARES_TOTAL")
    i=1
    while IFS= read -r line; do
        echo "$line" > "${TDE_SHARE_DIR}/share-${i}.txt"
        chmod 600 "${TDE_SHARE_DIR}/share-${i}.txt"
        log_ok "TDE share ${i} written to ${TDE_SHARE_DIR}/share-${i}.txt"
        i=$((i + 1))
    done <<< "$SHARES_OUTPUT"
else
    SHARES_OUTPUT=$(python_split "$TDE_KEY" "$SHARES_THRESHOLD" "$SHARES_TOTAL")
    i=1
    while IFS= read -r line; do
        echo "$line" > "${TDE_SHARE_DIR}/share-${i}.txt"
        chmod 600 "${TDE_SHARE_DIR}/share-${i}.txt"
        log_ok "TDE share ${i} written to ${TDE_SHARE_DIR}/share-${i}.txt"
        i=$((i + 1))
    done <<< "$SHARES_OUTPUT"
fi

# ── Split Backup key ─────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}=== Splitting Backup Encryption Key (${SHARES_THRESHOLD}-of-${SHARES_TOTAL}) ===${NC}"

if [ "$SHAMIR_TOOL" = "ssss" ]; then
    SHARES_OUTPUT=$(ssss_split_key "$BACKUP_KEY_HEX" "$SHARES_THRESHOLD" "$SHARES_TOTAL")
    i=1
    while IFS= read -r line; do
        echo "$line" > "${BACKUP_SHARE_DIR}/share-${i}.txt"
        chmod 600 "${BACKUP_SHARE_DIR}/share-${i}.txt"
        log_ok "Backup share ${i} written to ${BACKUP_SHARE_DIR}/share-${i}.txt"
        i=$((i + 1))
    done <<< "$SHARES_OUTPUT"
else
    SHARES_OUTPUT=$(python_split "$BACKUP_KEY_HEX" "$SHARES_THRESHOLD" "$SHARES_TOTAL")
    i=1
    while IFS= read -r line; do
        echo "$line" > "${BACKUP_SHARE_DIR}/share-${i}.txt"
        chmod 600 "${BACKUP_SHARE_DIR}/share-${i}.txt"
        log_ok "Backup share ${i} written to ${BACKUP_SHARE_DIR}/share-${i}.txt"
        i=$((i + 1))
    done <<< "$SHARES_OUTPUT"
fi

# ── Write key fingerprints (SHA-256 of the key, NOT the key itself) ───────────
TDE_FINGERPRINT=$(echo -n "$TDE_KEY" | sha256sum | awk '{print $1}')
BACKUP_FINGERPRINT=$(echo -n "$BACKUP_KEY_HEX" | sha256sum | awk '{print $1}')

cat > "${OUTPUT_DIR}/ceremony-record.json" <<EOF
{
    "ceremony_date": "$(date -Iseconds)",
    "shamir_threshold": ${SHARES_THRESHOLD},
    "shamir_total_shares": ${SHARES_TOTAL},
    "shamir_tool": "${SHAMIR_TOOL}",
    "backup_key_representation": "$BACKUP_KEY_REPRESENTATION",
    "tde_key_fingerprint_sha256": "${TDE_FINGERPRINT}",
    "backup_key_fingerprint_sha256": "${BACKUP_FINGERPRINT}",
    "tde_key_length_bits": $((${#TDE_KEY} * 4)),
    "backup_key_length_bits": $((${#BACKUP_KEY_HEX} * 4))
}
EOF
chmod 600 "${OUTPUT_DIR}/ceremony-record.json"

# ── Instructions ──────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}=========================================="
echo "Key Ceremony Complete"
echo -e "==========================================${NC}"
echo ""
echo "Output directory: ${OUTPUT_DIR}"
echo ""
echo -e "${BOLD}Share Distribution Instructions:${NC}"
echo ""
echo "  TDE Principal Key Shares (${TDE_SHARE_DIR}/):"
echo "    share-1.txt  ->  Custodian 1 (e.g., CTO / Security Lead)"
echo "    share-2.txt  ->  Custodian 2 (e.g., Lead DevOps Engineer)"
echo "    share-3.txt  ->  Custodian 3 (e.g., DBA / Infrastructure Lead)"
echo "    share-4.txt  ->  Custodian 4 (e.g., Compliance Officer)"
echo "    share-5.txt  ->  Custodian 5 (e.g., Off-site secure storage)"
echo ""
echo "  Backup Encryption Key Shares (${BACKUP_SHARE_DIR}/):"
echo "    share-1.txt  ->  Custodian 1"
echo "    share-2.txt  ->  Custodian 2"
echo "    share-3.txt  ->  Custodian 3"
echo "    share-4.txt  ->  Custodian 4"
echo "    share-5.txt  ->  Custodian 5"
echo ""
echo -e "${YELLOW}IMPORTANT:${NC}"
echo "  1. Distribute shares to DIFFERENT custodians"
echo "  2. Each custodian should store their share in a DIFFERENT secure location"
echo "  3. No single person should hold more than one share of the same key"
echo "  4. Store shares on encrypted USB drives, in sealed envelopes, or in a"
echo "     physical safe -- NOT on shared drives or email"
echo "  5. Keep the ceremony-record.json (contains only fingerprints, not keys)"
echo "  6. DELETE the output directory after distributing shares:"
echo "     shred -u ${OUTPUT_DIR}/tde-shares/share-*.txt"
echo "     shred -u ${OUTPUT_DIR}/backup-shares/share-*.txt"
echo "  7. Any ${SHARES_THRESHOLD} of ${SHARES_TOTAL} shares can reconstruct the key"
echo "  8. Record which custodian received which share number in a secure log"
echo ""
echo "  Key fingerprints (safe to store -- these are SHA-256 of the keys):"
echo "    TDE:    ${TDE_FINGERPRINT}"
echo "    Backup: ${BACKUP_FINGERPRINT}"
echo ""
