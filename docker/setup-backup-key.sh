#!/bin/bash
# setup-backup-key.sh — Initialize backup encryption key in secure location
#
# Creates /etc/chronicle/backup-encryption-key, separate from backup data.

set -euo pipefail

KEY_DIR="/etc/chronicle"
KEY_FILE="${KEY_DIR}/backup-encryption-key"

if [ -f "$KEY_FILE" ]; then
    echo "Backup encryption key already exists at ${KEY_FILE}"
    echo "Permissions: $(stat -c '%a %U:%G' "$KEY_FILE")"
    exit 0
fi

sudo mkdir -p "$KEY_DIR"

echo "Generating new backup encryption key..."
openssl rand -base64 64 | sudo tee "$KEY_FILE" > /dev/null

sudo chmod 600 "$KEY_FILE"
sudo chown root:root "$KEY_FILE"
echo "Backup encryption key ready at ${KEY_FILE}"
echo "Permissions: $(stat -c '%a %U:%G' "$KEY_FILE")"
