#!/usr/bin/env bash
# Format emitted by the current backup and key-ceremony writers.
# shellcheck disable=SC2034 # Sourced contract values consumed by backup, restore and key-ceremony callers.
BACKUP_MANIFEST_VERSION=2
# shellcheck disable=SC2034 # Sourced by the encryption and decryption callers.
BACKUP_PBKDF2_ITERATIONS=600000
# shellcheck disable=SC2034 # Sourced by key-ceremony and key-recovery.
BACKUP_KEY_REPRESENTATION=passphrase-file-bytes
