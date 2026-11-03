# Chronicle Server Vault Policy
# Grants least-privilege access to application secrets.
#
# Path structure: secret/data/chronicle/{category}
#   database  — PostgreSQL credentials
#   jwt       — JWT signing key
#   smtp      — Email service credentials
#   hazelcast — Cluster authentication passwords
#   mobile    — Mobile app signing secret and API key
#   twilio    — SMS provider credentials
#   crowdsec  — WAF bouncer API key
#   grafana   — Monitoring dashboard admin password

# Read application secrets (KV v2 data path)
path "secret/data/chronicle/*" {
    capabilities = ["read"]
}

# Read secret metadata (required for versioned reads)
path "secret/metadata/chronicle/*" {
    capabilities = ["read", "list"]
}

# Per-study envelope-encryption PRIVATE keys live at
#   secret/data/encryption/study/{studyId}/{keyId}  (VaultStudyKeyStore).
# The backend WRITES these when provisioning/rotating a study key and READS them for
# decrypt-on-read/export — so this path needs create/update/read (the chronicle/* secrets
# above are read-only by contrast). Keys are never deleted in place (rotation mints a new
# keyId); destructive ops stay denied below so prior ciphertext stays decryptable.
path "secret/data/encryption/*" {
    capabilities = ["create", "update", "read"]
}

path "secret/metadata/encryption/*" {
    capabilities = ["read", "list"]
}

# Deny destructive operations on secrets
path "secret/delete/chronicle/*" {
    capabilities = ["deny"]
}

path "secret/destroy/chronicle/*" {
    capabilities = ["deny"]
}

path "secret/delete/encryption/*" {
    capabilities = ["deny"]
}

path "secret/destroy/encryption/*" {
    capabilities = ["deny"]
}

# Deny access to TDE keys (managed separately by PostgreSQL)
path "secret/data/chronicle/tde-principal-key" {
    capabilities = ["deny"]
}
