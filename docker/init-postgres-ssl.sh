#!/bin/bash
# Chronicle PostgreSQL SSL/TLS Certificate Initialization Script
# This script generates self-signed certificates for PostgreSQL SSL connections
#
# Usage:
#   ./init-postgres-ssl.sh [OPTIONS]
#
# Options:
#   --dev           Generate development certificates (default)
#   --prod          Generate production-ready certificates (requires more configuration)
#   --renew         Renew existing certificates
#   --verify        Verify current SSL configuration
#   --help          Show this help message
#
# Every database connection is encrypted in transit.
# This script sets up SSL/TLS encryption between the application and PostgreSQL.
#
# Production Considerations:
#   - Replace self-signed certificates with CA-signed certificates
#   - Use a proper PKI infrastructure or cloud-provided certificates
#   - Consider mutual TLS (mTLS) for additional security
#   - Set up automated certificate rotation

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SSL_DIR="${SCRIPT_DIR}/postgres-ssl"
CA_DIR="${SSL_DIR}/ca"
SERVER_DIR="${SSL_DIR}/server"
CLIENT_DIR="${SSL_DIR}/client"

# Certificate validity periods
DEV_CERT_DAYS=365
PROD_CERT_DAYS=365
CA_CERT_DAYS=3650

# Default certificate subject fields
COUNTRY="${SSL_COUNTRY:-US}"
STATE="${SSL_STATE:-California}"
LOCALITY="${SSL_LOCALITY:-San Francisco}"
ORGANIZATION="${SSL_ORGANIZATION:-Chronicle}"
ORG_UNIT="${SSL_ORG_UNIT:-Database Security}"
CA_CN="${SSL_CA_CN:-Chronicle PostgreSQL CA}"
SERVER_CN="${SSL_SERVER_CN:-postgres}"
CLIENT_CN="${SSL_CLIENT_CN:-chronicle-backend}"

# Key sizes
KEY_SIZE=4096

echo_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

echo_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

echo_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

show_help() {
    head -30 "$0" | tail -28 | sed 's/^# *//'
    exit 0
}

# Parse command line arguments
MODE="dev"
ACTION="generate"

while [[ $# -gt 0 ]]; do
    case $1 in
        --dev)
            MODE="dev"
            shift
            ;;
        --prod)
            MODE="prod"
            shift
            ;;
        --renew)
            ACTION="renew"
            shift
            ;;
        --verify)
            ACTION="verify"
            shift
            ;;
        --help|-h)
            show_help
            ;;
        *)
            echo_error "Unknown option: $1"
            show_help
            ;;
    esac
done

# Create directory structure
create_directories() {
    echo_info "Creating SSL directory structure..."
    mkdir -p "${CA_DIR}"
    mkdir -p "${SERVER_DIR}"
    mkdir -p "${CLIENT_DIR}"
    chmod 700 "${SSL_DIR}" "${CA_DIR}" "${SERVER_DIR}" "${CLIENT_DIR}"
}

# Generate CA certificate
generate_ca() {
    echo_info "Generating Certificate Authority (CA)..."

    # Check if CA already exists
    if [[ -f "${CA_DIR}/ca.crt" && "$ACTION" != "renew" ]]; then
        echo_warn "CA certificate already exists. Use --renew to regenerate."
        return 0
    fi

    # Generate CA private key
    openssl genrsa -out "${CA_DIR}/ca.key" ${KEY_SIZE}
    chmod 600 "${CA_DIR}/ca.key"

    # Generate CA certificate
    openssl req -new -x509 -days ${CA_CERT_DAYS} \
        -key "${CA_DIR}/ca.key" \
        -out "${CA_DIR}/ca.crt" \
        -subj "/C=${COUNTRY}/ST=${STATE}/L=${LOCALITY}/O=${ORGANIZATION}/OU=${ORG_UNIT}/CN=${CA_CN}"

    # Create CA serial file
    echo "01" > "${CA_DIR}/ca.srl"

    echo_info "CA certificate generated: ${CA_DIR}/ca.crt"
}

# Generate server certificate for PostgreSQL
generate_server_cert() {
    echo_info "Generating PostgreSQL server certificate..."

    # Check if server cert already exists
    if [[ -f "${SERVER_DIR}/server.crt" && "$ACTION" != "renew" ]]; then
        echo_warn "Server certificate already exists. Use --renew to regenerate."
        return 0
    fi

    local cert_days=${DEV_CERT_DAYS}
    if [[ "$MODE" == "prod" ]]; then
        cert_days=${PROD_CERT_DAYS}
    fi

    # Generate server private key
    openssl genrsa -out "${SERVER_DIR}/server.key" ${KEY_SIZE}
    chmod 600 "${SERVER_DIR}/server.key"

    # Create server certificate signing request (CSR)
    openssl req -new \
        -key "${SERVER_DIR}/server.key" \
        -out "${SERVER_DIR}/server.csr" \
        -subj "/C=${COUNTRY}/ST=${STATE}/L=${LOCALITY}/O=${ORGANIZATION}/OU=${ORG_UNIT}/CN=${SERVER_CN}"

    # Create server certificate extension file for SAN (Subject Alternative Names)
    cat > "${SERVER_DIR}/server.ext" << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${SERVER_CN}
DNS.2 = localhost
DNS.3 = chronicle-postgres
DNS.4 = postgres
IP.1 = 127.0.0.1
EOF

    # Sign server certificate with CA
    openssl x509 -req -days ${cert_days} \
        -in "${SERVER_DIR}/server.csr" \
        -CA "${CA_DIR}/ca.crt" \
        -CAkey "${CA_DIR}/ca.key" \
        -CAserial "${CA_DIR}/ca.srl" \
        -out "${SERVER_DIR}/server.crt" \
        -extfile "${SERVER_DIR}/server.ext"

    # Clean up CSR and extension file
    rm -f "${SERVER_DIR}/server.csr" "${SERVER_DIR}/server.ext"

    # Set proper permissions for PostgreSQL (must be readable by postgres user, not group/world)
    # Percona PostgreSQL image runs as UID 26 (postgres); the key must be owned by
    # the database user or root, and must not be accessible by group/world.
    chmod 600 "${SERVER_DIR}/server.key"
    chmod 644 "${SERVER_DIR}/server.crt"
    chown 26:26 "${SERVER_DIR}/server.key"

    echo_info "Server certificate generated: ${SERVER_DIR}/server.crt"
}

# Generate client certificate for application
generate_client_cert() {
    echo_info "Generating client certificate for application..."

    # Check if client cert already exists
    if [[ -f "${CLIENT_DIR}/client.crt" && "$ACTION" != "renew" ]]; then
        echo_warn "Client certificate already exists. Use --renew to regenerate."
        return 0
    fi

    local cert_days=${DEV_CERT_DAYS}
    if [[ "$MODE" == "prod" ]]; then
        cert_days=${PROD_CERT_DAYS}
    fi

    # Generate client private key
    openssl genrsa -out "${CLIENT_DIR}/client.key" ${KEY_SIZE}
    chmod 600 "${CLIENT_DIR}/client.key"

    # Create client certificate signing request (CSR)
    openssl req -new \
        -key "${CLIENT_DIR}/client.key" \
        -out "${CLIENT_DIR}/client.csr" \
        -subj "/C=${COUNTRY}/ST=${STATE}/L=${LOCALITY}/O=${ORGANIZATION}/OU=${ORG_UNIT}/CN=${CLIENT_CN}"

    # Create client certificate extension file
    cat > "${CLIENT_DIR}/client.ext" << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = clientAuth
EOF

    # Sign client certificate with CA
    openssl x509 -req -days ${cert_days} \
        -in "${CLIENT_DIR}/client.csr" \
        -CA "${CA_DIR}/ca.crt" \
        -CAkey "${CA_DIR}/ca.key" \
        -CAserial "${CA_DIR}/ca.srl" \
        -out "${CLIENT_DIR}/client.crt" \
        -extfile "${CLIENT_DIR}/client.ext"

    # Clean up CSR and extension file
    rm -f "${CLIENT_DIR}/client.csr" "${CLIENT_DIR}/client.ext"

    # Set proper permissions
    chmod 600 "${CLIENT_DIR}/client.key"
    chmod 644 "${CLIENT_DIR}/client.crt"

    # Convert to PKCS12 format for Java applications
    openssl pkcs12 -export \
        -in "${CLIENT_DIR}/client.crt" \
        -inkey "${CLIENT_DIR}/client.key" \
        -out "${CLIENT_DIR}/client.p12" \
        -name "chronicle-client" \
        -CAfile "${CA_DIR}/ca.crt" \
        -caname "Chronicle CA" \
        -password "pass:$(cat "${CLIENT_DIR}/p12-password" 2>/dev/null || openssl rand -hex 24 | tee "${CLIENT_DIR}/p12-password")"

    chmod 600 "${CLIENT_DIR}/client.p12"

    echo_info "Client certificate generated: ${CLIENT_DIR}/client.crt"
    chmod 600 "${CLIENT_DIR}/p12-password"
    echo_info "PKCS12 keystore generated: ${CLIENT_DIR}/client.p12 (password in ${CLIENT_DIR}/p12-password)"
}

# Generate PostgreSQL SSL configuration snippet
generate_postgres_ssl_config() {
    echo_info "Generating PostgreSQL SSL configuration..."

    cat > "${SSL_DIR}/postgresql-ssl.conf" << 'EOF'
# PostgreSQL SSL Configuration
# Add these settings to postgresql.conf or mount as a config file

# Enable SSL
ssl = on

# Certificate files (paths relative to data directory or absolute)
ssl_cert_file = '/var/lib/postgresql/ssl/server.crt'
ssl_key_file = '/var/lib/postgresql/ssl/server.key'
ssl_ca_file = '/var/lib/postgresql/ssl/ca.crt'

# SSL protocol settings
ssl_min_protocol_version = 'TLSv1.2'
ssl_prefer_server_ciphers = on

# Cipher suites (modern, secure configuration)
# TLS 1.3 ciphers are automatically included when TLS 1.3 is available
ssl_ciphers = 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256'

# Optional: Require client certificates (mTLS)
# Uncomment for mutual TLS authentication
# ssl_crl_file = '/var/lib/postgresql/ssl/crl.pem'
EOF

    # Generate pg_hba.conf snippet for SSL
    cat > "${SSL_DIR}/pg_hba-ssl.conf" << 'EOF'
# PostgreSQL Host-Based Authentication with SSL
# Add these lines to pg_hba.conf

# TYPE  DATABASE        USER            ADDRESS                 METHOD

# Reject all non-SSL connections from remote hosts
# hostnossl all          all             0.0.0.0/0               reject
# hostnossl all          all             ::/0                    reject

# Require SSL for all remote connections
hostssl all             all             0.0.0.0/0               scram-sha-256
hostssl all             all             ::/0                    scram-sha-256

# Local connections (within container) - SSL optional
host    all             all             127.0.0.1/32            scram-sha-256
host    all             all             ::1/128                 scram-sha-256

# Docker network connections with SSL required
hostssl all             all             172.16.0.0/12           scram-sha-256
hostssl all             all             10.0.0.0/8              scram-sha-256
hostssl all             all             192.168.0.0/16          scram-sha-256
EOF

    echo_info "PostgreSQL configuration files generated in ${SSL_DIR}/"
}

# Verify SSL configuration
verify_ssl() {
    echo_info "Verifying SSL configuration..."

    local errors=0

    # Check CA certificate
    if [[ -f "${CA_DIR}/ca.crt" ]]; then
        echo_info "CA certificate: EXISTS"
        openssl x509 -in "${CA_DIR}/ca.crt" -noout -dates
    else
        echo_error "CA certificate: MISSING"
        ((errors++))
    fi

    # Check server certificate
    if [[ -f "${SERVER_DIR}/server.crt" ]]; then
        echo_info "Server certificate: EXISTS"
        openssl x509 -in "${SERVER_DIR}/server.crt" -noout -dates

        # Verify server cert is signed by CA
        if openssl verify -CAfile "${CA_DIR}/ca.crt" "${SERVER_DIR}/server.crt" > /dev/null 2>&1; then
            echo_info "Server certificate: VALID (signed by CA)"
        else
            echo_error "Server certificate: INVALID (not signed by CA)"
            ((errors++))
        fi
    else
        echo_error "Server certificate: MISSING"
        ((errors++))
    fi

    # Check client certificate
    if [[ -f "${CLIENT_DIR}/client.crt" ]]; then
        echo_info "Client certificate: EXISTS"
        openssl x509 -in "${CLIENT_DIR}/client.crt" -noout -dates

        # Verify client cert is signed by CA
        if openssl verify -CAfile "${CA_DIR}/ca.crt" "${CLIENT_DIR}/client.crt" > /dev/null 2>&1; then
            echo_info "Client certificate: VALID (signed by CA)"
        else
            echo_error "Client certificate: INVALID (not signed by CA)"
            ((errors++))
        fi
    else
        echo_error "Client certificate: MISSING"
        ((errors++))
    fi

    # Check file permissions
    echo_info "Checking file permissions..."

    if [[ -f "${SERVER_DIR}/server.key" ]]; then
        local perms
        perms=$(stat -c "%a" "${SERVER_DIR}/server.key" 2>/dev/null || stat -f "%OLp" "${SERVER_DIR}/server.key")
        if [[ "$perms" == "600" ]]; then
            echo_info "Server key permissions: OK (600)"
        else
            echo_warn "Server key permissions: ${perms} (should be 600)"
        fi
    fi

    if [[ $errors -eq 0 ]]; then
        echo_info "SSL verification: PASSED"
        return 0
    else
        echo_error "SSL verification: FAILED ($errors errors)"
        return 1
    fi
}

# Print summary and next steps
print_summary() {
    echo ""
    echo "=========================================="
    echo "PostgreSQL SSL Certificate Generation Complete"
    echo "=========================================="
    echo ""
    echo "Generated files:"
    echo "  CA Certificate:     ${CA_DIR}/ca.crt"
    echo "  Server Certificate: ${SERVER_DIR}/server.crt"
    echo "  Server Key:         ${SERVER_DIR}/server.key"
    echo "  Client Certificate: ${CLIENT_DIR}/client.crt"
    echo "  Client Key:         ${CLIENT_DIR}/client.key"
    echo "  Client PKCS12:      ${CLIENT_DIR}/client.p12"
    echo ""
    echo "Configuration files:"
    echo "  PostgreSQL config:  ${SSL_DIR}/postgresql-ssl.conf"
    echo "  pg_hba.conf:        ${SSL_DIR}/pg_hba-ssl.conf"
    echo ""

    if [[ "$MODE" == "dev" ]]; then
        echo_warn "DEVELOPMENT MODE: These are self-signed certificates."
        echo_warn "For production, use CA-signed certificates from a trusted authority."
        echo ""
    fi

    echo "Next steps:"
    echo "  1. Update docker-compose.yml to mount SSL certificates"
    echo "  2. Add POSTGRES_SSL_MODE=require to your .env file"
    echo "  3. Restart containers: docker-compose down && docker-compose up -d"
    echo "  4. Verify SSL: docker exec chronicle-postgres psql -U chronicle -c \"SHOW ssl\""
    echo ""
    echo "JDBC URL example with SSL:"
    echo "  jdbc:postgresql://postgres:5432/chronicle?sslmode=require&sslrootcert=/app/ssl/ca.crt"
    echo ""

    if [[ "$MODE" == "prod" ]]; then
        echo "PRODUCTION CHECKLIST:"
        echo "  [ ] Replace self-signed certs with CA-signed certificates"
        echo "  [ ] Configure certificate rotation policy"
        echo "  [ ] Set up certificate monitoring/alerting"
        echo "  [ ] Enable mutual TLS (mTLS) if required"
        echo "  [ ] Secure certificate storage and backup"
        echo "  [ ] Document certificate renewal procedures"
        echo ""
    fi
}

# Main execution
main() {
    echo_info "PostgreSQL SSL/TLS Setup - Mode: ${MODE}, Action: ${ACTION}"
    echo ""

    case $ACTION in
        generate)
            create_directories
            generate_ca
            generate_server_cert
            generate_client_cert
            generate_postgres_ssl_config
            print_summary
            ;;
        renew)
            echo_info "Renewing certificates..."
            generate_ca
            generate_server_cert
            generate_client_cert
            print_summary
            ;;
        verify)
            verify_ssl
            ;;
    esac
}

main
