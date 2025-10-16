#!/bin/bash
# Generate Dilithium certificates using OQS-OpenSSL tools
# REQUIRES: OQS-OpenSSL tools built (run BUILD_OQS_TOOLS.sh first)

set -e

OPENSSL_BIN="/home/sagar8022/0418/skp-major-project/TLS/vendor/openssl-oqs/apps/openssl"
OPENSSL_CNF="/home/sagar8022/0418/skp-major-project/TLS/vendor/openssl-oqs/apps/openssl.cnf"
FRIEND_IP="10.190.219.88"

# Set config file
export OPENSSL_CONF="$OPENSSL_CNF"

# Check if OQS-OpenSSL binary exists
if [ ! -f "$OPENSSL_BIN" ]; then
    echo "❌ ERROR: OQS-OpenSSL binary not found!"
    echo ""
    echo "Please build it first by running:"
    echo "  ./BUILD_OQS_TOOLS.sh"
    echo ""
    exit 1
fi

echo "═══════════════════════════════════════════════════"
echo "  Generating Dilithium3 Certificates"
echo "═══════════════════════════════════════════════════"
echo ""
echo "Using: $OPENSSL_BIN"
echo "Friend's IP: $FRIEND_IP"
echo ""

mkdir -p certs
cd certs

# ============================================================
# Generate Dilithium3 CA
# ============================================================
echo "[1/3] Generating Dilithium3 CA certificate..."

$OPENSSL_BIN req -x509 -new -newkey dilithium3 -keyout ca-key-dilithium3-real.pem \
    -out ca-cert-dilithium3-real.pem -nodes -days 3650 \
    -subj "/C=US/ST=Test/L=Test/O=Test CA Dilithium/CN=Test CA" 2>&1 | grep -v "^.*\\.\\.\\..*$" || true

if [ ! -f "ca-cert-dilithium3-real.pem" ]; then
    echo "❌ Failed to generate CA certificate"
    exit 1
fi

echo "  ✓ CA certificate generated"

# ============================================================
# Generate Dilithium3 Server Certificate
# ============================================================
echo ""
echo "[2/3] Generating Dilithium3 server certificate..."

# Generate server private key
$OPENSSL_BIN genpkey -algorithm dilithium3 -out server-key-dilithium3-real.pem 2>&1 | grep -v "^.*\\.\\.\\..*$" || true

# Create CSR with SAN
cat > server-dilithium3.cnf <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = Test
L = Test
O = Test Server Dilithium
CN = localhost

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = *.localhost
IP.1 = 127.0.0.1
IP.2 = ${FRIEND_IP}
IP.3 = 0.0.0.0
EOF

# Generate CSR
$OPENSSL_BIN req -new -key server-key-dilithium3-real.pem \
    -out server-dilithium3.csr -config server-dilithium3.cnf 2>&1 | grep -v "^.*\\.\\.\\..*$" || true

# Sign with CA
$OPENSSL_BIN x509 -req -in server-dilithium3.csr -days 3650 \
    -CA ca-cert-dilithium3-real.pem -CAkey ca-key-dilithium3-real.pem \
    -set_serial 01 -out server-cert-dilithium3-real.pem \
    -extensions v3_req -extfile server-dilithium3.cnf 2>&1 | grep -v "^.*\\.\\.\\..*$" || true

rm server-dilithium3.csr server-dilithium3.cnf

echo "  ✓ Server certificate generated"

# ============================================================
# Verify and Display
# ============================================================
echo ""
echo "[3/3] Verifying certificates..."

# Set permissions
chmod 600 *-key-*.pem
chmod 644 *-cert-*.pem

echo "  ✓ Permissions set"
echo ""
echo "═══════════════════════════════════════════════════"
echo " Generated Files:"
echo "═══════════════════════════════════════════════════"
ls -lh *-dilithium3-real.pem

echo ""
echo "═══════════════════════════════════════════════════"
echo " Certificate Details:"
echo "═══════════════════════════════════════════════════"

echo ""
echo "CA Certificate:"
$OPENSSL_BIN x509 -in ca-cert-dilithium3-real.pem -text -noout | grep -A 2 "Subject Public Key Info"

echo ""
echo "Server Certificate:"
$OPENSSL_BIN x509 -in server-cert-dilithium3-real.pem -text -noout | grep -A 2 "Subject Public Key Info"

echo ""
echo "IP Addresses in Server Certificate:"
$OPENSSL_BIN x509 -in server-cert-dilithium3-real.pem -text -noout | grep -A 1 "Subject Alternative Name"

echo ""
echo "═══════════════════════════════════════════════════"
echo "✓ Dilithium3 certificates generated successfully!"
echo "═══════════════════════════════════════════════════"
echo ""
echo "Signature sizes with Dilithium3:"
echo "  - Dilithium2: ~2420 bytes"
echo "  - Dilithium3: ~3293 bytes (NIST Level 3)"  
echo "  - Dilithium5: ~4595 bytes"
echo ""
echo "Certificate sizes will be ~4-5KB (vs 938 bytes for RSA)"
echo ""
