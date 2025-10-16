#!/bin/bash
# Generate test certificates for Quantum TLS with IP address support

set -e

echo "=== Generating Quantum TLS Certificates with IP Support ==="

# Get friend's IP address (update this!)
FRIEND_IP="10.164.69.88"

# Create directories
mkdir -p certs
cd certs

echo "Certificates will support:"
echo "  - localhost"
echo "  - 127.0.0.1"
echo "  - ${FRIEND_IP}"
echo ""

# ============================================================
# Generate CA certificate (used by both classic and quantum)
# ============================================================
echo "Generating CA certificate..."
openssl genrsa -out ca-key.pem 2048
openssl req -new -x509 -days 3650 -key ca-key.pem -out ca-cert.pem \
    -subj "/C=US/ST=Test/L=Test/O=Test CA/CN=Test CA"

# ============================================================
# Generate regular server certificate with IP in SAN
# ============================================================
echo "Generating regular server certificate..."
openssl genrsa -out server.key 2048

# Create OpenSSL config for SAN
cat > server-san.cnf <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = Test
L = Test
O = Test Server
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

openssl req -new -key server.key -out server-req.pem \
    -config server-san.cnf
openssl x509 -req -in server-req.pem -days 3650 -CA ca-cert.pem \
    -CAkey ca-key.pem -set_serial 01 -out server.crt \
    -extensions v3_req -extfile server-san.cnf
rm server-req.pem server-san.cnf

# ============================================================
# Generate Dilithium CA and server certificates  
# ============================================================
echo "Generating Dilithium CA certificate..."
# Note: Using regular OpenSSL for now since we don't have Dilithium cert generation
# In production, you'd use OpenSSL with OQS provider
cp ca-key.pem ca-key-dilithium.pem
cp ca-cert.pem ca-cert-dilithium.pem

echo "Generating Dilithium server certificate..."
openssl genrsa -out server-dilithium.key 2048

# Create OpenSSL config for Dilithium cert with SAN
cat > server-dilithium-san.cnf <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = Test
L = Test
O = Test Server-PQ
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

openssl req -new -key server-dilithium.key -out server-dilithium-req.pem \
    -config server-dilithium-san.cnf
openssl x509 -req -in server-dilithium-req.pem -days 3650 -CA ca-cert-dilithium.pem \
    -CAkey ca-key-dilithium.pem -set_serial 02 -out server-dilithium.crt \
    -extensions v3_req -extfile server-dilithium-san.cnf
rm server-dilithium-req.pem server-dilithium-san.cnf

# Set permissions
chmod 600 *-key.pem *.key
chmod 644 *-cert.pem *.crt

echo ""
echo "✓ Certificates generated successfully!"
echo ""
echo "Generated files:"
ls -lh *.pem *.crt *.key
echo ""
echo "Verifying IP addresses in certificates:"
echo ""
echo "Regular certificate:"
openssl x509 -in server.crt -text -noout | grep -A 1 "Subject Alternative Name" || echo "No SAN found"
echo ""
echo "Dilithium certificate:"
openssl x509 -in server-dilithium.crt -text -noout | grep -A 1 "Subject Alternative Name" || echo "No SAN found"
echo ""
echo "✓ Ready to use!"
