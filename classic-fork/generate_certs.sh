#!/bin/bash
# Generate test certificates for Classic TLS (Forked OpenSSL)
# Using NIST Level 3: ECDSA P-384 for TRUE 192-bit security (matching Dilithium3)

set -e

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║  Generating TRUE NIST Level 3 Test Certificates              ║"
echo "║  Using ECDSA P-384 (192-bit security)                        ║"
echo "║  Matches Dilithium3 security level exactly!                  ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Create directories
mkdir -p certs
cd certs

# Generate CA private key and certificate with ECDSA P-384
echo "Generating CA certificate (ECDSA P-384)..."
openssl ecparam -name secp384r1 -genkey -noout -out ca-key.pem
openssl req -new -x509 -days 3650 -key ca-key.pem -out ca-cert.pem -sha384 \
    -subj "/C=US/ST=Test/L=Test/O=Test CA Level 3/CN=Test CA ECDSA-P384"

# Generate server private key and certificate with ECDSA P-384
echo "Generating server certificate (ECDSA P-384)..."
openssl ecparam -name secp384r1 -genkey -noout -out server-key.pem

# Create OpenSSL config for SAN (Subject Alternative Names)
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
IP.2 = 10.190.219.88
IP.3 = 0.0.0.0
EOF

openssl req -new -key server-key.pem -out server-req.pem \
    -config server-san.cnf
openssl x509 -req -in server-req.pem -days 3650 -CA ca-cert.pem \
    -CAkey ca-key.pem -set_serial 01 -out server-cert.pem \
    -extensions v3_req -extfile server-san.cnf
rm server-req.pem server-san.cnf

# Set permissions
chmod 600 *-key.pem
chmod 644 *-cert.pem

echo "✓ TRUE NIST Level 3 Certificates generated successfully!"
echo ""
echo "Generated files:"
ls -lh *.pem
echo ""
echo "Security Level: ECDSA P-384 (~192-bit) + X448 (224-bit) key exchange"
echo "TRUE NIST Level 3 - Directly comparable to: Kyber-768 + Dilithium3"
echo ""
echo "You can now run:"
echo "  Server: ./build/tls_server"
echo "  Client: ./build/tls_client <server_ip> 4433"
