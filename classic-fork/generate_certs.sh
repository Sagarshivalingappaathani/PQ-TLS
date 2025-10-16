#!/bin/bash
# Generate test certificates for Classic TLS (Forked OpenSSL)

set -e

echo "=== Generating Test Certificates ==="

# Create directories
mkdir -p certs
cd certs

# Generate CA private key and certificate
echo "Generating CA certificate..."
openssl genrsa -out ca-key.pem 2048
openssl req -new -x509 -days 3650 -key ca-key.pem -out ca-cert.pem \
    -subj "/C=US/ST=Test/L=Test/O=Test CA/CN=Test CA"

# Generate server private key and certificate
echo "Generating server certificate..."
openssl genrsa -out server-key.pem 2048

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

# Generate client private key and certificate (optional)
echo "Generating client certificate..."
openssl genrsa -out client-key.pem 2048
openssl req -new -key client-key.pem -out client-req.pem \
    -subj "/C=US/ST=Test/L=Test/O=Test Client/CN=client"
openssl x509 -req -in client-req.pem -days 3650 -CA ca-cert.pem \
    -CAkey ca-key.pem -set_serial 02 -out client-cert.pem
rm client-req.pem

# Set permissions
chmod 600 *-key.pem
chmod 644 *-cert.pem

echo "✓ Certificates generated successfully!"
echo ""
echo "Generated files:"
ls -lh *.pem
echo ""
echo "You can now run:"
echo "  Server: ./build/fork_tls_server 4433 certs/server-cert.pem certs/server-key.pem"
echo "  Client: ./build/fork_tls_client localhost 4433"
