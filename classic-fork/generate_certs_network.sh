#!/bin/bash
# Generate test certificates for Classic TLS with network support (SAN)

set -e

echo "=== Generating Network-Ready Test Certificates ==="

# Get system information
HOSTNAME=$(hostname)
IP_ADDRESS=$(hostname -I | awk '{print $1}')

echo "Detected:"
echo "  Hostname: $HOSTNAME"
echo "  IP Address: $IP_ADDRESS"
echo ""

# Create directories
mkdir -p certs
cd certs

# Create OpenSSL config for SAN
cat > server_cert.conf <<EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = v3_req

[dn]
C = US
ST = Test
L = Test
O = Test Server
CN = $HOSTNAME

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = $HOSTNAME
IP.1 = 127.0.0.1
IP.2 = $IP_ADDRESS
EOF

# Generate CA private key and certificate
echo "Generating CA certificate..."
openssl genrsa -out ca-key.pem 2048 2>/dev/null
openssl req -new -x509 -days 3650 -key ca-key.pem -out ca-cert.pem \
    -subj "/C=US/ST=Test/L=Test/O=Test CA/CN=Test CA"

# Generate server private key and CSR with SAN
echo "Generating server certificate with SAN..."
openssl genrsa -out server-key.pem 2048 2>/dev/null
openssl req -new -key server-key.pem -out server-req.pem -config server_cert.conf

# Sign the certificate with SAN extensions
openssl x509 -req -in server-req.pem -days 3650 -CA ca-cert.pem \
    -CAkey ca-key.pem -set_serial 01 -out server-cert.pem \
    -extensions v3_req -extfile server_cert.conf

rm server-req.pem

# Generate client private key and certificate (optional)
echo "Generating client certificate..."
openssl genrsa -out client-key.pem 2048 2>/dev/null
openssl req -new -key client-key.pem -out client-req.pem \
    -subj "/C=US/ST=Test/L=Test/O=Test Client/CN=client"
openssl x509 -req -in client-req.pem -days 3650 -CA ca-cert.pem \
    -CAkey ca-key.pem -set_serial 02 -out client-cert.pem
rm client-req.pem

# Create symbolic links for compatibility
ln -sf server-cert.pem server.crt
ln -sf server-key.pem server.key

# Set permissions
chmod 600 *-key.pem
chmod 644 *-cert.pem

# Verify the certificate
echo ""
echo "=== Certificate Details ==="
openssl x509 -in server-cert.pem -noout -text | grep -A 5 "Subject Alternative Name"

echo ""
echo "✓ Network-ready certificates generated successfully!"
echo ""
echo "Generated files:"
ls -lh *.pem *.crt *.key 2>/dev/null
echo ""
echo "The certificate is valid for:"
echo "  - localhost"
echo "  - $HOSTNAME"
echo "  - 127.0.0.1"
echo "  - $IP_ADDRESS"
echo ""
echo "Your friend needs the CA certificate to trust your server:"
echo "  Copy 'certs/ca-cert.pem' to your friend's system"
echo ""
echo "To test across network:"
echo "  Server (your system): ./build/tls_server"
echo "  Client (friend's system): ./build/tls_client <YOUR_IP>"
echo "  Where YOUR_IP = $IP_ADDRESS"
