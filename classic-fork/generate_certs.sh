#!/bin/bash#!/bin/bash

# Generate test certificates for Classic TLS (Forked OpenSSL)

# Classic TLS Certificate Generation# Using NIST Level 3: ECDSA P-384 for TRUE 192-bit security (matching Dilithium3)

# Generates 3-tier PKI: Root CA → Intermediate CA → Server Certificate

# Levels: 1 (P-256), 3 (P-384), 5 (RSA-15360)set -e



set -eecho "╔════════════════════════════════════════════════════════════════╗"

echo "║  Generating TRUE NIST Level 3 Test Certificates              ║"

RED='\033[0;31m'echo "║  Using ECDSA P-384 (192-bit security)                        ║"

GREEN='\033[0;32m'echo "║  Matches Dilithium3 security level exactly!                  ║"

BLUE='\033[0;34m'echo "╚════════════════════════════════════════════════════════════════╝"

NC='\033[0m'echo ""



print_header() {# Create directories

    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"mkdir -p certs

    echo -e "${BLUE}  $1${NC}"cd certs

    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"

}# Generate CA private key and certificate with ECDSA P-384

echo "Generating CA certificate (ECDSA P-384)..."

print_info() {openssl ecparam -name secp384r1 -genkey -noout -out ca-key.pem

    echo -e "${GREEN}✓${NC} $1"openssl req -new -x509 -days 3650 -key ca-key.pem -out ca-cert.pem -sha384 \

}    -subj "/C=US/ST=Test/L=Test/O=Test CA Level 3/CN=Test CA ECDSA-P384"



generate_ecdsa_certs() {# Generate server private key and certificate with ECDSA P-384

    local level=$1echo "Generating server certificate (ECDSA P-384)..."

    local curve=$2openssl ecparam -name secp384r1 -genkey -noout -out server-key.pem

    local cert_dir="certs/level${level}"

    # Create OpenSSL config for SAN (Subject Alternative Names)

    print_header "Generating Level ${level} Certificates (${curve})"cat > server-san.cnf <<EOF

    [req]

    mkdir -p "$cert_dir"distinguished_name = req_distinguished_name

    cd "$cert_dir"req_extensions = v3_req

    prompt = no

    print_info "Generating Root CA..."

    openssl ecparam -name $curve -genkey -noout -out root-ca-key.pem[req_distinguished_name]

    openssl req -new -x509 -days 3650 -key root-ca-key.pem -out root-ca-cert.pem \C = US

        -subj "/C=US/ST=State/L=City/O=TestOrg/CN=Root-CA-Level${level}" \ST = Test

        -addext "basicConstraints=critical,CA:TRUE" \L = Test

        -addext "keyUsage=critical,keyCertSign,cRLSign"O = Test Server

    CN = localhost

    print_info "Generating Intermediate CA..."

    openssl ecparam -name $curve -genkey -noout -out intermediate-ca-key.pem[v3_req]

    openssl req -new -key intermediate-ca-key.pem -out intermediate-ca.csr \subjectAltName = @alt_names

        -subj "/C=US/ST=State/L=City/O=TestOrg/CN=Intermediate-CA-Level${level}"

    [alt_names]

    cat > intermediate-ca-ext.cnf << EOFDNS.1 = localhost

basicConstraints = critical,CA:TRUE,pathlen:0DNS.2 = *.localhost

keyUsage = critical,keyCertSign,cRLSignIP.1 = 127.0.0.1

EOFIP.2 = 10.190.219.88

    IP.3 = 0.0.0.0

    openssl x509 -req -in intermediate-ca.csr -CA root-ca-cert.pem \EOF

        -CAkey root-ca-key.pem -CAcreateserial -out intermediate-ca-cert.pem \

        -days 1825 -sha256 -extfile intermediate-ca-ext.cnfopenssl req -new -key server-key.pem -out server-req.pem \

        -config server-san.cnf

    print_info "Generating Server Certificate..."openssl x509 -req -in server-req.pem -days 3650 -CA ca-cert.pem \

    openssl ecparam -name $curve -genkey -noout -out server-key.pem    -CAkey ca-key.pem -set_serial 01 -out server-cert.pem \

    openssl req -new -key server-key.pem -out server.csr \    -extensions v3_req -extfile server-san.cnf

        -subj "/C=US/ST=State/L=City/O=TestOrg/CN=TLS-Test-Server"rm server-req.pem server-san.cnf

    

    cat > server-ext.cnf << EOF# Set permissions

basicConstraints = CA:FALSEchmod 600 *-key.pem

keyUsage = digitalSignature, keyEnciphermentchmod 644 *-cert.pem

extendedKeyUsage = serverAuth

subjectAltName = DNS:localhost, DNS:tls-test-serverecho "✓ TRUE NIST Level 3 Certificates generated successfully!"

EOFecho ""

    echo "Generated files:"

    openssl x509 -req -in server.csr -CA intermediate-ca-cert.pem \ls -lh *.pem

        -CAkey intermediate-ca-key.pem -CAcreateserial -out server-cert.pem \echo ""

        -days 365 -sha256 -extfile server-ext.cnfecho "Security Level: ECDSA P-384 (~192-bit) + X448 (224-bit) key exchange"

    echo "TRUE NIST Level 3 - Directly comparable to: Kyber-768 + Dilithium3"

    cat intermediate-ca-cert.pem root-ca-cert.pem > ca-chain.pemecho ""

    echo "You can now run:"

    rm -f intermediate-ca.csr intermediate-ca-ext.cnf server.csr server-ext.cnf *.srlecho "  Server: ./build/tls_server"

    echo "  Client: ./build/tls_client <server_ip> 4433"

    print_info "Certificates created: Root CA → Intermediate CA → Server"
    
    cd - > /dev/null
}

generate_rsa_certs() {
    local cert_dir="certs/level5"
    
    print_header "Generating Level 5 Certificates (RSA-15360)"
    
    mkdir -p "$cert_dir"
    cd "$cert_dir"
    
    print_info "Generating Root CA (RSA-15360) - Takes several minutes..."
    openssl genrsa -out root-ca-key.pem 15360 2>/dev/null
    openssl req -new -x509 -days 3650 -key root-ca-key.pem -out root-ca-cert.pem \
        -subj "/C=US/ST=State/L=City/O=TestOrg/CN=Root-CA-Level5" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign"
    
    print_info "Generating Intermediate CA (RSA-15360) - Takes several minutes..."
    openssl genrsa -out intermediate-ca-key.pem 15360 2>/dev/null
    openssl req -new -key intermediate-ca-key.pem -out intermediate-ca.csr \
        -subj "/C=US/ST=State/L=City/O=TestOrg/CN=Intermediate-CA-Level5"
    
    cat > intermediate-ca-ext.cnf << EOF
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
EOF
    
    openssl x509 -req -in intermediate-ca.csr -CA root-ca-cert.pem \
        -CAkey root-ca-key.pem -CAcreateserial -out intermediate-ca-cert.pem \
        -days 1825 -sha256 -extfile intermediate-ca-ext.cnf
    
    print_info "Generating Server Certificate (RSA-15360) - Takes several minutes..."
    openssl genrsa -out server-key.pem 15360 2>/dev/null
    openssl req -new -key server-key.pem -out server.csr \
        -subj "/C=US/ST=State/L=City/O=TestOrg/CN=TLS-Test-Server"
    
    cat > server-ext.cnf << EOF
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost, DNS:tls-test-server
EOF
    
    openssl x509 -req -in server.csr -CA intermediate-ca-cert.pem \
        -CAkey intermediate-ca-key.pem -CAcreateserial -out server-cert.pem \
        -days 365 -sha256 -extfile server-ext.cnf
    
    cat intermediate-ca-cert.pem root-ca-cert.pem > ca-chain.pem
    
    rm -f intermediate-ca.csr intermediate-ca-ext.cnf server.csr server-ext.cnf *.srl
    
    print_info "Certificates created: Root CA → Intermediate CA → Server"
    
    cd - > /dev/null
}

print_header "Classic TLS Certificate Generation"
echo ""
echo "Generating network-independent certificates:"
echo "  Level 1: ECDSA P-256"
echo "  Level 3: ECDSA P-384"
echo "  Level 5: RSA-15360"
echo ""

generate_ecdsa_certs 1 "secp256r1"
generate_ecdsa_certs 3 "secp384r1"
generate_rsa_certs

print_header "Complete!"
echo ""
echo "Certificates: certs/{level1,level3,level5}/"
echo "✅ Network-independent (works on any network)"
echo ""
