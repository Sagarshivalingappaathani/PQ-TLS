#!/bin/bash

# Generate test certificates for Classic TLS (3-tier PKI)
# Levels: 1 (P-256), 3 (P-384), 5 (P-521)

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Classic TLS Certificate Generation (3-tier PKI)             ║${NC}"
echo -e "${BLUE}║  Level 1: ECDSA P-256 (128-bit)                              ║${NC}"
echo -e "${BLUE}║  Level 3: ECDSA P-384 (192-bit)                              ║${NC}"
echo -e "${BLUE}║  Level 5: ECDSA P-521 (256-bit)                              ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Create base certs directory
mkdir -p certs
cd certs

# Function to generate ECDSA certificates (all levels)
generate_ecdsa_certs() {
    local level=$1
    local curve=$2
    local curve_name=$3
    
    echo -e "${YELLOW}[Level $level] Generating ECDSA $curve_name certificates...${NC}"
    
    mkdir -p level${level}
    cd level${level}
    
    # 1. Generate Root CA
    echo "  [1/7] Generating Root CA private key..."
    openssl ecparam -name $curve -genkey -noout -out root-ca-key.pem
    
    echo "  [2/7] Creating Root CA certificate..."
    openssl req -new -x509 -days 3650 -key root-ca-key.pem -out root-ca-cert.pem \
        -subj "/C=US/ST=State/L=City/O=Test-Org/OU=Root-CA/CN=Test-Root-CA"
    
    # 2. Generate Intermediate CA
    echo "  [3/7] Generating Intermediate CA private key..."
    openssl ecparam -name $curve -genkey -noout -out intermediate-ca-key.pem
    
    echo "  [4/7] Creating Intermediate CA CSR..."
    openssl req -new -key intermediate-ca-key.pem -out intermediate-ca.csr \
        -subj "/C=US/ST=State/L=City/O=Test-Org/OU=Intermediate-CA/CN=Test-Intermediate-CA"
    
    echo "  [5/7] Signing Intermediate CA certificate..."
    openssl x509 -req -days 1825 -in intermediate-ca.csr \
        -CA root-ca-cert.pem -CAkey root-ca-key.pem -CAcreateserial \
        -out intermediate-ca-cert.pem \
        -extfile <(echo "basicConstraints=critical,CA:true,pathlen:0
keyUsage=critical,keyCertSign,cRLSign")
    
    # 3. Generate Server Certificate
    echo "  [6/7] Generating Server private key..."
    openssl ecparam -name $curve -genkey -noout -out server-key.pem
    
    echo "  [7/7] Creating and signing Server certificate..."
    openssl req -new -key server-key.pem -out server.csr \
        -subj "/C=US/ST=State/L=City/O=Test-Org/OU=Server/CN=tls-test-server"
    
    openssl x509 -req -days 365 -in server.csr \
        -CA intermediate-ca-cert.pem -CAkey intermediate-ca-key.pem -CAcreateserial \
        -out server-cert.pem \
        -extfile <(echo "subjectAltName=DNS:localhost,DNS:tls-test-server,IP:127.0.0.1,IP:192.168.1.100,IP:192.168.43.1,IP:3.108.41.178
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth")
    
    # Create certificate chain (Server + Intermediate)
    cat server-cert.pem intermediate-ca-cert.pem > ca-chain.pem
    
    # Cleanup CSR files
    rm -f intermediate-ca.csr server.csr root-ca-cert.srl intermediate-ca-cert.srl
    
    echo -e "  ${GREEN}✓ Level $level certificates generated successfully!${NC}"
    echo ""
    
    cd ..
}

# Generate certificates for all levels
echo -e "${BLUE}Starting certificate generation for all 3 levels...${NC}"
echo ""

# Level 1: ECDSA P-256 (128-bit security)
generate_ecdsa_certs 1 "secp256r1" "P-256"

# Level 3: ECDSA P-384 (192-bit security)
generate_ecdsa_certs 3 "secp384r1" "P-384"

# Level 5: ECDSA P-521 (256-bit security)
generate_ecdsa_certs 5 "secp521r1" "P-521"

cd ..

echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  All certificates generated successfully!                     ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Certificate structure for each level:"
echo "  certs/level1/, level3/, level5/ each contain:"
echo "  - root-ca-cert.pem       (Root CA certificate)"
echo "  - root-ca-key.pem        (Root CA private key)"
echo "  - intermediate-ca-cert.pem (Intermediate CA certificate)"
echo "  - intermediate-ca-key.pem  (Intermediate CA private key)"
echo "  - server-cert.pem        (Server certificate)"
echo "  - server-key.pem         (Server private key)"
echo "  - ca-chain.pem           (Full chain: server + intermediate)"
echo ""
