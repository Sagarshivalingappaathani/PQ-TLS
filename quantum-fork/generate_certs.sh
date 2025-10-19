#!/bin/bash

# Generate test certificates for Quantum TLS (3-tier PKI)
# Levels: 1 (Dilithium2), 3 (Dilithium3), 5 (Dilithium5)

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

# OQS-OpenSSL path (absolute path)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPENSSL_CMD="$SCRIPT_DIR/../vendor/openssl-oqs/apps/openssl"
OQS_PROVIDER=""
export OPENSSL_CONF="$SCRIPT_DIR/../vendor/openssl-oqs/apps/openssl.cnf"

echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  Quantum TLS Certificate Generation (3-tier PKI)             ║${NC}"
echo -e "${BLUE}║  Level 1: Dilithium2 (128-bit)                               ║${NC}"
echo -e "${BLUE}║  Level 3: Dilithium3 (192-bit)                               ║${NC}"
echo -e "${BLUE}║  Level 5: Dilithium5 (256-bit)                               ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Create base certs directory
mkdir -p certs
cd certs

# Function to generate Dilithium certificates
generate_dilithium_certs() {
    local level=$1
    local dilithium_alg=$2
    
    echo -e "${YELLOW}[Level $level] Generating $dilithium_alg certificates...${NC}"
    
    mkdir -p level${level}
    cd level${level}
    
    # 1. Generate Root CA
    echo "  [1/7] Generating Root CA private key ($dilithium_alg)..."
    $OPENSSL_CMD req -x509 -new -newkey $dilithium_alg $OQS_PROVIDER \
        -keyout root-ca-key.pem -out root-ca-cert.pem -nodes -days 3650 \
        -subj "/C=US/ST=State/L=City/O=Test-Org/OU=Root-CA/CN=Test-Root-CA"
    
    # 2. Generate Intermediate CA
    echo "  [2/7] Generating Intermediate CA private key ($dilithium_alg)..."
    $OPENSSL_CMD req -new -newkey $dilithium_alg $OQS_PROVIDER \
        -keyout intermediate-ca-key.pem -out intermediate-ca.csr -nodes \
        -subj "/C=US/ST=State/L=City/O=Test-Org/OU=Intermediate-CA/CN=Test-Intermediate-CA" 2>/dev/null
    
    echo "  [3/7] Signing Intermediate CA certificate..."
    $OPENSSL_CMD x509 -req -days 1825 -in intermediate-ca.csr $OQS_PROVIDER \
        -CA root-ca-cert.pem -CAkey root-ca-key.pem -CAcreateserial \
        -out intermediate-ca-cert.pem \
        -extfile <(echo "basicConstraints=critical,CA:true,pathlen:0
keyUsage=critical,keyCertSign,cRLSign") 2>/dev/null
    
    # 3. Generate Server Certificate
    echo "  [4/7] Generating Server private key ($dilithium_alg)..."
    $OPENSSL_CMD req -new -newkey $dilithium_alg $OQS_PROVIDER \
        -keyout server-key.pem -out server.csr -nodes \
        -subj "/C=US/ST=State/L=City/O=Test-Org/OU=Server/CN=tls-test-server" 2>/dev/null
    
    echo "  [5/7] Signing Server certificate..."
    $OPENSSL_CMD x509 -req -days 365 -in server.csr $OQS_PROVIDER \
        -CA intermediate-ca-cert.pem -CAkey intermediate-ca-key.pem -CAcreateserial \
        -out server-cert.pem \
        -extfile <(echo "subjectAltName=DNS:localhost,DNS:tls-test-server,IP:127.0.0.1,IP:192.168.1.100,IP:192.168.43.1,IP:3.108.41.178,IP:172.31.32.138,IP:15.206.70.28
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth") 2>/dev/null
    
    # 4. Create certificate chain (Server + Intermediate)
    echo "  [6/7] Creating certificate chain..."
    cat server-cert.pem intermediate-ca-cert.pem > ca-chain.pem
    
    # 5. Cleanup CSR files
    echo "  [7/7] Cleaning up..."
    rm -f intermediate-ca.csr server.csr root-ca-cert.srl intermediate-ca-cert.srl
    
    echo -e "  ${GREEN}✓ Level $level certificates generated successfully!${NC}"
    echo ""
    
    cd ..
}

# Generate certificates for all levels
echo -e "${BLUE}Starting certificate generation for all 3 levels...${NC}"
echo ""

# Level 1: Dilithium2 (128-bit security)
generate_dilithium_certs 1 "dilithium2"

# Level 3: Dilithium3 (192-bit security)
generate_dilithium_certs 3 "dilithium3"

# Level 5: Dilithium5 (256-bit security)
generate_dilithium_certs 5 "dilithium5"

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
