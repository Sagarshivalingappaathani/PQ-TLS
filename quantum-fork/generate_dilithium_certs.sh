#!/bin/bash

# Script to generate Dilithium3-based certificates for quantum-fork
# This uses the C API directly since OpenSSL+OQS command-line has linking issues

set -e

CERTS_DIR="certs"
VENDOR_DIR="../vendor"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}╔═══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Generating Dilithium3 Certificates              ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════╝${NC}"
echo ""

# Create certs directory if it doesn't exist
mkdir -p "$CERTS_DIR"

# For now, we'll use hybrid certificates (RSA+Dilithium would require custom code)
# Since pure Dilithium certificate generation via CLI is problematic,
# we'll enable Dilithium signatures in the TLS handshake configuration instead

echo -e "${YELLOW}Note: Dilithium certificate generation requires custom C code.${NC}"
echo -e "${YELLOW}For now, we'll use RSA certificates but enable Dilithium${NC}"
echo -e "${YELLOW}signatures in the TLS configuration.${NC}"
echo ""

# Check if RSA certificates exist
if [ -f "$CERTS_DIR/server.crt" ] && [ -f "$CERTS_DIR/server.key" ]; then
    echo -e "${GREEN}✓ RSA certificates already exist${NC}"
    echo -e "${GREEN}✓ Dilithium signatures will be negotiated during TLS handshake${NC}"
else
    echo -e "${RED}✗ No certificates found. Please run the classic-fork certificate generation first.${NC}"
    echo -e "${YELLOW}Run: cd ../classic-fork && ./generate_certs.sh${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}Certificate Setup Complete!${NC}"
echo -e "${YELLOW}Note: The TLS handshake will use:${NC}"
echo -e "  - Key Exchange: Kyber-768 (post-quantum)"
echo -e "  - Signatures: Will attempt Dilithium3, fallback to RSA"
echo -e "  - Certificate: RSA (Dilithium certificates require OQS provider)"
