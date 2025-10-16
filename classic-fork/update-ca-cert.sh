#!/bin/bash
# Script to help update CA certificate from friend's server

echo "=== Update CA Certificate from Friend's Server ==="
echo ""
echo "Ask your friend to run this command on their machine:"
echo "----------------------------------------"
echo "cat ~/Major\\ Project/PQ-TLS-system/classic/certs/ca-cert.pem"
echo "----------------------------------------"
echo ""
echo "Then paste the certificate content below and press Ctrl+D when done:"
echo ""

# Read the certificate from stdin
cat > /home/sagar8022/0418/skp-major-project/TLS/classic-fork/certs/ca-cert-friend.pem

echo ""
echo "✓ Certificate saved to: certs/ca-cert-friend.pem"
echo ""
echo "Now test the connection with:"
echo "  ./build/tls_client 10.190.219.88 4433"
echo ""
echo "If you want to use this permanently, run:"
echo "  cp certs/ca-cert-friend.pem certs/ca-cert.pem"
