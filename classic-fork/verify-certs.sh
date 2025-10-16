#!/bin/bash
# Certificate Verification Script
# Run this on both client and server to verify you have matching certificates

echo "════════════════════════════════════════════════════════════"
echo "  CERTIFICATE VERIFICATION"
echo "════════════════════════════════════════════════════════════"
echo ""

# Check if certs directory exists
if [ ! -d "certs" ]; then
    echo "❌ ERROR: certs directory not found!"
    echo "   Current directory: $(pwd)"
    echo "   Please run this from the project directory"
    exit 1
fi

echo "📂 Certificates location: $(pwd)/certs"
echo ""

# Check CA certificate
if [ -f "certs/ca-cert.pem" ]; then
    echo "✓ CA Certificate:"
    echo "  Subject:     $(openssl x509 -in certs/ca-cert.pem -subject -noout | sed 's/subject=//')"
    echo "  Fingerprint: $(openssl x509 -in certs/ca-cert.pem -fingerprint -noout | sed 's/SHA256 Fingerprint=//')"
    echo ""
else
    echo "❌ CA certificate not found: certs/ca-cert.pem"
    echo ""
fi

# Check server certificate
if [ -f "certs/server-cert.pem" ]; then
    echo "✓ Server Certificate:"
    echo "  Subject:     $(openssl x509 -in certs/server-cert.pem -subject -noout | sed 's/subject=//')"
    echo "  Fingerprint: $(openssl x509 -in certs/server-cert.pem -fingerprint -noout | sed 's/SHA256 Fingerprint=//')"
    echo ""
    
    # Check SAN (Subject Alternative Names)
    echo "  IP Addresses allowed:"
    openssl x509 -in certs/server-cert.pem -text -noout | grep -A 1 "Subject Alternative Name" | tail -1 | sed 's/^[ \t]*/    /'
    echo ""
else
    echo "❌ Server certificate not found: certs/server-cert.pem"
    echo ""
fi

# Check server key
if [ -f "certs/server-key.pem" ]; then
    echo "✓ Server Private Key:"
    echo "  Fingerprint: $(openssl rsa -in certs/server-key.pem -pubout -outform DER 2>/dev/null | openssl dgst -sha256 | cut -d' ' -f2)"
    echo ""
else
    echo "❌ Server private key not found: certs/server-key.pem"
    echo ""
fi

echo "════════════════════════════════════════════════════════════"
echo ""
echo "📋 VERIFICATION INSTRUCTIONS:"
echo ""
echo "1. Both you and your friend run this script"
echo "2. Compare the CA Certificate Fingerprint - MUST BE IDENTICAL"
echo "3. Compare the Server Certificate Fingerprint - MUST BE IDENTICAL"
echo "4. Verify the IP address is in the 'IP Addresses allowed' list"
echo ""
echo "If fingerprints don't match, the server needs to use the"
echo "certificates from the client!"
echo ""
echo "════════════════════════════════════════════════════════════"
