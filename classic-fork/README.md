# Classic-Fork: Traditional TLS 1.3 Implementation

A reference implementation of TLS 1.3 using classical cryptographic algorithms (X25519 for key exchange and RSA-2048 for signatures).

## 🎯 Purpose

This implementation serves as a **baseline** for comparing performance with post-quantum cryptographic algorithms. It uses industry-standard classical algorithms that are currently deployed in production systems worldwide.

## 🔒 Cryptographic Algorithms

| Component | Algorithm | Security Level |
|-----------|-----------|----------------|
| **Key Exchange** | X25519 (ECDH) | ~128-bit classical |
| **Signatures** | RSA-2048 | ~112-bit classical |
| **Cipher** | AES-128-GCM | 128-bit symmetric |
| **Hash** | SHA-256 | 256-bit |
| **TLS Version** | 1.3 | Latest |

## 📊 Performance Metrics

The implementation tracks **5 key metrics** for comparison:

1. **Total Handshake Time** - Complete TLS handshake duration (milliseconds)
2. **Signing Time** - Server signature generation time (milliseconds)
3. **Verification Time** - Client signature verification time (milliseconds)
4. **Signature Size** - CertificateVerify message size (bytes)
5. **Certificate Size** - X.509 certificate size (bytes)

## 🏗️ Architecture

```
classic-fork/
├── src/
│   ├── tls_client.c         # TLS 1.3 client implementation
│   ├── tls_server.c         # TLS 1.3 server implementation
│   └── performance.c        # Performance measurement utilities
├── include/
│   └── performance.h        # Performance metrics structure
├── certs/                   # RSA-2048 certificates
│   ├── ca-cert.pem         # Root CA certificate
│   ├── ca-key.pem          # CA private key
│   ├── server.crt          # Server certificate
│   └── server.key          # Server private key
├── results/                # Performance test results (CSV)
├── Makefile               # Build configuration
└── README.md              # This file
```

## 🚀 Quick Start

### Prerequisites

- GCC compiler
- OpenSSL 1.1.1 with OQS support (installed in `../vendor/`)
- liboqs 0.10.1 (installed in `../vendor/`)

### Build

```bash
make clean
make
```

This compiles both client and server binaries to `build/` directory.

### Generate Certificates

```bash
./generate_certs.sh
```

Generates self-signed RSA-2048 certificates for testing.

### Run Server

```bash
./build/tls_server
```

Server listens on `0.0.0.0:4433` by default.

### Run Client

```bash
./build/tls_client
```

Client connects to `localhost:4433` by default.

## 📈 Typical Performance

Based on testing with RSA-2048 certificates:

| Metric | Value |
|--------|-------|
| Handshake Time (Client) | ~6.24 ms |
| Handshake Time (Server) | ~6.46 ms |
| Signing Time | ~2.50 ms |
| Verification Time | ~0.20 ms |
| Signature Size | 256 bytes |
| Certificate Size | 927 bytes |
| ClientHello Size | ~512 bytes |
| ServerHello Size | ~122 bytes |

*Performance may vary based on hardware and system load*

## 📝 Output Format

### Console Output

The client and server provide detailed, color-coded output showing:
- Initialization steps
- TLS handshake progress
- Certificate verification status
- Performance metrics summary

### CSV Export

Results are automatically saved to:
- `results/client_metrics.csv` - Client-side measurements
- `results/server_metrics.csv` - Server-side measurements

**CSV Format:**
```csv
protocol,cipher_suite,handshake_ms,signing_ms,verification_ms,signature_bytes,certificate_bytes
TLSv1.3,TLS_AES_128_GCM_SHA256,6.24,0.00,0.20,256,927
```

## 🔧 Configuration

### Modify Server Port

```bash
./build/tls_server 8443  # Use port 8443
```

### Connect to Different Server

```bash
./build/tls_client example.com 8443
```

## ⚠️ Security Notes

**This is a demonstration implementation for educational and benchmarking purposes.**

- ✅ Uses industry-standard cryptography
- ✅ Proper certificate validation
- ✅ Secure random number generation
- ⚠️ Self-signed certificates (for testing only)
- ⚠️ Simplified error handling
- ❌ **NOT recommended for production use without thorough security review**

### Quantum Computing Resistance

**This implementation is NOT quantum-resistant:**
- ❌ X25519 vulnerable to Shor's algorithm (quantum key recovery)
- ❌ RSA-2048 vulnerable to Shor's algorithm (factoring)
- ✅ AES-128 resistant (Grover's algorithm only halves security to 64-bit)

For quantum-resistant TLS, see **quantum-fork**.

## 🔗 Related

- **quantum-fork** - Post-quantum TLS 1.3 implementation (Kyber-768 + Dilithium-3)
- **vendor/** - Shared OpenSSL+OQS and liboqs libraries

## 📄 License

Educational and research use.

---

**Last Updated:** October 15, 2025  
**OpenSSL Version:** OQS-OpenSSL_1_1_1-stable  
**liboqs Version:** 0.10.1
