# Classical TLS 1.3 Implementation

This directory contains a complete Classical TLS 1.3 implementation using **ECDHE P-256** for key exchange and **RSA-2048** for digital signatures, built with OpenSSL 3.x.

## Overview

This implementation uses **OpenSSL's TLS 1.3** stack with detailed message-level callbacks to provide precise timing measurements and performance analysis. This serves as the baseline for comparison with post-quantum cryptography.

### Algorithms

- **Key Exchange**: ECDHE P-256 (Elliptic Curve Diffie-Hellman Ephemeral)
  - Public Key: 65 bytes (uncompressed point)
  - Shared Secret: 32 bytes
  - Security Level: ~128-bit classical security
  - **⚠️ Vulnerable to quantum computers** (Shor's algorithm)

- **Digital Signature**: RSA-2048 with SHA-256
  - Public Key: 256 bytes (2048-bit modulus)
  - Signature: 256 bytes
  - Security Level: ~112-bit classical security
  - **⚠️ Vulnerable to quantum computers** (Shor's algorithm)

- **Cipher Suite**: TLS_AES_128_GCM_SHA256
  - Symmetric Encryption: AES-128-GCM (post-handshake)
  - AEAD: Galois/Counter Mode with authentication
  - Hash: SHA-256

## Directory Structure

```
classic/
├── Makefile                    # Build system
├── README.md                   # This file
├── src/
│   ├── tls_client.c           # TLS 1.3 client with OpenSSL
│   ├── tls_server.c           # TLS 1.3 server with OpenSSL
│   └── performance.c          # Performance measurement
├── include/
│   ├── performance.h          # Performance metrics API
│   └── tls13/                 # (Reserved for future headers)
├── build/                     # Compiled binaries
│   ├── tls_client            # TLS client executable
│   └── tls_server            # TLS server executable
├── certs/                     # X.509 certificates
│   ├── server.crt            # RSA-2048 server certificate
│   └── server.key            # RSA-2048 private key
└── results/                   # CSV performance data
    ├── classical_tls_metrics.csv  # Client-side metrics
    └── server_metrics.csv         # Server-side metrics
```

## Building

### Prerequisites

- **GCC compiler**: `gcc` version 9.0 or higher
- **OpenSSL 3.x**: Development libraries
- **Make**: GNU Make

Install dependencies on Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install build-essential libssl-dev
```

### Compile

Build everything (binaries + certificates):
```bash
make all
make certs
```

Or build individually:
```bash
make build       # Build client and server
make certs       # Generate RSA-2048 certificates
```

### Build Targets

```bash
make all         # Build client and server
make certs       # Generate self-signed certificates
make test        # Run automated test
make clean       # Remove binaries
make distclean   # Remove binaries, certificates, and results
make help        # Show help message
```

## Usage

### Run Automated Test

The easiest way to test:
```bash
make test
```

This will:
1. Start server in background (port 4433)
2. Run client to connect
3. Complete handshake and exchange data
4. Stop server
5. Display performance metrics

### Manual Usage

**Terminal 1 - Start Server:**
```bash
./build/tls_server [port]
# Default port: 4433
# Listens on 0.0.0.0:4433
```

**Terminal 2 - Run Client:**
```bash
./build/tls_client [host] [port]
# Default: 127.0.0.1:4433
```

Example with custom host/port:
```bash
# Server
./build/tls_server 8443

# Client
./build/tls_client 192.168.1.100 8443
```

## TLS 1.3 Handshake Flow

```
Client                                          Server
------                                          ------
1. Generate ECDHE P-256 keypair
   ClientHello
   + KeyShare (ECDHE public key)   ----------->
   + SupportedVersions (TLS 1.3)
   + CipherSuites
                                                2. Select ECDHE P-256
                                                   Compute shared secret
                                <-------------- ServerHello
                                                + KeyShare (ECDHE)
                                <-------------- {EncryptedExtensions}
                                <-------------- {Certificate} (RSA-2048)
                                <-------------- {CertificateVerify} (RSA sig)
                                                + Finished
3. Verify RSA-2048 signature
   Compute shared secret
   {Finished} ----------------------------->
                                                4. Handshake complete
   <--------------- Application Data ------------------->
   
Note: {...} indicates encrypted messages
```

### Message Flow Details

1. **ClientHello**: Client proposes TLS 1.3, cipher suites, ECDHE public key
2. **ServerHello**: Server selects parameters, sends ECDHE public key
3. **EncryptedExtensions**: Additional parameters (encrypted)
4. **Certificate**: Server's RSA-2048 X.509 certificate
5. **CertificateVerify**: RSA-2048 signature over handshake transcript
6. **Finished**: HMAC over all handshake messages
7. **Client Finished**: Client confirms handshake completion
8. **Application Data**: Encrypted with AES-128-GCM

## Performance Metrics

The implementation tracks detailed timing and network metrics using OpenSSL message callbacks.

### Timing Metrics

- **Total Handshake Time**: End-to-end handshake duration (ClientHello → Finished)
- **Key Exchange Time**: 
  - **Client**: ClientHello SEND → ServerHello RECEIVE (includes network latency)
  - **Server**: ClientHello RECEIVE → ServerHello SEND (pure crypto + network)
- **Signature Generation Time**: Server-side RSA-2048 signing
- **Signature Verification Time**: Client-side RSA-2048 verification

### Network Metrics

- **Bytes Sent**: Total handshake message bytes sent
- **Bytes Received**: Total handshake message bytes received
- **Message Types Tracked**: 
  - ClientHello, ServerHello
  - EncryptedExtensions
  - Certificate, CertificateVerify
  - Finished, NewSessionTicket

### Crypto Metrics

- **Public Key Size**: RSA-2048 modulus (256 bytes)
- **Signature Size**: RSA-2048 signature (256 bytes)
- **Certificate Size**: Full X.509 certificate chain

### System Metrics

- **Memory Usage**: RSS (Resident Set Size) in KB

## Performance Results

### Typical Client-Side Performance

```
Handshake Performance:
  • Total Time:      11.42 ms
  • Key Exchange:    7.35 ms  (includes network RTT)
  • Verification:    0.25 ms  (RSA-2048 verify)

Network Overhead:
  • Bytes Sent:      256 bytes
  • Bytes Received:  1,348 bytes
  • Total:           1,604 bytes

Cryptographic Sizes:
  • Public Key:      256 bytes
  • Signature:       256 bytes
```

### Typical Server-Side Performance

```
Handshake Performance:
  • Total Time:      11.23 ms
  • Key Exchange:    0.87 ms  (ECDHE scalar multiplication)
  • Signature Gen:   5.39 ms  (RSA-2048 signing)

Network Overhead:
  • Bytes Sent:      1,348 bytes
  • Bytes Received:  256 bytes
```

### Performance Breakdown

| Operation | Time (ms) | Notes |
|-----------|-----------|-------|
| **ECDHE Keygen** | ~0.5 | Client P-256 keypair generation |
| **ECDHE Exchange** | ~0.4 | Server scalar multiplication |
| **RSA-2048 Sign** | ~5.4 | Slowest operation (uses private key) |
| **RSA-2048 Verify** | ~0.25 | Fast (uses public exponent) |
| **Network RTT** | ~6-7 | Round-trip time (localhost) |
| **Total Handshake** | ~11.4 | End-to-end |

## Output Files

Performance metrics are automatically saved to CSV files:

- **`results/classical_tls_metrics.csv`** - Client-side metrics
- **`results/server_metrics.csv`** - Server-side metrics

### CSV Format

```csv
protocol,cipher_suite,handshake_ms,key_exchange_ms,signature_ms,verify_ms,
bytes_sent,bytes_received,public_key_size,signature_size,memory_kb
```

Example row:
```csv
TLSv1.3,TLS_AES_128_GCM_SHA256,11.42,7.35,0.00,0.25,
256,1348,256,256,6824
```

**Note**: Client CSV shows `signature_ms=0.00` (server-only), Server CSV shows `verify_ms=0.00` (client-only).

## Certificate Generation

The `make certs` command generates a self-signed RSA-2048 certificate:

```bash
make certs
```

This creates:
- `certs/server.key` - RSA-2048 private key (PEM format)
- `certs/server.crt` - X.509 certificate (PEM format)

### Certificate Details

```
Subject: C=US, ST=State, L=City, O=Organization, CN=localhost
Issuer: Self-signed
Validity: 365 days
Public Key: RSA 2048 bits
Signature: sha256WithRSAEncryption
```

To view certificate details:
```bash
openssl x509 -in certs/server.crt -text -noout
```

## Logging and Debugging

### Message Callback Logging

The implementation includes detailed color-coded logging for all TLS messages:

**Colors**:
- 🟢 **GREEN**: Client sending messages
- 🔵 **CYAN**: Client receiving messages
- 🟣 **MAGENTA**: Server sending messages
- 🟡 **YELLOW**: Phase markers (Key Exchange, Signature, etc.)

### Example Output

```
╔═══════════════════════════════════════════════════════════════╗
║              CLASSICAL TLS 1.3 CLIENT                         ║
╚═══════════════════════════════════════════════════════════════╝

→ Connecting to server 127.0.0.1:4433...
✓ Connected to server

═══ TLS Handshake Messages ═══

→ Sending: ClientHello (256 bytes)
← Received: ServerHello (122 bytes)
← Received: EncryptedExtensions (10 bytes)
← Received: Certificate (897 bytes)
← Received: CertificateVerify (264 bytes)
← Received: Finished (36 bytes)
→ Sending: Finished (36 bytes)

═══════════════════════════════════════════════════════════════
  CLASSICAL TLS HANDSHAKE COMPLETED SUCCESSFULLY!
═══════════════════════════════════════════════════════════════

╔═══════════════════════════════════════════════════════════════╗
║         CLASSICAL TLS PERFORMANCE SUMMARY                     ║
╚═══════════════════════════════════════════════════════════════╝

Protocol:
  • Version:     TLSv1.3
  • Cipher:      TLS_AES_128_GCM_SHA256

Handshake Performance:
  • Total Time:  11.42 ms

Timing Breakdown:
  • Key Exchange: 7.35 ms
  • Verification: 0.25 ms

Network Overhead:
  • Bytes Sent:     256 bytes
  • Bytes Received: 1,348 bytes
  • Total:          1,604 bytes

Cryptographic Sizes:
  • Public Key: 256 bytes
  • Signature:  256 bytes

System Resources:
  • Memory:     6,824 KB

✓ Metrics saved to: results/classical_tls_metrics.csv
```

## Implementation Details

### OpenSSL Integration

The implementation uses:
- **SSL_CTX**: TLS context configuration
- **SSL**: Connection state machine
- **SSL_set_msg_callback()**: Message-level interception for timing
- **SSL_connect() / SSL_accept()**: Handshake execution
- **TLSv1_3_method()**: Force TLS 1.3 only (no fallback)

### Timing Measurement

Timing is measured using **message callbacks**:

```c
void msg_callback(int write_p, int version, int content_type,
                  const void *buf, size_t len, SSL *ssl, void *arg)
{
    // Track timing for:
    // - ClientHello → ServerHello (key exchange)
    // - CertificateVerify → Finished (signature verification)
    
    if (content_type == SSL3_RT_HANDSHAKE) {
        uint8_t msg_type = ((uint8_t *)buf)[0];
        
        if (msg_type == SSL3_MT_CLIENT_HELLO && write_p) {
            g_key_exchange_start_us = get_time_us();
        }
        // ... more tracking
    }
}
```

### Why Message Callbacks?

OpenSSL's `SSL_connect()` and `SSL_accept()` are **black boxes** - you can't see inside. Message callbacks allow us to:

1. **Track individual operations**: Key exchange, signature verification
2. **Count network bytes**: Measure actual handshake overhead
3. **Extract crypto sizes**: Signature length, certificate size
4. **Maintain compatibility**: Still use OpenSSL's TLS stack

## Performance Considerations

### Why is RSA Signing Slow?

RSA-2048 signature generation (~5.4 ms) is the slowest operation because:
1. **Private key operations** are expensive (modular exponentiation with large exponent)
2. **Constant-time implementation** to prevent timing attacks
3. **2048-bit arithmetic** requires many CPU cycles

In contrast, RSA verification (~0.25 ms) is **22× faster** because it uses a small public exponent (typically 65537).

### Network Latency Impact

The client-side "Key Exchange" time (7.35 ms) includes:
- ECDHE key generation: ~0.5 ms
- Network RTT to server: ~6-7 ms (localhost)
- Server processing: ~0.4 ms

On WAN connections, this could be 50-200 ms depending on distance.

## Security Considerations

### ⚠️ This is a Research/Educational Implementation

**NOT for production use**:
- ❌ No certificate validation (accepts any certificate)
- ❌ No hostname verification
- ❌ Self-signed certificates only
- ❌ No certificate chain validation
- ❌ No session resumption
- ❌ No cipher suite negotiation (forces TLS_AES_128_GCM_SHA256)
- ❌ Fixed to TLS 1.3 only (no version negotiation)

### Quantum Threat

⚠️ **All classical public-key cryptography in this implementation is vulnerable to quantum computers**:

- **ECDHE P-256**: Broken by Shor's algorithm on a large quantum computer (~2000 qubits)
- **RSA-2048**: Broken by Shor's algorithm on a large quantum computer (~4000 qubits)

**Impact**: 
- An adversary with a quantum computer could:
  - Decrypt past traffic (if they recorded it)
  - Forge signatures
  - Impersonate servers

**Solution**: Migrate to post-quantum cryptography (see `../quantum/` directory)

## Comparison with Post-Quantum TLS

| Metric | Classical (This) | Post-Quantum | Winner |
|--------|-----------------|--------------|---------|
| **Handshake** | 11.4 ms | 4.1 ms | PQ (2.8× faster) |
| **Key Exchange** | 7.4 ms | 3.5 ms | PQ (2.1× faster) |
| **Signature Gen** | 5.4 ms | 0.2 ms | **PQ (27× faster)** |
| **Signature Verify** | 0.25 ms | 0.09 ms | PQ (2.8× faster) |
| **Network** | **1.6 KB** | 6.0 KB | Classical (3.8× less) |
| **Quantum-Safe** | ❌ | ✅ | **PQ** |

**Trade-off**: Classical is more **bandwidth-efficient**, but post-quantum is **faster and quantum-safe**.

## Troubleshooting

### Common Issues

**1. "libssl.so.3: cannot open shared object file"**
```bash
sudo apt-get install libssl-dev
sudo ldconfig
```

**2. "Address already in use" (server won't start)**
```bash
# Kill existing server
pkill -f tls_server
# Or use different port
./build/tls_server 8443
```

**3. "Certificate verify failed"**
- This is expected with self-signed certificates
- Client is configured to ignore verification (SSL_VERIFY_NONE)

**4. "No such file or directory: certs/server.crt"**
```bash
make certs  # Generate certificates first
```

**5. Compilation errors**
```bash
# Ensure OpenSSL 3.x is installed
openssl version  # Should show "OpenSSL 3.x"

# Update OpenSSL if needed
sudo apt-get update
sudo apt-get install --upgrade libssl-dev
```

## Testing and Validation

### Verify TLS Version

Ensure TLS 1.3 is being used:
```bash
# Run server
./build/tls_server &

# Test with OpenSSL client
openssl s_client -connect 127.0.0.1:4433 -tls1_3
# Look for: "Protocol  : TLSv1.3"
```

### Verify Cipher Suite

Check the negotiated cipher:
```bash
openssl s_client -connect 127.0.0.1:4433 -tls1_3 | grep "Cipher"
# Should show: "Cipher    : TLS_AES_128_GCM_SHA256"
```

### Performance Testing

Run multiple iterations:
```bash
for i in {1..10}; do
    make test 2>&1 | grep "Total Time"
done
```

## Files and Their Purpose

| File | Purpose |
|------|---------|
| `src/tls_client.c` | TLS 1.3 client implementation with OpenSSL |
| `src/tls_server.c` | TLS 1.3 server implementation with OpenSSL |
| `src/performance.c` | Performance measurement and CSV export |
| `include/performance.h` | Performance metrics structure |
| `Makefile` | Build automation |
| `certs/server.crt` | RSA-2048 X.509 certificate (generated) |
| `certs/server.key` | RSA-2048 private key (generated) |
| `results/*.csv` | Performance data exports |


## References

### Standards
- [RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3](https://datatracker.ietf.org/doc/html/rfc8446)
- [RFC 5280: X.509 Public Key Infrastructure](https://datatracker.ietf.org/doc/html/rfc5280)
- [FIPS 186-4: Digital Signature Standard (DSS)](https://csrc.nist.gov/publications/detail/fips/186/4/final)

### Libraries
- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [OpenSSL Wiki: TLS 1.3](https://wiki.openssl.org/index.php/TLS1.3)

### Security
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Quantum Computing Threat Timeline](https://globalriskinstitute.org/publications/quantum-threat-timeline/)

## Cleaning Up

```bash
make clean      # Remove binaries only
make distclean  # Remove binaries, certificates, and results
```

To start fresh:
```bash
make distclean
make all
make certs
make test
```