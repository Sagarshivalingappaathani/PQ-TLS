# Post-Quantum TLS 1.3 Implementation

This directory contains a complete Post-Quantum TLS 1.3 implementation using **ML-KEM-768 (Kyber)** for key encapsulation and **ML-DSA-44 (Dilithium2)** for digital signatures.

## Overview

This implementation uses pure **liboqs** with manual TLS handshake construction to provide complete control over timing measurements and performance analysis.

### Algorithms

- **Key Encapsulation Mechanism (KEM)**: ML-KEM-768 (NIST-standardized Kyber-768)
  - Public Key: 1,184 bytes
  - Ciphertext: 1,088 bytes
  - Shared Secret: 32 bytes
  - Security Level: NIST Level 3 (128-bit quantum security)

- **Digital Signature**: ML-DSA-44 (NIST-standardized Dilithium2)
  - Public Key: 1,312 bytes
  - Signature: ~2,420 bytes
  - Security Level: NIST Level 2

- **Symmetric Encryption**: AES-128-GCM-SHA256 (post-handshake)

## Directory Structure

```
quantum/
├── Makefile                    # Build system
├── README.md                   # This file
├── src/
│   ├── pq_crypto.c            # PQ crypto wrappers (Kyber + Dilithium)
│   ├── pq_performance.c       # Performance measurement
│   ├── pq_tls_client.c        # PQ-TLS client implementation
│   └── pq_tls_server.c        # PQ-TLS server implementation
├── include/
│   ├── pq_crypto.h            # PQ crypto API
│   └── pq_performance.h       # Performance metrics API
├── bin/                       # Compiled binaries
├── results/                   # CSV performance data
└── certs/                     # (Future: PQ certificates)
```

## Building

### Prerequisites

- GCC compiler
- liboqs library (installed in `/usr/local/lib`)
- OpenSSL 3.x (for AES-GCM)

### Compile

```bash
make
```

This builds:
- `bin/pq_tls_client` - Post-Quantum TLS client
- `bin/pq_tls_server` - Post-Quantum TLS server

## Usage

### Run Automated Test

```bash
make test
```

This starts the server in the background, runs the client, and stops the server.

### Manual Usage

**Terminal 1 - Start Server:**
```bash
./bin/pq_tls_server [port]
# Default port: 4433
```

**Terminal 2 - Run Client:**
```bash
./bin/pq_tls_client [host] [port]
# Default: 127.0.0.1:4433
```

## Handshake Flow

```
Client                                          Server
------                                          ------
1. Generate Kyber-768 keypair
   ClientHello (+ Kyber PK) ------------------>
                                                2. Kyber encapsulation
                                <-------------- ServerHello (+ Kyber CT)
3. Kyber decapsulation
   (derive shared secret)
                                <-------------- Certificate (Dilithium PK)
                                <-------------- CertificateVerify (Dilithium sig)
4. Verify Dilithium signature
   Finished ----------------------------------->
                                                5. Handshake complete
   <------------------- Application Data --------------------->
```

## Performance Metrics

The implementation tracks:

### Timing Metrics
- **Total Handshake Time**: End-to-end handshake duration
- **KEM Keygen Time**: Kyber-768 keypair generation (client)
- **KEM Encaps Time**: Kyber-768 encapsulation (server)
- **KEM Decaps Time**: Kyber-768 decapsulation (client)
- **Signature Time**: Dilithium2 signing (server)
- **Verification Time**: Dilithium2 verification (client)

### Network Metrics
- **Bytes Sent/Received**: Total handshake message sizes
- **Network Overhead**: ~6 KB (vs ~1.6 KB for classical TLS)

### Crypto Sizes
- KEM public key, ciphertext sizes
- Signature public key, signature sizes

### System Resources
- Memory usage (KB)

## Performance Results

### Typical Client-Side Performance
- **Total Handshake**: 3-5 ms
- **Kyber Keygen**: 3-4 ms
- **Kyber Decapsulation**: 0.04-0.08 ms
- **Dilithium Verification**: 0.08-0.15 ms

### Typical Server-Side Performance
- **Kyber Encapsulation**: 0.05-0.08 ms
- **Dilithium Signing**: 0.15-0.25 ms

### Network Overhead
- **Client Sends**: ~1,209 bytes
- **Client Receives**: ~4,835 bytes
- **Total**: ~6,044 bytes (3.8× classical TLS)

## Output Files

Performance metrics are saved to:
- `results/pq_tls_metrics.csv` - Client-side metrics
- `results/pq_server_metrics.csv` - Server-side metrics

CSV Format:
```
protocol,cipher_suite,kem_algorithm,sig_algorithm,
handshake_ms,kem_keygen_ms,kem_encaps_ms,kem_decaps_ms,
signature_ms,verify_ms,bytes_sent,bytes_received,
kem_public_key_size,kem_ciphertext_size,
sig_public_key_size,signature_size,memory_kb
```

## Cleaning

```bash
make clean      # Remove binaries
make distclean  # Remove binaries and results
```

## Implementation Notes

### Why Manual Handshake Construction?

1. **Precise Timing**: Measure individual crypto operations (keygen, encaps, decaps, sign, verify)
2. **Full Control**: No black-box TLS stack obscuring performance
3. **Accurate Comparison**: Direct apples-to-apples comparison with classical TLS

### Security Considerations

⚠️ **This is a research/educational implementation**:
- No certificate validation
- Simplified handshake transcript hashing
- No session resumption
- No cipher suite negotiation
- Fixed algorithms (ML-KEM-768 + ML-DSA-44)

For production use, integrate with OpenSSL/BoringSSL using the OQS provider.

## Comparison with Classical TLS

| Metric | Classical (ECDHE+RSA) | Post-Quantum (Kyber+Dilithium) | Ratio |
|--------|----------------------|--------------------------------|-------|
| Handshake Time | ~11 ms | ~4 ms | **0.36×** (faster) |
| Key Exchange | ~7 ms (client) | ~3.5 ms | **0.5×** (faster) |
| Signature Gen | ~5 ms | ~0.2 ms | **0.04×** (much faster) |
| Signature Verify | ~0.25 ms | ~0.1 ms | **0.4×** (faster) |
| Network Overhead | ~1.6 KB | ~6 KB | **3.75×** (larger) |
| Public Key Size | 256 bytes | 1,184 bytes (KEM) | **4.6×** (larger) |
| Signature Size | 256 bytes | 2,420 bytes | **9.5×** (larger) |

**Key Insight**: PQ-TLS is **faster** for crypto operations but uses **4× more bandwidth**.

## Future Work

- [ ] Hybrid mode (Classical + PQ)
- [ ] Multiple algorithm support (Dilithium3, Kyber-1024, etc.)
- [ ] Certificate chain support
- [ ] TLS 1.3 extensions (ALPN, SNI, etc.)
- [ ] Integration with OpenSSL OQS provider
- [ ] Performance optimization (assembly, AVX-512, etc.)

## References

- [NIST PQC Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [ML-KEM (FIPS 203)](https://csrc.nist.gov/pubs/fips/203/final)
- [ML-DSA (FIPS 204)](https://csrc.nist.gov/pubs/fips/204/final)
- [liboqs](https://github.com/open-quantum-safe/liboqs)
- [Open Quantum Safe Project](https://openquantumsafe.org/)

## License

Same as parent project (TLS implementation research).
