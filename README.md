# TLS Performance Analysis: Classical vs Post-Quantum

This project implements and compares **Classical TLS 1.3** with **Post-Quantum TLS 1.3** to analyze performance implications of quantum-resistant cryptography.

## Project Structure

```
TLS/
├── classic/                    # Classical TLS 1.3 (ECDHE + RSA)
│   ├── src/                   # Client/Server implementation
│   ├── include/               # Headers
│   ├── results/               # Performance CSV data
│   ├── certs/                 # RSA-2048 certificates
│   └── Makefile              # Build system
│
├── quantum/                   # Post-Quantum TLS (Kyber + Dilithium)
│   ├── src/                  # Client/Server implementation
│   ├── include/              # Headers
│   ├── bin/                  # Compiled binaries
│   ├── results/              # Performance CSV data
│   ├── README.md            # Detailed PQ-TLS documentation
│   └── Makefile             # Build system
│
└── hybrid/                   # (Future) Hybrid Classical+PQ
```

## Implementations

### Classical TLS 1.3

**Location**: `classic/`

**Algorithms**:
- **Key Exchange**: ECDHE P-256 (Elliptic Curve Diffie-Hellman)
- **Signatures**: RSA-2048 with SHA-256
- **Cipher**: TLS_AES_128_GCM_SHA256
- **Library**: OpenSSL 3.x

**Performance**:
- Handshake Time: ~11 ms
- Key Exchange: ~7 ms (client includes network latency)
- Signature Generation: ~5 ms
- Signature Verification: ~0.25 ms
- Network Overhead: ~1.6 KB

### Post-Quantum TLS 1.3

**Location**: `quantum/`

**Algorithms**:
- **KEM**: ML-KEM-768 (NIST-standardized Kyber-768, FIPS 203)
- **Signatures**: ML-DSA-44 (NIST-standardized Dilithium2, FIPS 204)
- **Cipher**: AES_128_GCM_SHA256
- **Library**: liboqs (Open Quantum Safe)

**Performance**:
- Handshake Time: ~4 ms (**2.75× faster**)
- Kyber Keygen: ~3.5 ms
- Kyber Encapsulation: ~0.06 ms (**116× faster** than ECDHE)
- Kyber Decapsulation: ~0.05 ms
- Dilithium Signing: ~0.2 ms (**25× faster** than RSA)
- Dilithium Verification: ~0.09 ms (**2.8× faster** than RSA)
- Network Overhead: ~6 KB (**3.75× larger**)

## Building

### Prerequisites

**Classical TLS**:
```bash
sudo apt-get install libssl-dev
```

**Post-Quantum TLS**:
```bash
# Build liboqs from source
git clone https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs
cd /tmp/liboqs
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local ..
make -j$(nproc)
sudo make install
```

### Compile

**Classical TLS**:
```bash
cd classic
make all
make certs    # Generate RSA-2048 certificates
```

**Post-Quantum TLS**:
```bash
cd quantum
make all
```

## Running Tests

### Classical TLS

```bash
cd classic
make test
```

### Post-Quantum TLS

```bash
cd quantum
make test
```

## Performance Comparison

### Cryptographic Operations

| Operation | Classical (ECDHE+RSA) | Post-Quantum (Kyber+Dilithium) | Speedup |
|-----------|----------------------|-------------------------------|---------|
| **Key Exchange (Client)** | 7.35 ms | 3.50 ms | **2.1×** |
| **Key Exchange (Server)** | 0.87 ms | 0.06 ms | **14.5×** |
| **Signature Generation** | 5.39 ms | 0.20 ms | **27×** |
| **Signature Verification** | 0.25 ms | 0.09 ms | **2.8×** |
| **Total Handshake** | 11.42 ms | 4.10 ms | **2.8×** |

✅ **Result**: Post-quantum cryptography is **significantly faster** for all operations.

### Network Overhead

| Metric | Classical | Post-Quantum | Increase |
|--------|-----------|--------------|----------|
| **Bytes Sent (Client)** | 256 bytes | 1,209 bytes | **4.7×** |
| **Bytes Received (Client)** | 1,348 bytes | 4,835 bytes | **3.6×** |
| **Total Handshake** | 1,604 bytes | 6,044 bytes | **3.8×** |

⚠️ **Trade-off**: Post-quantum uses **3.8× more bandwidth**.

### Cryptographic Sizes

| Component | Classical | Post-Quantum | Ratio |
|-----------|-----------|--------------|-------|
| **Public Key (KEM/KEX)** | 256 bytes (ECDHE) | 1,184 bytes (Kyber) | 4.6× |
| **Ciphertext/Exchange** | - | 1,088 bytes | - |
| **Public Key (Sig)** | 256 bytes (RSA) | 1,312 bytes (Dilithium) | 5.1× |
| **Signature** | 256 bytes | 2,420 bytes | **9.5×** |

## Key Findings

### 1. **Performance**: Post-Quantum Wins 🏆

- **2.8× faster handshakes** (11ms → 4ms)
- **27× faster signature generation** (quantum-resistant algorithms are optimized for modern CPUs)
- **14.5× faster key exchange** (server-side Kyber encapsulation vs ECDHE scalar multiplication)

### 2. **Network Overhead**: Classical Wins 📶

- **3.8× more bandwidth** required for PQ-TLS
- Primarily due to larger signatures (9.5× bigger)
- Impact depends on network conditions:
  - **LAN**: Negligible (microseconds)
  - **Mobile**: Could add 10-50ms latency
  - **Satellite**: Could add 100-500ms latency

### 3. **Security**: Post-Quantum is Future-Proof 🔒

- Classical ECDHE/RSA: **Vulnerable to quantum computers**
- Post-Quantum (Kyber/Dilithium): **Quantum-resistant** (NIST-standardized)

## Implementation Approach

Both implementations use **manual TLS handshake construction** instead of OpenSSL's built-in TLS stack:

### Why Manual Construction?

1. **Precise Timing**: Measure individual crypto operations (keygen, sign, verify, etc.)
2. **Full Control**: No black-box obscuring what's being measured
3. **Fair Comparison**: Identical handshake flow for both implementations
4. **Educational**: Demonstrates TLS 1.3 handshake protocol clearly

### Handshake Flow

```
Client                                          Server
------                                          ------

ClientHello
+ KeyShare (ECDHE PK / Kyber PK)    -------->
                                                ServerHello
                                                + KeyShare (ECDHE / Kyber CT)
                                     <-------- EncryptedExtensions
                                                Certificate (RSA / Dilithium PK)
                                                CertificateVerify (RSA / Dilithium Sig)
                                                Finished
Finished                            -------->
                                                
Application Data                    <------> Application Data
```

## Metrics Collected

Both implementations track:

### Timing Metrics
- Total handshake duration
- Key exchange time (keygen, encaps/exchange, decaps)
- Signature generation time
- Signature verification time

### Network Metrics  
- Bytes sent/received
- Total handshake overhead

### Crypto Metrics
- Public key sizes
- Signature sizes
- Ciphertext sizes

### System Metrics
- Memory usage (RSS)

## Output Format

All metrics are saved to CSV files for analysis:

**Classical**:
- `classic/results/classical_tls_metrics.csv` (client)
- `classic/results/server_metrics.csv` (server)

**Post-Quantum**:
- `quantum/results/pq_tls_metrics.csv` (client)
- `quantum/results/pq_server_metrics.csv` (server)

## Recommendations

### Use Post-Quantum TLS When:
- ✅ Performance is critical (PQ is faster!)
- ✅ Network bandwidth is plentiful (LAN, datacenter)
- ✅ Long-term security required ("store now, decrypt later" attacks)
- ✅ Regulatory compliance (NIST PQC migration)

### Use Classical TLS When:
- ✅ Bandwidth-constrained (satellite, IoT, mobile)
- ✅ Legacy compatibility required
- ✅ Near-term security only (no quantum threat yet)

### Use Hybrid TLS When:
- ✅ Maximum security needed (belt-and-suspenders approach)
- ✅ Transitioning between classical and PQ
- ✅ Defense-in-depth strategy

## Future Work

- [ ] **Hybrid Implementation**: Combine ECDHE+Kyber and RSA+Dilithium
- [ ] **Algorithm Variants**: Test Kyber-512, Dilithium3, Falcon, etc.
- [ ] **Network Simulation**: Test over various latency/bandwidth conditions
- [ ] **Integration**: OpenSSL OQS provider integration
- [ ] **Optimization**: Assembly, AVX-512, constant-time implementations
- [ ] **Analysis**: Power consumption, side-channel resistance

## References

### Standards
- [NIST Post-Quantum Cryptography Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [FIPS 203: ML-KEM (Kyber)](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204: ML-DSA (Dilithium)](https://csrc.nist.gov/pubs/fips/204/final)
- [RFC 8446: TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446)

### Libraries
- [OpenSSL](https://www.openssl.org/)
- [liboqs - Open Quantum Safe](https://github.com/open-quantum-safe/liboqs)
- [OQS-OpenSSL Provider](https://github.com/open-quantum-safe/oqs-provider)

### Research
- [NIST PQC Competition](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [Cloudflare: Post-Quantum TLS](https://blog.cloudflare.com/post-quantum-for-all/)
- [Google: CECPQ2 Hybrid](https://security.googleblog.com/2018/12/a-quantum-resistant-key-exchange.html)

## License

Research/Educational implementation for TLS performance analysis.

## Authors

Post-Quantum TLS Implementation Project
October 2025
