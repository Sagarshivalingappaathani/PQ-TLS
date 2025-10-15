# Post-Quantum TLS 1.3 Performance Analysis# TLS Performance Analysis: Classical vs Post-Quantum



A comprehensive performance comparison between traditional and post-quantum cryptographic algorithms in TLS 1.3, demonstrating that quantum-resistant encryption can be **faster** than classical methods.This project implements and compares **Classical TLS 1.3** with **Post-Quantum TLS 1.3** to analyze performance implications of quantum-resistant cryptography.



## 🎯 Project Overview## Project Structure



This project implements and compares two complete TLS 1.3 implementations:```

TLS/

- **Classic-Fork**: Traditional TLS 1.3 using X25519 and RSA-2048├── classic/                    # Classical TLS 1.3 (ECDHE + RSA)

- **Quantum-Fork**: Post-Quantum TLS 1.3 using Kyber-768 and Dilithium-3│   ├── src/                   # Client/Server implementation

│   ├── include/               # Headers

## 🔑 Key Findings│   ├── results/               # Performance CSV data

│   ├── certs/                 # RSA-2048 certificates

**Post-Quantum TLS is Actually FASTER!**│   └── Makefile              # Build system

│

| Metric | Classical | Post-Quantum | Improvement |├── quantum/                   # Post-Quantum TLS (Kyber + Dilithium)

|--------|-----------|--------------|-------------|│   ├── src/                  # Client/Server implementation

| **Handshake Time** | 6.24 ms | 2.69 ms | **57% faster** ⚡ |│   ├── include/              # Headers

| **Signing Time** | 2.50 ms | 0.51 ms | **80% faster** ⚡ |│   ├── bin/                  # Compiled binaries

| **Verification Time** | 1.24 ms | 0.42 ms | **66% faster** ⚡ |│   ├── results/              # Performance CSV data

| **Signature Size** | 256 bytes | 3,293 bytes | 13× larger |│   ├── README.md            # Detailed PQ-TLS documentation

| **Certificate Size** | 927 bytes | 5,624 bytes | 6× larger |│   └── Makefile             # Build system

│

**Security Status:**└── hybrid/                   # (Future) Hybrid Classical+PQ

- ❌ **Classical TLS**: Vulnerable to quantum computers (Shor's algorithm)```

- ✅ **Post-Quantum TLS**: Quantum-resistant (NIST PQC standards)

## Implementations

## 📁 Repository Structure

### Classical TLS 1.3

```

TLS/**Location**: `classic/`

├── classic-fork/          Traditional TLS 1.3 implementation

│   ├── src/              Client and server source code**Algorithms**:

│   ├── include/          Performance measurement headers- **Key Exchange**: ECDHE P-256 (Elliptic Curve Diffie-Hellman)

│   ├── certs/            RSA-2048 certificates- **Signatures**: RSA-2048 with SHA-256

│   └── README.md         Detailed implementation guide- **Cipher**: TLS_AES_128_GCM_SHA256

│- **Library**: OpenSSL 3.x

├── quantum-fork/          Post-Quantum TLS 1.3 implementation

│   ├── src/              Client and server source code**Performance**:

│   ├── include/          Performance measurement headers- Handshake Time: ~11 ms

│   ├── certs/            Dilithium-3 certificates- Key Exchange: ~7 ms (client includes network latency)

│   ├── QUANTUM_STATUS.md Technical details on PQ algorithms- Signature Generation: ~5 ms

│   └── README.md         Detailed implementation guide- Signature Verification: ~0.25 ms

│- Network Overhead: ~1.6 KB

├── vendor/               Cryptographic libraries

│   ├── openssl-oqs-install/  OpenSSL with liboqs integration### Post-Quantum TLS 1.3

│   └── liboqs-install/       Standalone liboqs library

│**Location**: `quantum/`

├── PROJECT_SUMMARY.md     Complete project analysis

└── QUICK_REFERENCE.md     Quick start guide**Algorithms**:

```- **KEM**: ML-KEM-768 (NIST-standardized Kyber-768, FIPS 203)

- **Signatures**: ML-DSA-44 (NIST-standardized Dilithium2, FIPS 204)

## 🚀 Quick Start- **Cipher**: AES_128_GCM_SHA256

- **Library**: liboqs (Open Quantum Safe)

### Prerequisites

- Linux/Unix environment**Performance**:

- GCC compiler- Handshake Time: ~4 ms (**2.75× faster**)

- Make- Kyber Keygen: ~3.5 ms

- Kyber Encapsulation: ~0.06 ms (**116× faster** than ECDHE)

### Build and Run- Kyber Decapsulation: ~0.05 ms

- Dilithium Signing: ~0.2 ms (**25× faster** than RSA)

**Classic-Fork (Traditional TLS):**- Dilithium Verification: ~0.09 ms (**2.8× faster** than RSA)

```bash- Network Overhead: ~6 KB (**3.75× larger**)

cd classic-fork

make## Building

./build/tls_server &    # Terminal 1

./build/tls_client      # Terminal 2### Prerequisites

```

**Classical TLS**:

**Quantum-Fork (Post-Quantum TLS):**```bash

```bashsudo apt-get install libssl-dev

cd quantum-fork```

make

./build/tls_server &    # Terminal 1**Post-Quantum TLS**:

./build/tls_client      # Terminal 2```bash

```# Build liboqs from source

git clone https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs

### View Resultscd /tmp/liboqs

```bashmkdir build && cd build

# Performance metrics are saved to CSVcmake -DCMAKE_INSTALL_PREFIX=/usr/local ..

cat classic-fork/results/client_metrics.csvmake -j$(nproc)

cat quantum-fork/results/client_metrics.csvsudo make install

``````



## 🔬 Algorithms Used### Compile



### Classic-Fork**Classical TLS**:

- **Key Exchange**: X25519 (Elliptic Curve Diffie-Hellman)```bash

- **Signatures**: RSA-2048 with SHA-256cd classic

- **Cipher Suite**: TLS_AES_128_GCM_SHA256make all

make certs    # Generate RSA-2048 certificates

### Quantum-Fork```

- **Key Exchange**: Kyber-768 (NIST PQC Round 3 finalist)

- **Signatures**: Dilithium-3 (NIST PQC standard)**Post-Quantum TLS**:

- **Cipher Suite**: TLS_AES_128_GCM_SHA256```bash

cd quantum

## 📊 Performance Metricsmake all

```

Both implementations measure:

1. **Total Handshake Time** - Complete TLS handshake duration## Running Tests

2. **Signing Time** - Time to generate digital signatures

3. **Verification Time** - Time to verify digital signatures### Classical TLS

4. **Signature Size** - Size of cryptographic signatures

5. **Certificate Size** - Size of X.509 certificates```bash

cd classic

All measurements use high-precision microsecond timing and are exported to CSV format for analysis.make test

```

## 🛠️ Technology Stack

### Post-Quantum TLS

- **OpenSSL 1.1.1** with OQS integration

- **liboqs 0.10.1** - Open Quantum Safe library```bash

- **C Programming Language**cd quantum

- **TLS 1.3 Protocol**make test

- **NIST Post-Quantum Cryptography Standards**```



## 📖 Documentation## Performance Comparison



- **[classic-fork/README.md](classic-fork/README.md)** - Traditional TLS implementation guide### Cryptographic Operations

- **[quantum-fork/README.md](quantum-fork/README.md)** - Post-quantum TLS implementation guide

- **[quantum-fork/QUANTUM_STATUS.md](quantum-fork/QUANTUM_STATUS.md)** - Technical details on PQ algorithms| Operation | Classical (ECDHE+RSA) | Post-Quantum (Kyber+Dilithium) | Speedup |

- **[PROJECT_SUMMARY.md](PROJECT_SUMMARY.md)** - Complete project analysis|-----------|----------------------|-------------------------------|---------|

- **[QUICK_REFERENCE.md](QUICK_REFERENCE.md)** - Quick start commands| **Key Exchange (Client)** | 7.35 ms | 3.50 ms | **2.1×** |

| **Key Exchange (Server)** | 0.87 ms | 0.06 ms | **14.5×** |

## 🎓 Use Cases| **Signature Generation** | 5.39 ms | 0.20 ms | **27×** |

| **Signature Verification** | 0.25 ms | 0.09 ms | **2.8×** |

- **Research**: Academic study of post-quantum cryptography performance| **Total Handshake** | 11.42 ms | 4.10 ms | **2.8×** |

- **Education**: Learning TLS 1.3 and post-quantum algorithms

- **Benchmarking**: Comparing classical vs. quantum-resistant crypto✅ **Result**: Post-quantum cryptography is **significantly faster** for all operations.

- **Migration Planning**: Understanding PQC implementation impact

### Network Overhead

## 🔐 Security Considerations

| Metric | Classical | Post-Quantum | Increase |

### Quantum Threat Timeline|--------|-----------|--------------|----------|

- **Current**: Classical cryptography is secure| **Bytes Sent (Client)** | 256 bytes | 1,209 bytes | **4.7×** |

- **~10-15 years**: Quantum computers may break RSA/ECDH| **Bytes Received (Client)** | 1,348 bytes | 4,835 bytes | **3.6×** |

- **"Harvest now, decrypt later"**: Adversaries storing encrypted data today| **Total Handshake** | 1,604 bytes | 6,044 bytes | **3.8×** |



### Migration Strategy⚠️ **Trade-off**: Post-quantum uses **3.8× more bandwidth**.

This project demonstrates that migrating to post-quantum cryptography:

- ✅ **Improves** computational performance (faster signing/verification)### Cryptographic Sizes

- ⚠️ **Increases** bandwidth requirements (larger signatures/certificates)

- ✅ **Provides** quantum resistance against future threats| Component | Classical | Post-Quantum | Ratio |

|-----------|-----------|--------------|-------|

## 📝 License| **Public Key (KEM/KEX)** | 256 bytes (ECDHE) | 1,184 bytes (Kyber) | 4.6× |

| **Ciphertext/Exchange** | - | 1,088 bytes | - |

This project is for educational and research purposes.| **Public Key (Sig)** | 256 bytes (RSA) | 1,312 bytes (Dilithium) | 5.1× |

| **Signature** | 256 bytes | 2,420 bytes | **9.5×** |

## 👥 Author

## Key Findings

Sagar Shivalingappa Athani  

GitHub: [@Sagarshivalingappaathani](https://github.com/Sagarshivalingappaathani)### 1. **Performance**: Post-Quantum Wins 🏆



## 🙏 Acknowledgments- **2.8× faster handshakes** (11ms → 4ms)

- **27× faster signature generation** (quantum-resistant algorithms are optimized for modern CPUs)

- **Open Quantum Safe (OQS)** - liboqs library and OQS-OpenSSL integration- **14.5× faster key exchange** (server-side Kyber encapsulation vs ECDHE scalar multiplication)

- **NIST Post-Quantum Cryptography Project** - Algorithm standards

- **OpenSSL Project** - TLS implementation foundation### 2. **Network Overhead**: Classical Wins 📶



---- **3.8× more bandwidth** required for PQ-TLS

- Primarily due to larger signatures (9.5× bigger)

**Note**: This implementation uses self-signed certificates for testing. For production use, obtain certificates from a trusted Certificate Authority.- Impact depends on network conditions:

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

- [ ] **Algorithm Variants**: Test Kyber-512, Dilithium3, Falcon, etc.
- [ ] **Network Simulation**: Test over various latency/bandwidth conditions
- [ ] **Integration**: OpenSSL OQS provider integration

## References

### Libraries
- [OpenSSL](https://www.openssl.org/)
- [liboqs - Open Quantum Safe](https://github.com/open-quantum-safe/liboqs)
- [OQS-OpenSSL Provider](https://github.com/open-quantum-safe/oqs-provider)

### Standards
- [NIST Post-Quantum Cryptography Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [FIPS 203: ML-KEM (Kyber)](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204: ML-DSA (Dilithium)](https://csrc.nist.gov/pubs/fips/204/final)
- [RFC 8446: TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446)

## License

Research/Educational implementation for TLS performance analysis.

