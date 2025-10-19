# Post-Quantum TLS 1.3 Implementation & Comparison

A comprehensive implementation comparing **classical cryptography** (RSA-2048 + X25519) with **post-quantum cryptography** (Dilithium-3 + Kyber-768) in TLS 1.3. This project demonstrates the security benefits and performance trade-offs of quantum-resistant algorithms.

## 🎯 Project Overview

This repository contains two parallel TLS 1.3 implementations:

1. **classic-fork** - Traditional cryptography baseline (X25519 + RSA-2048)
2. **quantum-fork** - Post-quantum secure implementation (Kyber-768 + Dilithium-3)

Both implementations support **network testing** between client and server on different machines, allowing real-world performance analysis.

## 🔐 Why Post-Quantum Cryptography?

### The Quantum Threat

Current public-key cryptography (RSA, ECDH) is vulnerable to attacks from quantum computers:

- **Shor's Algorithm** - Breaks RSA factoring and elliptic curve discrete logarithm in polynomial time
- **Store Now, Decrypt Later** - Adversaries can capture encrypted traffic today and decrypt it when quantum computers become available

### The Solution

Post-quantum cryptography uses mathematical problems that are hard even for quantum computers:

- **Kyber-768** - Lattice-based key exchange (Module-LWE)
- **Dilithium-3** - Lattice-based digital signatures (Module-LWE)

Both are **NIST Level 3** algorithms (equivalent to AES-192 security) and selected by NIST for standardization.

## 📂 Repository Structure

```
TLS/
├── classic-fork/           # Traditional TLS 1.3 implementation
│   ├── src/               # Client, server, performance tracking
│   ├── certs/             # RSA-2048 certificates
│   ├── results/           # Performance CSV outputs
│   ├── Makefile           # Build configuration
│   └── README.md          # Classical TLS documentation
│
├── quantum-fork/          # Post-quantum TLS 1.3 implementation
│   ├── src/               # PQ client, server, performance tracking
│   ├── certs/             # Dilithium-3 certificates
│   ├── results/           # Performance CSV outputs
│   ├── Makefile           # Build configuration
│   ├── generate_dilithium_certs.sh  # Certificate generation script
│   └── README.md          # Post-quantum TLS documentation
│
├── vendor/                # Shared dependencies (build locally)
│   ├── openssl-oqs/       # OpenSSL with OQS support
│   └── liboqs/            # Post-quantum algorithm library
│
├── .gitignore             # Excludes vendor/ from git
└── README.md              # This file
```

## 🔒 Cryptographic Comparison

| Component | Classic-Fork | Quantum-Fork | Quantum Safe? |
|-----------|-------------|--------------|---------------|
| **Key Exchange** | X25519 (ECDH) | **Kyber-768** (Lattice) | ❌ → ✅ |
| **Signatures** | RSA-2048 | **Dilithium-3** (Lattice) | ❌ → ✅ |
| **Cipher** | AES-128-GCM | AES-128-GCM | ⚠️ (Grover) |
| **Hash** | SHA-256 | SHA-256 | ✅ |
| **TLS Version** | 1.3 | 1.3 | ✅ |
| **Security Level** | ~128-bit classical | ~192-bit quantum | - |

### Algorithm Sizes

| Metric | RSA-2048 | Dilithium-3 | Increase |
|--------|----------|-------------|----------|
| **Public Key** | ~256 bytes | ~1,952 bytes | **+664%** |
| **Signature** | ~256 bytes | ~3,293 bytes | **+1186%** |
| **Certificate** | ~935 bytes | ~5,610 bytes | **+500%** |

| Metric | X25519 | Kyber-768 | Increase |
|--------|--------|-----------|----------|
| **Public Key** | 32 bytes | ~1,184 bytes | **+3600%** |
| **Ciphertext** | - | ~1,088 bytes | - |

## 📊 Performance Comparison

### Handshake Latency

| Implementation | Server Handshake | Client Handshake | Overhead |
|----------------|------------------|------------------|----------|
| **Classic-Fork** | ~10.70 ms | ~10.54 ms | Baseline |
| **Quantum-Fork** | ~12.21 ms | ~12.78 ms | **+14-21%** |

### Cryptographic Operations

| Operation | Classical | Post-Quantum | Difference |
|-----------|-----------|--------------|------------|
| **Signing** | 2.71 ms (RSA) | **0.64 ms** (Dilithium) | **76% faster** ✅ |
| **Verification** | 0.16 ms (RSA) | 0.27 ms (Dilithium) | +69% |

### Network Bandwidth Impact

| Component | Classical | Post-Quantum | Overhead |
|-----------|-----------|--------------|----------|
| **Certificate** | 935 B | 5,610 B | **+4,675 B** |
| **ServerHello** | ~300 B | ~1,178 B | **+878 B** |
| **CertificateVerify** | 264 B | 3,301 B | **+3,037 B** |

**Total handshake overhead:** ~8-9 KB additional data transfer for post-quantum security.

## 🚀 Getting Started

### Prerequisites

Before building, ensure you have:

- **GCC** - C compiler (tested with gcc 11.4+)
- **GNU Make** - Build automation
- **Git** - Version control
- **CMake** - For liboqs build (>= 3.12)

### 1. Clone Repository

```bash
git clone https://github.com/Sagarshivalingappaathani/PQ-TLS.git
cd PQ-TLS/TLS
```

### 2. Build Dependencies

The `vendor/` directory is **not included in git** due to size. You must build the dependencies locally:

#### Build liboqs (Post-Quantum Algorithms Library)

```bash
cd vendor
git clone --branch 0.10.1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=ON ..
make -j$(nproc)
sudo make install
sudo ldconfig
cd ../../..
```

#### Build OpenSSL-OQS (OpenSSL with PQ Support)

```bash
cd vendor
git clone --branch OQS-OpenSSL_1_1_1-stable https://github.com/open-quantum-safe/openssl.git openssl-oqs
cd openssl-oqs
./Configure no-shared linux-x86_64 -lm
make -j$(nproc)
cd ../..
```

Verify the build:
```bash
./vendor/openssl-oqs/apps/openssl version
# Expected: OpenSSL 1.1.1u  30 May 2023
```

**Build time:** ~5-10 minutes on modern hardware.

### 3. Build Classic-Fork (Traditional TLS)

```bash
cd classic-fork
make clean && make
```

**Generate RSA Certificates:**
```bash
./generate_certs.sh
```

**Run Server:**
```bash
./build/tls_server
```

**Run Client (different terminal):**
```bash
./build/tls_client
```

### 4. Build Quantum-Fork (Post-Quantum TLS)

```bash
cd ../quantum-fork
make clean && make
```

**Generate Dilithium Certificates:**
```bash
./generate_dilithium_certs.sh
```

This generates:
- `certs/ca-cert-dilithium3-real.pem` (7.6 KB)
- `certs/server-cert-dilithium3-real.pem` (7.5 KB)

**Run Server:**
```bash
./build/tls_server
```

**Run Client (different terminal):**
```bash
./build/tls_client
```

## 🌐 Network Testing Between Machines

Both implementations support testing between different machines (e.g., you = client, friend = server).

### Server Setup (Friend's Machine)

1. **Build the project** (follow steps above)

2. **Configure IP Address:**
   ```bash
   cd quantum-fork
   # Edit generate_dilithium_certs.sh and set:
   FRIEND_IP="<friend's actual IP address>"
   ```

3. **Generate certificates with correct IP:**
   ```bash
   ./generate_dilithium_certs.sh
   ```
   
   Verify IP in certificate:
   ```bash
   ../vendor/openssl-oqs/apps/openssl x509 -in certs/server-cert-dilithium3-real.pem -text -noout | grep "IP Address"
   # Should show: IP Address:10.50.42.188 (or your friend's IP)
   ```

4. **Run server:**
   ```bash
   ./build/tls_server
   # Server listens on 0.0.0.0:4433
   ```

### Client Setup (Your Machine)

1. **Get certificates from server machine:**
   
   Option 1 - Clone from GitHub (if certs are pushed):
   ```bash
   git pull origin main
   ```
   
   Option 2 - Use certificate archive:
   ```bash
   # Friend sends you quantum-certs.zip
   cd quantum-fork
   unzip -o quantum-certs.zip
   ```

2. **Update client code with server IP:**
   ```c
   // In src/client.c, modify:
   #define SERVER_IP "10.50.42.188"  // Friend's IP
   #define SERVER_PORT 4433
   ```

3. **Rebuild and run:**
   ```bash
   make clean && make
   ./build/tls_client
   ```

### Expected Output (Successful PQ Handshake)

**Server:**
```
╔════════════════════════════════════════╗
║   Post-Quantum TLS 1.3 Server         ║
╚════════════════════════════════════════╝

✓ Key Exchange Algorithm: kyber768
✓ Signature Algorithm: dilithium3

--- Key Metrics ---
1. Total Handshake Time:  12.21 ms
2. Signing Time:          0.64 ms
4. Signature Size:        3293 bytes
5. Certificate Size:      5610 bytes
```

**Client:**
```
╔════════════════════════════════════════╗
║   Post-Quantum TLS 1.3 Client         ║
╚════════════════════════════════════════╝

✓ Key Exchange Algorithm: kyber768
✓ Signature Algorithm: dilithium3

--- Key Metrics ---
1. Total Handshake Time:  12.78 ms
3. Verification Time:     0.27 ms
4. Signature Size:        3293 bytes
5. Certificate Size:      5624 bytes
```

### Troubleshooting Network Issues

**Error: IP address mismatch (Error 64)**
- Certificate SAN doesn't match server IP
- Regenerate certificates with correct `FRIEND_IP`
- Verify IP with: `openssl x509 -text | grep "IP Address"`

**Error: Connection refused**
- Check firewall allows port 4433
- Verify server is listening: `netstat -tuln | grep 4433`

**Error: Certificate verification failed**
- Ensure client has latest CA certificate
- Check certificate dates: `openssl x509 -dates`

## 📁 Output Files

Both implementations export performance data to CSV:

**Classic-Fork:**
```
classic-fork/results/tls_client_performance.csv
classic-fork/results/tls_server_performance.csv
```

**Quantum-Fork:**
```
quantum-fork/results/tls_client_performance.csv
quantum-fork/results/tls_server_performance.csv
```

### CSV Format

```csv
protocol,cipher_suite,handshake_ms,signing_ms,verification_ms,signature_bytes,certificate_bytes
TLSv1.3,TLS_AES_128_GCM_SHA256,12.78,0.00,0.27,3293,5624
```

## 🔐 Security Considerations

### Post-Quantum Security

✅ **Protected Against:**
- Shor's algorithm (factoring RSA, discrete log for ECDH)
- Store-now-decrypt-later attacks
- Future quantum computers

⚠️ **Partially Protected:**
- AES-128-GCM security reduced from 128-bit to ~64-bit by Grover's algorithm
- Consider upgrading to AES-256-GCM for full quantum resistance

### Classical Cryptography Risks

❌ **Classic-Fork Vulnerabilities:**
- RSA-2048 will be broken by sufficiently large quantum computers
- X25519 ECDH will be broken by Shor's algorithm
- Traffic captured today can be decrypted in 10-20 years

### Certificate Security

⚠️ **Important:** Private keys are included in this repository for **educational/testing purposes only**.

**For production use:**
- Generate new certificates with secure private keys
- Store private keys in hardware security modules (HSMs)
- Use proper certificate rotation policies
- Remove IP addresses from SAN if not needed

## 📚 References & Resources

### Standards & Specifications

- **NIST Post-Quantum Cryptography:** [csrc.nist.gov/projects/post-quantum-cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- **TLS 1.3 RFC 8446:** [datatracker.ietf.org/doc/html/rfc8446](https://datatracker.ietf.org/doc/html/rfc8446)
- **NIST PQC Selected Algorithms (2022):** Kyber (ML-KEM) and Dilithium (ML-DSA)

### Algorithm Documentation

- **Kyber (CRYSTALS-Kyber):** [pq-crystals.org/kyber](https://pq-crystals.org/kyber/)
- **Dilithium (CRYSTALS-Dilithium):** [pq-crystals.org/dilithium](https://pq-crystals.org/dilithium/)
- **Kyber Specification:** NIST Round 3 Finalist (Selected for ML-KEM)
- **Dilithium Specification:** NIST Round 3 Finalist (Selected for ML-DSA)

### Libraries & Tools

- **Open Quantum Safe (OQS):** [openquantumsafe.org](https://openquantumsafe.org/)
- **liboqs:** [github.com/open-quantum-safe/liboqs](https://github.com/open-quantum-safe/liboqs)
- **OQS-OpenSSL:** [github.com/open-quantum-safe/openssl](https://github.com/open-quantum-safe/openssl)

## 🛠️ Development

### Modifying Algorithms

**Classic-Fork** (`classic-fork/src/client.c` and `server.c`):
```c
// Key Exchange
SSL_CTX_set1_groups_list(ctx, "X25519:prime256v1");

// Signatures
SSL_CTX_set1_sigalgs_list(ctx, "RSA-PSS+SHA256:ECDSA+SHA256");
```

**Quantum-Fork** (`quantum-fork/src/client.c` and `server.c`):
```c
// Key Exchange: Kyber preferred, fallback to X25519
SSL_CTX_set1_groups_list(ctx, "kyber768:kyber512:X25519");

// Signatures: Dilithium preferred, fallback to RSA
SSL_CTX_set1_sigalgs_list(ctx, "dilithium3:dilithium2:RSA-PSS+SHA256");
```

### Performance Tracking

Both implementations track:
1. **Total Handshake Time** - End-to-end TLS handshake duration
2. **Signing Time** - Server signature generation
3. **Verification Time** - Client signature verification
4. **Signature Size** - Bytes in CertificateVerify message
5. **Certificate Size** - X.509 certificate total size

Data is exported to CSV for analysis and comparison.

## 📄 License

This project is for **educational and research purposes**.

**Third-party libraries:**
- OpenSSL: Apache License 2.0
- liboqs: MIT License
- NIST PQC Algorithms: Public domain (reference implementations)

## 🤝 Contributing

This is a research/educational project. Feel free to:

- Report issues or bugs
- Suggest performance improvements
- Add new post-quantum algorithms
- Improve documentation

## 📧 Contact

**Repository:** [github.com/Sagarshivalingappaathani/PQ-TLS](https://github.com/Sagarshivalingappaathani/PQ-TLS)

---

**Last Updated:** October 15, 2025  
**OpenSSL Version:** OQS-OpenSSL_1_1_1-stable  
**liboqs Version:** 0.10.1  
**Algorithms:** Kyber-768, Dilithium-3 (NIST PQC Selected Algorithms)
