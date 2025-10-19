# Quantum-Fork: Post-Quantum TLS 1.3 Implementation

A post-quantum secure implementation of TLS 1.3 using **Kyber-768** for key exchange and **Dilithium-3** for digital signatures. This implementation is resistant to attacks from both classical and quantum computers.

## 🎯 Purpose

This implementation demonstrates **post-quantum cryptography** in TLS 1.3, providing security against future quantum computer attacks. It serves as a direct performance comparison with classical cryptography (see **classic-fork**).

## 🔒 Cryptographic Algorithms

| Component | Algorithm | Security Level |
|-----------|-----------|----------------|
| **Key Exchange** | **Kyber-768** | NIST Level 3 (~192-bit quantum) |
| **Signatures** | **Dilithium-3** | NIST Level 3 (~192-bit quantum) |
| **Cipher** | AES-128-GCM | 128-bit symmetric |
| **Hash** | SHA-256 | 256-bit |
| **TLS Version** | 1.3 | Latest |

### Algorithm Details

#### Kyber-768 (Key Encapsulation Mechanism)
- **Public Key:** ~1,184 bytes
- **Ciphertext:** ~1,088 bytes
- **Shared Secret:** 32 bytes
- **Security:** NIST Level 3 (equivalent to AES-192)
- **Type:** Lattice-based (Module-LWE)

#### Dilithium-3 (Digital Signature)
- **Public Key:** ~1,952 bytes
- **Signature:** ~3,293 bytes
- **Security:** NIST Level 3 (equivalent to AES-192)
- **Type:** Lattice-based (Module-LWE)

## 📊 Performance Metrics

The implementation tracks **5 key metrics** for comparison with classical TLS:

1. **Total Handshake Time** - Complete TLS handshake duration (milliseconds)
2. **Signing Time** - Server Dilithium signature generation (milliseconds)
3. **Verification Time** - Client Dilithium signature verification (milliseconds)
4. **Signature Size** - CertificateVerify message size (bytes)
5. **Certificate Size** - X.509 certificate with Dilithium public key (bytes)

## 🚀 Quick Start

### Prerequisites

- GCC compiler
- OpenSSL 1.1.1 with OQS support (installed in `../vendor/`)
- liboqs 0.10.1 with Kyber and Dilithium (installed in `../vendor/`)

### Build

```bash
make clean
make
```

Compiles both client and server with post-quantum algorithm support.

### Generate Post-Quantum Certificates

```bash
gcc -o generate_dilithium_cert generate_dilithium_cert.c \
    -I../vendor/openssl-oqs-install/include \
    ../vendor/openssl-oqs-install/lib/libssl.a \
    ../vendor/openssl-oqs-install/lib/libcrypto.a \
    ../vendor/openssl-oqs-install/lib/liboqs.a \
    -lpthread -ldl

./generate_dilithium_cert
```

Generates Dilithium-3 based certificates.

### Run Server

```bash
./build/tls_server
```

Server listens on `0.0.0.0:4433` and uses Dilithium certificates.

### Run Client

```bash
./build/tls_client
```

Client connects to `localhost:4433` and negotiates post-quantum algorithms.

## 📈 Performance Comparison

Server Side

| Metric | Value |
|--------|-------|
| Handshake Time (Server) | ~12.21 ms |
| Signing Time | ~0.64 ms |
| Verification Time | ~0.00 ms |
| Signature Size | 3293 bytes |
| Certificate Size | 5610 bytes |

Client Side

| Metric | Value |
|--------|-------|
| Handshake Time (Client) | ~12.78 ms |
| Signing Time | ~0.00 ms |
| Verification Time | ~0.27 ms |
| Signature Size | 3293 bytes |
| Certificate Size | 5610 bytes |

### Post-Quantum vs Classical TLS

| Metric | Classical | Post-Quantum | Difference |
|--------|-----------|--------------|------------|
| Handshake Time (Server) | 10.70 ms | 12.21 ms | **+14%** ⚠️ |
| Handshake Time (Client) | 10.54 ms | 12.78 ms | **+21%** ⚠️ |
| Signing Time | 2.71 ms | **0.64 ms** | **76% faster** ✅ |
| Verification Time | 0.16 ms | 0.27 ms | **+69%** ⚠️ |
| Signature Size | 256 B | **3,293 B** | **+1186%** 🔴 |
| Certificate Size | 935 B | **5,610 B** | **+500%** 🔴 |


## 🔐 Security Analysis

### Quantum Resistance

| Algorithm | Classical Security | Quantum Security |
|-----------|-------------------|------------------|
| **Kyber-768** | NIST Level 3 | ✅ **Secure** |
| **Dilithium-3** | NIST Level 3 | ✅ **Secure** |
| AES-128-GCM | 128-bit | ⚠️ ~64-bit (Grover) |

### Attack Resistance

| Attack Vector | Classical TLS | Quantum-Fork |
|---------------|---------------|--------------|
| **Store Now, Decrypt Later** | ❌ Vulnerable | ✅ Protected |
| **Shor's Algorithm (Factoring)** | ❌ Breaks RSA | ✅ Not applicable |
| **Shor's Algorithm (DLP)** | ❌ Breaks ECDH | ✅ Not applicable |
| **Grover's Algorithm** | ⚠️ Halves security | ⚠️ Halves security |

## 📝 Output Format

### Console Output Example

```
╔════════════════════════════════════════╗
║   Post-Quantum TLS 1.3 Client         ║
╚════════════════════════════════════════╝

✓ Key Exchange Algorithm: kyber768
✓ Signature Algorithm: dilithium3

--- Key Metrics ---
1. Total Handshake Time:  2.69 ms
3. Verification Time:     0.26 ms
4. Signature Size:        3293 bytes
5. Certificate Size:      5624 bytes
```

### CSV Export

```csv
protocol,cipher_suite,handshake_ms,signing_ms,verification_ms,signature_bytes,certificate_bytes
TLSv1.3,TLS_AES_128_GCM_SHA256,2.69,0.00,0.26,3293,5624
```

## 🔧 Configuration

### Algorithm Preferences

```c
// Key Exchange: Kyber-768 preferred, fallback to Kyber-512, then X25519
SSL_CTX_set1_groups_list(ctx, "kyber768:kyber512:X25519");

// Signatures: Dilithium-3 preferred, fallback to Dilithium-2, then RSA
SSL_CTX_set1_sigalgs_list(ctx, "dilithium3:dilithium2:RSA-PSS+SHA256");
```

## 🧪 Testing & Validation

### Quick Test

```bash
# Terminal 1: Start server
./build/tls_server

# Terminal 2: Run client
./build/tls_client
```

### Verify Post-Quantum Algorithms

Look for these indicators:

✅ **Key Exchange:**
```
✓ Key Exchange Algorithm: kyber768
```

✅ **Signatures:**
```
Signature Size: 3293 bytes  (vs 256 bytes for RSA)
Certificate Size: 5624 bytes  (vs 927 bytes for RSA)
```

## 📚 References

- **NIST PQC:** [csrc.nist.gov/projects/post-quantum-cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- **Kyber:** [pq-crystals.org/kyber](https://pq-crystals.org/kyber/)
- **Dilithium:** [pq-crystals.org/dilithium](https://pq-crystals.org/dilithium/)
- **Open Quantum Safe:** [openquantumsafe.org](https://openquantumsafe.org/)

## 🔗 Related

- **classic-fork** - Classical TLS 1.3 for performance baseline
- **QUANTUM_STATUS.md** - Detailed implementation status

## 📄 License

Educational and research use.

---

**Last Updated:** October 15, 2025  
**OpenSSL Version:** OQS-OpenSSL_1_1_1-stable  
**liboqs Version:** 0.10.1  
**Kyber:** NIST Round 3 Finalist (Selected for Standardization)  
**Dilithium:** NIST Round 3 Finalist (Selected for Standardization)