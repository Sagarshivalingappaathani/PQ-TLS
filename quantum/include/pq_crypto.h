#ifndef PQ_CRYPTO_H
#define PQ_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

// Kyber-768 (ML-KEM-768) constants
#define KYBER_PUBLIC_KEY_BYTES    1184
#define KYBER_SECRET_KEY_BYTES    2400
#define KYBER_CIPHERTEXT_BYTES    1088
#define KYBER_SHARED_SECRET_BYTES 32

// Dilithium2 (ML-DSA-44) constants  
#define DILITHIUM_PUBLIC_KEY_BYTES  1312
#define DILITHIUM_SECRET_KEY_BYTES  2560
#define DILITHIUM_SIGNATURE_BYTES   2420

// Kyber (ML-KEM) functions
int pq_kyber_keypair(uint8_t *pk, uint8_t *sk);
int pq_kyber_encapsulate(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int pq_kyber_decapsulate(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

// Dilithium (ML-DSA) functions
int pq_dilithium_keypair(uint8_t *pk, uint8_t *sk);
int pq_dilithium_sign(uint8_t *sig, size_t *sig_len, const uint8_t *msg, 
                      size_t msg_len, const uint8_t *sk);
int pq_dilithium_verify(const uint8_t *sig, size_t sig_len, const uint8_t *msg,
                        size_t msg_len, const uint8_t *pk);

#endif // PQ_CRYPTO_H
