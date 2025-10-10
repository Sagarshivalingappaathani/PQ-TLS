#include "pq_crypto.h"
#include <oqs/oqs.h>
#include <string.h>
#include <stdio.h>

// Kyber-768 (ML-KEM-768) wrapper functions
int pq_kyber_keypair(uint8_t *pk, uint8_t *sk) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (kem == NULL) {
        fprintf(stderr, "ERROR: OQS_KEM_new failed for ML-KEM-768\n");
        return -1;
    }
    
    OQS_STATUS status = OQS_KEM_keypair(kem, pk, sk);
    OQS_KEM_free(kem);
    
    return (status == OQS_SUCCESS) ? 0 : -1;
}

int pq_kyber_encapsulate(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (kem == NULL) {
        fprintf(stderr, "ERROR: OQS_KEM_new failed for ML-KEM-768\n");
        return -1;
    }
    
    OQS_STATUS status = OQS_KEM_encaps(kem, ct, ss, pk);
    OQS_KEM_free(kem);
    
    return (status == OQS_SUCCESS) ? 0 : -1;
}

int pq_kyber_decapsulate(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (kem == NULL) {
        fprintf(stderr, "ERROR: OQS_KEM_new failed for ML-KEM-768\n");
        return -1;
    }
    
    OQS_STATUS status = OQS_KEM_decaps(kem, ss, ct, sk);
    OQS_KEM_free(kem);
    
    return (status == OQS_SUCCESS) ? 0 : -1;
}

// Dilithium2 (ML-DSA-44) wrapper functions
int pq_dilithium_keypair(uint8_t *pk, uint8_t *sk) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
    if (sig == NULL) {
        fprintf(stderr, "ERROR: OQS_SIG_new failed for ML-DSA-44\n");
        return -1;
    }
    
    OQS_STATUS status = OQS_SIG_keypair(sig, pk, sk);
    OQS_SIG_free(sig);
    
    return (status == OQS_SUCCESS) ? 0 : -1;
}

int pq_dilithium_sign(uint8_t *sig_out, size_t *sig_len, const uint8_t *msg, 
                      size_t msg_len, const uint8_t *sk) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
    if (sig == NULL) {
        fprintf(stderr, "ERROR: OQS_SIG_new failed for ML-DSA-44\n");
        return -1;
    }
    
    OQS_STATUS status = OQS_SIG_sign(sig, sig_out, sig_len, msg, msg_len, sk);
    OQS_SIG_free(sig);
    
    return (status == OQS_SUCCESS) ? 0 : -1;
}

int pq_dilithium_verify(const uint8_t *sig_in, size_t sig_len, const uint8_t *msg,
                        size_t msg_len, const uint8_t *pk) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_44);
    if (sig == NULL) {
        fprintf(stderr, "ERROR: OQS_SIG_new failed for ML-DSA-44\n");
        return -1;
    }
    
    OQS_STATUS status = OQS_SIG_verify(sig, msg, msg_len, sig_in, sig_len, pk);
    OQS_SIG_free(sig);
    
    return (status == OQS_SUCCESS) ? 0 : -1;
}
