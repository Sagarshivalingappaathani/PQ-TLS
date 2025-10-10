#ifndef PQ_PERFORMANCE_H
#define PQ_PERFORMANCE_H

#include <stdint.h>
#include <stddef.h>
#include <sys/time.h>

// Performance metrics structure for Post-Quantum TLS
typedef struct {
    char protocol[32];
    char cipher_suite[128];
    char kem_algorithm[64];
    char sig_algorithm[64];
    
    // Handshake timing
    uint64_t handshake_duration_us;
    
    // KEM (Key Encapsulation Mechanism) timing
    uint64_t kem_keygen_time_us;      // Client: Kyber keypair generation
    uint64_t kem_encaps_time_us;      // Server: Kyber encapsulation
    uint64_t kem_decaps_time_us;      // Client: Kyber decapsulation
    
    // Signature timing
    uint64_t signature_time_us;       // Server: Dilithium sign
    uint64_t verify_time_us;          // Client: Dilithium verify
    
    // Network overhead
    size_t bytes_sent;
    size_t bytes_received;
    
    // Crypto sizes
    size_t kem_public_key_size;
    size_t kem_ciphertext_size;
    size_t sig_public_key_size;
    size_t signature_size;
    
    // System resources
    size_t memory_kb;
} pq_performance_metrics_t;

// Helper functions
void pq_perf_init(pq_performance_metrics_t *metrics);
void pq_perf_start_handshake(pq_performance_metrics_t *metrics);
void pq_perf_end_handshake(pq_performance_metrics_t *metrics);
void pq_perf_print_summary(const pq_performance_metrics_t *metrics);
int pq_perf_save_to_csv(const pq_performance_metrics_t *metrics, const char *filepath);
uint64_t pq_get_time_us(void);
double pq_microseconds_to_milliseconds(uint64_t us);

#endif // PQ_PERFORMANCE_H
