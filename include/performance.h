#ifndef PERFORMANCE_H
#define PERFORMANCE_H

#include <stdint.h>
#include <stddef.h>
#include <sys/time.h>

// Performance metrics structure
typedef struct {
    // Timing measurements (in microseconds)
    uint64_t handshake_start_us;
    uint64_t handshake_end_us;
    uint64_t handshake_duration_us;
    
    uint64_t key_gen_time_us;
    uint64_t key_exchange_time_us;
    uint64_t signature_time_us;
    uint64_t verify_time_us;
    uint64_t encryption_time_us;
    uint64_t decryption_time_us;
    
    // Network measurements
    size_t bytes_sent;
    size_t bytes_received;
    size_t handshake_bytes_sent;
    size_t handshake_bytes_received;
    
    // Cryptographic sizes
    size_t public_key_size;
    size_t private_key_size;
    size_t signature_size;
    size_t certificate_size;
    size_t session_ticket_size;
    
    // System resources
    size_t memory_usage_kb;
    double cpu_usage_percent;
    
    // Algorithm information
    char cipher_suite[128];
    char key_exchange_algorithm[64];
    char signature_algorithm[64];
    char encryption_algorithm[64];
    
    // Connection information
    char protocol_version[16];
    int connection_id;
    int is_resumption;
} performance_metrics_t;

// Timing utilities
uint64_t get_time_microseconds(void);
double microseconds_to_milliseconds(uint64_t us);
double microseconds_to_seconds(uint64_t us);

// Performance tracking functions
void perf_init(performance_metrics_t *metrics);
void perf_start_handshake(performance_metrics_t *metrics);
void perf_end_handshake(performance_metrics_t *metrics);
void perf_record_bytes(performance_metrics_t *metrics, size_t sent, size_t received);
void perf_print_summary(const performance_metrics_t *metrics);
void perf_save_to_csv(const performance_metrics_t *metrics, const char *filename);
void perf_save_to_json(const performance_metrics_t *metrics, const char *filename);

// Memory tracking
size_t get_memory_usage_kb(void);
double get_cpu_usage_percent(void);

#endif // PERFORMANCE_H