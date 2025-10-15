#ifndef PERFORMANCE_H
#define PERFORMANCE_H

#include <stdint.h>
#include <stddef.h>
#include <sys/time.h>

// Simplified performance metrics structure - only essential metrics
typedef struct {
    // Timing measurements (in microseconds)
    uint64_t handshake_start_us;
    uint64_t handshake_end_us;
    uint64_t handshake_duration_us;  // Total handshake time
    
    uint64_t signature_time_us;      // Signing time (server)
    uint64_t verify_time_us;         // Verification time (client)
    
    // Cryptographic sizes
    size_t signature_size;           // Signature size
    size_t certificate_size;         // Certificate size
    
    // Algorithm information (for reference)
    char cipher_suite[128];
    char protocol_version[16];
} performance_metrics_t;

// Timing utilities
uint64_t get_time_microseconds(void);
double microseconds_to_milliseconds(uint64_t us);

// Performance tracking functions
void perf_init(performance_metrics_t *metrics);
void perf_start_handshake(performance_metrics_t *metrics);
void perf_end_handshake(performance_metrics_t *metrics);
void perf_print_summary(const performance_metrics_t *metrics);
void perf_save_to_csv(const performance_metrics_t *metrics, const char *filename);

#endif // PERFORMANCE_H
