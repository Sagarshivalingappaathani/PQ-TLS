#include "performance.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Get current time in microseconds
uint64_t get_time_microseconds(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000 + (uint64_t)tv.tv_usec;
}

// Convert microseconds to milliseconds
double microseconds_to_milliseconds(uint64_t us) {
    return (double)us / 1000.0;
}

// Initialize performance metrics
void perf_init(performance_metrics_t *metrics) {
    if (!metrics) return;
    memset(metrics, 0, sizeof(performance_metrics_t));
    strcpy(metrics->protocol_version, "TLSv1.3");
}

// Start handshake timing
void perf_start_handshake(performance_metrics_t *metrics) {
    if (!metrics) return;
    metrics->handshake_start_us = get_time_microseconds();
}

// End handshake timing
void perf_end_handshake(performance_metrics_t *metrics) {
    if (!metrics) return;
    metrics->handshake_end_us = get_time_microseconds();
    metrics->handshake_duration_us = metrics->handshake_end_us - metrics->handshake_start_us;
}

// Print performance summary - only the 5 essential metrics
void perf_print_summary(const performance_metrics_t *metrics) {
    if (!metrics) return;
    
    printf("\n╔════════════════════════════════════════╗\n");
    printf("║     TLS Performance Metrics           ║\n");
    printf("╚════════════════════════════════════════╝\n\n");
    
    printf("Protocol: %s\n", metrics->protocol_version);
    printf("Cipher Suite: %s\n\n", metrics->cipher_suite);
    
    printf("--- Key Metrics ---\n");
    printf("1. Total Handshake Time:  %.2f ms\n", 
           microseconds_to_milliseconds(metrics->handshake_duration_us));
    
    if (metrics->signature_time_us > 0) {
        printf("2. Signing Time:          %.2f ms\n", 
               microseconds_to_milliseconds(metrics->signature_time_us));
    }
    
    if (metrics->verify_time_us > 0) {
        printf("3. Verification Time:     %.2f ms\n", 
               microseconds_to_milliseconds(metrics->verify_time_us));
    }
    
    printf("4. Signature Size:        %zu bytes\n", metrics->signature_size);
    printf("5. Certificate Size:      %zu bytes\n", metrics->certificate_size);
    
    printf("═══════════════════════════════════════\n\n");
}

// Save metrics to CSV - only the 5 essential metrics
void perf_save_to_csv(const performance_metrics_t *metrics, const char *filename) {
    if (!metrics || !filename) return;
    
    FILE *fp = fopen(filename, "a");
    if (!fp) {
        perror("Failed to open CSV file");
        return;
    }
    
    // Check if file is empty (write header)
    fseek(fp, 0, SEEK_END);
    if (ftell(fp) == 0) {
        fprintf(fp, "protocol,cipher_suite,handshake_ms,signing_ms,verification_ms,signature_bytes,certificate_bytes\n");
    }
    
    fprintf(fp, "%s,%s,%.2f,%.2f,%.2f,%zu,%zu\n",
            metrics->protocol_version,
            metrics->cipher_suite,
            microseconds_to_milliseconds(metrics->handshake_duration_us),
            microseconds_to_milliseconds(metrics->signature_time_us),
            microseconds_to_milliseconds(metrics->verify_time_us),
            metrics->signature_size,
            metrics->certificate_size);
    
    fclose(fp);
}
