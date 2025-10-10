#include "pq_performance.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/resource.h>

// Color codes for output
#define COLOR_RESET   "\033[0m"
#define COLOR_BOLD    "\033[1m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_CYAN    "\033[36m"

uint64_t pq_get_time_us(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

double pq_microseconds_to_milliseconds(uint64_t us) {
    return (double)us / 1000.0;
}

void pq_perf_init(pq_performance_metrics_t *metrics) {
    memset(metrics, 0, sizeof(pq_performance_metrics_t));
    strncpy(metrics->protocol, "PQ-TLS-1.3", sizeof(metrics->protocol) - 1);
    strncpy(metrics->cipher_suite, "AES_128_GCM_SHA256", sizeof(metrics->cipher_suite) - 1);
    strncpy(metrics->kem_algorithm, "ML-KEM-768 (Kyber)", sizeof(metrics->kem_algorithm) - 1);
    strncpy(metrics->sig_algorithm, "ML-DSA-44 (Dilithium2)", sizeof(metrics->sig_algorithm) - 1);
}

void pq_perf_start_handshake(pq_performance_metrics_t *metrics) {
    metrics->handshake_duration_us = pq_get_time_us();
}

void pq_perf_end_handshake(pq_performance_metrics_t *metrics) {
    uint64_t end = pq_get_time_us();
    metrics->handshake_duration_us = end - metrics->handshake_duration_us;
    
    // Get memory usage
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
    metrics->memory_kb = usage.ru_maxrss;
}

void pq_perf_print_summary(const pq_performance_metrics_t *metrics) {
    printf("\n");
    printf(COLOR_BOLD COLOR_CYAN "╔═══════════════════════════════════════════════════════════════╗\n" COLOR_RESET);
    printf(COLOR_BOLD COLOR_CYAN "║         POST-QUANTUM TLS PERFORMANCE SUMMARY                  ║\n" COLOR_RESET);
    printf(COLOR_BOLD COLOR_CYAN "╚═══════════════════════════════════════════════════════════════╝\n" COLOR_RESET);
    printf("\n");
    
    printf(COLOR_BOLD "Protocol:\n" COLOR_RESET);
    printf("  • Version:     %s\n", metrics->protocol);
    printf("  • Cipher:      %s\n", metrics->cipher_suite);
    printf("  • KEM:         %s\n", metrics->kem_algorithm);
    printf("  • Signature:   %s\n", metrics->sig_algorithm);
    printf("\n");
    
    printf(COLOR_BOLD COLOR_GREEN "Handshake Performance:\n" COLOR_RESET);
    printf("  • Total Time:  %.2f ms\n", pq_microseconds_to_milliseconds(metrics->handshake_duration_us));
    printf("\n");
    
    printf(COLOR_BOLD COLOR_YELLOW "Key Encapsulation Mechanism (KEM) Timing:\n" COLOR_RESET);
    if (metrics->kem_keygen_time_us > 0) {
        printf("  • Keypair Gen: %.2f ms\n", pq_microseconds_to_milliseconds(metrics->kem_keygen_time_us));
    }
    if (metrics->kem_encaps_time_us > 0) {
        printf("  • Encapsulate: %.2f ms\n", pq_microseconds_to_milliseconds(metrics->kem_encaps_time_us));
    }
    if (metrics->kem_decaps_time_us > 0) {
        printf("  • Decapsulate: %.2f ms\n", pq_microseconds_to_milliseconds(metrics->kem_decaps_time_us));
    }
    printf("\n");
    
    printf(COLOR_BOLD COLOR_YELLOW "Digital Signature Timing:\n" COLOR_RESET);
    if (metrics->signature_time_us > 0) {
        printf("  • Signature:   %.2f ms\n", pq_microseconds_to_milliseconds(metrics->signature_time_us));
    }
    if (metrics->verify_time_us > 0) {
        printf("  • Verify:      %.2f ms\n", pq_microseconds_to_milliseconds(metrics->verify_time_us));
    }
    printf("\n");
    
    printf(COLOR_BOLD "Network Overhead:\n" COLOR_RESET);
    printf("  • Bytes Sent:     %zu bytes\n", metrics->bytes_sent);
    printf("  • Bytes Received: %zu bytes\n", metrics->bytes_received);
    printf("  • Total:          %zu bytes\n", metrics->bytes_sent + metrics->bytes_received);
    printf("\n");
    
    printf(COLOR_BOLD "Cryptographic Sizes:\n" COLOR_RESET);
    printf("  • KEM Public Key:    %zu bytes\n", metrics->kem_public_key_size);
    printf("  • KEM Ciphertext:    %zu bytes\n", metrics->kem_ciphertext_size);
    printf("  • Sig Public Key:    %zu bytes\n", metrics->sig_public_key_size);
    printf("  • Signature:         %zu bytes\n", metrics->signature_size);
    printf("\n");
    
    printf(COLOR_BOLD "System Resources:\n" COLOR_RESET);
    printf("  • Memory:      %zu KB\n", metrics->memory_kb);
    printf("\n");
}

int pq_perf_save_to_csv(const pq_performance_metrics_t *metrics, const char *filepath) {
    // Check if file exists
    FILE *check = fopen(filepath, "r");
    int file_exists = (check != NULL);
    if (check) fclose(check);
    
    // Open file for appending
    FILE *file = fopen(filepath, "a");
    if (!file) {
        perror("Failed to open CSV file");
        return -1;
    }
    
    // Write header if new file
    if (!file_exists) {
        fprintf(file, "protocol,cipher_suite,kem_algorithm,sig_algorithm,");
        fprintf(file, "handshake_ms,kem_keygen_ms,kem_encaps_ms,kem_decaps_ms,");
        fprintf(file, "signature_ms,verify_ms,");
        fprintf(file, "bytes_sent,bytes_received,");
        fprintf(file, "kem_public_key_size,kem_ciphertext_size,");
        fprintf(file, "sig_public_key_size,signature_size,memory_kb\n");
    }
    
    fprintf(file, "%s,%s,%s,%s,%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,%zu,%zu,%zu,%zu,%zu,%zu,%zu\n",
            metrics->protocol,
            metrics->cipher_suite,
            metrics->kem_algorithm,
            metrics->sig_algorithm,
            pq_microseconds_to_milliseconds(metrics->handshake_duration_us),
            pq_microseconds_to_milliseconds(metrics->kem_keygen_time_us),
            pq_microseconds_to_milliseconds(metrics->kem_encaps_time_us),
            pq_microseconds_to_milliseconds(metrics->kem_decaps_time_us),
            pq_microseconds_to_milliseconds(metrics->signature_time_us),
            pq_microseconds_to_milliseconds(metrics->verify_time_us),
            metrics->bytes_sent,
            metrics->bytes_received,
            metrics->kem_public_key_size,
            metrics->kem_ciphertext_size,
            metrics->sig_public_key_size,
            metrics->signature_size,
            metrics->memory_kb);
    
    fclose(file);
    printf(COLOR_GREEN "✓ Metrics saved to: %s\n" COLOR_RESET, filepath);
    return 0;
}
