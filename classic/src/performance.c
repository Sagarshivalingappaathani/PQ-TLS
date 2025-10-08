#include "performance.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
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

// Convert microseconds to seconds
double microseconds_to_seconds(uint64_t us) {
    return (double)us / 1000000.0;
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

// Record bytes sent/received
void perf_record_bytes(performance_metrics_t *metrics, size_t sent, size_t received) {
    if (!metrics) return;
    metrics->bytes_sent += sent;
    metrics->bytes_received += received;
}

// Get memory usage in KB
size_t get_memory_usage_kb(void) {
    FILE *fp = fopen("/proc/self/status", "r");
    if (!fp) return 0;
    
    char line[256];
    size_t rss_kb = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "VmRSS:", 6) == 0) {
            sscanf(line + 6, "%zu", &rss_kb);
            break;
        }
    }
    
    fclose(fp);
    return rss_kb;
}

// Get CPU usage percentage
double get_cpu_usage_percent(void) {
    // Simplified CPU usage - would need more sophisticated tracking
    return 0.0;
}

// Print performance summary
void perf_print_summary(const performance_metrics_t *metrics) {
    if (!metrics) return;
    
    printf("\n=== TLS Performance Summary ===\n");
    printf("Protocol: %s\n", metrics->protocol_version);
    printf("Cipher Suite: %s\n", metrics->cipher_suite);
    printf("\n--- Timing (ms) ---\n");
    printf("Handshake Total:    %.2f ms\n", microseconds_to_milliseconds(metrics->handshake_duration_us));
    printf("Key Exchange:       %.2f ms\n", microseconds_to_milliseconds(metrics->key_exchange_time_us));
    
    // Only show signature time if > 0 (server side)
    if (metrics->signature_time_us > 0) {
        printf("Signature Gen:      %.2f ms\n", microseconds_to_milliseconds(metrics->signature_time_us));
    }
    
    // Only show verification time if > 0 (client side)
    if (metrics->verify_time_us > 0) {
        printf("Signature Verify:   %.2f ms\n", microseconds_to_milliseconds(metrics->verify_time_us));
    }
    
    printf("\n--- Network (bytes) ---\n");
    printf("Total Sent:         %zu bytes\n", metrics->bytes_sent);
    printf("Total Received:     %zu bytes\n", metrics->bytes_received);
    printf("Handshake Sent:     %zu bytes\n", metrics->handshake_bytes_sent);
    printf("Handshake Received: %zu bytes\n", metrics->handshake_bytes_received);
    
    printf("\n--- Crypto Sizes (bytes) ---\n");
    if (metrics->public_key_size > 0) {
        printf("Public Key:         %zu bytes\n", metrics->public_key_size);
    }
    printf("Signature:          %zu bytes\n", metrics->signature_size);
    if (metrics->certificate_size > 0) {
        printf("Certificate:        %zu bytes\n", metrics->certificate_size);
    }
    
    printf("\n--- System Resources ---\n");
    printf("Memory Usage:       %zu KB\n", metrics->memory_usage_kb);
    
    printf("================================\n\n");
}

// Save metrics to CSV
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
        fprintf(fp, "protocol,cipher_suite,handshake_ms,key_exchange_ms,signature_ms,verify_ms,");
        fprintf(fp, "bytes_sent,bytes_received,public_key_size,signature_size,memory_kb\n");
    }
    
    fprintf(fp, "%s,%s,%.2f,%.2f,%.2f,%.2f,%zu,%zu,%zu,%zu,%zu\n",
            metrics->protocol_version,
            metrics->cipher_suite,
            microseconds_to_milliseconds(metrics->handshake_duration_us),
            microseconds_to_milliseconds(metrics->key_exchange_time_us),
            microseconds_to_milliseconds(metrics->signature_time_us),
            microseconds_to_milliseconds(metrics->verify_time_us),
            metrics->bytes_sent,
            metrics->bytes_received,
            metrics->public_key_size,
            metrics->signature_size,
            metrics->memory_usage_kb);
    
    fclose(fp);
}

// Save metrics to JSON
void perf_save_to_json(const performance_metrics_t *metrics, const char *filename) {
    if (!metrics || !filename) return;
    
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        perror("Failed to open JSON file");
        return;
    }
    
    fprintf(fp, "{\n");
    fprintf(fp, "  \"protocol\": \"%s\",\n", metrics->protocol_version);
    fprintf(fp, "  \"cipher_suite\": \"%s\",\n", metrics->cipher_suite);
    fprintf(fp, "  \"timing\": {\n");
    fprintf(fp, "    \"handshake_ms\": %.2f,\n", microseconds_to_milliseconds(metrics->handshake_duration_us));
    fprintf(fp, "    \"key_exchange_ms\": %.2f,\n", microseconds_to_milliseconds(metrics->key_exchange_time_us));
    fprintf(fp, "    \"signature_ms\": %.2f,\n", microseconds_to_milliseconds(metrics->signature_time_us));
    fprintf(fp, "    \"verify_ms\": %.2f\n", microseconds_to_milliseconds(metrics->verify_time_us));
    fprintf(fp, "  },\n");
    fprintf(fp, "  \"network\": {\n");
    fprintf(fp, "    \"bytes_sent\": %zu,\n", metrics->bytes_sent);
    fprintf(fp, "    \"bytes_received\": %zu\n", metrics->bytes_received);
    fprintf(fp, "  },\n");
    fprintf(fp, "  \"crypto_sizes\": {\n");
    fprintf(fp, "    \"public_key_bytes\": %zu,\n", metrics->public_key_size);
    fprintf(fp, "    \"signature_bytes\": %zu,\n", metrics->signature_size);
    fprintf(fp, "    \"certificate_bytes\": %zu\n", metrics->certificate_size);
    fprintf(fp, "  },\n");
    fprintf(fp, "  \"resources\": {\n");
    fprintf(fp, "    \"memory_kb\": %zu\n", metrics->memory_usage_kb);
    fprintf(fp, "  }\n");
    fprintf(fp, "}\n");
    
    fclose(fp);
}