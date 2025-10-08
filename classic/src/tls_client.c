#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "../include/performance.h"

#define SERVER_ADDR "127.0.0.1"
#define SERVER_PORT 4433
#define BUFFER_SIZE 4096

// Color codes for output
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN    "\033[36m"

// Global counters for handshake bytes (tracked in message callback)
static size_t g_handshake_bytes_sent = 0;
static size_t g_handshake_bytes_received = 0;

// Timing for key exchange
static uint64_t g_key_exchange_start_us = 0;
static uint64_t g_key_exchange_end_us = 0;

// Timing for signature verification
static uint64_t g_verify_start_us = 0;
static uint64_t g_verify_end_us = 0;

// Signature size from CertificateVerify
static size_t g_signature_size = 0;

// Message type to string
const char* get_msg_type(int content_type, int msg_type) {
    if (content_type == 22) { // Handshake
        switch (msg_type) {
            case 1: return "ClientHello";
            case 2: return "ServerHello";
            case 4: return "NewSessionTicket";
            case 8: return "EncryptedExtensions";
            case 11: return "Certificate";
            case 13: return "CertificateRequest";
            case 15: return "CertificateVerify";
            case 20: return "Finished";
            default: return "Unknown Handshake";
        }
    } else if (content_type == 20) {
        return "ChangeCipherSpec";
    } else if (content_type == 21) {
        return "Alert";
    } else if (content_type == 23) {
        return "ApplicationData";
    }
    return "Unknown";
}

// SSL message callback for detailed logging
void msg_callback(int write_p, int version, int content_type, const void *buf, 
                  size_t len, SSL *ssl, void *arg) {
    const char *direction = write_p ? ">>>" : "<<<";
    const char *color = write_p ? COLOR_GREEN : COLOR_CYAN;
    
    const unsigned char *data = (const unsigned char *)buf;
    int msg_type = (len > 0) ? data[0] : -1;
    
    // Track handshake bytes
    if (content_type == 22) { // Handshake messages
        if (write_p) {
            g_handshake_bytes_sent += len;
            // Start timing when ClientHello is sent (includes key share generation)
            if (msg_type == 1) {
                g_key_exchange_start_us = get_time_microseconds();
            }
        } else {
            g_handshake_bytes_received += len;
            // End timing when ServerHello is received (key exchange complete)
            if (msg_type == 2) {
                g_key_exchange_end_us = get_time_microseconds();
            }
            // Track signature verification timing
            if (msg_type == 15) { // CertificateVerify received - start verification
                g_verify_start_us = get_time_microseconds();
                // Extract signature size (TLS 1.3: 2 bytes sig_algo + 2 bytes length + signature)
                if (len >= 8) {
                    // Bytes 4-5 are signature algorithm, bytes 6-7 are signature length
                    g_signature_size = (data[6] << 8) | data[7];
                }
            }
            if (msg_type == 20) { // Finished received - verification complete
                if (g_verify_start_us > 0) {
                    g_verify_end_us = get_time_microseconds();
                }
            }
        }
    }
    
    printf("%s%s [%s] ", color, direction, write_p ? "SEND" : "RECV");
    
    // Print message type
    if (content_type == 22 && len > 0) { // Handshake message
        printf("%s (%d bytes)\n", get_msg_type(content_type, msg_type), (int)len);
        
        // Show key details for specific messages
        if (msg_type == 1 && len >= 38) { // ClientHello
            printf("    - TLS Version: 0x%02x%02x\n", data[4], data[5]);
            printf("    - Random: ");
            for (int i = 6; i < 38 && i < len; i++) printf("%02x", data[i]);
            printf("\n");
        } else if (msg_type == 2 && len >= 38) { // ServerHello
            printf("    - TLS Version: 0x%02x%02x\n", data[4], data[5]);
            printf("    - Random: ");
            for (int i = 6; i < 38 && i < len; i++) printf("%02x", data[i]);
            printf("\n");
        } else if (msg_type == 11) { // Certificate
            printf("    - Certificate chain received\n");
        } else if (msg_type == 15) { // CertificateVerify
            printf("    - Server signature verification\n");
        } else if (msg_type == 20) { // Finished
            printf("    - Handshake verification data\n");
        }
    } else if (content_type == 20) {
        printf("ChangeCipherSpec (%d bytes)\n", (int)len);
    } else if (content_type == 21) {
        printf("Alert (%d bytes)\n", (int)len);
        if (len >= 2) {
            printf("    - Level: %d, Description: %d\n", data[0], data[1]);
        }
    } else if (content_type == 23) {
        printf("ApplicationData (%d bytes)\n", (int)len);
    } else {
        printf("ContentType=%d (%d bytes)\n", content_type, (int)len);
    }
    
    printf("%s", COLOR_RESET);
}

// Initialize OpenSSL
void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

// Cleanup OpenSSL
void cleanup_openssl() {
    EVP_cleanup();
}

// Create SSL context for TLS 1.3
SSL_CTX *create_tls13_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Force TLS 1.3 only
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    // Set cipher suites (TLS 1.3)
    if (SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256") != 1) {
        fprintf(stderr, "Failed to set cipher suites\n");
        ERR_print_errors_fp(stderr);
    }

    // Enable detailed message logging
    SSL_CTX_set_msg_callback(ctx, msg_callback);

    return ctx;
}

// Create TCP socket connection
int create_socket(const char *hostname, int port) {
    int sockfd;
    struct sockaddr_in addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, hostname, &addr.sin_addr) <= 0) {
        perror("Invalid address");
        exit(EXIT_FAILURE);
    }

    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    return sockfd;
}

// Extract performance metrics from SSL connection
void extract_metrics(SSL *ssl, performance_metrics_t *metrics) {
    const SSL_CIPHER *cipher;
    X509 *cert;
    EVP_PKEY *pkey;

    // Get cipher suite information
    cipher = SSL_get_current_cipher(ssl);
    if (cipher) {
        snprintf(metrics->cipher_suite, sizeof(metrics->cipher_suite), 
                 "%s", SSL_CIPHER_get_name(cipher));
    }

    // Get certificate information
    cert = SSL_get_peer_certificate(ssl);
    if (cert) {
        // Get certificate size
        unsigned char *cert_der = NULL;
        int cert_len = i2d_X509(cert, &cert_der);
        if (cert_len > 0) {
            metrics->certificate_size = cert_len;
            OPENSSL_free(cert_der);
        }

        // Get public key
        pkey = X509_get_pubkey(cert);
        if (pkey) {
            metrics->public_key_size = EVP_PKEY_size(pkey);
            EVP_PKEY_free(pkey);
        }

        X509_free(cert);
    }

    // Get protocol version
    const char *version = SSL_get_version(ssl);
    if (version) {
        snprintf(metrics->protocol_version, sizeof(metrics->protocol_version), 
                 "%s", version);
    }
}

// Perform TLS handshake and measure performance
int perform_handshake(SSL *ssl, performance_metrics_t *metrics) {
    int ret;

    // Reset global counters
    g_handshake_bytes_sent = 0;
    g_handshake_bytes_received = 0;
    g_key_exchange_start_us = 0;
    g_key_exchange_end_us = 0;
    g_verify_start_us = 0;
    g_verify_end_us = 0;
    g_signature_size = 0;

    printf("\n%s=== Starting TLS 1.3 Handshake ===%s\n\n", COLOR_YELLOW, COLOR_RESET);
    
    perf_start_handshake(metrics);
    
    ret = SSL_connect(ssl);
    
    perf_end_handshake(metrics);

    if (ret != 1) {
        int ssl_err = SSL_get_error(ssl, ret);
        fprintf(stderr, "%sSSL_connect failed: %d%s\n", COLOR_RED, ssl_err, COLOR_RESET);
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // Copy handshake byte counts to metrics
    metrics->handshake_bytes_sent = g_handshake_bytes_sent;
    metrics->handshake_bytes_received = g_handshake_bytes_received;
    metrics->bytes_sent = g_handshake_bytes_sent;
    metrics->bytes_received = g_handshake_bytes_received;

    // Calculate key exchange time (ClientHello send -> ServerHello receive)
    if (g_key_exchange_start_us > 0 && g_key_exchange_end_us > 0) {
        metrics->key_exchange_time_us = g_key_exchange_end_us - g_key_exchange_start_us;
    }

    // Calculate verification time (CertificateVerify receive -> Finished receive)
    if (g_verify_start_us > 0 && g_verify_end_us > 0) {
        metrics->verify_time_us = g_verify_end_us - g_verify_start_us;
    }

    // Copy signature size
    metrics->signature_size = g_signature_size;

    printf("\n%s=== TLS Handshake Completed Successfully ===%s\n", COLOR_GREEN, COLOR_RESET);
    printf("Handshake time: %.2f ms\n", 
           microseconds_to_milliseconds(metrics->handshake_duration_us));
    printf("Key Exchange time: %.2f ms (ClientHello -> ServerHello)\n", 
           microseconds_to_milliseconds(metrics->key_exchange_time_us));
    printf("Signature Verification time: %.2f ms\n", 
           microseconds_to_milliseconds(metrics->verify_time_us));
    printf("Signature size: %zu bytes\n", metrics->signature_size);
    printf("Bytes sent: %zu, Bytes received: %zu\n", 
           metrics->handshake_bytes_sent, metrics->handshake_bytes_received);

    // Extract metrics after successful handshake
    extract_metrics(ssl, metrics);

    return 0;
}

// Send and receive data
int exchange_data(SSL *ssl, performance_metrics_t *metrics) {
    const char *request = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    char buffer[BUFFER_SIZE];
    int bytes;
    size_t total_sent = 0;
    size_t total_received = 0;

    uint64_t send_start = get_time_microseconds();
    
    // Send data
    bytes = SSL_write(ssl, request, strlen(request));
    if (bytes > 0) {
        total_sent += bytes;
        printf("Sent %d bytes\n", bytes);
    }

    uint64_t send_end = get_time_microseconds();
    metrics->encryption_time_us = send_end - send_start;

    uint64_t recv_start = get_time_microseconds();
    
    // Receive response
    while ((bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes] = '\0';
        total_received += bytes;
        printf("Received %d bytes\n", bytes);
    }

    uint64_t recv_end = get_time_microseconds();
    metrics->decryption_time_us = recv_end - recv_start;

    perf_record_bytes(metrics, total_sent, total_received);
    
    return 0;
}

int main(int argc, char *argv[]) {
    SSL_CTX *ctx;
    SSL *ssl;
    int sockfd;
    performance_metrics_t metrics;
    const char *server = SERVER_ADDR;
    int port = SERVER_PORT;

    // Parse command line arguments
    if (argc > 1) {
        server = argv[1];
    }
    if (argc > 2) {
        port = atoi(argv[2]);
    }

    printf("\n%s╔════════════════════════════════════════╗%s\n", COLOR_BLUE, COLOR_RESET);
    printf("%s║   Classical TLS 1.3 Client            ║%s\n", COLOR_BLUE, COLOR_RESET);
    printf("%s╚════════════════════════════════════════╝%s\n", COLOR_BLUE, COLOR_RESET);
    printf("Target: %s:%d\n\n", server, port);

    // Initialize
    init_openssl();
    perf_init(&metrics);

    // Create SSL context
    printf("[1] Creating TLS 1.3 SSL context...\n");
    ctx = create_tls13_context();
    printf("    ✓ SSL context created (TLS 1.3 only)\n\n");

    // Create socket
    printf("[2] Establishing TCP connection...\n");
    sockfd = create_socket(server, port);
    printf("    ✓ TCP connection established to %s:%d\n\n", server, port);

    // Create SSL structure
    printf("[3] Creating SSL connection object...\n");
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    printf("    ✓ SSL object bound to socket\n\n");

    printf("[4] Beginning TLS 1.3 handshake...\n");
    
    // Perform handshake with performance measurement
    if (perform_handshake(ssl, &metrics) != 0) {
        fprintf(stderr, "%sHandshake failed%s\n", COLOR_RED, COLOR_RESET);
        goto cleanup;
    }

    // Get memory usage
    metrics.memory_usage_kb = get_memory_usage_kb();

    // Print performance summary
    perf_print_summary(&metrics);

    // Save results
    perf_save_to_csv(&metrics, "results/classical_tls_metrics.csv");

    // Exchange data (optional)
    // exchange_data(ssl, &metrics);

cleanup:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
    cleanup_openssl();

    printf("Connection closed\n");
    return 0;
}