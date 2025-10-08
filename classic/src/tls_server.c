#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "../include/performance.h"

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

// Timing for signature generation
static uint64_t g_signature_start_us = 0;
static uint64_t g_signature_end_us = 0;

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
    const char *color = write_p ? COLOR_MAGENTA : COLOR_CYAN;
    
    const unsigned char *data = (const unsigned char *)buf;
    int msg_type = (len > 0) ? data[0] : -1;
    
    // Track handshake bytes
    if (content_type == 22) { // Handshake messages
        if (write_p) {
            g_handshake_bytes_sent += len;
            // End timing when ServerHello is sent (key exchange complete on server)
            if (msg_type == 2) {
                g_key_exchange_end_us = get_time_microseconds();
                // Start signature generation timing (happens after ServerHello)
                g_signature_start_us = get_time_microseconds();
            }
            // Track signature generation timing
            if (msg_type == 15) { // CertificateVerify sent - signature generation complete
                g_signature_end_us = get_time_microseconds();
                // Extract signature size
                if (len >= 8) {
                    g_signature_size = (data[6] << 8) | data[7];
                }
            }
        } else {
            g_handshake_bytes_received += len;
            // Start timing when ClientHello is received
            if (msg_type == 1) {
                g_key_exchange_start_us = get_time_microseconds();
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
            printf("    - Client Random: ");
            for (int i = 6; i < 38 && i < len; i++) printf("%02x", data[i]);
            printf("\n");
        } else if (msg_type == 2 && len >= 38) { // ServerHello
            printf("    - TLS Version: 0x%02x%02x\n", data[4], data[5]);
            printf("    - Server Random: ");
            for (int i = 6; i < 38 && i < len; i++) printf("%02x", data[i]);
            printf("\n");
        } else if (msg_type == 11) { // Certificate
            printf("    - Certificate chain sent\n");
        } else if (msg_type == 15) { // CertificateVerify
            printf("    - Server signing handshake\n");
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

    method = TLS_server_method();
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

// Configure SSL context with certificate and key
void configure_context(SSL_CTX *ctx) {
    // Use certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, "certs/server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "certs/server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Verify private key
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the certificate\n");
        exit(EXIT_FAILURE);
    }
}

// Create server socket
int create_server_socket(int port) {
    int sockfd;
    struct sockaddr_in addr;
    int opt = 1;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    // Set socket options
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt failed");
        exit(EXIT_FAILURE);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(sockfd, 5) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    return sockfd;
}

// Handle client connection
void handle_client(SSL *ssl, performance_metrics_t *metrics) {
    char buffer[BUFFER_SIZE];
    int bytes;
    size_t total_received = 0;
    size_t total_sent = 0;

    // Reset global counters
    g_handshake_bytes_sent = 0;
    g_handshake_bytes_received = 0;
    g_key_exchange_start_us = 0;
    g_key_exchange_end_us = 0;
    g_signature_start_us = 0;
    g_signature_end_us = 0;
    g_signature_size = 0;

    printf("\n%s=== Starting TLS 1.3 Handshake (Server Side) ===%s\n\n", COLOR_YELLOW, COLOR_RESET);
    
    // Perform handshake
    perf_start_handshake(metrics);
    
    if (SSL_accept(ssl) <= 0) {
        fprintf(stderr, "%sSSL_accept failed%s\n", COLOR_RED, COLOR_RESET);
        ERR_print_errors_fp(stderr);
        perf_end_handshake(metrics);
        return;
    }
    
    perf_end_handshake(metrics);

    // Copy handshake byte counts to metrics
    metrics->handshake_bytes_sent = g_handshake_bytes_sent;
    metrics->handshake_bytes_received = g_handshake_bytes_received;
    metrics->bytes_sent = g_handshake_bytes_sent;
    metrics->bytes_received = g_handshake_bytes_received;

    // Calculate key exchange time (ClientHello receive -> ServerHello send)
    if (g_key_exchange_start_us > 0 && g_key_exchange_end_us > 0) {
        metrics->key_exchange_time_us = g_key_exchange_end_us - g_key_exchange_start_us;
    }

    // Calculate signature generation time (ServerHello send -> CertificateVerify send)
    if (g_signature_start_us > 0 && g_signature_end_us > 0) {
        metrics->signature_time_us = g_signature_end_us - g_signature_start_us;
    }

    // Copy signature size
    metrics->signature_size = g_signature_size;

    printf("\n%s=== TLS Handshake Completed Successfully (Server) ===%s\n", COLOR_GREEN, COLOR_RESET);
    printf("Handshake time: %.2f ms\n", 
           microseconds_to_milliseconds(metrics->handshake_duration_us));
    printf("Key Exchange time: %.2f ms (ClientHello -> ServerHello)\n", 
           microseconds_to_milliseconds(metrics->key_exchange_time_us));
    printf("Signature Generation time: %.2f ms\n", 
           microseconds_to_milliseconds(metrics->signature_time_us));
    printf("Signature size: %zu bytes\n", metrics->signature_size);
    printf("Bytes sent: %zu, Bytes received: %zu\n", 
           metrics->handshake_bytes_sent, metrics->handshake_bytes_received);

    // Read client data
    bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes > 0) {
        buffer[bytes] = '\0';
        total_received += bytes;
        printf("\n%sReceived from client:%s %s\n", COLOR_CYAN, COLOR_RESET, buffer);
    }

    // Send response
    const char *response = 
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 62\r\n"
        "Connection: close\r\n"
        "\r\n"
        "<html><body><h1>TLS 1.3 Server</h1><p>Success!</p></body></html>";

    bytes = SSL_write(ssl, response, strlen(response));
    if (bytes > 0) {
        total_sent += bytes;
        printf("%sSent HTTP response:%s %d bytes\n", COLOR_GREEN, COLOR_RESET, bytes);
    }

    perf_record_bytes(metrics, total_sent, total_received);

    // Extract metrics
    const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
    if (cipher) {
        snprintf(metrics->cipher_suite, sizeof(metrics->cipher_suite), 
                 "%s", SSL_CIPHER_get_name(cipher));
    }

    const char *version = SSL_get_version(ssl);
    if (version) {
        snprintf(metrics->protocol_version, sizeof(metrics->protocol_version), 
                 "%s", version);
    }

    metrics->memory_usage_kb = get_memory_usage_kb();

    // Print and save metrics
    printf("\n");
    perf_print_summary(metrics);
    perf_save_to_csv(metrics, "results/server_metrics.csv");
}

int main(int argc, char *argv[]) {
    SSL_CTX *ctx;
    int server_fd;
    int port = SERVER_PORT;

    if (argc > 1) {
        port = atoi(argv[1]);
    }

    printf("\n%s╔════════════════════════════════════════╗%s\n", COLOR_BLUE, COLOR_RESET);
    printf("%s║   Classical TLS 1.3 Server            ║%s\n", COLOR_BLUE, COLOR_RESET);
    printf("%s╚════════════════════════════════════════╝%s\n", COLOR_BLUE, COLOR_RESET);
    printf("Port: %d\n\n", port);

    // Initialize
    printf("[1] Initializing OpenSSL...\n");
    init_openssl();
    printf("    ✓ OpenSSL initialized\n\n");
    
    printf("[2] Creating TLS 1.3 context...\n");
    ctx = create_tls13_context();
    printf("    ✓ TLS 1.3 context created\n\n");
    
    printf("[3] Loading certificates...\n");
    configure_context(ctx);
    printf("    ✓ Certificate: certs/server.crt\n");
    printf("    ✓ Private key: certs/server.key\n\n");

    // Create server socket
    printf("[4] Creating server socket...\n");
    server_fd = create_server_socket(port);
    printf("    ✓ Server listening on 0.0.0.0:%d\n\n", port);

    printf("%s[Server Ready - Waiting for connections]%s\n", COLOR_GREEN, COLOR_RESET);
    printf("%s═══════════════════════════════════════════%s\n\n", COLOR_GREEN, COLOR_RESET);

    // Accept connections
    while (1) {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;
        performance_metrics_t metrics;
        
        printf("%sWaiting for connection...%s\n", COLOR_YELLOW, COLOR_RESET);
        
        int client = accept(server_fd, (struct sockaddr*)&addr, &len);
        if (client < 0) {
            perror("Unable to accept");
            continue;
        }

        printf("%s✓ Client connected from %s:%d%s\n", COLOR_GREEN,
               inet_ntoa(addr.sin_addr), ntohs(addr.sin_port), COLOR_RESET);

        // Initialize metrics
        perf_init(&metrics);

        // Create SSL structure
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        // Handle client
        handle_client(ssl, &metrics);

        // Cleanup
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client);
        
        printf("\n%s✓ Client disconnected%s\n", COLOR_YELLOW, COLOR_RESET);
        printf("%s═══════════════════════════════════════════%s\n\n", COLOR_YELLOW, COLOR_RESET);
    }

    close(server_fd);
    SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}