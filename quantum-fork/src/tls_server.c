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

// Timing for signature generation
static uint64_t g_signature_start_us = 0;
static uint64_t g_signature_end_us = 0;

// Signature size from CertificateVerify
static size_t g_signature_size = 0;

// Certificate size from Certificate message
static size_t g_certificate_size = 0;

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
            // Track certificate size when sent
            if (msg_type == 11) { // Certificate message
                g_certificate_size = len;
            }
            // Start signature generation timing when Certificate is sent
            if (msg_type == 11) {
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

// Create SSL context for TLS 1.3 with level-specific algorithms
SSL_CTX *create_tls13_context(int level) {
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

    // Configure post-quantum algorithms based on security level
    const char *kem_name, *sig_name;
    switch(level) {
        case 1:
            kem_name = "kyber512";
            sig_name = "dilithium2";
            break;
        case 3:
            kem_name = "kyber768";
            sig_name = "dilithium3";
            break;
        case 5:
            kem_name = "kyber1024";
            sig_name = "dilithium5";
            break;
        default:
            fprintf(stderr, "Invalid security level: %d\n", level);
            exit(EXIT_FAILURE);
    }

    // Configure PURE post-quantum key exchange (NO FALLBACKS!)
    if (SSL_CTX_set1_groups_list(ctx, kem_name) != 1) {
        fprintf(stderr, "Failed to set %s key exchange\n", kem_name);
        ERR_print_errors_fp(stderr);
    }

    // Configure PURE post-quantum signatures (NO FALLBACKS!)
    if (SSL_CTX_set1_sigalgs_list(ctx, sig_name) != 1) {
        fprintf(stderr, "Failed to set %s signatures\n", sig_name);
        ERR_print_errors_fp(stderr);
    }
    
    printf("%s[Config] PURE Post-Quantum: %s (KEM) + %s (Signature)%s\n", 
           COLOR_BLUE, kem_name, sig_name, COLOR_RESET);

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
void configure_context(SSL_CTX *ctx, int level) {
    char cert_path[256];
    char key_path[256];
    const char *dilithium_names[] = {"", "Dilithium2", "", "Dilithium3", "", "Dilithium5"};
    
    // Build paths to level-specific certificates
    snprintf(cert_path, sizeof(cert_path), "certs/level%d/ca-chain.pem", level);
    snprintf(key_path, sizeof(key_path), "certs/level%d/server-key.pem", level);
    
    // Load post-quantum certificate chain (server cert + intermediate CA)
    if (SSL_CTX_use_certificate_chain_file(ctx, cert_path) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    printf("    ✓ Certificate: %s (%s)\n", cert_path, dilithium_names[level]);
    printf("    ✓ Private key: %s (%s)\n\n", key_path, dilithium_names[level]);

    // Verify the key matches the certificate
    if (SSL_CTX_check_private_key(ctx) != 1) {
        fprintf(stderr, "    ✗ Private key does not match the certificate\n");
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
void handle_client(SSL *ssl, performance_metrics_t *metrics, const char *output_file) {
    char buffer[BUFFER_SIZE];
    int bytes;
    size_t total_received = 0;
    size_t total_sent = 0;

    // Reset global counters
    g_handshake_bytes_sent = 0;
    g_handshake_bytes_received = 0;
    g_signature_start_us = 0;
    g_signature_end_us = 0;
    g_signature_size = 0;
    g_certificate_size = 0;

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

    // Copy performance metrics
    // Signature generation time (Certificate send -> CertificateVerify send)
    if (g_signature_start_us > 0 && g_signature_end_us > 0) {
        metrics->signature_time_us = g_signature_end_us - g_signature_start_us;
    }

    // Copy cryptographic sizes
    metrics->signature_size = g_signature_size;
    metrics->certificate_size = g_certificate_size;

    printf("\n%s=== TLS Handshake Completed Successfully (Server) ===%s\n", COLOR_GREEN, COLOR_RESET);

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

    // Display negotiated key exchange algorithm (group)
    printf("\n");
    int nid = SSL_get_shared_group(ssl, 0);
    if (nid != NID_undef && nid != 0) {
        const char *group_name = OBJ_nid2sn(nid);
        if (group_name) {
            printf("%s✓ Key Exchange Algorithm: %s%s\n", COLOR_GREEN, group_name, COLOR_RESET);
        } else {
            printf("%s✓ Key Exchange Algorithm: NID=%d (name not found)%s\n", COLOR_GREEN, nid, COLOR_RESET);
        }
    } else {
        printf("%s⚠ Key Exchange Algorithm: Could not determine (NID=%d)%s\n", COLOR_YELLOW, nid, COLOR_RESET);
    }

    // Display signature algorithm used
    int sig_nid = SSL_get_peer_signature_nid(ssl, &nid);
    if (sig_nid > 0 && nid != NID_undef) {
        const char *sig_name = OBJ_nid2sn(nid);
        if (sig_name) {
            printf("%s✓ Signature Algorithm: %s%s\n", COLOR_GREEN, sig_name, COLOR_RESET);
        } else {
            printf("%s✓ Signature Algorithm: NID=%d%s\n", COLOR_GREEN, nid, COLOR_RESET);
        }
    }

    // Print and save metrics
    perf_print_summary(metrics);
    perf_save_to_csv(metrics, output_file);
}

int main(int argc, char *argv[]) {
    SSL_CTX *ctx;
    int server_fd;
    int port = SERVER_PORT;
    int level, network;

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <level> <network>\n", argv[0]);
        fprintf(stderr, "  level:   1 (128-bit), 3 (192-bit), 5 (256-bit)\n");
        fprintf(stderr, "  network: 1 (same-machine), 2 (lan), 3 (hotspot), 4 (vm)\n");
        fprintf(stderr, "\nExample: %s 3 1\n", argv[0]);
        exit(1);
    }

    level = atoi(argv[1]);
    network = atoi(argv[2]);

    if (level != 1 && level != 3 && level != 5) {
        fprintf(stderr, "Error: Invalid level '%d' (must be 1, 3, or 5)\n", level);
        exit(1);
    }

    if (network < 1 || network > 4) {
        fprintf(stderr, "Error: Invalid network '%d' (must be 1-4)\n", network);
        exit(1);
    }

    const char *network_names[] = {"", "same-machine", "two-machines-lan", "mobile-hotspot", "laptop-to-vm"};

    // Construct output path
    char output_dir[512];
    char output_file[512];
    snprintf(output_dir, sizeof(output_dir), "../results/level%d/%s/quantum", level, network_names[network]);
    snprintf(output_file, sizeof(output_file), "%s/server_metrics.csv", output_dir);
    
    // Create output directory
    char mkdir_cmd[600];
    snprintf(mkdir_cmd, sizeof(mkdir_cmd), "mkdir -p %s", output_dir);
    system(mkdir_cmd);

    printf("\n%s╔════════════════════════════════════════╗%s\n", COLOR_BLUE, COLOR_RESET);
    printf("%s║   Post-Quantum TLS 1.3 Server         ║%s\n", COLOR_BLUE, COLOR_RESET);
    printf("%s╚════════════════════════════════════════╝%s\n", COLOR_BLUE, COLOR_RESET);
    printf("Port: %d\n", port);
    printf("Level: %d\n", level);
    printf("Network: %d (%s)\n", network, network_names[network]);
    printf("Output: %s\n\n", output_file);

    // Initialize
    printf("[1] Initializing OpenSSL...\n");
    init_openssl();
    printf("    ✓ OpenSSL initialized\n\n");
    
    printf("[2] Creating TLS 1.3 context...\n");
    ctx = create_tls13_context(level);
    printf("    ✓ TLS 1.3 context created\n\n");
    
    printf("[3] Loading certificates...\n");
    configure_context(ctx, level);

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
        handle_client(ssl, &metrics, output_file);

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
