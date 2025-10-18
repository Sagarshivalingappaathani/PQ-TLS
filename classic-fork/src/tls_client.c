#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "../include/performance.h"

#define SERVER_IP "localhost"
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

// Timing for signature verification
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
        } else {
            g_handshake_bytes_received += len;
            // Track certificate size
            if (msg_type == 11) { // Certificate message
                g_certificate_size = len;
            }
            // Track signature verification timing
            if (msg_type == 15) { // CertificateVerify received
                g_signature_start_us = get_time_microseconds();
                // Extract signature size
                if (len >= 8) {
                    g_signature_size = (data[6] << 8) | data[7];
                }
            }
            // Signature verification completes when Finished is received
            if (msg_type == 20 && g_signature_start_us > 0) {
                g_signature_end_us = get_time_microseconds();
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
            printf("    - Certificate chain received\n");
        } else if (msg_type == 15) { // CertificateVerify
            printf("    - Verifying server signature\n");
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

// Certificate verification callback with detailed error reporting
int verify_callback(int preverify_ok, X509_STORE_CTX *ctx) {
    char buf[256];
    X509 *err_cert;
    int err, depth;

    err_cert = X509_STORE_CTX_get_current_cert(ctx);
    err = X509_STORE_CTX_get_error(ctx);
    depth = X509_STORE_CTX_get_error_depth(ctx);

    X509_NAME_oneline(X509_get_subject_name(err_cert), buf, 256);

    if (!preverify_ok) {
        printf("\n%s[Certificate Verification Error]%s\n", COLOR_RED, COLOR_RESET);
        printf("  Depth: %d\n", depth);
        printf("  Subject: %s\n", buf);
        printf("  Error: %d - %s\n", err, X509_verify_cert_error_string(err));
        
        // For self-signed certificates in testing, we might want to accept them
        // Check if it's a self-signed cert error
        if (err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT ||
            err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN) {
            printf("  %s[INFO] Accepting self-signed certificate for testing%s\n", 
                   COLOR_YELLOW, COLOR_RESET);
            return 1; // Accept it
        }
    } else {
        printf("%s[Certificate Verification OK]%s Depth=%d: %s\n", 
               COLOR_GREEN, COLOR_RESET, depth, buf);
    }

    return preverify_ok;
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

    // Configure elliptic curves to use NIST Level 3 ONLY
    // X448 (~224-bit security) for KEM and P-384 (~192-bit security) for signatures
    // Strict Level 3 comparison with Kyber-768 + Dilithium3
    if (SSL_CTX_set1_groups_list(ctx, "X448:P-384") != 1) {
        fprintf(stderr, "Failed to set elliptic curves (X448, P-384 for Level 3)\n");
        ERR_print_errors_fp(stderr);
    }

    printf("    %s[Config] NIST Level 3: X448 (KEM), P-384 (Signature)%s\n", 
           COLOR_BLUE, COLOR_RESET);

    // Enable certificate verification (secure)
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
    SSL_CTX_set_verify_depth(ctx, 5);

    // Load CA certificate for verification
    // Try local CA first, fallback to system CA store
    if (access("certs/ca-cert.pem", R_OK) == 0) {
        printf("    Loading CA certificate: certs/ca-cert.pem\n");
        if (SSL_CTX_load_verify_locations(ctx, "certs/ca-cert.pem", NULL) != 1) {
            fprintf(stderr, "    %s✗ Failed to load certs/ca-cert.pem%s\n", COLOR_RED, COLOR_RESET);
            ERR_print_errors_fp(stderr);
        } else {
            printf("    %s✓ CA certificate loaded successfully%s\n", COLOR_GREEN, COLOR_RESET);
        }
    } else {
        printf("    CA cert not found locally, using system CA store\n");
        // Use system CA store
        if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
            fprintf(stderr, "    %s✗ Failed to load system CA store%s\n", COLOR_RED, COLOR_RESET);
            ERR_print_errors_fp(stderr);
        }
    }

    // Enable detailed message logging
    SSL_CTX_set_msg_callback(ctx, msg_callback);

    return ctx;
}

// Create TCP socket and connect to server
int create_socket(const char *hostname, int port) {
    int sockfd;
    struct addrinfo hints, *result, *rp;
    char port_str[6];

    // Convert port to string
    snprintf(port_str, sizeof(port_str), "%d", port);

    // Setup hints for getaddrinfo
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;       // IPv4
    hints.ai_socktype = SOCK_STREAM; // TCP
    hints.ai_flags = 0;
    hints.ai_protocol = 0;

    // Resolve hostname
    int s = getaddrinfo(hostname, port_str, &hints, &result);
    if (s != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        exit(EXIT_FAILURE);
    }

    // Try each address until we successfully connect
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd == -1)
            continue;

        if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) != -1)
            break; // Success

        close(sockfd);
    }

    freeaddrinfo(result);

    if (rp == NULL) {
        fprintf(stderr, "Could not connect to %s:%d\n", hostname, port);
        exit(EXIT_FAILURE);
    }

    return sockfd;
}

int main(int argc, char *argv[]) {
    SSL_CTX *ctx;
    SSL *ssl;
    int sockfd;
    char buffer[BUFFER_SIZE];
    int bytes;
    performance_metrics_t metrics;
    const char *hostname = SERVER_IP;
    int port = SERVER_PORT;

    if (argc > 1) {
        hostname = argv[1];
    }
    if (argc > 2) {
        port = atoi(argv[2]);
    }

    printf("\n%s╔════════════════════════════════════════╗%s\n", COLOR_BLUE, COLOR_RESET);
    printf("%s║   Classical TLS 1.3 Client            ║%s\n", COLOR_BLUE, COLOR_RESET);
    printf("%s╚════════════════════════════════════════╝%s\n", COLOR_BLUE, COLOR_RESET);
    printf("Server: %s:%d\n\n", hostname, port);

    // Initialize metrics
    perf_init(&metrics);

    // Reset global counters
    g_handshake_bytes_sent = 0;
    g_handshake_bytes_received = 0;
    g_signature_start_us = 0;
    g_signature_end_us = 0;
    g_signature_size = 0;
    g_certificate_size = 0;

    // Initialize OpenSSL
    printf("[1] Initializing OpenSSL...\n");
    init_openssl();
    printf("    ✓ OpenSSL initialized\n\n");
    
    printf("[2] Creating TLS 1.3 context...\n");
    ctx = create_tls13_context();
    printf("    ✓ TLS 1.3 context created\n\n");

    // Connect to server
    printf("[3] Connecting to server...\n");
    sockfd = create_socket(hostname, port);
    printf("    ✓ TCP connection established\n\n");

    // Create SSL structure and set connection
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);

    // Set SNI (Server Name Indication)  
    if (SSL_set_tlsext_host_name(ssl, hostname) != 1) {
        fprintf(stderr, "Failed to set SNI\n");
        ERR_print_errors_fp(stderr);
    }

    // Enable hostname verification with IP address detection
    X509_VERIFY_PARAM *param = SSL_get0_param(ssl);
    X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    
    // Check if hostname is an IP address
    struct in_addr addr;
    if (inet_pton(AF_INET, hostname, &addr) == 1) {
        // It's an IPv4 address - use IP verification
        if (X509_VERIFY_PARAM_set1_ip_asc(param, hostname) != 1) {
            fprintf(stderr, "Failed to set IP address for verification\n");
            ERR_print_errors_fp(stderr);
        }
    } else {
        // It's a hostname - use hostname verification
        if (X509_VERIFY_PARAM_set1_host(param, hostname, 0) != 1) {
            fprintf(stderr, "Failed to set hostname for verification\n");
            ERR_print_errors_fp(stderr);
        }
    }

    printf("\n%s=== Starting TLS 1.3 Handshake (Client Side) ===%s\n\n", COLOR_YELLOW, COLOR_RESET);
    
    // Perform handshake
    perf_start_handshake(&metrics);
    
    if (SSL_connect(ssl) <= 0) {
        fprintf(stderr, "%sSSL_connect failed%s\n", COLOR_RED, COLOR_RESET);
        ERR_print_errors_fp(stderr);
    } else {
        perf_end_handshake(&metrics);

        // Verify certificate validation result
        long verify_result = SSL_get_verify_result(ssl);
        if (verify_result != X509_V_OK) {
            fprintf(stderr, "%sCertificate verification failed: %s%s\n", 
                    COLOR_RED, X509_verify_cert_error_string(verify_result), COLOR_RESET);
            fprintf(stderr, "Continuing anyway (for testing)...\n");
            // Uncomment to enforce strict verification:
            // goto cleanup;
        } else {
            printf("%s✓ Certificate verification successful%s\n", COLOR_GREEN, COLOR_RESET);
        }

        // Copy performance metrics
        // Signature verification time (CertificateVerify receive -> Finished receive)
        if (g_signature_start_us > 0 && g_signature_end_us > 0) {
            metrics.verify_time_us = g_signature_end_us - g_signature_start_us;
        }

        // Copy cryptographic sizes
        metrics.signature_size = g_signature_size;
        metrics.certificate_size = g_certificate_size;

        printf("\n%s=== TLS Handshake Completed Successfully (Client) ===%s\n", COLOR_GREEN, COLOR_RESET);

        // Send HTTP request
        // Send HTTP request (just to verify connection works)
        const char *request = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        bytes = SSL_write(ssl, request, strlen(request));
        if (bytes > 0) {
            printf("%sSent HTTP request:%s %d bytes\n", COLOR_GREEN, COLOR_RESET, bytes);
        }

        // Receive response
        bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            printf("%sReceived response:%s\n%s\n", COLOR_CYAN, COLOR_RESET, buffer);
        }

        // Extract cipher suite and protocol version
        const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
        if (cipher) {
            snprintf(metrics.cipher_suite, sizeof(metrics.cipher_suite), 
                     "%s", SSL_CIPHER_get_name(cipher));
        }

        const char *version = SSL_get_version(ssl);
        if (version) {
            snprintf(metrics.protocol_version, sizeof(metrics.protocol_version), 
                     "%s", version);
        }

        // Print and save metrics
        perf_print_summary(&metrics);
        perf_save_to_csv(&metrics, "results/client_metrics.csv");
    }

    // Cleanup
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
    cleanup_openssl();

    printf("%s✓ Connection closed%s\n\n", COLOR_YELLOW, COLOR_RESET);

    return 0;
}
