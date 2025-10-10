#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "pq_crypto.h"
#include "pq_performance.h"

// Color codes for logging
#define COLOR_RESET   "\033[0m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_BOLD    "\033[1m"

// Handshake message types
#define MSG_CLIENT_HELLO         1
#define MSG_SERVER_HELLO         2
#define MSG_CERTIFICATE          3
#define MSG_CERTIFICATE_VERIFY   4
#define MSG_FINISHED             5
#define MSG_APPLICATION_DATA     6

typedef struct {
    uint8_t type;
    uint32_t length;
    uint8_t *data;
} handshake_message_t;

// Function prototypes
int connect_to_server(const char *host, int port);
int send_message(int sock, const handshake_message_t *msg);
int receive_message(int sock, handshake_message_t *msg);
void free_message(handshake_message_t *msg);

int main(int argc, char *argv[]) {
    const char *server_host = "127.0.0.1";
    int server_port = 4433;
    
    if (argc > 1) {
        server_host = argv[1];
    }
    if (argc > 2) {
        server_port = atoi(argv[2]);
    }
    
    printf(COLOR_BOLD COLOR_CYAN "\n╔═══════════════════════════════════════════════════════════════╗\n" COLOR_RESET);
    printf(COLOR_BOLD COLOR_CYAN "║          POST-QUANTUM TLS 1.3 CLIENT                          ║\n" COLOR_RESET);
    printf(COLOR_BOLD COLOR_CYAN "╚═══════════════════════════════════════════════════════════════╝\n" COLOR_RESET);
    printf("\n");
    
    // Initialize performance metrics
    pq_performance_metrics_t metrics;
    pq_perf_init(&metrics);
    
    // Connect to server
    printf(COLOR_YELLOW "→ Connecting to server %s:%d...\n" COLOR_RESET, server_host, server_port);
    int sock = connect_to_server(server_host, server_port);
    if (sock < 0) {
        fprintf(stderr, "Failed to connect to server\n");
        return 1;
    }
    printf(COLOR_GREEN "✓ Connected to server\n\n" COLOR_RESET);
    
    // Start handshake timer
    pq_perf_start_handshake(&metrics);
    
    // ============================================================
    // STEP 1: Generate Kyber keypair and send ClientHello
    // ============================================================
    printf(COLOR_BOLD "═══ Phase 1: Client Key Generation ═══\n" COLOR_RESET);
    
    uint8_t kyber_pk[KYBER_PUBLIC_KEY_BYTES];
    uint8_t kyber_sk[KYBER_SECRET_KEY_BYTES];
    
    uint64_t kem_keygen_start = pq_get_time_us();
    if (pq_kyber_keypair(kyber_pk, kyber_sk) != 0) {
        fprintf(stderr, "ERROR: Kyber keypair generation failed\n");
        close(sock);
        return 1;
    }
    metrics.kem_keygen_time_us = pq_get_time_us() - kem_keygen_start;
    metrics.kem_public_key_size = KYBER_PUBLIC_KEY_BYTES;
    
    printf(COLOR_GREEN "✓ Generated Kyber-768 keypair (%.2f ms)\n" COLOR_RESET, 
           pq_microseconds_to_milliseconds(metrics.kem_keygen_time_us));
    printf("  • Public Key Size: %zu bytes\n", metrics.kem_public_key_size);
    printf("\n");
    
    // Send ClientHello with Kyber public key
    handshake_message_t client_hello = {
        .type = MSG_CLIENT_HELLO,
        .length = KYBER_PUBLIC_KEY_BYTES,
        .data = kyber_pk
    };
    
    printf(COLOR_GREEN "→ Sending ClientHello with Kyber public key...\n" COLOR_RESET);
    if (send_message(sock, &client_hello) < 0) {
        fprintf(stderr, "ERROR: Failed to send ClientHello\n");
        close(sock);
        return 1;
    }
    metrics.bytes_sent += sizeof(client_hello.type) + sizeof(client_hello.length) + client_hello.length;
    printf(COLOR_GREEN "✓ ClientHello sent (%u bytes)\n\n" COLOR_RESET, client_hello.length + 5);
    
    // ============================================================
    // STEP 2: Receive ServerHello with Kyber ciphertext
    // ============================================================
    printf(COLOR_BOLD "═══ Phase 2: Server Hello ═══\n" COLOR_RESET);
    
    handshake_message_t server_hello;
    printf(COLOR_CYAN "← Receiving ServerHello...\n" COLOR_RESET);
    if (receive_message(sock, &server_hello) < 0 || server_hello.type != MSG_SERVER_HELLO) {
        fprintf(stderr, "ERROR: Failed to receive ServerHello\n");
        close(sock);
        return 1;
    }
    metrics.bytes_received += sizeof(server_hello.type) + sizeof(server_hello.length) + server_hello.length;
    metrics.kem_ciphertext_size = server_hello.length;
    printf(COLOR_GREEN "✓ ServerHello received (%u bytes)\n" COLOR_RESET, server_hello.length + 5);
    printf("  • Kyber Ciphertext Size: %zu bytes\n", metrics.kem_ciphertext_size);
    printf("\n");
    
    // Decapsulate to get shared secret
    uint8_t shared_secret[KYBER_SHARED_SECRET_BYTES];
    uint64_t kem_decaps_start = pq_get_time_us();
    if (pq_kyber_decapsulate(shared_secret, server_hello.data, kyber_sk) != 0) {
        fprintf(stderr, "ERROR: Kyber decapsulation failed\n");
        free_message(&server_hello);
        close(sock);
        return 1;
    }
    metrics.kem_decaps_time_us = pq_get_time_us() - kem_decaps_start;
    
    printf(COLOR_GREEN "✓ Decapsulated shared secret (%.2f ms)\n" COLOR_RESET,
           pq_microseconds_to_milliseconds(metrics.kem_decaps_time_us));
    printf("  • Shared Secret: %d bytes\n", KYBER_SHARED_SECRET_BYTES);
    printf("\n");
    free_message(&server_hello);
    
    // ============================================================
    // STEP 3: Receive Certificate (Dilithium public key)
    // ============================================================
    printf(COLOR_BOLD "═══ Phase 3: Certificate ═══\n" COLOR_RESET);
    
    handshake_message_t certificate;
    printf(COLOR_CYAN "← Receiving Certificate...\n" COLOR_RESET);
    if (receive_message(sock, &certificate) < 0 || certificate.type != MSG_CERTIFICATE) {
        fprintf(stderr, "ERROR: Failed to receive Certificate\n");
        close(sock);
        return 1;
    }
    metrics.bytes_received += sizeof(certificate.type) + sizeof(certificate.length) + certificate.length;
    metrics.sig_public_key_size = certificate.length;
    
    printf(COLOR_GREEN "✓ Certificate received (%u bytes)\n" COLOR_RESET, certificate.length + 5);
    printf("  • Dilithium Public Key: %zu bytes\n", metrics.sig_public_key_size);
    printf("\n");
    
    uint8_t *dilithium_pk = certificate.data;
    
    // ============================================================
    // STEP 4: Receive and verify CertificateVerify
    // ============================================================
    printf(COLOR_BOLD "═══ Phase 4: Certificate Verification ═══\n" COLOR_RESET);
    
    handshake_message_t cert_verify;
    printf(COLOR_CYAN "← Receiving CertificateVerify...\n" COLOR_RESET);
    if (receive_message(sock, &cert_verify) < 0 || cert_verify.type != MSG_CERTIFICATE_VERIFY) {
        fprintf(stderr, "ERROR: Failed to receive CertificateVerify\n");
        free_message(&certificate);
        close(sock);
        return 1;
    }
    metrics.bytes_received += sizeof(cert_verify.type) + sizeof(cert_verify.length) + cert_verify.length;
    metrics.signature_size = cert_verify.length;
    
    printf(COLOR_GREEN "✓ CertificateVerify received (%u bytes)\n" COLOR_RESET, cert_verify.length + 5);
    printf("  • Dilithium Signature: %zu bytes\n", metrics.signature_size);
    printf("\n");
    
    // Verify signature (signing handshake transcript hash)
    uint8_t transcript[] = "handshake_transcript_hash";
    uint64_t verify_start = pq_get_time_us();
    int verify_result = pq_dilithium_verify(cert_verify.data, cert_verify.length,
                                            transcript, sizeof(transcript) - 1, dilithium_pk);
    metrics.verify_time_us = pq_get_time_us() - verify_start;
    
    if (verify_result != 0) {
        fprintf(stderr, "ERROR: Signature verification failed\n");
        free_message(&certificate);
        free_message(&cert_verify);
        close(sock);
        return 1;
    }
    
    printf(COLOR_GREEN "✓ Signature verified successfully (%.2f ms)\n" COLOR_RESET,
           pq_microseconds_to_milliseconds(metrics.verify_time_us));
    printf("\n");
    
    free_message(&cert_verify);
    
    // ============================================================
    // STEP 5: Send Finished message
    // ============================================================
    printf(COLOR_BOLD "═══ Phase 5: Handshake Completion ═══\n" COLOR_RESET);
    
    uint8_t finished_data[] = "client_finished";
    handshake_message_t finished = {
        .type = MSG_FINISHED,
        .length = sizeof(finished_data) - 1,
        .data = finished_data
    };
    
    printf(COLOR_GREEN "→ Sending Finished...\n" COLOR_RESET);
    if (send_message(sock, &finished) < 0) {
        fprintf(stderr, "ERROR: Failed to send Finished\n");
        free_message(&certificate);
        close(sock);
        return 1;
    }
    metrics.bytes_sent += sizeof(finished.type) + sizeof(finished.length) + finished.length;
    printf(COLOR_GREEN "✓ Finished sent\n\n" COLOR_RESET);
    
    free_message(&certificate);
    
    // End handshake timer
    pq_perf_end_handshake(&metrics);
    
    printf(COLOR_BOLD COLOR_GREEN "═══════════════════════════════════════════════════════════════\n" COLOR_RESET);
    printf(COLOR_BOLD COLOR_GREEN "  POST-QUANTUM TLS HANDSHAKE COMPLETED SUCCESSFULLY!\n" COLOR_RESET);
    printf(COLOR_BOLD COLOR_GREEN "═══════════════════════════════════════════════════════════════\n" COLOR_RESET);
    printf("\n");
    
    // Print performance summary
    pq_perf_print_summary(&metrics);
    
    // Save to CSV
    pq_perf_save_to_csv(&metrics, "results/pq_tls_metrics.csv");
    
    // Exchange application data
    printf(COLOR_BOLD "═══ Application Data Exchange ═══\n" COLOR_RESET);
    const char *app_msg = "Hello from PQ-TLS client!";
    handshake_message_t app_data = {
        .type = MSG_APPLICATION_DATA,
        .length = strlen(app_msg),
        .data = (uint8_t *)app_msg
    };
    
    printf(COLOR_GREEN "→ Sending: \"%s\"\n" COLOR_RESET, app_msg);
    send_message(sock, &app_data);
    
    handshake_message_t server_response;
    if (receive_message(sock, &server_response) >= 0) {
        printf(COLOR_CYAN "← Received: \"%.*s\"\n\n" COLOR_RESET, 
               server_response.length, server_response.data);
        free_message(&server_response);
    }
    
    close(sock);
    printf(COLOR_GREEN "✓ Connection closed\n\n" COLOR_RESET);
    
    return 0;
}

int connect_to_server(const char *host, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }
    
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &server_addr.sin_addr) <= 0) {
        perror("inet_pton");
        close(sock);
        return -1;
    }
    
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(sock);
        return -1;
    }
    
    return sock;
}

int send_message(int sock, const handshake_message_t *msg) {
    // Send type (1 byte)
    if (send(sock, &msg->type, 1, 0) != 1) {
        perror("send type");
        return -1;
    }
    
    // Send length (4 bytes, network byte order)
    uint32_t length_net = htonl(msg->length);
    if (send(sock, &length_net, 4, 0) != 4) {
        perror("send length");
        return -1;
    }
    
    // Send data
    if (msg->length > 0) {
        size_t sent = 0;
        while (sent < msg->length) {
            ssize_t n = send(sock, msg->data + sent, msg->length - sent, 0);
            if (n <= 0) {
                perror("send data");
                return -1;
            }
            sent += n;
        }
    }
    
    return 0;
}

int receive_message(int sock, handshake_message_t *msg) {
    // Receive type (1 byte)
    if (recv(sock, &msg->type, 1, MSG_WAITALL) != 1) {
        perror("recv type");
        return -1;
    }
    
    // Receive length (4 bytes, network byte order)
    uint32_t length_net;
    if (recv(sock, &length_net, 4, MSG_WAITALL) != 4) {
        perror("recv length");
        return -1;
    }
    msg->length = ntohl(length_net);
    
    // Allocate and receive data
    if (msg->length > 0) {
        msg->data = malloc(msg->length);
        if (!msg->data) {
            perror("malloc");
            return -1;
        }
        
        size_t received = 0;
        while (received < msg->length) {
            ssize_t n = recv(sock, msg->data + received, msg->length - received, MSG_WAITALL);
            if (n <= 0) {
                perror("recv data");
                free(msg->data);
                return -1;
            }
            received += n;
        }
    } else {
        msg->data = NULL;
    }
    
    return 0;
}

void free_message(handshake_message_t *msg) {
    if (msg && msg->data) {
        free(msg->data);
        msg->data = NULL;
    }
}
