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
int create_server_socket(int port);
int accept_client(int server_sock);
int send_message(int sock, const handshake_message_t *msg);
int receive_message(int sock, handshake_message_t *msg);
void free_message(handshake_message_t *msg);
void handle_client(int client_sock);

// Global Dilithium keypair (generated once)
uint8_t g_dilithium_pk[DILITHIUM_PUBLIC_KEY_BYTES];
uint8_t g_dilithium_sk[DILITHIUM_SECRET_KEY_BYTES];

int main(int argc, char *argv[]) {
    int port = 4433;
    if (argc > 1) {
        port = atoi(argv[1]);
    }
    
    printf(COLOR_BOLD COLOR_MAGENTA "\n╔═══════════════════════════════════════════════════════════════╗\n" COLOR_RESET);
    printf(COLOR_BOLD COLOR_MAGENTA "║          POST-QUANTUM TLS 1.3 SERVER                          ║\n" COLOR_RESET);
    printf(COLOR_BOLD COLOR_MAGENTA "╚═══════════════════════════════════════════════════════════════╝\n" COLOR_RESET);
    printf("\n");
    
    // Generate Dilithium keypair once
    printf(COLOR_YELLOW "→ Generating Dilithium2 keypair...\n" COLOR_RESET);
    uint64_t keygen_start = pq_get_time_us();
    if (pq_dilithium_keypair(g_dilithium_pk, g_dilithium_sk) != 0) {
        fprintf(stderr, "ERROR: Dilithium keypair generation failed\n");
        return 1;
    }
    uint64_t keygen_time = pq_get_time_us() - keygen_start;
    printf(COLOR_GREEN "✓ Dilithium2 keypair generated (%.2f ms)\n" COLOR_RESET,
           pq_microseconds_to_milliseconds(keygen_time));
    printf("  • Public Key: %d bytes\n", DILITHIUM_PUBLIC_KEY_BYTES);
    printf("  • Secret Key: %d bytes\n\n", DILITHIUM_SECRET_KEY_BYTES);
    
    // Create server socket
    int server_sock = create_server_socket(port);
    if (server_sock < 0) {
        fprintf(stderr, "Failed to create server socket\n");
        return 1;
    }
    
    printf(COLOR_GREEN "✓ Server listening on 0.0.0.0:%d\n\n" COLOR_RESET, port);
    printf(COLOR_YELLOW "Waiting for clients...\n\n" COLOR_RESET);
    
    while (1) {
        int client_sock = accept_client(server_sock);
        if (client_sock < 0) {
            continue;
        }
        
        handle_client(client_sock);
        close(client_sock);
        
        printf("\n" COLOR_YELLOW "Waiting for next client...\n\n" COLOR_RESET);
    }
    
    close(server_sock);
    return 0;
}

void handle_client(int client_sock) {
    printf(COLOR_BOLD COLOR_CYAN "═══════════════════════════════════════════════════════════════\n" COLOR_RESET);
    printf(COLOR_BOLD COLOR_CYAN "  New client connected - Starting PQ-TLS handshake\n" COLOR_RESET);
    printf(COLOR_BOLD COLOR_CYAN "═══════════════════════════════════════════════════════════════\n" COLOR_RESET);
    printf("\n");
    
    // Initialize performance metrics
    pq_performance_metrics_t metrics;
    pq_perf_init(&metrics);
    
    // Start handshake timer
    pq_perf_start_handshake(&metrics);
    
    // ============================================================
    // STEP 1: Receive ClientHello with Kyber public key
    // ============================================================
    printf(COLOR_BOLD "═══ Phase 1: Client Hello ═══\n" COLOR_RESET);
    
    handshake_message_t client_hello;
    printf(COLOR_CYAN "← Receiving ClientHello...\n" COLOR_RESET);
    if (receive_message(client_sock, &client_hello) < 0 || client_hello.type != MSG_CLIENT_HELLO) {
        fprintf(stderr, "ERROR: Failed to receive ClientHello\n");
        return;
    }
    metrics.bytes_received += sizeof(client_hello.type) + sizeof(client_hello.length) + client_hello.length;
    metrics.kem_public_key_size = client_hello.length;
    
    printf(COLOR_GREEN "✓ ClientHello received (%u bytes)\n" COLOR_RESET, client_hello.length + 5);
    printf("  • Kyber Public Key: %zu bytes\n", metrics.kem_public_key_size);
    printf("\n");
    
    uint8_t *kyber_pk = client_hello.data;
    
    // ============================================================
    // STEP 2: Encapsulate and send ServerHello
    // ============================================================
    printf(COLOR_BOLD "═══ Phase 2: Server Key Encapsulation ═══\n" COLOR_RESET);
    
    uint8_t kyber_ct[KYBER_CIPHERTEXT_BYTES];
    uint8_t shared_secret[KYBER_SHARED_SECRET_BYTES];
    
    uint64_t kem_encaps_start = pq_get_time_us();
    if (pq_kyber_encapsulate(kyber_ct, shared_secret, kyber_pk) != 0) {
        fprintf(stderr, "ERROR: Kyber encapsulation failed\n");
        free_message(&client_hello);
        return;
    }
    metrics.kem_encaps_time_us = pq_get_time_us() - kem_encaps_start;
    metrics.kem_ciphertext_size = KYBER_CIPHERTEXT_BYTES;
    
    printf(COLOR_GREEN "✓ Encapsulated shared secret (%.2f ms)\n" COLOR_RESET,
           pq_microseconds_to_milliseconds(metrics.kem_encaps_time_us));
    printf("  • Ciphertext: %zu bytes\n", metrics.kem_ciphertext_size);
    printf("  • Shared Secret: %d bytes\n", KYBER_SHARED_SECRET_BYTES);
    printf("\n");
    
    free_message(&client_hello);
    
    // Send ServerHello
    handshake_message_t server_hello = {
        .type = MSG_SERVER_HELLO,
        .length = KYBER_CIPHERTEXT_BYTES,
        .data = kyber_ct
    };
    
    printf(COLOR_MAGENTA "→ Sending ServerHello with Kyber ciphertext...\n" COLOR_RESET);
    if (send_message(client_sock, &server_hello) < 0) {
        fprintf(stderr, "ERROR: Failed to send ServerHello\n");
        return;
    }
    metrics.bytes_sent += sizeof(server_hello.type) + sizeof(server_hello.length) + server_hello.length;
    printf(COLOR_GREEN "✓ ServerHello sent (%u bytes)\n\n" COLOR_RESET, server_hello.length + 5);
    
    // ============================================================
    // STEP 3: Send Certificate (Dilithium public key)
    // ============================================================
    printf(COLOR_BOLD "═══ Phase 3: Certificate ═══\n" COLOR_RESET);
    
    handshake_message_t certificate = {
        .type = MSG_CERTIFICATE,
        .length = DILITHIUM_PUBLIC_KEY_BYTES,
        .data = g_dilithium_pk
    };
    
    printf(COLOR_MAGENTA "→ Sending Certificate (Dilithium public key)...\n" COLOR_RESET);
    if (send_message(client_sock, &certificate) < 0) {
        fprintf(stderr, "ERROR: Failed to send Certificate\n");
        return;
    }
    metrics.bytes_sent += sizeof(certificate.type) + sizeof(certificate.length) + certificate.length;
    metrics.sig_public_key_size = DILITHIUM_PUBLIC_KEY_BYTES;
    
    printf(COLOR_GREEN "✓ Certificate sent (%u bytes)\n" COLOR_RESET, certificate.length + 5);
    printf("  • Dilithium Public Key: %zu bytes\n", metrics.sig_public_key_size);
    printf("\n");
    
    // ============================================================
    // STEP 4: Sign and send CertificateVerify
    // ============================================================
    printf(COLOR_BOLD "═══ Phase 4: Certificate Verification ═══\n" COLOR_RESET);
    
    // Sign handshake transcript
    uint8_t transcript[] = "handshake_transcript_hash";
    uint8_t signature[DILITHIUM_SIGNATURE_BYTES];
    size_t sig_len = DILITHIUM_SIGNATURE_BYTES;
    
    uint64_t sign_start = pq_get_time_us();
    if (pq_dilithium_sign(signature, &sig_len, transcript, sizeof(transcript) - 1, g_dilithium_sk) != 0) {
        fprintf(stderr, "ERROR: Dilithium signing failed\n");
        return;
    }
    metrics.signature_time_us = pq_get_time_us() - sign_start;
    metrics.signature_size = sig_len;
    
    printf(COLOR_GREEN "✓ Generated Dilithium signature (%.2f ms)\n" COLOR_RESET,
           pq_microseconds_to_milliseconds(metrics.signature_time_us));
    printf("  • Signature Size: %zu bytes\n", metrics.signature_size);
    printf("\n");
    
    // Send CertificateVerify
    handshake_message_t cert_verify = {
        .type = MSG_CERTIFICATE_VERIFY,
        .length = sig_len,
        .data = signature
    };
    
    printf(COLOR_MAGENTA "→ Sending CertificateVerify...\n" COLOR_RESET);
    if (send_message(client_sock, &cert_verify) < 0) {
        fprintf(stderr, "ERROR: Failed to send CertificateVerify\n");
        return;
    }
    metrics.bytes_sent += sizeof(cert_verify.type) + sizeof(cert_verify.length) + cert_verify.length;
    printf(COLOR_GREEN "✓ CertificateVerify sent (%zu bytes)\n\n" COLOR_RESET, sig_len + 5);
    
    // ============================================================
    // STEP 5: Receive Finished message
    // ============================================================
    printf(COLOR_BOLD "═══ Phase 5: Handshake Completion ═══\n" COLOR_RESET);
    
    handshake_message_t finished;
    printf(COLOR_CYAN "← Receiving Finished...\n" COLOR_RESET);
    if (receive_message(client_sock, &finished) < 0 || finished.type != MSG_FINISHED) {
        fprintf(stderr, "ERROR: Failed to receive Finished\n");
        return;
    }
    metrics.bytes_received += sizeof(finished.type) + sizeof(finished.length) + finished.length;
    printf(COLOR_GREEN "✓ Finished received\n\n" COLOR_RESET);
    free_message(&finished);
    
    // End handshake timer
    pq_perf_end_handshake(&metrics);
    
    printf(COLOR_BOLD COLOR_GREEN "═══════════════════════════════════════════════════════════════\n" COLOR_RESET);
    printf(COLOR_BOLD COLOR_GREEN "  POST-QUANTUM TLS HANDSHAKE COMPLETED SUCCESSFULLY!\n" COLOR_RESET);
    printf(COLOR_BOLD COLOR_GREEN "═══════════════════════════════════════════════════════════════\n" COLOR_RESET);
    printf("\n");
    
    // Print performance summary
    pq_perf_print_summary(&metrics);
    
    // Save to CSV
    pq_perf_save_to_csv(&metrics, "results/pq_server_metrics.csv");
    
    // Exchange application data
    printf(COLOR_BOLD "═══ Application Data Exchange ═══\n" COLOR_RESET);
    
    handshake_message_t app_data;
    if (receive_message(client_sock, &app_data) >= 0 && app_data.type == MSG_APPLICATION_DATA) {
        printf(COLOR_CYAN "← Received: \"%.*s\"\n" COLOR_RESET, 
               app_data.length, app_data.data);
        free_message(&app_data);
        
        const char *response = "Hello from PQ-TLS server!";
        handshake_message_t server_response = {
            .type = MSG_APPLICATION_DATA,
            .length = strlen(response),
            .data = (uint8_t *)response
        };
        printf(COLOR_MAGENTA "→ Sending: \"%s\"\n\n" COLOR_RESET, response);
        send_message(client_sock, &server_response);
    }
    
    printf(COLOR_GREEN "✓ Client session completed\n" COLOR_RESET);
}

int create_server_socket(int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }
    
    int opt = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        close(sock);
        return -1;
    }
    
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);
    
    if (bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(sock);
        return -1;
    }
    
    if (listen(sock, 5) < 0) {
        perror("listen");
        close(sock);
        return -1;
    }
    
    return sock;
}

int accept_client(int server_sock) {
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    
    int client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &addr_len);
    if (client_sock < 0) {
        perror("accept");
        return -1;
    }
    
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    printf(COLOR_GREEN "✓ Client connected from %s:%d\n\n" COLOR_RESET,
           client_ip, ntohs(client_addr.sin_port));
    
    return client_sock;
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
