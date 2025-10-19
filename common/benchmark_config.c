#include "benchmark_config.h"
#include "network_config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

int init_benchmark_config(BenchmarkConfig *config, int level, const char *mode, int network_type) {
    config->level = level;
    strncpy(config->mode, mode, sizeof(config->mode) - 1);
    config->network_type = network_type;
    config->server_port = 4433;
    config->num_iterations = 10;
    
    strncpy(config->network_name, network_type_to_string(network_type), sizeof(config->network_name) - 1);
    strncpy(config->server_ip, get_server_ip(network_type), sizeof(config->server_ip) - 1);
    
    if (strcmp(mode, "classic") == 0) {
        switch (level) {
            case 1:
                strcpy(config->kex_algorithm, "X25519");
                strcpy(config->sig_algorithm, "ECDSA+SHA256:P-256");
                strcpy(config->cipher_suite, "TLS_AES_128_GCM_SHA256");
                break;
            case 3:
                strcpy(config->kex_algorithm, "X448");
                strcpy(config->sig_algorithm, "ECDSA+SHA256:P-384");
                strcpy(config->cipher_suite, "TLS_AES_128_GCM_SHA256");
                break;
            case 5:
                strcpy(config->kex_algorithm, "P-521");
                strcpy(config->sig_algorithm, "RSA-PSS+SHA256");
                strcpy(config->cipher_suite, "TLS_AES_256_GCM_SHA384");
                break;
            default:
                fprintf(stderr, "Invalid security level: %d\n", level);
                return -1;
        }
    } else if (strcmp(mode, "quantum") == 0) {
        switch (level) {
            case 1:
                strcpy(config->kex_algorithm, "kyber512");
                strcpy(config->sig_algorithm, "dilithium2");
                strcpy(config->cipher_suite, "TLS_AES_128_GCM_SHA256");
                break;
            case 3:
                strcpy(config->kex_algorithm, "kyber768");
                strcpy(config->sig_algorithm, "dilithium3");
                strcpy(config->cipher_suite, "TLS_AES_128_GCM_SHA256");
                break;
            case 5:
                strcpy(config->kex_algorithm, "kyber1024");
                strcpy(config->sig_algorithm, "dilithium5");
                strcpy(config->cipher_suite, "TLS_AES_256_GCM_SHA384");
                break;
            default:
                fprintf(stderr, "Invalid security level: %d\n", level);
                return -1;
        }
    } else {
        fprintf(stderr, "Invalid mode: %s\n", mode);
        return -1;
    }
    
    generate_output_path(config);
    
    return 0;
}

void generate_output_path(BenchmarkConfig *config) {
    snprintf(config->output_dir, sizeof(config->output_dir),
             "results/level%d/%s/%s",
             config->level, config->network_name, config->mode);
    
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "mkdir -p %s", config->output_dir);
    system(cmd);
}
