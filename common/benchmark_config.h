#ifndef BENCHMARK_CONFIG_H
#define BENCHMARK_CONFIG_H

typedef struct {
    int level;
    char mode[16];
    int network_type;
    char network_name[32];
    char server_ip[64];
    int server_port;
    char output_dir[256];
    int num_iterations;
    char kex_algorithm[64];
    char sig_algorithm[128];
    char cipher_suite[64];
} BenchmarkConfig;

int init_benchmark_config(BenchmarkConfig *config, int level, const char *mode, int network_type);
void generate_output_path(BenchmarkConfig *config);

#endif
