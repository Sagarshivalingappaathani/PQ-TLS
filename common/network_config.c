#include "network_config.h"
#include <stdio.h>

const char* network_type_to_string(int network_type) {
    switch (network_type) {
        case 1: return "same-machine";
        case 2: return "two-machines-lan";
        case 3: return "mobile-hotspot";
        case 4: return "laptop-to-vm";
        default: return "unknown";
    }
}

const char* get_server_ip(int network_type) {
    switch (network_type) {
        case 1: return "127.0.0.1";
        case 2: return "192.168.1.100";
        case 3: return "192.168.43.1";
        case 4: return "3.108.41.178";
        default: return "127.0.0.1";
    }
}
