#ifndef NETWORK_CONFIG_H
#define NETWORK_CONFIG_H

typedef enum {
    NETWORK_SAME_MACHINE = 1,
    NETWORK_TWO_MACHINES_LAN = 2,
    NETWORK_MOBILE_HOTSPOT = 3,
    NETWORK_LAPTOP_TO_VM = 4
} NetworkType;

const char* network_type_to_string(int network_type);
const char* get_server_ip(int network_type);

#endif
