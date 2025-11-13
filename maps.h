#ifndef __MAPS_H__
#define __MAPS_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800

#define MAX_GEO_ALLOWED 32
#define MAX_GEO_BLOCKED 32

struct geo_ip_key {
    __u32 prefix_len;   // Длина префикса в битах
    __u32 ip;           //IP адрес
};

struct geo_value {
    __u32 geoname_id;
};

struct cfg_geo {
    __u32 allowed_geos[MAX_GEO_ALLOWED];
    __u32 blocked_geos[MAX_GEO_BLOCKED];
    __u8 default_action;  // 0 = разрешить не указанные, 1 = запретить не указанные
    __u8 enabled;
    __u16 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32); // policy_id
    __type(value, struct cfg_geo);
    __uint(max_entries, 1);
} cfg_geo_m SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct geo_ip_key);
    __type(value, struct geo_value);
    __uint(max_entries, 600000);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} geo_m SEC(".maps");

#endif

