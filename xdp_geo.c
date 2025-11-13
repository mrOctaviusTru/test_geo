#include "maps.h"

static __always_inline int check_geo(__u32 src_ip) {
    __u32 config_key = 0;
    struct cfg_geo *geo_cfg = bpf_map_lookup_elem(&cfg_geo_m, &config_key);
    
    if (!geo_cfg || !geo_cfg->enabled)
        return XDP_PASS;

    struct geo_ip_key key = {
        .prefix_len = 32,
        .ip = src_ip,
    };

    struct geo_value *geo = bpf_map_lookup_elem(&geo_m, &key);
    if (!geo)
        return geo_cfg->default_action ? XDP_DROP : XDP_PASS;

    // Сначала проверяем явно разрешенные
    #pragma unroll
    for (int i = 0; i < MAX_GEO_ALLOWED; i++) {
        if (geo_cfg->allowed_geos[i] == 0) break;
        if (geo_cfg->allowed_geos[i] == geo->geoname_id) {
            bpf_printk("xdp_geo_filter: PASS - country %u in allow list", geo->geoname_id);
            return XDP_PASS;
        }
    }

    // Затем проверяем явно запрещенные
    #pragma unroll
    for (int i = 0; i < MAX_GEO_BLOCKED; i++) {
        if (geo_cfg->blocked_geos[i] == 0) break;
        if (geo_cfg->blocked_geos[i] == geo->geoname_id) {
            bpf_printk("xdp_geo_filter: DROP - country %u in block list", geo->geoname_id);
            return XDP_DROP;
        }
    }

    return geo_cfg->default_action ? XDP_DROP : XDP_PASS;
}

SEC("xdp")
int xdp_geo_filter(struct xdp_md *ctx) {

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    
    if ((void *)(eth + 1) > data_end) return XDP_PASS; 
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return XDP_PASS; 
    }

    __u32 src_ip = iph->saddr;

    if (check_geo(src_ip) == XDP_DROP) {
        return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";

