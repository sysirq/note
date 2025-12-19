# dns over tls

```c
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"

//dns header struct(RFC 1035)
typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} dns_header_t;

/**
 * Converts a domain name to DNS label format.
 * Example: "www.google.com" -> "\x03www\x06google\x03com\x00"
 */
static void encode_dns_name(const char *domain, unsigned char *output) {
    const char *start = domain;
    const char *pos;
    int i = 0;

    while ((pos = strchr(start, '.')) != NULL) {
        int len = pos - start;
        output[i++] = (unsigned char)len;
        memcpy(&output[i], start, len);
        i += len;
        start = pos + 1;
    }
    // Handle the last segment
    int len = strlen(start);
    output[i++] = (unsigned char)len;
    memcpy(&output[i], start, len);
    i += len;
    output[i++] = 0x00; // Root null terminator
}

/**
 * DNS over TLS (DoT) Query Function
 * Returns: 0 on success, negative value on failure
 */
int get_ip_via_dot(const char *server_ip, const char *server_port, const char *query_domain, char *out_ip, size_t out_ip_len) {
    int ret = -1;
    mbedtls_net_context server_fd;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;

    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    // 1. Seed the Random Number Generator (RNG)
    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0) != 0) goto cleanup;

    // 2. Establish TCP Connection
    if (mbedtls_net_connect(&server_fd, server_ip, server_port, MBEDTLS_NET_PROTO_TCP) != 0) goto cleanup;

    // 3. Configure TLS
    if (mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, 
                                   MBEDTLS_SSL_TRANSPORT_STREAM, 
                                   MBEDTLS_SSL_PRESET_DEFAULT) != 0) goto cleanup;
    
    // NOTE: In production, load CA certs and use MBEDTLS_SSL_VERIFY_REQUIRED
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE); 
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    
    if (mbedtls_ssl_setup(&ssl, &conf) != 0) goto cleanup;

    // SNI is often required by DoT providers like Google or Cloudflare
    mbedtls_ssl_set_hostname(&ssl, "dns.google");
    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    // 4. Perform TLS Handshake
    if (mbedtls_ssl_handshake(&ssl) != 0) goto cleanup;

    // 5. Construct DNS Query Packet
    unsigned char packet[512];
    unsigned char name_buf[256];
    encode_dns_name(query_domain, name_buf);
    
    // Calculate name length including labels and the final 0x00
    int name_raw_len = 0;
    while(1) {
        int label_len = name_buf[name_raw_len];
        name_raw_len++;
        if (label_len == 0) break;
        name_raw_len += label_len;
    }

    dns_header_t header;
    header.id = htons(0x1234);     // Transaction ID
    header.flags = htons(0x0100);  // Recursion Desired
    header.qdcount = htons(1);     // 1 Question
    header.ancount = 0;
    header.nscount = 0;
    header.arcount = 0;

    // RFC 7858: DoT requires a 2-byte length prefix before the DNS message
    int dns_msg_body_len = sizeof(dns_header_t) + name_raw_len + 4;
    packet[0] = (dns_msg_body_len >> 8) & 0xFF;
    packet[1] = dns_msg_body_len & 0xFF;
    
    memcpy(packet + 2, &header, sizeof(dns_header_t));
    memcpy(packet + 2 + sizeof(dns_header_t), name_buf, name_raw_len);
    
    // Set Query Type A (0x0001) and Class IN (0x0001)
    uint16_t q_type = htons(1);
    uint16_t q_class = htons(1);
    memcpy(packet + 2 + sizeof(dns_header_t) + name_raw_len, &q_type, 2);
    memcpy(packet + 2 + sizeof(dns_header_t) + name_raw_len + 2, &q_class, 2);

    // 6. Send Request and Receive Response
    if (mbedtls_ssl_write(&ssl, packet, dns_msg_body_len + 2) <= 0) goto cleanup;

    unsigned char resp[1024];
    // Read the 2-byte length prefix of the response
    if (mbedtls_ssl_read(&ssl, resp, 2) <= 0) goto cleanup; 
    uint16_t resp_len = (resp[0] << 8) | resp[1];
    
    // Read the actual DNS response body
    if (mbedtls_ssl_read(&ssl, resp, resp_len) <= 0) goto cleanup; 

    // 7. Parse Response (Basic extraction of the first A record)
    // Skip DNS Header (12 bytes)
    unsigned char *p = resp + sizeof(dns_header_t);
    
    // Skip Question section (Name + Type(2) + Class(2))
    while (*p != 0) p++; 
    p += 5; 

    // Now pointing to Answer section. Handle possible DNS pointer compression (0xc0)
    if ((*p & 0xc0) == 0xc0) {
        p += 2; // Skip compressed name pointer
    } else {
        while (*p != 0) p++; // Skip full name
        p += 1;
    }

    // Skip Type(2), Class(2), TTL(4)
    p += 8;
    
    // Read Data Length (RDLENGTH)
    uint16_t rdlen = (p[0] << 8) | p[1];
    p += 2;

    // If RDLENGTH is 4, it is an IPv4 address
    if (rdlen == 4) {
        snprintf(out_ip, out_ip_len, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
        ret = 0; // Success
    }

cleanup:
    // Resource cleanup
    mbedtls_net_free(&server_fd);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return ret;
}

int main() {
    char ip[64];
    const char *domain = "www.google.com";
    
    printf("Querying %s via DoT (8.8.8.8:853)...\n", domain);
    
    if (get_ip_via_dot("8.8.8.8", "853", domain, ip, sizeof(ip)) == 0) {
        printf("Success! IP address: %s\n", ip);
    } else {
        printf("Failed to resolve domain. Possible reasons: Network error or timeout.\n");
    }

    return 0;
}
```