```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>

#define BUFFER_SIZE 1024

#define DNS_HEADER_SIZE 12
#define MAX_HOSTNAME_SIZE 255
#define DNS_PORT 53
#define DNS_ADDR "192.168.182.133"


/*rcode:
返回码字段，表示响应的差错状态。当值为 0 时，表示没有错误；当值为 1 时，表示报文格式错误（Format error），服务器不能理解请求的报文；
当值为 2 时，表示域名服务器失败（Server failure），因为服务器的原因导致没办法处理这个请求；当值为 3 时，表示名字错误（Name Error），
只有对授权域名解析服务器有意义，指出解析的域名不存在；当值为 4 时，表示查询类型不支持（Not Implemented），即域名服务器不支持查询类型；
当值为 5 时，表示拒绝（Refused），一般是服务器由于设置的策略拒绝给出应答，如服务器不希望对某些请求者给出应答。
*/
// DNS Header结构
struct DNSHeader {
    uint16_t id;         // 会话标识
    uint8_t rd : 1;      // 递归请求标志
    uint8_t tc : 1;      // 截断标志
    uint8_t aa : 1;      // 授权回答标志
    uint8_t opcode : 4;  // 操作代码
    uint8_t qr : 1;      // 查询/响应标志
    uint8_t rcode : 4;   // 响应代码
    uint8_t cd : 1;      // 检查禁用标志
    uint8_t ad : 1;      // 授权数据标志
    uint8_t z : 1;       // 保留标志
    uint8_t ra : 1;      // 递归可用标志
    uint16_t qdcount;    // 问题数
    uint16_t ancount;    // 回答数
    uint16_t nscount;    // 授权回答数
    uint16_t arcount;    // 额外信息数
};

// 构造DNS查询数据包
int build_dns_query(const char *hostname, uint8_t *buffer, size_t buffer_size) {
    // 检查缓冲区大小是否足够
    if (buffer_size < (DNS_HEADER_SIZE + strlen(hostname) + 2 + 2 + 2)) {
        fprintf(stderr, "Buffer size too small for DNS query.\n");
        return -1;
    }

    // 构造DNS Header
    struct DNSHeader *dnsHeader = (struct DNSHeader *)buffer;
    memset(dnsHeader, 0, DNS_HEADER_SIZE);
    dnsHeader->id = htons((uint16_t)rand());

    srand(time(NULL));

    // 设置查询标志和问题数
    dnsHeader->qr = 0;    // 查询标志
    dnsHeader->rd = 1;    // 递归请求标志
    dnsHeader->qdcount = htons(1);

    // 构造DNS Question部分
    uint8_t *question = buffer + DNS_HEADER_SIZE;
    size_t question_len = strlen(hostname) + 2 + 2 + 2;

    // 将域名转换为DNS格式
    size_t i, j,len_pos;
    for ( i = 0,j=1,len_pos = 0; i < strlen(hostname); ++i , ++j ) {
        if(hostname[i] == '.'){
            question[len_pos] = i - len_pos;
            len_pos = j;
        }else{
            question[j] = hostname[i];
        }
    }
    question[len_pos] = i - len_pos;
    question[j] = '\0';

    // 添加查询类型和类别（这里使用A记录查询，IPv4地址）
    *(uint16_t *)(question + j + 1) = htons(1);  // Type A
    *(uint16_t *)(question + j + 3) = htons(1);  // Class IN

    return DNS_HEADER_SIZE + question_len;
}

// 解析DNS响应数据包
void parse_dns_response(uint8_t *buffer, size_t buffer_size) {
    // 解析DNS Header
    struct DNSHeader *dnsHeader = (struct DNSHeader *)buffer;
    uint16_t answer_count = ntohs(dnsHeader->ancount);

    printf("DNS Response ID: %d\n", ntohs(dnsHeader->id));
    printf("DNS Response QR (Query/Response): %s\n", dnsHeader->qr ? "Response" : "Query");
    printf("DNS Response RCode (Response Code): %d\n", dnsHeader->rcode);
    printf("Number of Answers: %d\n", answer_count);

    if(dnsHeader->rcode != 0){
        return;
    }

    // 跳过DNS question 部分
    uint8_t *answer =  buffer + DNS_HEADER_SIZE;
    while(*answer){
        answer = answer + *answer + 1;
    }
    answer += 5;
   
    // 解析answer
    for (int i = 0; i < answer_count; ++i) {
        // 解析域名
        uint16_t name_field = ntohs(*((uint16_t*)answer));
        if(name_field & 0xC000 ){
            uint16_t offset = name_field & 0x3FFF;
            answer+=2;
        }else{
            while(*answer){
                answer++;
            }
            answer++;
        }

        // 解析Type和Class
        uint16_t type_field = ntohs(*(uint16_t *)answer);
        answer+=2;
        uint16_t class_field = ntohs(*(uint16_t *)(answer));
        answer+=2;

        // 解析TTL和数据长度
        uint32_t ttl_field = ntohl(*(uint32_t *)(answer));
        answer+=4;
        uint16_t data_len_field = ntohs(*(uint16_t *)(answer));
        answer+=2;

        if (type_field == 1 && class_field == 1 && data_len_field == 4) {
            printf("%d.%d.%d.%d\n",answer[0],answer[1],answer[2],answer[3]);
        }

        //network byte
        answer += data_len_field;
    }
}

int main() {
    const char *hostname = "www.dnps.com";
    uint8_t dns_query[BUFFER_SIZE];
    uint8_t dns_response[BUFFER_SIZE];
    uint16_t dns_response_size = 0;
    int sockfd;
    struct sockaddr_in server_addr;

    // 创建 UDP 套接字
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    // 配置服务器地址信息
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(DNS_ADDR);
    server_addr.sin_port = htons(DNS_PORT);

    // 构造DNS查询数据包
    int query_size = build_dns_query(hostname, dns_query+2, sizeof(dns_query)-2);
    if (query_size < 0) {
        return 1;
    }
    *(uint16_t*)dns_query = htons(query_size);

    if(connect(sockfd,(struct sockaddr *)(&server_addr),sizeof(server_addr))!= 0){
        perror("connect");
        goto fault;
    }

    // 送DNS查询数据包到DNS服务器并接收响应
    if(send(sockfd, dns_query, query_size+2, 0) == -1){
        perror("send");
        goto fault;
    }
    if(recv(sockfd, &dns_response_size, 2, 0) == -1){
        perror("recv");
        goto fault;
    }
    dns_response_size = ntohs(dns_response_size);
    if(dns_response_size > BUFFER_SIZE){
        perror("dns_response_size");
        goto fault;
    }
    printf("dns_response_size:%d\n",dns_response_size);
    query_size = recv(sockfd, dns_response, dns_response_size, 0);
    if(query_size == -1){
        perror("recv");
        goto fault;
    }

    // 解析DNS响应数据包
    parse_dns_response(dns_response, query_size);

    close(sockfd);
    return 0;
fault:
    close(sockfd);
    return -1;
}
```