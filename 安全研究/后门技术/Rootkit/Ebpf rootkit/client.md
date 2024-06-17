```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "common.h"
#include "crc16.h"

typedef struct __attribute__((packed))
{
    uint16_t length;
    char command[COMMAND_MAX_LENGTH];
} Payload;

int read_random_data(char *dst, size_t len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1)
    {
        perror("open /dev/urandom error");
        return -1;
    }

    read(fd, dst, len);
    
    close(fd);

    return 0;
}

char *gen_payload_data(char *cmd,size_t *payload_data_len)
{
    Payload payload;
    char trigger_fragment1[START_PAD + CRC_DATA_LENGTH] = {0};
    int ret;
    uint16_t checksum;
    uint16_t trigger_fragment2_len;
    char trigger_fragment2[RANDOM_PAD_MAX_LEN] = {0};
    char *data;
    int data_len;
    int data_offset = 0;
    uint16_t tmp_16;
    int i;

    if (strlen(cmd) >= COMMAND_MAX_LENGTH)
    {
        return NULL;
    }

    payload.length = strlen(cmd);
    memcpy(payload.command, cmd, strlen(cmd));

    ret = read_random_data(trigger_fragment1, START_PAD + CRC_DATA_LENGTH);
    if (ret != 0)
    {
        return NULL;
    }

    checksum = crc16(trigger_fragment1 + START_PAD, CRC_DATA_LENGTH);
    trigger_fragment2_len = checksum % RANDOM_PAD_MAX_LEN;
    printf("CRC16: 0x%04X\n", checksum);
    printf("trigger_fragment2_len:%d\n",trigger_fragment2_len);

    ret = read_random_data(trigger_fragment2, trigger_fragment2_len);
    if (ret != 0)
    {
        return NULL;
    }

    *payload_data_len = data_len = START_PAD + CRC_DATA_LENGTH + trigger_fragment2_len + 2 + 2 + 2 + payload.length;//2 for crc16 , 2 for % 127 , 2 for payload.length field
    
    printf("total payload length:%d\n",data_len);

    data = malloc(data_len);
    if(data == NULL)
    {
        return NULL;
    }
    
    data_offset = 0;
    memcpy(data + data_offset,trigger_fragment1,START_PAD + CRC_DATA_LENGTH);
    
    data_offset += START_PAD + CRC_DATA_LENGTH;
    memcpy(data + data_offset,trigger_fragment2,trigger_fragment2_len);
    
    data_offset += trigger_fragment2_len;
    tmp_16 = htons(checksum);
    memcpy(data + data_offset,&tmp_16,2);

    data_offset += 2;
    tmp_16 = htons( ((*(uint16_t*)data)%516)*127 );
    memcpy(data + data_offset,&tmp_16,2);

    data_offset += 2;
    tmp_16 = htons(payload.length);
    memcpy(data + data_offset,&tmp_16,2);

    data_offset += 2;
    for(i = 0 ; i < payload.length ;i++){
        data[data_offset + i] = data[ START_PAD + (i%CRC_DATA_LENGTH)] ^ payload.command[i];
    }

    return data;
}

int check_payload_data(char *data,size_t len)
{
    ssize_t data_offset = 0;
    uint16_t checksum;
    uint16_t net_checksum;
    uint16_t trigger_fragment2_len;
    uint16_t validator;
    uint16_t command_len;
    size_t want_len;
    int i;

    want_len = START_PAD + CRC_DATA_LENGTH;
    if(len < want_len){
        return -1;
    }
    checksum = crc16(data + START_PAD, CRC_DATA_LENGTH);

    printf("CRC16: 0x%04X\n", checksum);

    trigger_fragment2_len = checksum % RANDOM_PAD_MAX_LEN;

    data_offset = START_PAD + CRC_DATA_LENGTH + trigger_fragment2_len;
    want_len = data_offset + 2;
    if(len < want_len){
        return -1;
    }
    net_checksum = ntohs(*(uint16_t*)(data+data_offset));
    if(checksum != net_checksum){
        printf ("CRC = 0x%2.2x, CRC check failed\n", checksum);
        return -1;
    }


    data_offset +=2;
    want_len = data_offset + 2;
    if(len < want_len){
        return -1;
    }
    validator = ntohs(*(uint16_t*)(data+data_offset));
    if( (validator % 127)!=0 ){
        printf ("Validator check failed: validator = 0x%2.2x\n", validator);
        return -1;
    }

    data_offset +=2;
    want_len = data_offset + 2;
    if(len < want_len){
        return -1;
    }
    command_len = ntohs(*(uint16_t*)(data+data_offset));

    printf("command_len:%d\n",command_len);

    data_offset +=2;
    want_len = data_offset + command_len;
    if(len < want_len){
        return -1;
    }

    for(i = 0;i<command_len;i++){
        printf("%c",data[START_PAD + (i % CRC_DATA_LENGTH)]^data[data_offset + i]);
    }
    printf("\n");

    return 0;
}

int main(int argc,char *argv[])
{
    char *data = NULL;
    int sockfd;
    struct sockaddr_in serveraddr;
    int ret; 
    size_t payload_data_len = 0;

    if(argc != 4){
        printf("\nUsage: %s ip port command\n\n", argv[0]);
        return -1;
    }

    memset(&serveraddr,0,sizeof(serveraddr));

    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(atoi(argv[2]));
    serveraddr.sin_addr.s_addr = inet_addr(argv[1]);

    sockfd = socket(AF_INET,SOCK_DGRAM,0);
    if(sockfd == -1){
        perror("create socket error:");
        return -1;
    }
    data = gen_payload_data(argv[3],&payload_data_len);
    if(data == NULL){
        printf("gen_payload_data error\n");
        return -1;
    }

    ret = sendto(sockfd,data,payload_data_len,0,(struct sockaddr*)&serveraddr,sizeof(serveraddr));
    if(ret == -1){
        perror("sendto error:");
        return -1;
    }
    check_payload_data(data,payload_data_len);
    free(data);
    return 0;
}
```

