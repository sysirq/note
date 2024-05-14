# &#x20;server

```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define PORT 23333
#define SERVER_IP "127.0.0.1"

int main(void){
    int ret;
    int server_fd = socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in server_addr;

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
    server_addr.sin_port = htons(PORT);

    bind(server_fd,(struct sockaddr*)&server_addr,sizeof(server_addr));

    ret = listen(server_fd,5);
    
    if(ret){
        perror("listen error");
    }

    char ch;
    int client_fd;
    struct sockaddr_in client_addr;
    socklen_t len = sizeof(client_addr);

    while(1){
        printf("server waiting....\n");

        client_fd = accept(server_fd,(struct sockaddr*)&client_addr,&len);

        read(client_fd,&ch,1);

        printf("get char from client:%c \n",ch);
        ch++;
        write(client_fd,&ch,1);
        close(client_fd);
    }

    return 0;
}
```

# client

```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>

#define PORT 23333
#define SERVER_IP "127.0.0.1"

int main(void){
    int sockfd = socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in address;

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(SERVER_IP);
    address.sin_port = htons(PORT);

    int result = connect(sockfd,(struct sockaddr*)&address,sizeof(address));
    if(result == -1){
        perror("connect failed:");
        exit(-1);
    }

    char ch = 'A';
    write(sockfd,&ch,1);
    read(sockfd,&ch,1);
    printf("get char from server:%c\n",ch);

    close(sockfd);

    return 0;
}
```

