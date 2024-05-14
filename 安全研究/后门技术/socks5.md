# server

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <netdb.h>

#define BUFFER_SIZE 1024

int handle_client(int sock_in,int sock_out);

int main() {
    // 创建 socket
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }

    // 设置服务器地址结构
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(1080);  // SOCKS5默认端口
    server_addr.sin_addr.s_addr = INADDR_ANY;

    // 绑定 socket
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("Error binding socket");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    // 监听连接请求
    if (listen(server_socket, 10) == -1) {
        perror("Error listening for connections");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    printf("SOCKS5 Proxy Server listening on port 1080...\n");

    while (1) {
        // 接受连接请求
        int client_socket = accept(server_socket, NULL, NULL);
        if (client_socket == -1) {
            perror("Error accepting connection");
            continue;
        }

        // 处理客户端请求
        handle_client(client_socket,dup(client_socket));
    }

    // 关闭服务器 socket
    close(server_socket);

    return 0;
}

int handle_client(int sock_in,int sock_out) {
    char buffer[BUFFER_SIZE];
    ssize_t bytes_received;
    int snd_size  = 1;
    int nmethods = 0;

    setsockopt(sock_out, SOL_SOCKET , SO_SNDBUF , (char *)&snd_size, sizeof(int));
    
    // SOCKS5协商
    bytes_received = recv(sock_in, buffer, 2, 0);
    nmethods = buffer[1];
    if (bytes_received != 2 || buffer[0] != 0x05 || nmethods == 0x00) {// buffer[0]: 版本号，对于socks5协议固定是0x05 ; buffer[1] :methods的数量，决定了后面methods的长度
        // 不是SOCKS5协议或者不支持的版本号
        close(sock_in);
        close(sock_out);
        return -1;
    }
    if(recv(sock_in, buffer, nmethods, 0) != nmethods ){//读取 METHODS 列表
        close(sock_in);
        close(sock_out);
        return -1;
    }

    // 发送支持的认证方法（无认证）
    buffer[0] = 0x05;
    buffer[1] = 0x00;
    send(sock_out, buffer, 2, 0);//buffer[0]:协议版本号，固定0x05 ; buffer[1]: 表明服务端接受的客户端的验证方法 , 0x00: 无需认证

    // 接收客户端发来的连接请求
    //buffer[0]: 协议版本号，固定0x05
    //buffer[1]: CMD有三种情况，0x01表示CONNECT，0x02表示BIND，0x03表示UDP
    //buffer[2]: RSV为保留字，固定为0x00
    //buffer[3]: ATYP表示后面的地址类型，0x01表示IPv4地址，0x03表示域名，0x04表示IPv6地址
    //DST.ADDR表示目标主机地址，对于域名类型，第一位表示长度，对于IPv4和IPv6分为占4 bytes 和16 bytes
    //DST.PORT表示目标主机端口
    bytes_received = recv(sock_in, buffer, BUFFER_SIZE, 0);
    if (bytes_received < 8 || buffer[0] != 0x05 || buffer[1] != 0x01 || buffer[2] != 0x00) {
        // 不是SOCKS5协议的连接请求
        close(sock_in);
        close(sock_out);
        return -1;
    }

    // 解析目标地址和端口
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    
    char domain[BUFFER_SIZE];
    uint16_t dest_port;
    if (buffer[3] == 0x01) {  // 4个字节，对应 IPv4 地址
        dest_addr.sin_port = (*(uint16_t*)(buffer + 8));
        memcpy(&dest_addr.sin_addr,buffer + 4,4);
    } else if (buffer[3] == 0x03) {  // 域名
        struct hostent *host_info;
        char **ip;
        uint8_t domain_len = buffer[4];
        dest_addr.sin_port = (*(uint16_t*)(buffer + 5 + domain_len));
        memcpy(domain, buffer + 5, domain_len);
        domain[domain_len] = '\0';
        host_info = gethostbyname(domain);
        if(host_info == NULL){
            close(sock_in);
            close(sock_out);
            return -1;
        }
        for (ip = host_info->h_addr_list; *ip != NULL; ip++) {
		    memcpy(&dest_addr.sin_addr, *ip, sizeof(struct in_addr));
            break;
        }
    } else {
        // 不支持的地址类型
        close(sock_in);
        close(sock_out);
        return -1;
    }

    // 创建与目标服务器的连接
    int dest_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (dest_socket == -1) {
        perror("Error creating destination socket");
        close(sock_in);
        close(sock_out);
        return -1;
    }

    if (connect(dest_socket, (struct sockaddr*)&dest_addr, sizeof(dest_addr)) == -1) {
        perror("Error connecting to destination");
        close(sock_in);
        close(sock_out);
        close(dest_socket);
        return -1;
    }



    printf("Connection established: %d.%d.%d.%d:%d\n",  ((uint8_t*)&dest_addr.sin_addr)[0],
                                                        ((uint8_t*)&dest_addr.sin_addr)[1],
                                                        ((uint8_t*)&dest_addr.sin_addr)[2],
                                                        ((uint8_t*)&dest_addr.sin_addr)[3], 
                                                        ntohs(dest_addr.sin_port));
    // 响应连接请求
    buffer[0] = 0x05;
    buffer[1] = 0x00;
    buffer[2] = 0x00;
    buffer[3] = 0x01;
    buffer[4] = 0x00;
    buffer[5] = 0x00;
    buffer[6] = 0x00;
    buffer[7] = 0x00;
    buffer[8] = 0x00;
    buffer[9] = 0x00;
    send(sock_out, buffer, 10, 0);

    // 开始转发数据
    fd_set fd_set_read;
    while (1) {
        FD_ZERO(&fd_set_read);
        FD_SET(sock_in, &fd_set_read);
        FD_SET(dest_socket, &fd_set_read);

        int max_fd = (sock_in > dest_socket) ? sock_in : dest_socket;
        if (select(max_fd + 1, &fd_set_read, NULL, NULL, NULL) == -1) {
            perror("Error in select");
            break;
        }

        if (FD_ISSET(sock_in, &fd_set_read)) {
            // 从客户端读取数据并转发到目标服务器
            bytes_received = recv(sock_in, buffer, BUFFER_SIZE, 0);
            if (bytes_received <= 0) {
                break;
            }
            send(dest_socket, buffer, bytes_received, 0);
        }

        if (FD_ISSET(dest_socket, &fd_set_read)) {
            // 从目标服务器读取数据并转发到客户端
            bytes_received = recv(dest_socket, buffer, BUFFER_SIZE, 0);
            if (bytes_received <= 0) {
                break;
            }
            send(sock_out, buffer, bytes_received, 0);
        }
    }

    // 关闭连接
    close(sock_in);
    close(sock_out);
    close(dest_socket);

    return 0;
}
```

# client

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 1080
#define BUFFER_SIZE 1024

#define IPV4_ATYP 0x01
#define DOMAIN_ATYPE 0x03

int socks_auth(int client_socket)
{
    char buffer[BUFFER_SIZE];
    ssize_t bytes_received;

    buffer[0] = 0x05;//ver
    buffer[1] = 0x01;//NMETHODS
    buffer[2] = 0x00;
    send(client_socket, buffer, 3, 0);

    bytes_received = recv(client_socket, buffer, 2, 0);
    if (bytes_received != 2 || buffer[0] != 0x05 || buffer[1] != 0x00)
    {
        return -1;
    }

    return 0;
}

int socks_connect(int client_socket,uint16_t port,uint8_t atype,uint8_t* addr)
{
    char buffer[BUFFER_SIZE];
    ssize_t bytes_received;
    int idx = 0;
    uint16_t net_port = htons(port);

    buffer[0] = 0x05;//version
    buffer[1] = 0x01;//cmd,0x01 = CONNECT
    buffer[2] = 0x00;//RSV
    buffer[3] = atype;//ATYP 地址类型，0x01=IPv4，0x03=域名，0x04=IPv6

    if(atype == IPV4_ATYP){
        memcpy(buffer+4,addr,4);
        idx = 4 + 4;
    }
    else if(atype == DOMAIN_ATYPE){
        buffer[4] = strlen(addr);
        memcpy(buffer+5,addr,buffer[4]);
        idx = 5 + buffer[4];
    }
    else{
        return -1;
    }

    memcpy(buffer+idx,&net_port,sizeof(net_port));
    idx += sizeof(net_port);
    send(client_socket, buffer, idx, 0);

    bytes_received = recv(client_socket, buffer, 10, 0);
    
    if(bytes_received != 10 || buffer[1] != 0){
        return -1;
    }

    return 0;
}

int main() {
    int client_socket;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];

    // 创建客户端套接字
    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket == -1) {
        perror("Error creating socket");
        exit(EXIT_FAILURE);
    }

    // 设置服务器地址结构
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    server_addr.sin_port = htons(PORT);

    // 连接到服务器
    if (connect(client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("Error connecting to server");
        close(client_socket);
        exit(EXIT_FAILURE);
    }

    printf("Connected to server %s:%d\n", inet_ntoa(server_addr.sin_addr), ntohs(server_addr.sin_port));
    //Start socks5
    if(socks_auth(client_socket) != 0){
        printf("unsupport auth method\n");
        goto cleanup;
    }

    //Socks Connect
    uint32_t ip;
    inet_pton(AF_INET,"93.184.216.34",&ip);

    if(socks_connect(client_socket,80,IPV4_ATYP,(uint8_t*)&ip)!=0){
        printf("socks connect error\n");
        goto cleanup;
    }

    char request[] = "GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n";
    send(client_socket,request,strlen(request),0);
    recv(client_socket,buffer,BUFFER_SIZE,0);
    printf("%s\n",buffer);

cleanup:
    // 关闭连接
    close(client_socket);

    return 0;
}
```

# 测试

```c
 curl --proxy "socks5://127.0.0.1:1080" http://www.baidu.com
```

# 资料

用c语言写一个socks5代理服务器

<https://www.lyytaw.com/%E7%BD%91%E7%BB%9C/%E7%94%A8c%E8%AF%AD%E8%A8%80%E5%86%99%E4%B8%80%E4%B8%AAsocks5%E4%BB%A3%E7%90%86%E6%9C%8D%E5%8A%A1%E5%99%A8/#%E5%BA%94%E7%94%A8%E6%9E%B6%E6%9E%84>

实战：150行Go实现高性能socks5代理

<https://segmentfault.com/a/1190000038247560>

Socks5 udp代理

<https://www.jianshu.com/p/cf88c619ee5c>
