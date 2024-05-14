```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main() {
    struct ifaddrs *ifaddr, *ifa;

    // 获取本机所有网络接口的地址信息
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    // 遍历接口地址信息
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
            continue;
        }

        // 排除非 IPv4 地址和回环接口
        if (ifa->ifa_addr->sa_family == AF_INET && strcmp(ifa->ifa_name, "lo") != 0) {
            struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
            char ip_address[INET_ADDRSTRLEN];

            // 将二进制形式的 IP 地址转换为可读形式
            if (inet_ntop(AF_INET, &sa->sin_addr, ip_address, INET_ADDRSTRLEN) == NULL) {
                perror("inet_ntop");
                exit(EXIT_FAILURE);
            }

            printf("Interface: %s, IP Address: %s\n", ifa->ifa_name, ip_address);
        }
    }

    // 释放地址信息
    freeifaddrs(ifaddr);

    return 0;
}
```