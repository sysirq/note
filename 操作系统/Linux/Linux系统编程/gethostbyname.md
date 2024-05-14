```c
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main() {
    const char *hostname = "www.example.com";
    struct hostent *host_info;

    host_info = gethostbyname(hostname);

    if (host_info == NULL) {
        herror("gethostbyname");
        return 1;
    }

    printf("Official name: %s\n", host_info->h_name);

    // Print the list of IP addresses associated with the host
    char **ip;
    for (ip = host_info->h_addr_list; *ip != NULL; ip++) {
        struct in_addr addr;
        uint8_t *u8;
		u8 = (uint8_t*)*ip;
		memcpy(&addr, *ip, sizeof(struct in_addr));
		printf("IP Address: %d.%d.%d.%d\n",u8[0],u8[1],u8[2],u8[3]);
        printf("IP Address: %s\n", inet_ntoa(addr));
    }

    return 0;
}
```