```c
    int serverfd = socket(AF_INET, SOCK_STREAM, 0);
    struct linger so_linger;

    so_linger.l_onoff  = 1;
    so_linger.l_linger = 0;

    if (serverfd == -1)
    {
        DLX(4, printf("\tcreate socket error\n"));
        return -1;
    }

    if(setsockopt(serverfd,SOL_SOCKET,SO_LINGER,&so_linger,sizeof(so_linger)) == -1){
        DLX(4, printf("\tsetsockopt SO_LINGER error\n"));
        close(serverfd);
    }

```