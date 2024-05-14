在存放公钥私钥(id_rsa和id_rsa.pub，位于家目录的.ssh文件)的文件里，新建config文本，内容如下：

```
Host github.com
User r1ng0hacking
Hostname ssh.github.com
PreferredAuthentications publickey
IdentityFile ~/.ssh/id_rsa
Port 443
```