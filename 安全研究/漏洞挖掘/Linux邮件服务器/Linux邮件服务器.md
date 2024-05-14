名词解析

MTA: Mail Transfer Protocol.邮件传输代理,是SMTP的一种实现.常用的MTA有sendmail,Postfix.本例中使用Postfix.MTA仅仅负责邮件的传输,MDA负责把接收到的邮件保存在硬盘中.	

MUA:Mail User Agent.用户邮件代理,用户通过MUA接收发送邮件.例如Outlook, formail等.

MRA: Mail Receive Agent,邮件接收代理,用来实现IMAP,POP3协议,负责与MUA交互,将服务器上的邮件通过IMAP以及POP3传输给客户端.本例中使用的MRA是Dovecot.



攻击面：

1.MUA:通过伪造服务器向MUA发送恶意数据

2.MTA:向服务器发送恶意数据（比如Exim 爆的漏洞）

3.MRA:通过伪造MUA向服务器发送恶意数据



对应软件:

1.MUA:Thunderbird.....

2.MTA:sendmail(exploit-db中的利用最多),Exim,Postfix,Qmail....

3.MRA:Dovecot



参考质料:

从零开始邮件服务器搭建:https://www.jianshu.com/p/610d9bf0ae8b

用Centos搭建自己的邮件系统：https://bfchengnuo.com/2017/03/21/用Centos搭建自己的邮件系统/

6 Best Mail Transfer Agents (MTA’s) for Linux:https://www.tecmint.com/best-mail-transfer-agents-mta-for-linux/

6 Best Email Clients for Linux Systems:https://www.tecmint.com/best-email-clients-linux/

