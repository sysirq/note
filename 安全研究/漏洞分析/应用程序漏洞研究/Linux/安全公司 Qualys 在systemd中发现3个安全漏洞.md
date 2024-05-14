# 摘要

Qualys安全公司在systemd-journald中发现了3个漏洞

- CVE-2018-16864、CVE-2018-16865：内存破坏
- CVE-2018-16866：信息泄露（越界读）

Qualys安全公司表示，利用CVE-2018-16865 和 CVE-2018-16866 ，在10分钟左右获取了运行在i386体系结构上的Linux的root权限，在70分钟左右获取了运行在amd64体系结构上的Linux的root权限(该EXP未发布)。如果systemd以-fstack-clash-protection标志编译，则漏洞无法利用(因为防止了堆栈冲突，通过下面的分析。就可以知道，漏洞利用的核心就是堆栈冲突)。

# systemd-journald服务介绍

systemd-journald 是一个收集并存储各类日志数据的系统服务。 它创建并维护一个带有索引的、结构化的日志数据库， 并可以收集来自各种不同渠道的日志：

- 通过 kmsg 收集内核日志
- 通过 libc 的 syslog接口收集系统日志
- 通过本地日志接口 sd_journal_print 收集结构化的系统日志
- 捕获服务单元的标准输出(STDOUT)与标准错误(STDERR)
- 通过内核审计子系统收集审计记录

# CVE-2018-16864

### 分析

函数dispatch_message_real()（journal/journald-server.c）通过将每个字段转换为格式为“<field-name> = <field-value>”的字符串来写入日志。这些字符串是使用basic/string-util.h中定义的strjoina()函数构造的，其使用alloca()在栈上分配结果字符串。

如果攻击者能够通过构造较长的字符串，来使得栈与其他内存区域产生冲突，那么就有可能覆盖其他区域的数据，导致崩溃或代码执行。

在特殊的情况下，一个程序可能有一个很大的cmdline(可以通过/proc/<pid>/cmdline读取)造成堆栈冲突，从而造成systemd-journald崩溃或代码执行。

### 利用

首先，从一个cmdline小的进程，发送一个大的、优先级高的消息给journald。这个消息强制一个大的写 /var/log/journal/的操作(1MB与2MB之间)，并强制创建一个短暂的线程调用fsync等待从内存写入磁盘的操作完成（重点：该线程的栈区域是在mmap区域中分配）

接下来，创建一些进程(32到64个)写大文件（1MB -- 8MB）到 /var/tmp/中.这些进程使得journald中调用fsync的线程能够存活更久，让我们更能容易利用该漏洞。

最后，通过一个进程发送一个小的，低优先级的消息到journald。其cmdline非常大的（128MB左右，为栈区与 mmap 区域的距离），使得调用alloca()函数时，能够覆盖掉journald中调用fsync()线程的栈空间，从而造成代码执行。

# CVE-2018-16865
 
### 分析

journal-file.c中的journal_file_append_entry()函数通过alloca()分配一个EntryItem结构数组,其条目数可以由本地攻击者控制。  

 通过直接访问UNIX域套接字（默认位于/run/systemd/journal/socket），攻击者可以向套接字发送许多条目，从而使得 alloca() 函数分配EntryItem结构数组覆盖其他内存区域。进而造成systemd-journald崩溃或权限提升。

### 利用

首先跳跃到libc的读写段并覆盖一个函数指针。但是这并不简单，从“for”循环（在journal_file_append_entry（）中）调用的函数可能会破坏掉在目标函数指针下方的字节， 因此会覆盖可能崩溃或死锁的重要libc变量。因此，我们有时必须稍微改变我们的alloca()跳跃，以避免覆盖这些重要变量。

我们想用另一个函数或ROP链的地址覆盖我们的目标函数指针，但不幸的是，在“for”循环中调用的函数的栈帧（在journal_file_append_entry（）中）不包含我们控制的任何数据。但是，写入alloca（）ted“items”的64位“哈希”值是由jenkins_hashlittle2（）生成的，这是一个非加密哈希函数：我们可以很容易地找到一个短字符串哈希到指定值（将覆盖我们的目标函数指针的地址），也是valid_user_field（）（或journal_field_valid（））。

为了完成我们的利用，我们需要journald的栈指针，以及libc读写段中目标函数指针的地址，因此我们需要一个信息泄露漏洞。

# CVE-2018-16866

### 分析

journald-syslog.c中的syslog_parse_identifier()函数没有正确解析以":"结尾的日志字符串，返回超出原始字符串限制的指针。从而使得攻击者可以利用该漏洞泄露systemd-journal进程的内存地址。

### 利用

从journald泄漏堆栈地址或mmap地址：

首先，发送一个较大的本地消息到/run/systemd/journal/socket中;journald会调用mmap()，将我们的消息映射到内存，然后调用malloc()分配大量的iovec结构：大多数结构指向我们已经mmap()的消息，但是有少数指向栈（在 dispatch_message_real()）.iovec数组的内容在调用free()由heap hole保存（在journald 中处理完我们的消息后）

接下来，发送大量的syslog信息到/run/systemd/journal/dev-log;journald为了接受我们的大量消息，会调用realloc()从而获取刚刚保存iovec数组的heap hole（其中仍然保存着mmap和栈指针）

最后，我们发送一个利用CVE-2018-16866的大型syslog消息： journald在其服务器缓冲区(在先前包含iovec数组的堆块中)接收到大型消息，如果我们仔细选择消息的大小，并将其结束符“:”放置在剩余的mmap或堆栈指针前面，然后我们可以泄漏这个指针（它被错误地解读为我们信息的正文）

# CVE-2018-16865 与 CVE-2018-16866的结合造成任意代码执行

通过 CVE-2018-16866 我们可以获得libc的地址，然后利用CVE-2018-16865我们可以改写libc中的__free_hook函数指针为system函数的地址，从而造成任意代码执行。

详细过程参考资料4

# 影响版本

CVE-2018-16864 于 2013 年 4 月引入（systemd v203），并在 2016 年 2 月可利用（systemd v230）。

CVE-2018-16865 于 2011 年 12 月引入（systemd v38），在 2013 年 4 月可利用（systemd v201）。

CVE-2018-16866 于 2015 年 6 月引入（systemd v221），于 2018 年 8 月无意中被修复。

已知受影响的Linux 发行版有:Debian，Red Hat，Ubuntu。请自行查看自己系统中的systemd版本是否受影响。

# 时间线

2018-11-26：Qualys安全公司向红帽发送漏洞报告

2018-12-26：Qualys安全公司向linux-distros@...nwall.发送补丁

2019-01-09：Qualys安全公司协调发布时间

# 资料

1.CVE-2018-16864

https://bugzilla.redhat.com/show_bug.cgi?id=1653855

2.CVE-2018-16865

https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2018-16865

3.CVE-2018-16866

https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2018-16866

4.Openwall

https://www.openwall.com/lists/oss-security/2019/01/09/3

5.Stack Clash

https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt