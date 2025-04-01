# Libreswan

编译：

```
make clean
make -j$(nproc) DEBUG=1 CFLAGS="-g -O0" LDFLAGS="-g"
```

调试：

```
file /usr/local/libexec/ipsec/pluto
# 输出应包含 `with debug_info`

sudo gdb /usr/local/libexec/ipsec/pluto
```

在 gdb 中运行：

```
set args --nofork --debug-all
run
```

启用更详细的调试日志:

```
sudo ipsec pluto --stderrlog --debug-all
```



### 资料

https://github.com/libreswan/libreswan

# 历史漏洞

Linux内存越界漏洞分析（CVE-2017-7184）

https://zhuanlan.zhihu.com/p/32868292

Nftables - Netfilter and VPN/IPsec packet flow

https://thermalcircle.de/doku.php?id=blog:linux:nftables_ipsec_packet_flow

Automated state machine learning of IPsec implementations

https://www.cs.ru.nl/bachelors-theses/2017/Bart_Veldhuizen___4492765___Automated_state_machine_learning_of_IPsec_implementations.pdf

What is the difference between “Main” mode and “Quick” mode when using IPsec in Windows Server?

https://serverfault.com/questions/550894/what-is-the-difference-between-main-mode-and-quick-mode-when-using-ipsec-in

IPSec for Dummies: Getting Started with IPSec VPN

https://jiwanbhattarai.com/blog/ipsec-for-dummies-getting-started-with-ipsec-vpn-a-quick-guide-for-beginners/