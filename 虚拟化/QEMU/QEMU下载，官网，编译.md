官网地址：www.qemu.org

下载地址：download.qemu.org

编译：https://wiki.qemu.org/Hosts/Linux

在线代码阅读：https://elixir.bootlin.com/qemu/v4.1.0/source

understanding qemu: https://richardweiyang.gitbooks.io/understanding_qemu/device_model/00-devices.html

vnc下载：https://www.realvnc.com/en/connect/download/vnc/windows/

编译：./configure --target-list=x86_64-softmmu --enable-debug --enable-debug-stack-usage --enable-debug-info --enable-kvm --prefix=/home/john/MyBin/qemu

qemu实现嵌套虚拟化：-enable-kvm -cpu qemu64,+vmx（设置虚拟机CPU为qemu64型号,添加vmx支持）