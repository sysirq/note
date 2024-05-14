1. 删除编译生成的内核文件

sudo rm -rf /lib/modules/4.0.0 
sudo rm -rf /usr/src/linux-4.0 # (LinuxMint17) 
sudo rm -rf /usr/src/kernels/linux-4.0 (Fedora21) 
sudo rm /boot/*4.0.0* 


2. 重新生成grub.cfg配置文件

sudo update-grub 