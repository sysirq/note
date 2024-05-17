# tpm

宿主机准备：

```sh
apt install swtpm ovmf
mkdir /tmp/tpm
sudo swtpm socket --tpmstate dir=/tmp/tpm --tpm2 --ctrl type=unixio,path=/tmp/swtpm-sock,mode=0777
```

qemu 命令:

```sh
-chardev socket,id=chrtpm,path=/tmp/swtpm-sock -tpmdev emulator,id=tmp0,chardev=chrtpm -device tpm-tis,tpmdev=tmp0
```

# vnc 漂移问题

```
-usbdevice tablet
```

# 完整启动Windows命令

安装命令

```sh
sudo qemu-system-x86_64 -accel kvm \
												-m 16G \
												-smp 4 \
												-pflash /usr/share/OVMF/OVMF_CODE.fd \
												-chardev socket,id=chrtpm,path=/tmp/swtpm-sock \
												-tpmdev emulator,id=tmp0,chardev=chrtpm \
												-device tpm-tis,tpmdev=tmp0 -hda hd.qcow2 \
												-cdrom ../iso/Win11_23H2_EnglishInternational_x64v2.iso \
												-boot order=d \
												-usbdevice tablet \
												-vnc 10.4.21.2:1
```

启动命令

```sh
sudo qemu-system-x86_64 --accel kvm \
												-m 16G \
												-smp 4 \
												-pflash /usr/share/OVMF/OVMF_CODE_4M.fd \
												-chardev socket,id=chrtpm,path=/tmp/swtpm-sock \
												-tpmdev emulator,id=tpm0,chardev=chrtpm \
												-device tpm-tis,tpmdev=tpm0 \
												-hda hd.qcow2 \
												-usbdevice tablet \
												-vnc 10.4.21.2:1
```



# virtio

https://pve.proxmox.com/wiki/Windows_VirtIO_Drivers

https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/archive-virtio/virtio-win-0.1.248-1/

# 半虚拟化

下载 virtio-win
安装(先不启用virtio-net)：

```sh
sudo qemu-system-x86_64 --accel kvm \
                        -m 16G \
                        -smp 8 \
                        -pflash /usr/share/OVMF/OVMF_CODE_4M.fd \
                        -chardev socket,id=chrtpm,path=/tmp/swtpm-sock \
                        -tpmdev emulator,id=tpm0,chardev=chrtpm \
                        -device tpm-tis,tpmdev=tpm0 \
                        -blockdev driver=file,node-name=hdfile,filename=hd.qcow2 \
                        -blockdev driver=qcow2,file=hdfile,node-name=hd \
                        -device virtio-blk,drive=hd \
                        -device virtio-mouse \
                        -device virtio-vga \
                        -device virtio-keyboard \
                        -usbdevice tablet \
                        -drive file=../iso/virtio-win.iso,media=cdrom \
                        -drive file=../iso/Win11_23H2_EnglishInternational_x64v2.iso,media=cdrom \
                        -vnc 10.4.21.2:1
```



During the install process windows won’t be able to see our newly created disk image unless we load the `virtio` drivers during the install process. Including `./virtio-win-0.1.217.iso` as a virtual CD will let you do this. Now go ahead and begin the installation.

During the **windows install process**, select *custom install*. Select *load driver* and go ahead and select the `E:\amd\w10\viostor.inf` controller from the `virtio` CD we added in the previous step. Now you should be able to select the new disk image as the windows install location.

安装完成之后，在宿主机中，在进入virtio-win.iso 安装剩余的virtio驱动



启动!!!!



```sh
sudo qemu-system-x86_64 --accel kvm \
                        -m 16G \
                        -smp 8 \
                        -pflash /usr/share/OVMF/OVMF_CODE_4M.fd \
                        -chardev socket,id=chrtpm,path=/tmp/swtpm-sock \
                        -tpmdev emulator,id=tpm0,chardev=chrtpm \
                        -device tpm-tis,tpmdev=tpm0 \
                        -blockdev driver=file,node-name=hdfile,filename=hd.qcow2 \
                        -blockdev driver=qcow2,file=hdfile,node-name=hd \
                        -device virtio-blk,drive=hd \
                        -netdev tap,ifname=tap0,script=no,downscript=no,id=nc0 \
                        -device virtio-net,netdev=nc0 \
                        -device virtio-mouse \
                        -device virtio-vga \
                        -device virtio-keyboard \
                        -usbdevice tablet \
                        -vnc 10.4.21.2:1
```



3389 nat 转换

```shell
iptables -t nat -A PREROUTING -p tcp --dport 3389 -i wg0 -j DNAT --to-destination <WINDOWS SERVER IP>
iptables -t nat -A POSTROUTING -o wlp0s20f3 -j MASQUERADE
```







# 资料

Qemu cannot run Windows 11

https://serverfault.com/questions/1096400/qemu-cannot-run-windows-11