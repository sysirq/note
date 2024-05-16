# tpm

宿主机准备：

```sh
apt install swtpm
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

```
sudo qemu-system-x86_64 -accel kvm -m 16G -smp 4 -pflash /usr/share/OVMF/OVMF_CODE.fd -chardev socket,id=chrtpm,path=/tmp/swtpm-sock -tpmdev emulator,id=tmp0,chardev=chrtpm -device tpm-tis,tpmdev=tmp0 -hda hd.qcow2 -cdrom ../iso/Win11_23H2_EnglishInternational_x64v2.iso -boot order=d -usbdevice tablet -vnc 10.4.21.2:1
```

# 资料

Qemu cannot run Windows 11

https://serverfault.com/questions/1096400/qemu-cannot-run-windows-11