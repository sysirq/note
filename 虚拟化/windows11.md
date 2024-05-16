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

# boot

```
apt install ovmf
sudo qemu-system-x86_64 -accel kvm -m 16G -smp 4 -pflash /usr/share/OVMF/OVMF_CODE.fd -pflash /usr/share/OVMF/OVMF_VARS.fd -chardev socket,id=chrtpm,path=/tmp/swtpm-sock -tpmdev emulator,id=tmp0,chardev=chrtpm -device tpm-tis,tpmdev=tmp0 -hda hd.qcow2 -cdrom ../iso/Win11_23H2_EnglishInternational_x64v2.iso -boot order=d -vnc 10.4.21.2:1
```

# 资料

Qemu cannot run Windows 11

https://serverfault.com/questions/1096400/qemu-cannot-run-windows-11