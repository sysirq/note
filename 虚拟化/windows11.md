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

# secure boot

How to enable secure boot for Windows

https://projectacrn.github.io/1.6/tutorials/waag-secure-boot.html

How to install a windows guest in qemu/kvm with secure boot enabled

https://superuser.com/questions/1660806/how-to-install-a-windows-guest-in-qemu-kvm-with-secure-boot-enabled

# 资料

Qemu cannot run Windows 11

https://serverfault.com/questions/1096400/qemu-cannot-run-windows-11