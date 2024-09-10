# 工具下载

asuswrt-merlin

https://github.com/RMerl/asuswrt-merlin

```
sudo ln -s /home/lzx/tools/asuswrt-merlin-master/tools/brcm/hndtools-mipsel-uclibc /opt/brcm-mipsel
```

PATH 、CC、LD_LIBRARY_PATH设置

```
➜  libnvram git:(master) ✗ head -n 10 ~/.zshrc 
# If you come from bash you might have to change your $PATH.
# export PATH=$HOME/bin:$HOME/.local/bin:/usr/local/bin:$PATH
# Path to your Oh My Zsh installation.
export ZSH="$HOME/.oh-my-zsh"
export PATH="$PATH:/opt/brcm-mipsel/bin"
export CC=mipsel-uclibc-gcc
export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:/opt/brcm-arm/lib:/usr/local/lib:/usr/lib"
```



# libnvram

https://github.com/firmadyne/libnvram

Makefile:

```
CFLAGS=-O1 -g -D_FORTIFY_SOURCE=0 -D_GNU_SOURCE -fPIC -Wall
LDFLAGS=-shared -nostdlib

TARGET=libnvram.so libnvram_ioctl.so

all: $(SOURCES) $(TARGET)

libnvram.so: nvram.o
	$(CC) $(LDFLAGS) $< -o $@

libnvram_ioctl.so: nvram_ioctl.o
	$(CC) $(LDFLAGS) $< -o $@

.c.o:
	$(CC) -c $(CFLAGS) $< -o $@

nvram_ioctl.o: nvram.c
	$(CC) -c $(CFLAGS) -DFIRMAE_KERNEL $< -o $@

clean:
	rm -f *.o libnvram.so libnvram_ioctl.so

.PHONY: clean
```

# 问题定位区

### nvram_init: Unable to mount tmpfs on mount point XXXXXXXXX!

注意权限问题：

- 手动挂载：sudo mount -t tmpfs -o size=10M tmpfs ./mnt/libnvram

- docker权限设置：docker container run --privileged --cap-add=SYS_ADMIN  -it cve-2023-26801  /qemu-mipsel-static /bin/sh

# 注意事项

**不能混用** mipsel-uclibc-gcc 和 mipsel-linux-gcc **编译的动态库**，除非在非常受控的条件下确保二者的库和运行时环境兼容，否则会产生无法预料的错误。

- C 库不兼容：glibc 和 uClibc 的实现差异使得它们的动态库在符号解析、系统调用封装、数据结构等方面无法兼容。
- 动态链接器不同：glibc 和 uClibc 使用不同的动态链接器，导致运行时无法正确加载和解析库。
- ABI 不一致：两者在应用二进制接口（ABI）上存在不兼容，特别是在结构体、函数调用约定等方面。
- 运行时依赖不同：每个库依赖的其他共享库和资源不同，混用时可能导致运行时加载错误。

# 资料

libnvram.so编译教程

https://ioo0s.art/2023/02/20/libnvram-so编译教程/

模拟固件下的patch与hook

https://www.iotsec-zone.com/article/202