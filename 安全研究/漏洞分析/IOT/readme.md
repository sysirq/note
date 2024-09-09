# 其他平台gcc编译环境安装

```shell
sudo apt install binutils-mipsel-linux-gnu
sudo apt install gcc-10-multilib-mipsel-linux-gnu
```

### 编译

```
➜  libnvram git:(master) cat Makefile 
CFLAGS=-O2 -fPIC -Wall
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
➜  libnvram git:(master) make CC=mipsel-linux-gnu-gcc-10
```

# 通过LD_PRELOAD机制，patch函数

eg:

```
 sudo chroot . ./qemu-mipsel-static -L . -E LD_PRELOAD="/libnvram.so" ./bin/goahead
```

# 有用的帮助

### 尝试禁用强化检查

在编译时，可以通过禁用 glibc 的强化检查来避免使用 __fprintf_chk 函数。你可以尝试在编译时加入以下编译选项：

```
-D_FORTIFY_SOURCE=0
```

这将禁用类似 __fprintf_chk 的强化检查函数，回退到标准的 fprintf 函数。

# 资料

物联网终端安全入门与实践之玩转物联网固件（中）(其中的nvma 通过LD_PRELOAD 模拟值得学习)

https://zhuanlan.zhihu.com/p/544793994

https://github.com/pr0v3rbs/FirmAE/tree/master/sources

基于QEMU的NVRAM仿真

https://blog.csdn.net/qq_21063873/article/details/103037515

模拟固件下的patch与hook

https://www.iotsec-zone.com/article/202

