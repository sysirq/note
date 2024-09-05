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





# 资料

物联网终端安全入门与实践之玩转物联网固件（中）(其中的nvma 通过LD_PRELOAD 模拟值得学习)

https://zhuanlan.zhihu.com/p/544793994