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

# 资料

libnvram.so编译教程

https://ioo0s.art/2023/02/20/libnvram-so编译教程/