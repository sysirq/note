# 静态编译

CC='gcc -m32' ./Configure no-shared 386 linux-x32

./Configure -m32 386 no-shared no-asm linux-generic32

./Configure -m32 linux-generic32 no-shared no-dso no-threads -static

CC="/home/build/xxcompile/musl-cross-make/output/bin/i386-linux-musl-gcc" ./Configure -m32 linux-generic32 no-shared no-dso no-threads -static

# nmap

```
CC="/home/build/xxcompile/musl-cross-make/output/bin/i386-linux-musl-gcc -static -fPIC -DLUA_C89_NUMBERS -I/home/build/nmap_static_compile/openssl-1.0.2j/include" CXX="/home/build/xxcompile/musl-cross-make/output/bin/i386-linux-musl-g++ -static -static-libstdc++ -fPIC -DLUA_C89_NUMBERS -I/home/build/nmap_static_compile/openssl-1.0.2j/include" LDFLAGS="-L/home/build/nmap_static_compile/openssl-1.0.2j/" \
 ./configure \
       -q \
       --without-ndiff \
       --without-zenmap \
       --without-nping \
       --without-ncat \
       --without-nmap-update \
       --with-pcap=linux \
       --with-openssl="/home/build/nmap_static_compile/openssl-1.0.2j/" \
       --prefix "/home/build/tmp/"

```

# 参考资料

static-compile-scripts

https://github.com/CaledoniaProject/static-compile-scripts/tree/master