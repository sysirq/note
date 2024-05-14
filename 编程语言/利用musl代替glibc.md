地址 ： <https://www.musl-libc.org/>

    ./configure CFLAGS="--pie -O3 -s -fno-unwind-tables -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections -Wl,-gc-sections -fno-stack-protector"

    make 

    make install

    sudo ln -s /usr/local/musl/bin/musl-gcc /usr/bin/musl-gcc

