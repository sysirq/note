# Gdbserver 静态编译

```
apt install texinfo
apt install libmpc-dev
tar -xvf gdb-15.1.tar.xz
cd gdb-15.1/
mkdir build
cd build
../configure LDFLAGS="-static" # 编译会报错，但是gdbserver是编译成功了的，可以通过file gdbserver/gdbserver 查看
```

# 参考资料

gdb-static

https://github.com/guyush1/gdb-static/tree/develop