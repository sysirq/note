# eg

```
--pie -O3 -s -fno-unwind-tables -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections -Wl,-gc-sections -fno-stack-protector
```

# 使用-O标志进行优化

启用编译器的优化选项可以减小生成的二进制文件的大小。使用-O1、-O2或-O3标志来开启不同级别的优化。请注意，更高级别的优化可能会导致编译时间增加。

```sh
gcc -o your_executable source.c -O2
```

# 删除调试信息

调试信息占用了可执行文件中的大量空间。通过使用-g标志可以将调试信息添加到可执行文件中。如果你不需要调试信息，可以删除它们以减小文件大小。

```sh
gcc -o your_executable source.c -O2 -s
```

-s标志用于删除符号信息，可以进一步减小可执行文件的大小。

# 只包含需要的静态链接库中的代码

使用-ffunction-sections -fdata-sections -Wl,-gc-sections。如果没有这个，来自每个需要的.o文件的所有代码都将被包括在内。这样只会包含所需的代码。

# 推荐的 GCC（和 Clang）标志：

- 使用-s从二进制文件中去除调试信息（不要使用-g）。
- 使用-Os优化输出文件大小。（这会使代码运行速度比-O2或-O3慢。
- 使用-m32编译 32 位二进制文​​件。32 位二进制文​​件比 64 位二进制文​​件小，因为指针更短。
- 在 C++ 中，如果您的代码不使用异常，请使用-fno-exceptions 。
- 在 C++ 中，如果您的代码不使用 RTTI（运行时类型识别）或dynamic_cast ，请使用-fno-rtti。
- 在 C++ 中，使用-fvtable-gc让链接器知道并删除未使用的虚方法表。
- 使用-fno-stack-protector。
- 使用-fomit-frame-pointer（这可能会使代码在 amd64 上变大）。
- 使用-ffunction-sections -fdata-sections -Wl,–gc-sections。如果没有这个，来自每个需要的.o文件的所有代码都将被包括在内。这样只会包含所需的代码。
- 对于 i386，使用-mpreferred-stack-boundary=2。
- 对于 i386，使用-falign-functions=1 -falign-jumps=1 -falign-loops=1。
- 在 C 中，使用-fno-unwind-tables -fno-asynchronous-unwind-tables。其中，-fno-asynchronous-unwind-tables产生了更大的差异（可能是几千字节）。
- 使用-fno-math-errno，并且在调用数学函数后不检查错误号。
- 尝试-fno-unroll-loops，有时它会使文件变小。
- 使用-fmerge-all-constants。
- 使用-fno-ident，这将阻止生成.ident汇编程序指令，该指令将编译器的标识添加到二进制文件中。
- 使用-mfpmath=387 -mfancy-math-387缩短浮点计算时间。
- 如果不需要双精度，但浮点精度就足够了，请使用-fshort-double -fsingle-precision-constant。
- 如果您不需要符合 IEEE 标准的浮点计算，请使用-ffast-math。
- 使用-Wl,-z,norelro进行链接，相当于ld -z norelro。
- 使用-Wl,–hash-style=gnu进行链接，相当于ld –hash-style=gnu。您也可以尝试=sysv而不是=gnu，有时它会小几个字节。这里的目标是避免=both，这是某些系统的默认设置。
- 使用-Wl,–build-id=none进行链接，相当于ld –build-id=none。
- 从diet.c的diet.c中的Os列表中获取更多标志，用于大约 15 种架构。
- 不要使用这些标志：-pie、-fpie、-fPIE、-fpic、-fPIC。其中一些在共享库中很有用，因此仅在编译共享库时启用它们。

# 资料

如何生成更小的 C 和 C++ 二进制文件

https://readbuf.com/posts/how-to-make-smaller-c-and-c++-binaries/