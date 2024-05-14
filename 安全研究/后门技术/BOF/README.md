# 在Linux上编译Windows程序

```
cargo build --bin windows_bof_test --target x86_64-pc-windows-gnu
```

# 开发

- 下载beacon.h 文件

https://github.com/Cobalt-Strike/bof_template/blob/main/beacon.h

https://github.com/trustedsec/CS-Situational-Awareness-BOF/blob/master/src/common/beacon.h

- 下载bofdefs.h 文件

https://github.com/trustedsec/CS-Situational-Awareness-BOF/blob/master/src/common/bofdefs.h

- 编译，生成中间文件


To compile this with Visual Studio:
```
cl.exe /c /GS- hello.c /Fohello.o
```
To compile this with x86 MinGW:
```
i686-w64-mingw32-gcc -c hello.c -o hello.o
```
To compile this with x64 MinGW:
```
x86_64-w64-mingw32-gcc -c hello.c -o hello.o
```

# BOF参数解析脚本

https://github.com/trustedsec/COFFLoader/blob/main/beacon_generate.py

# 通用开发环境

CS-Situational-Awareness-BOF

https://github.com/trustedsec/CS-Situational-Awareness-BOF

# 资料

聊聊Cobalt Strike 4.1的 BOF

https://mp.weixin.qq.com/s?spm=a2c6h.12873639.article-detail.7.b5ae4142ysye03&__biz=MzI5NzU0MTc5Mg==&mid=2247483809&idx=1&sn=c3723f82a7a383df5a03dfa9f5cf7914&chksm=ecb2c86edbc541780b2d3064dd71cffc9c0cd82289a6d16aaf69c7ace83eb4924a7eae858dca&scene=21#wechat_redirect

使用 Visual Studio 开发 CS 的 BOF

https://developer.aliyun.com/article/1342905

BOF C API

https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/beacon-object-files_bof-c-api.htm

==CS-Situational-Awareness-BOF==

https://github.com/trustedsec/CS-Situational-Awareness-BOF

A Developer's Introduction to Beacon Object Files

https://www.trustedsec.com/blog/a-developers-introduction-to-beacon-object-files

CS-Remote-OPs-BOF

https://github.com/trustedsec/CS-Remote-OPs-BOF

COFFLoader

https://github.com/trustedsec/COFFLoader