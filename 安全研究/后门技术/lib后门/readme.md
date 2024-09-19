# 目标

通过lib库，劫持特定程序的函数

# Demo说明

只适合拥有gnu_debugdata section的二进制文件，且二进制文件必须为单进程

# HOOK

```
CALLER
| ...
| CALL X -(1)---> X
| ...  <----.     | ...
` RET       |     ` RET -.
            `--------(2)-'
```

```
CALLER
| ...
| CALL X -(1)---> X
| ...  <----.     | JUMP -(2)----> khook_X_stub
` RET       |     | ???            | INCR use_count
            |     | ...  <----.    | CALL handler   -(3)----> khook_X
            |     | ...       |    | DECR use_count <----.    | ...
            |     ` RET -.    |    ` RET -.              |    | CALL origin -(4)----> khook_X_orig
            |            |    |           |              |    | ...  <----.           | N bytes of X
            |            |    |           |              |    ` RET -.    |           ` JMP X + N -.
            `------------|----|-------(8)-'              '-------(7)-'    |                        |
                         |    `-------------------------------------------|--------------------(5)-'
                         `-(6)--------------------------------------------'
```

# 动态库

# 参考资料

Acronyms relevant to Executable and Linkable Format (ELF)

https://stevens.netmeister.org/631/elf.html

Oracle Documentation Executable and Linking Format Specification, Version 1.2

https://docs.oracle.com/cd/E19683-01/817-3677/6mj8mbtc9/index.html#chapter6-79797

inject_got

https://github.com/zhougy0717/inject_got

Support for mini-debuginfo in LLDB

https://archive.fosdem.org/2020/schedule/event/debugging_mini/attachments/slides/4059/export/events/attachments/debugging_mini/slides/4059/fosdem2020_minidebuginfo_kkleine.pdf

为二进制文件添加.gnu_debugdata调试信息

https://blog.csdn.net/youyoulg/article/details/140343985