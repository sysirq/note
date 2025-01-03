以下分析以6.2.12 100d 的内核为主

# 0x00

```asm
seg000:0000000000000000                 mov     eax, 18h # 初始化段寄存器
seg000:0000000000000005                 mov     ds, eax
seg000:0000000000000007                 assume ds:nothing
seg000:0000000000000007
seg000:0000000000000007 loc_7:
seg000:0000000000000007                 mov     es, eax
seg000:0000000000000009                 assume es:nothing
seg000:0000000000000009                 mov     ss, eax
seg000:000000000000000B                 assume ss:nothing
seg000:000000000000000B                 lgdt    fword ptr cs:byte_100F11+1 # 加载 GDT
seg000:000000000000000B                                         ; DATA XREF: sub_2A98F5:loc_2A9AF1↓r
seg000:0000000000000012                 xor     eax, eax
seg000:0000000000000014                 or      eax, 20h
seg000:0000000000000017                 mov     cr4, rax # 用于启用物理地址扩展。
seg000:000000000000001A                 mov     edi, offset byte_180000
seg000:000000000000001F                 xor     eax, eax
seg000:0000000000000021                 mov     ecx, 1800h
seg000:0000000000000026                 rep stosd # 将 edi 设置为页表起始地址 0x180000。使用 rep stosd 将该地址范围清零。
seg000:0000000000000028                 mov     edi, offset byte_180000 #设置页表条目，从 0x181000 开始。每个页表条目指向内存的物理地址块。
seg000:000000000000002D                 lea     eax, [rdi+1007h]
seg000:0000000000000033                 mov     [rdi], eax
seg000:0000000000000035
seg000:0000000000000035 loc_35:                                 ; DATA XREF: sub_2E22D7:loc_2E27C1↓r
seg000:0000000000000035                 mov     edi, 181000h
seg000:000000000000003A                 lea     eax, [rdi+1007h]
seg000:0000000000000040                 mov     ecx, 4
seg000:0000000000000045
seg000:0000000000000045 loc_45:                                 ; CODE XREF: seg000:000000000000004F↓j
seg000:0000000000000045                 mov     [rdi], eax
seg000:0000000000000047                 add     eax, 1000h
seg000:000000000000004C                 add     edi, 8
seg000:000000000000004F                 jnz     short loc_45
seg000:0000000000000052                 mov     edi, offset unk_182000
seg000:0000000000000057                 mov     eax, 183h
seg000:000000000000005C                 mov     ecx, 800h
seg000:0000000000000061
seg000:0000000000000061 loc_61:                                 ; CODE XREF: seg000:000000000000006B↓j
seg000:0000000000000061                 mov     [rdi], eax
seg000:0000000000000063                 add     eax, 200000h
seg000:0000000000000068                 add     edi, 8
seg000:000000000000006B                 jnz     short loc_61
seg000:000000000000006E                 mov     eax, offset byte_180000
seg000:0000000000000073                 mov     cr3, rax # 设置页表基址 CR3。
seg000:0000000000000076                 mov     ecx, 0C0000080h
seg000:000000000000007B                 rdmsr
seg000:000000000000007D                 bts     eax, 8 # 长模式支持
seg000:0000000000000081                 wrmsr
seg000:0000000000000083                 mov     eax, 80000001h 
seg000:0000000000000088                 mov     cr0, rax # 切换到保护模式，
seg000:0000000000000088 ; ---------------------------------------------------------------------------
seg000:000000000000008B                 db 0EAh # 0EAh 是 JMP FAR 指令。
seg000:000000000000008C                 db    0 # 远跳转到段选择符 0x10，偏移地址 0x200。
seg000:000000000000008D                 db    2
seg000:000000000000008E                 db  10h
seg000:000000000000008F                 db    0
seg000:0000000000000090                 db  10h
seg000:0000000000000091                 db    0
seg000:0000000000000092                 db    0
```

# 0x01

```asm
seg000:0000000000000200 loc_200:                                ; DATA XREF: seg000:0000000000467AC0↓o
seg000:0000000000000200                                         ; seg000:00000000005B3750↓o ...
seg000:0000000000000200                 xor     eax, eax
seg000:0000000000000202                 mov     ds, eax
seg000:0000000000000204                 assume ds:nothing
seg000:0000000000000204                 mov     es, eax
seg000:0000000000000206                 assume es:nothing
seg000:0000000000000206                 mov     ss, eax
seg000:0000000000000208                 assume ss:nothing
seg000:0000000000000208                 mov     fs, eax
seg000:000000000000020A                 mov     gs, eax
seg000:000000000000020C                 lldt    ax
seg000:000000000000020F                 mov     eax, 20h ; ' '
seg000:0000000000000214                 ltr     ax
seg000:0000000000000217                 jmp     loc_100000 # 跳转
```

# 0x02

```asm
seg000:0000000000100000
seg000:0000000000100000
seg000:0000000000100000 sub_100000      proc near               ; CODE XREF: seg000:0000000000000217↑j
seg000:0000000000100000                                         ; DATA XREF: sub_100000↓o ...
seg000:0000000000100000                 lea     rbp, sub_100000
seg000:0000000000100007                 sub     rbp, 200000h    # 偏移地址计算
seg000:000000000010000E                 mov     rax, rbp
seg000:0000000000100011                 and     eax, (offset loc_1FFFFD+2)
seg000:0000000000100016                 test    eax, eax
seg000:0000000000100018                 jnz     loc_10018A
seg000:000000000010001E                 lea     rdx, sub_100000
seg000:0000000000100025                 mov     rax, 8000000000h
seg000:000000000010002F                 cmp     rdx, rax
seg000:0000000000100032                 jnb     loc_10018A
seg000:0000000000100038                 add     cs:qword_59F000, rbp
seg000:000000000010003F                 add     cs:qword_59F880, rbp
seg000:0000000000100046                 add     cs:qword_59FFF8, rbp
seg000:000000000010004D                 add     cs:qword_5A0000, rbp
seg000:0000000000100054                 add     cs:qword_5A1FF0, rbp
seg000:000000000010005B                 add     cs:qword_5A1FF8, rbp
seg000:0000000000100062                 add     cs:qword_5A2FD0, rbp
seg000:0000000000100069                 lea     rdi, sub_100000
seg000:0000000000100070                 and     rdi, 0FFFFFFFFFFE00000h
seg000:0000000000100077                 mov     rax, rdi
seg000:000000000010007A                 shr     rax, 1Eh
seg000:000000000010007E                 and     rax, 1FFh
seg000:0000000000100084                 jz      short loc_1000B7
seg000:0000000000100086                 lea     rdx, [rbp+6A6063h]
seg000:000000000010008D                 lea     rbx, qword_5A0000
seg000:0000000000100094                 mov     [rbx+rax*8], rdx
seg000:0000000000100098                 mov     rax, rdi
seg000:000000000010009B                 shr     rax, 15h
seg000:000000000010009F                 and     rax, 1FFh
seg000:00000000001000A5                 lea     rdx, [rdi+1E3h]
seg000:00000000001000AC                 lea     rbx, qword_5A6000
seg000:00000000001000B3                 mov     [rbx+rax*8], rdx
seg000:00000000001000B7
seg000:00000000001000B7 loc_1000B7:                             ; CODE XREF: sub_100000+84↑j
seg000:00000000001000B7                 lea     rdi, unk_5A5000
seg000:00000000001000BE                 lea     r8, [rdi+1000h]
seg000:00000000001000C5
seg000:00000000001000C5 loc_1000C5:                             ; CODE XREF: sub_100000+D8↓j
seg000:00000000001000C5                 test    qword ptr [rdi], 1
seg000:00000000001000CC                 jz      short loc_1000D1
seg000:00000000001000CE                 add     [rdi], rbp
seg000:00000000001000D1
seg000:00000000001000D1 loc_1000D1:                             ; CODE XREF: sub_100000+CC↑j
seg000:00000000001000D1                 add     rdi, 8
seg000:00000000001000D5                 cmp     rdi, r8
seg000:00000000001000D8                 jnz     short loc_1000C5
seg000:00000000001000DA                 add     cs:qword_5A7010, rbp
seg000:00000000001000E1                 add     cs:qword_645000, rbp
seg000:00000000001000E8                 add     cs:qword_645FF8, rbp
seg000:00000000001000EF                 jmp     short loc_100100
seg000:00000000001000EF ; ---------------------------------------------------------------------------
seg000:00000000001000F1                 align 20h
seg000:0000000000100100
seg000:0000000000100100 loc_100100:                             ; CODE XREF: sub_100000+EF↑j
seg000:0000000000100100                 mov     eax, 0A0h
seg000:0000000000100105                 mov     cr4, rax
seg000:0000000000100108                 mov     rax, 69F000h
seg000:000000000010010F                 add     rax, cs:qword_5A7010
seg000:0000000000100116                 mov     cr3, rax
seg000:0000000000100119                 mov     rax, 0FFFFFFFF80200122h
seg000:0000000000100120                 jmp     rax # 关键：jmp rax: 跳转到新的分页模式地址，进入的新执行路径。
seg000:0000000000100122 ; ---------------------------------------------------------------------------
seg000:0000000000100122                 mov     eax, 80000001h # 该地址应该已经更新为0FFFFFFFF80200122h
```

# ida修改显示地址,基地址

通过分析，设置image开始地址为0xFFFFFFFF80100000

```
Edit-->Segments-->Rebase Program
```

# 0x03

```asm
seg000:FFFFFFFF80200122                 mov     eax, 80000001h
................................................
................................................
................................................
................................................
seg000:FFFFFFFF8020017C                 mov     rax, cs:qword_FFFFFFFF806EDAE0
seg000:FFFFFFFF80200183                 push    0
seg000:FFFFFFFF80200185                 push    10h
seg000:FFFFFFFF80200187                 push    rax
seg000:FFFFFFFF80200188                 retfq
```

跳转到 cs:qword_FFFFFFFF806EDAE0 存储的地址

```asm
seg000:FFFFFFFF806EDAE0 qword_FFFFFFFF806EDAE0 dq 0FFFFFFFF8070826Fh
```

# 0x04 

```c
// write access to const memory has been detected, the output may be wrong!
void __fastcall __noreturn sub_FFFFFFFF8070826F(__int64 a1, unsigned __int64 a2)
{
  int v2; // eax
  unsigned __int64 v3; // kr00_8
  unsigned __int64 v4; // rax
  unsigned __int64 v5; // rsi
  unsigned __int64 v6; // rax
  unsigned __int64 v7; // rax
  __int64 v8; // rcx

  memset((void *)0xFFFFFFFF8074D000i64, 0, 9084928ui64);
  qword_FFFFFFFF8069F000 = 0i64;
  v2 = 0;
  if ( _bittest(&v2, 0xDu) )
  {
    v3 = __readeflags();
    _disable();
    v4 = __readcr4();
    v5 = v4;
    LOBYTE(v5) = v4 & 0x7F;
    __writecr4(v5);
    __writecr4(v4);
    __writeeflags(v3);
  }
  else
  {
    v6 = __readcr3();
    __writecr3(v6);
  }
  MEMORY[0xFFFFFFFF80750270] = 0x20000i64;
  v7 = 0xFFFFFFFF80708000ui64;
  v8 = 0xFFFFFFFF8074F000ui64;
  do
  {
    LOWORD(a2) = v7;
    a2 = (v7 >> 16 << 48) | (a2 & 0xFFFF00000000FFFFui64 | 0x8E0000100000i64) & 0xFFFFFFFFFFFFi64;
    *(_QWORD *)v8 = a2;
    *(_QWORD *)(v8 + 8) = HIDWORD(v7);
    v7 += 10i64;
    v8 += 16i64;
  }
  while ( v7 != 0xFFFFFFFF80708140ui64 );
  __lidt(word_FFFFFFFF806A95E0);
  sub_FFFFFFFF807081C0();//x86_64_start_reservations
}
```

跟进到尾部调用sub_FFFFFFFF807081C0

```c
void __fastcall __noreturn sub_FFFFFFFF807081C0()
{
  __int64 v0; // rdi
  _DWORD *v1; // rsi
  __int64 v2; // rcx
  _DWORD *v3; // rdi
  __int64 v4; // rcx
  __int64 v5; // rcx

  v1 = (_DWORD *)(v0 - 0x780000000000i64);
  v2 = 1024i64;
  v3 = (_DWORD *)&unk_FFFFFFFF80730300;
  while ( v2 )
  {
    *v3++ = *v1++;
    --v2;
  }
  sub_FFFFFFFF8071B3BA();
  sub_FFFFFFFF802198E8();
  sub_FFFFFFFF802198E8();
  sub_FFFFFFFF80714C50(v4, 0xFFFFFFFF806244B8ui64);
  sub_FFFFFFFF80708361(v5);
  sub_FFFFFFFF80708726();//start_kernel
}
```

通过fortigate 6.2.12 与fortigate 7.2.0的内核进行对比（都是3.2.16的内核版本） ，sub_FFFFFFFF807081C0 函数疑似为x86_64_start_reservations

那么sub_FFFFFFFF80708726函数 就是 start_kernel 函数



# 0x05

start_kernel 函数的最后一个调用为rest_init()函数

```c
void __noreturn sub_FFFFFFFF80708726()
{
................................
  sub_FFFFFFFF8055649C(); // rest_init 函数
}
```

# 0x06

根据 reset_init 函数， 找到 kernel_init 函数

```asm
sub_FFFFFFFF8055649C proc near
push    rax
call    sub_FFFFFFFF8028DD47
mov     edx, 0A00h
xor     esi, esi
mov     rdi, 0FFFFFFFF80708AADh # kernel_init 函数
call    sub_FFFFFFFF80207CC4
mov     edx, 600h
xor     esi, esi
mov     rdi, 0FFFFFFFF80271EF9h
call    sub_FFFFFFFF80207CC4
mov     rsi, 0FFFFFFFF806B0820h
mov     edi, eax
call    sub_FFFFFFFF8026F5A5
mov     cs:0FFFFFFFF8079D9D0h, rax
mov     rdi, 0FFFFFFFF8072EFA0h
call    sub_FFFFFFFF8024D7A0
mov     rdi, gs:0B5C0h
call    sub_FFFFFFFF8072C385
call    sub_FFFFFFFF8055FCE3
pop     rdx
jmp     sub_FFFFFFFF802007D1
sub_FFFFFFFF8055649C endp
```

# 0x07

kernel_init 函数的最后一个函数为调用用户空间init程序的函数

```c
void __noreturn sub_FFFFFFFF80708AAD()
{
............................
  sub_FFFFFFFF8055E0D5();
}
```

# 0x08

```asm
seg000:FFFFFFFF8055E0D5 sub_FFFFFFFF8055E0D5 proc near          ; CODE XREF: sub_FFFFFFFF80708AAD:loc_FFFFFFFF80708BBC↓p
seg000:FFFFFFFF8055E0D5                 push    rax
seg000:FFFFFFFF8055E0D6                 call    sub_FFFFFFFF802778FE
seg000:FFFFFFFF8055E0DB                 call    sub_FFFFFFFF8021511A
seg000:FFFFFFFF8055E0E0                 mov     cs:dword_FFFFFFFF806F02A0, 1
seg000:FFFFFFFF8055E0EA                 mov     rax, gs:0B5C0h
seg000:FFFFFFFF8055E0F3                 mov     rax, [rax+3F8h]
seg000:FFFFFFFF8055E0FA                 or      dword ptr [rax+5Ch], 40h
seg000:FFFFFFFF8055E0FE                 mov     rdi, cs:0FFFFFFFF80750090h
seg000:FFFFFFFF8055E105                 test    rdi, rdi
seg000:FFFFFFFF8055E108                 jz      short loc_FFFFFFFF8055E139
seg000:FFFFFFFF8055E10A                 mov     cs:qword_FFFFFFFF806A8280, rdi
seg000:FFFFFFFF8055E111                 mov     rdx, 0FFFFFFFF806A8160h
seg000:FFFFFFFF8055E118                 mov     rsi, 0FFFFFFFF806A8280h
seg000:FFFFFFFF8055E11F                 call    kernel_execve
seg000:FFFFFFFF8055E124                 mov     rsi, cs:0FFFFFFFF80750090h
seg000:FFFFFFFF8055E12B                 mov     rdi, 0FFFFFFFF806244F9h
seg000:FFFFFFFF8055E132                 xor     eax, eax
seg000:FFFFFFFF8055E134                 call    sub_FFFFFFFF8055E438
seg000:FFFFFFFF8055E139
seg000:FFFFFFFF8055E139 loc_FFFFFFFF8055E139:                   ; CODE XREF: sub_FFFFFFFF8055E0D5+33↑j
seg000:FFFFFFFF8055E139                 mov     rdi, cs:0FFFFFFFF80750098h
seg000:FFFFFFFF8055E140                 test    rdi, rdi
seg000:FFFFFFFF8055E143                 jz      short loc_FFFFFFFF8055E174
seg000:FFFFFFFF8055E145                 mov     cs:qword_FFFFFFFF806A8280, rdi
seg000:FFFFFFFF8055E14C                 mov     rdx, 0FFFFFFFF806A8160h
seg000:FFFFFFFF8055E153                 mov     rsi, 0FFFFFFFF806A8280h
seg000:FFFFFFFF8055E15A                 call    kernel_execve
seg000:FFFFFFFF8055E15F                 mov     rsi, cs:0FFFFFFFF80750098h
seg000:FFFFFFFF8055E166                 mov     rdi, 0FFFFFFFF80624860h
seg000:FFFFFFFF8055E16D                 xor     eax, eax
seg000:FFFFFFFF8055E16F                 call    sub_FFFFFFFF8055E438
seg000:FFFFFFFF8055E174
seg000:FFFFFFFF8055E174 loc_FFFFFFFF8055E174:                   ; CODE XREF: sub_FFFFFFFF8055E0D5+6E↑j
seg000:FFFFFFFF8055E174                 mov     rdi, 0FFFFFFFF80624511h #/sbin/init
seg000:FFFFFFFF8055E17B                 mov     cs:qword_FFFFFFFF806A8280, rdi
seg000:FFFFFFFF8055E182                 mov     rdx, 0FFFFFFFF806A8160h
seg000:FFFFFFFF8055E189                 mov     rsi, 0FFFFFFFF806A8280h
seg000:FFFFFFFF8055E190                 call    kernel_execve
seg000:FFFFFFFF8055E195                 mov     rdi, 0FFFFFFFF8062451Ch #/etc/init
seg000:FFFFFFFF8055E19C                 mov     cs:qword_FFFFFFFF806A8280, rdi
seg000:FFFFFFFF8055E1A3                 mov     rdx, 0FFFFFFFF806A8160h
seg000:FFFFFFFF8055E1AA                 mov     rsi, 0FFFFFFFF806A8280h
seg000:FFFFFFFF8055E1B1                 call    kernel_execve
seg000:FFFFFFFF8055E1B6                 mov     rdi, 0FFFFFFFF80624526h # /bin/init
seg000:FFFFFFFF8055E1BD                 mov     cs:qword_FFFFFFFF806A8280, rdi
seg000:FFFFFFFF8055E1C4                 mov     rdx, 0FFFFFFFF806A8160h
seg000:FFFFFFFF8055E1CB                 mov     rsi, 0FFFFFFFF806A8280h
seg000:FFFFFFFF8055E1D2                 call    kernel_execve
seg000:FFFFFFFF8055E1D7                 mov     rdi, 0FFFFFFFF80624530h # /bin/sh
seg000:FFFFFFFF8055E1DE                 mov     cs:qword_FFFFFFFF806A8280, rdi
seg000:FFFFFFFF8055E1E5                 mov     rdx, 0FFFFFFFF806A8160h
seg000:FFFFFFFF8055E1EC                 mov     rsi, 0FFFFFFFF806A8280h
seg000:FFFFFFFF8055E1F3                 call    kernel_execve
seg000:FFFFFFFF8055E1F8                 mov     rdi, 0FFFFFFFF80624898h
seg000:FFFFFFFF8055E1FF                 xor     eax, eax
seg000:FFFFFFFF8055E201                 call    panic
seg000:FFFFFFFF8055E201 sub_FFFFFFFF8055E0D5 endp
```

分析发现，该函数，并不会存在向虚拟机版本一样存在内核完整性检查机制？？？？？？



# 快速定位

对于向这种 ， 

```asm
mov     rdx, 0FFFFFFFF806244B8h  # 是个字符串 db 'TEXT DATA BSS',0
mov     rsi, rbx
mov     rdi, rax
call    sub_FFFFFFFF80714C50
```