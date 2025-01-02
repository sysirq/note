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
seg000:0000000000000217                 jmp     loc_100000
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
