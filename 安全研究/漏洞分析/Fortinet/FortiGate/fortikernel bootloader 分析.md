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
seg000:000000000000008C                 db    0 # 远跳转到段选择符 0x10，偏移地址 0x20000。
seg000:000000000000008D                 db    2
seg000:000000000000008E                 db  10h
seg000:000000000000008F                 db    0
seg000:0000000000000090                 db  10h
seg000:0000000000000091                 db    0
seg000:0000000000000092                 db    0
```

