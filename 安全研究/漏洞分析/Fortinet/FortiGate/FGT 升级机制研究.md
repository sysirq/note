# 代码逆向分析

通过字符串：

```
.rodata:000000000235D348	00000059	C	Error : Boot image on disk: %s is corrupted, please try to update the firmware again !\n 
```

以及：

```
.rodata:0000000002B729DB	0000001B	C	Bad upgrade image. Abort.\n
```

我们可以快速定位到固件升级处理函数，以FGT 6.2.5 为例，该版本的固件升级函数为：

```c
__int64 __fastcall sub_438C10(char *name, char *a2, int a3, int a4)
{
  int v5; // edx
  int v6; // ecx
  int v7; // er8
  int v8; // er9
  FILE *v9; // r14
  __off_t v10; // r12
  _BYTE *v11; // rax
  int v12; // edx
  int v13; // ecx
  int v14; // er8
  int v15; // er9
  _BYTE *v16; // rbx
  int v17; // edx
  int v18; // ecx
  int v19; // er8
  int v20; // er9
  unsigned int v21; // er12
  int i; // er14
  int v23; // edi
  int v24; // edx
  int v25; // ecx
  int v26; // esi
  int v27; // er8
  int v28; // er9
  int v29; // er15
  int v30; // eax
  int v31; // er14
  int v32; // er12
  int v33; // eax
  int v34; // edx
  int v35; // ecx
  int v36; // er8
  int v37; // er9
  int v38; // edi
  int v39; // er12
  const char *v40; // rdi
  char *v41; // rax
  unsigned __int8 *v42; // rdi
  const unsigned __int16 *v43; // rdx
  unsigned __int8 *v44; // rcx
  __int64 v45; // r8
  char *v46; // r9
  char *v47; // rax
  char *v48; // rsi
  int v49; // edx
  int v50; // ecx
  int v51; // er8
  int v52; // er9
  int v54; // edx
  int v55; // ecx
  int v56; // er8
  int v57; // er9
  int v58; // edi
  int v59; // eax
  int v60; // er13
  int v61; // edx
  int v62; // ecx
  int v63; // er8
  int v64; // er9
  int v65; // edx
  int v66; // ecx
  int v67; // er8
  int v68; // er9
  int v69; // edx
  int v70; // ecx
  int v71; // er8
  int v72; // er9
  int v73; // edx
  int v74; // ecx
  int v75; // er8
  int v76; // er9
  int v77; // edx
  int v78; // ecx
  int v79; // er8
  int v80; // er9
  int v81; // edx
  int v82; // ecx
  int v83; // er8
  int v84; // er9
  const char *v85; // rdi
  int v86; // [rsp+8h] [rbp-608h]
  int v87; // [rsp+Ch] [rbp-604h]
  int v88; // [rsp+10h] [rbp-600h]
  unsigned int v89; // [rsp+14h] [rbp-5FCh]
  int v90; // [rsp+18h] [rbp-5F8h]
  int v91; // [rsp+18h] [rbp-5F8h]
  int v93; // [rsp+28h] [rbp-5E8h]
  _DWORD stat_loc[7]; // [rsp+3Ch] [rbp-5D4h] BYREF
  char *v96; // [rsp+58h] [rbp-5B8h]
  int v97; // [rsp+60h] [rbp-5B0h]
  int v98; // [rsp+68h] [rbp-5A8h]
  __int64 v99; // [rsp+80h] [rbp-590h]
  __int64 v100; // [rsp+88h] [rbp-588h]
  __int64 v101; // [rsp+90h] [rbp-580h]
  char *argv[6]; // [rsp+B0h] [rbp-560h] BYREF
  struct stat stat_buf; // [rsp+E0h] [rbp-530h] BYREF
  char v104; // [rsp+170h] [rbp-4A0h] BYREF
  _BYTE v105[7]; // [rsp+171h] [rbp-49Fh] BYREF
  char v106; // [rsp+18Fh] [rbp-481h] BYREF
  char s[64]; // [rsp+190h] [rbp-480h] BYREF
  char v108[512]; // [rsp+1D0h] [rbp-440h] BYREF
  char buf[520]; // [rsp+3D0h] [rbp-240h] BYREF
  unsigned __int64 v110; // [rsp+5D8h] [rbp-38h]

  v110 = __readfsqword(0x28u);
  if ( __xstat(1, name, &stat_buf) || (v9 = fopen(name, "r")) == 0LL )
  {
    sub_1930AC0((unsigned int)"Cannot open file %s\n", (_DWORD)name, v5, v6, v7, v8);
    return (unsigned int)-1;
  }
  v10 = stat_buf.st_size;
  v11 = malloc(stat_buf.st_size);
  v16 = v11;
  if ( !v11 )
  {
    sub_1930AC0((unsigned int)"Cannot malloc %ld bytes.\n", v10, v12, v13, v14, v15);
    goto LABEL_42;
  }
  v21 = fread(v11, 1uLL, v10, v9);
  if ( (int)v21 < stat_buf.st_size )
  {
    sub_1930AC0((unsigned int)"Cannot read from file %s\n", (_DWORD)name, v17, v18, v19, v20);
    free(v16);
LABEL_42:
    v32 = -1;
    fclose(v9);
    return (unsigned int)v32;
  }
  fclose(v9);
  unlink(name);
  sleep(1u);
  if ( a4 )
  {
    memset(v108, 0, sizeof(v108));
    v86 = 1;
  }
  else
  {
    if ( (int)sub_20C1240(a2, v108) < 0 )
    {
      v32 = -1;
      sub_1930AC0((unsigned int)"Cannot read mbr %s\n", (_DWORD)a2, v54, v55, v56, v57);
      free(v16);
      return (unsigned int)v32;
    }
    v86 = sub_20C15E0(v108);
  }
  for ( i = 0; i != 1024; ++i )
  {
    v23 = i;
    close(v23);
  }
  v87 = sub_20D1FE0();
  if ( !v87 || !a3 )
  {
    if ( (unsigned int)sub_436250() )
    {
      v26 = *__errno_location();
      if ( v26 != 22 )
      {
        v85 = "umount shared data partition failed (%d)\n";
        goto LABEL_78;
      }
    }
    a3 = umount("/data");
    if ( a3 )
    {
      v26 = *__errno_location();
      if ( v26 != 22 )
      {
        v85 = "umount data directory failed (%d)\n";
        goto LABEL_78;
      }
      a3 = 0;
    }
  }
  v29 = sub_438410(v16, v21);
  if ( v29 < 0 )
  {
    v26 = *__errno_location();
    v85 = "check_gz_header() failed (%d)\n";
LABEL_78:
    v32 = -1;
    sub_1930AC0((_DWORD)v85, v26, v24, v25, v27, v28);
    free(v16);
    return (unsigned int)v32;
  }
  v99 = 0LL;
  v100 = 0LL;
  v101 = 0LL;
  v30 = inflateInit2_(&stat_loc[1], 4294967281LL, "1.2.11", 112LL);
  v31 = v30;
  if ( v30 )
  {
    v26 = v30;
    v85 = "inflateInit() failed (%d)\n";
    goto LABEL_78;
  }
  stat_loc[3] = v21 - v29;
  v32 = -1;
  *(_QWORD *)&stat_loc[1] = &v16[v29];
  v96 = buf;
  v97 = 512;
  v88 = 0;
  v93 = -1;
  v90 = 1;
  v89 = 1;
  while ( 1 )
  {
    v33 = inflate(&stat_loc[1], 0LL);
    if ( v33 == 1 )
      break;
    if ( v33 )
    {
      sub_1930AC0((unsigned int)"inflate() failed (%d)\n", v33, v34, v35, v36, v37);
      goto LABEL_47;
    }
    if ( !v97 )
    {
      sub_20C0800(buf, 512LL, 0LL);
      v31 += 512;
      if ( v90 )
      {
        if ( (unsigned int)sub_20C13C0(v108, buf) )
        {
          if ( a3 )
          {
            sub_1930AC0(
              (unsigned int)"\nImage with incompatible partition layout cannot \nbe restored to secondary partition.\n",
              a3,
              v61,
              v62,
              v63,
              v64);
            goto LABEL_47;
          }
          qmemcpy(v108, buf, sizeof(v108));
          v32 = open(a2, 66, 511LL);
          if ( v32 < 0 )
          {
            v32 = -1;
            sub_1930AC0((unsigned int)"Cannot open file %s\n", (_DWORD)a2, v81, v82, v83, v84);
            goto LABEL_40;
          }
          sub_2195FD0(s, a2, 0x40uLL);
          v93 = -1;
          v88 = v90;
        }
        else
        {
          if ( !v87 || v86 > 1 && (v89 = 2, (unsigned int)sub_20C1360(v108) != 1) )
            v89 = v90;
          v88 = sub_7A3560(s, 0x40uLL, a2);
          if ( v88 )
          {
            sub_1930AC0((unsigned int)"Error: in function hdconv2,device name invalid\n", 64, v65, v66, v67, v68);
LABEL_47:
            if ( v32 == -1 )
              goto LABEL_40;
            goto LABEL_48;
          }
          if ( (unsigned int)sub_1B2DB90(512LL) )
          {
            fflush(stdout);
            fflush(stderr);
            if ( !fork() )
            {
              argv[0] = "/bin/mke2fs";
              argv[1] = "-b4096";
              argv[2] = "-q";
              argv[3] = s;
              argv[4] = 0LL;
              execve("/bin/mke2fs", argv, &off_336CB20);
              exit(-1);
            }
            wait((__WAIT_STATUS)stat_loc);
          }
          v32 = open(s, 66, 511LL);
          if ( v32 < 0 )
          {
            v32 = -1;
            sub_1930AC0((unsigned int)"Cannot open file %s\n", (unsigned int)s, v69, v70, v71, v72);
            goto LABEL_40;
          }
          v93 = sub_20C14F0(buf);//恒定为512
          sub_20C1560(v108, 1LL);
          if ( (int)sub_20C12B0(a2, v108) < 0 )
          {
            sub_1930AC0((unsigned int)"can't modify mbr\n", (unsigned int)v108, v73, v74, v75, v76);
LABEL_48:
            v58 = v32;
            v32 = -1;
            close(v58);
            goto LABEL_40;
          }
        }
      }
      if ( v31 > v93 && (int)sub_438B90(v32, buf, 512) < 0 )//跳过第一块mbr，后面才进行mbr的写入
        goto LABEL_63;
      v96 = buf;
      v97 = 512;
      v90 = 0;
    }
  }
  if ( v98 - v31 > 0 )
  {
    v91 = v98 - v31;
    sub_20C0800(buf, (unsigned int)(v98 - v31), 0LL);
    if ( v31 > v93 && (int)sub_438B90(v32, buf, v91) < 0 )
    {
LABEL_63:
      sub_1930AC0(
        (unsigned int)"Error : Boot image on disk: %s is corrupted, please try to update the firmware again !\n ",
        (unsigned int)s,
        v77,
        v78,
        v79,
        v80);
      goto LABEL_47;
    }
  }
  fsync(v32);
  v38 = v32;
  v39 = 4;
  close(v38);
  v40 = v16 + 10;
  do
  {
    v41 = strchr(v40, 45);
    --v39;
    v40 = v41 + 1;
  }
  while ( v39 );
  v42 = (unsigned __int8 *)(v41 + 1);
  v43 = *__ctype_b_loc();
  while ( (v43[*v42] & 0x800) != 0 )
    ++v42;
  if ( v16 + 10 == v42 )
  {
    v48 = &v104;
  }
  else
  {
    v44 = v16 + 11;
    v46 = &v106;
    v104 = v16[10];
    v47 = v105;
    while ( 1 )
    {
      v48 = v47;
      if ( v42 == v44 )
        break;
      v45 = *v44++;
      *v47++ = v45;
      if ( &v106 == v48 + 1 )
      {
        v48 = &v106;
        break;
      }
    }
  }
  *v48 = 0;
  sub_20C1580(v108, v89, &v104, v44, v45, v46);
  if ( !a3 )
    sub_20C1510(v108, v89);
  if ( !v88 )
    sub_20C1560(v108, 0LL);
  if ( (int)sub_20C12B0(a2, v108) < 0 )
  {
    v32 = -1;
    sub_1930AC0((unsigned int)"can't modify mbr\n", (unsigned int)v108, v49, v50, v51, v52);
  }
  else
  {
    v32 = v98;
    if ( !a3 )
    {
      sync();
      sleep(2u);
      v59 = open(a2, 0);
      v60 = v59;
      if ( v59 >= 0 )
      {
        ioctl(v59, 0x125FuLL);
        close(v60);
        sync();
        sleep(4u);
      }
    }
  }
LABEL_40:
  inflateEnd(&stat_loc[1]);
  free(v16);
  return (unsigned int)v32;
}
```

该函数的主要逻辑为：

- 跳过固件文件的gz header
- 然后用libz库，以512字节为块进行解压缩
- 对512字节解压缩完毕的内容进行解密 ( 该版本对应的解密函数为 sub_20C0800 )

```c
void __fastcall sub_20C0800(__int64 a1, int a2, int a3)
{
  _BYTE *v3; // r9
  int v4; // esi
  __int64 v5; // r10
  int v6; // esi
  __int64 v7; // rcx
  char v8; // al
  char v9; // bl
  char v10; // r12
  char v11; // r8

  v3 = off_3994560;
  if ( off_3994560 )
  {
    if ( (a2 & 0x1FF) != 0 )
    {
      sub_1930AC0('\x02\x9B\xC3&');
    }
    else
    {
      v4 = a2 >> 9;
      if ( v4 > 0 )
      {
        v5 = a1 + (((unsigned int)(v4 - 1) + 1LL) << 9);
        do
        {
          v6 = 0;
          v7 = 0LL;
          v8 = 0xFF;
          do
          {
            while ( 1 )
            {
              v9 = *(_BYTE *)(a1 + v7);
              v10 = v3[v6];
              v6 = ((_BYTE)v6 + 1) & 0x1F;
              v11 = v7 & 0x1F;
              if ( !a3 )
                break;
              v8 ^= v10 ^ (v9 + v11);
              *(_BYTE *)(a1 + v7++) = v8;
              if ( v7 == 512 )
                goto LABEL_9;
            }
            *(_BYTE *)(a1 + v7++) = (v10 ^ v9 ^ v8) - v11;
            v8 = v9;
          }
          while ( v7 != 512 );
LABEL_9:
          a1 += 512LL;
        }
        while ( a1 != v5 );
      }
    }
  }
}
```

通过该函数，我们可以获取到各种用于解密的key值（off_3994560）

```python
import ida_bytes

start_address = 0x0000000003994180
end_address   = 0x0000000003994560
data_size = end_address - start_address
data = ida_bytes.get_bytes(start_address,data_size)

i = 0
while i < len(data):
    print(data[i:i+32])
    i+=32 
```

out：

```
b'a9bBCc0dpEFsgGHhkQj1kKoLJInNoOPP'
b'c3bOCc7d5EmjgGHhPISJkKlLmMTQo4PP'
b'c3bOCc7d5EmjgghhPISJkkllmMTQo4PP'
b'aAbBCcDdeESsgGHhkQj1kKoLJInNoOPP'
b'oAbBIcDde7FfgGHhiIjJ7TdLAsnN3OPP'
b'oAbBIcDde7FfgGHhiIjJ7KlLmsnN3OPP'
b'aAfBcCmMeEFfgJHhiIjJkqlLmInNo8PP'
b'aAbBcCmMeEFfgGHhiIjJkqlLmInNo8pP'
b'aAbBCcDdeEFfgGHhiIjJkKlLmMnNoOPP'
b'aAbBCcDdeEFfgGHhiIjJkKlLmMnNoOPP'
b'aAbBCcDdeiFMg0HhiIjuhUHLmMnNoOPP'
b'aAbNCcxdeE3btGDhi8AMkK7Lm9nM6McP'
b'aAbBCcDdeiFMg0HhiIjuhUHLmMnNoOPP'
b'aAbNCcDdeE3bgGDhi8jMkKLLm9nM6McP'
b'mPnNCcXdeE3bgGDhi8jMkKLLm9nH6McP'
b'mPnNCcXdeE3bgGDhi8jMkKLLm9nH6McP'
b'aAvRCcQdeE3bgGDhi8jZkKLLm9nY6McP'
b'aAbNCcxdeE3btGDhi8AMkK7Lm9nM6McP'
b'aAbNCcxdeE3btGDhi8AMkK7Lm9nM6McP'
b'bA8BWlDd0BFfCQ3h8IAJ8KZLmMCNzOzP'
b'BA8BWlDD0BFFCQ3H8IAJ8KZLmMCNzOzP'
b'aAbNCcxdeE3btGDhi8AMkK7Lm9nM6McP'
b'aA8BWlDd0EFfCQUh8IAJMKZLmMCNYOzP'
b'bTbJCcKdeE3dgGDhi8jYkKLLm9nU4McP'
b'aA8BWlDd0EFfCQUh8IAJMKZLmMCNYOzP'
b'n26B9laP0EFfiQBhiSAQWKXem7CnYizJ'
b'aA8BWlDd0EFfCQUh8IAJMKZLmMCNYOzP'
b'n2479laP0EFSiQBh8SAQMaXEm7CNY1zP'
b'n26B9laP0pFf3QBh8SAQMKXEm7CNYiKP'
b'n26B9l3P0EFXiQBh8SAQMKXEmLCNYizP'
b'n86B9laP0EFfiQBh8SAQ1KXEm7CNYizX'
```

对于FGT 6_2_5 用于解密的key为：

```
oAbBIcDde7FfgGHhiIjJ7KlLmsnN3OPP
```

该函数的逻辑为：

```c
//ciphertext 长度为512字节， key 长度为 32字节
int decrypt(uint8_t *ciphertext,uint8_t *key){
	size_t block_offset = 0;
	size_t key_offset = 0;
	uint8_t previous_ciphertext_byte = 0xFF;
	uint8_t xor = 0;

	while(block_offset < CHUNK_SIZE){
		xor = (key[key_offset] ^ (ciphertext[block_offset]) ^ previous_ciphertext_byte) - (block_offset & 0x1F);
		previous_ciphertext_byte = ciphertext[block_offset];
		ciphertext[block_offset] = xor;
		key_offset = (key_offset+1) & 0x1f;
		block_offset++;
	}

	return 0;
}
```

解压代码：

```c
#include <stdio.h>
#include <zlib.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#define  CHUNK_SIZE 512
#define GZ_INVALID_HEADER 0xFFFFFFFF

char *keys[] = {
"a9bBCc0dpEFsgGHhkQj1kKoLJInNoOPP",
"c3bOCc7d5EmjgGHhPISJkKlLmMTQo4PP",
"c3bOCc7d5EmjgghhPISJkkllmMTQo4PP",
"aAbBCcDdeESsgGHhkQj1kKoLJInNoOPP",
"oAbBIcDde7FfgGHhiIjJ7TdLAsnN3OPP",
"oAbBIcDde7FfgGHhiIjJ7KlLmsnN3OPP",
"aAfBcCmMeEFfgJHhiIjJkqlLmInNo8PP",
"aAbBcCmMeEFfgGHhiIjJkqlLmInNo8pP",
"aAbBCcDdeEFfgGHhiIjJkKlLmMnNoOPP",
"aAbBCcDdeEFfgGHhiIjJkKlLmMnNoOPP",
"aAbBCcDdeiFMg0HhiIjuhUHLmMnNoOPP",
"aAbNCcxdeE3btGDhi8AMkK7Lm9nM6McP",
"aAbBCcDdeiFMg0HhiIjuhUHLmMnNoOPP",
"aAbNCcDdeE3bgGDhi8jMkKLLm9nM6McP",
"mPnNCcXdeE3bgGDhi8jMkKLLm9nH6McP",
"mPnNCcXdeE3bgGDhi8jMkKLLm9nH6McP",
"aAvRCcQdeE3bgGDhi8jZkKLLm9nY6McP",
"aAbNCcxdeE3btGDhi8AMkK7Lm9nM6McP",
"aAbNCcxdeE3btGDhi8AMkK7Lm9nM6McP",
"bA8BWlDd0BFfCQ3h8IAJ8KZLmMCNzOzP",
"BA8BWlDD0BFFCQ3H8IAJ8KZLmMCNzOzP",
"aAbNCcxdeE3btGDhi8AMkK7Lm9nM6McP",
"aA8BWlDd0EFfCQUh8IAJMKZLmMCNYOzP",
"bTbJCcKdeE3dgGDhi8jYkKLLm9nU4McP",
"aA8BWlDd0EFfCQUh8IAJMKZLmMCNYOzP",
"n26B9laP0EFfiQBhiSAQWKXem7CnYizJ",
"aA8BWlDd0EFfCQUh8IAJMKZLmMCNYOzP",
"n2479laP0EFSiQBh8SAQMaXEm7CNY1zP",
"n26B9laP0pFf3QBh8SAQMKXEm7CNYiKP",
"n26B9l3P0EFXiQBh8SAQMKXEmLCNYizP",
"n86B9laP0EFfiQBh8SAQ1KXEm7CNYizX",
NULL
};

/* gzip header struct
offset len      name    desc
0	1	ID1	必须为 0x1F
1	1	ID2	必须为 0x8B
2	1	CM	压缩方法，通常为 8 (DEFLATE)
3	1	FLG	标志字节
4	4	MTIME	修改时间
8	1	XFL	额外标志
9	1	OS	操作系统类型
*/

// 检查 GZIP 文件头并返回头部长度
uint64_t check_gz_header(const uint8_t *buffer, size_t buffer_size) {
    if (!buffer || buffer_size < 10) {
        return GZ_INVALID_HEADER; // 缓冲区无效或长度不足
    }

    // 检查 GZIP 标识符
    if (buffer[0] != 0x1F || buffer[1] != 0x8B) {
        return GZ_INVALID_HEADER; // ID1 和 ID2 不匹配
    }

    // 检查压缩方法（CM）是否为 DEFLATE，以及标志字节（FLG）
    if (buffer[2] != 8 || (buffer[3] & 0xE0) != 0) {
        return GZ_INVALID_HEADER; // 非 DEFLATE 或标志字节非法
    }

    size_t header_length = 10; // 基本头部长度
    uint8_t flags = buffer[3]; // 标志字节

    // 处理 FEXTRA（扩展字段）
    if (flags & 0x04) {
        if (header_length + 2 > buffer_size) {
            return GZ_INVALID_HEADER; // 缓冲区不足
        }
        size_t extra_length = buffer[header_length] | (buffer[header_length + 1] << 8);
        header_length += 2 + extra_length;
        if (header_length > buffer_size) {
            return GZ_INVALID_HEADER; // 缓冲区不足
        }
    }

    // 处理 FNAME（文件名）
    if (flags & 0x08) {
        while (header_length < buffer_size && buffer[header_length] != '\0') {
            header_length++;
        }
        if (header_length >= buffer_size) {
            return GZ_INVALID_HEADER; // 缓冲区不足
        }
        header_length++; // 跳过 '\0'
    }

    // 处理 FCOMMENT（注释）
    if (flags & 0x10) {
        while (header_length < buffer_size && buffer[header_length] != '\0') {
            header_length++;
        }
        if (header_length >= buffer_size) {
            return GZ_INVALID_HEADER; // 缓冲区不足
        }
        header_length++; // 跳过 '\0'
    }

    // 处理 FHCRC（头部校验）
    if (flags & 0x02) {
        header_length += 2;
        if (header_length > buffer_size) {
            return GZ_INVALID_HEADER; // 缓冲区不足
        }
    }

    // 最终检查头部长度
    if (header_length > buffer_size) {
        return GZ_INVALID_HEADER; // 缓冲区不足
    }

    return header_length; // 返回头部长度
}

//ciphertext 长度为512字节， key 长度为 32字节
int decrypt(uint8_t *ciphertext,uint8_t *cleartext,uint8_t *key){
	size_t block_offset = 0;
	size_t key_offset = 0;
	uint8_t previous_ciphertext_byte = 0xFF;
	uint8_t xor = 0;

	while(block_offset < CHUNK_SIZE){
		xor = (key[key_offset] ^ (ciphertext[block_offset]) ^ previous_ciphertext_byte) - (block_offset & 0x1F);
		previous_ciphertext_byte = ciphertext[block_offset];
		cleartext[block_offset] = xor;
		key_offset = (key_offset+1) & 0x1f;
		block_offset++;
	}

	return 0;
}

#define MBR_SIZE 512
#define PARTITION_TABLE_OFFSET 446
#define PARTITION_ENTRY_SIZE 16
#define PARTITION_TABLE_SIZE 64
#define SIGNATURE_OFFSET 510
#define MBR_SIGNATURE 0xAA55

typedef struct {
    uint8_t boot_flag;       // 启动标志
    uint8_t start_chs[3];    // 起始CHS地址
    uint8_t partition_type;  // 分区类型
    uint8_t end_chs[3];      // 结束CHS地址
    uint32_t start_lba;      // 起始LBA地址
    uint32_t size_in_sectors; // 分区大小（扇区数）
} PartitionEntry;

int check_valid_mbr(uint8_t* mbr){
	uint16_t signature = *(uint16_t *)(mbr + SIGNATURE_OFFSET);
	uint8_t *partition_table = mbr + PARTITION_TABLE_OFFSET;
	uint32_t previous_lba_end = 0;
	if (signature != MBR_SIGNATURE)
		return -1;
	for (int i = 0; i < 4; i++) {
		PartitionEntry *entry = (PartitionEntry *)(partition_table + i * PARTITION_ENTRY_SIZE);
		if (entry->partition_type != 0x00) {
			if (entry->boot_flag != 0x00 && entry->boot_flag != 0x80) {//0x00: 非活动分区 , 0x80: 活动分区（最多一个）。
				return -1;
			}

			if (entry->size_in_sectors == 0) {
                return -1;
            }

			if(previous_lba_end != 0){
				if(previous_lba_end != entry->start_lba)
					return -1;
				if(previous_lba_end > entry->start_lba)
					return -1;
			}

			previous_lba_end = entry->start_lba + entry->size_in_sectors;
		} 
	}
	return 0;
}

int print_mbr_info(uint8_t* mbr)
{
	uint8_t *partition_table = mbr + PARTITION_TABLE_OFFSET;
	for (int i = 0; i < 4; i++) {
		PartitionEntry *entry = (PartitionEntry *)(partition_table + i * PARTITION_ENTRY_SIZE);

		if (entry->partition_type != 0x00) {
			if (entry->boot_flag != 0x00 && entry->boot_flag != 0x80) {
				return -1;
			}

			printf("分区 %d: 类型 0x%02X,分区标志 %x, 起始 LBA %u, 大小 %u 扇区\n",
                   i + 1, entry->partition_type,entry->boot_flag, entry->start_lba, entry->size_in_sectors);
		}
	}
	return 0;
}

int decompress(uint8_t *input_data,size_t input_data_size,char *out_file_name)
{
	z_stream strm;
	char *key = NULL;
	unsigned char out_buffer[CHUNK_SIZE];
	unsigned char cleartext[CHUNK_SIZE];
	int ret;
	FILE *fp;
	memset(&strm,0,sizeof(z_stream));
	int is_first_chunk = 1;
	
	fp = fopen(out_file_name,"wb");
	if(fp == NULL){
		printf("open out file error\n");
		return -1;
	}

	if(inflateInit2_(&strm,4294967281,"1.2.11",sizeof(strm)) != Z_OK){
		printf("inflate Init error\n");
		return -1;
	}
	
	strm.next_in = input_data;
	strm.avail_in = input_data_size;

	do{
		strm.next_out = out_buffer;
		strm.avail_out = CHUNK_SIZE;
		ret = inflate(&strm, Z_NO_FLUSH);
		switch(ret){
			case Z_STREAM_ERROR:
				fprintf(stderr, "inflate failed: Z_STREAM_ERROR\n");
				inflateEnd(&strm);
				return -1;
			case Z_MEM_ERROR:
				fprintf(stderr, "inflate failed: Z_MEM_ERROR\n");
				inflateEnd(&strm);
				return -1;
			case Z_DATA_ERROR:
				fprintf(stderr, "inflate failed: Z_DATA_ERROR\n");
				inflateEnd(&strm);
				return -1;

		
		}

		if(key == NULL){
			int i = 0;
			while(keys[i] != NULL){
				decrypt(out_buffer,cleartext,keys[i]);
				if(check_valid_mbr(cleartext) == 0){
					key = keys[i];
					printf("found key for decrypt:%s\n",key);
					break;
				}
				i++;
			}

			if(key == NULL){
				printf("not found valid key for firmware decrypt\n");
				exit(0);
			}
		}

		decrypt(out_buffer,cleartext,key);

		if(is_first_chunk == 1){
			print_mbr_info(cleartext);
			printf("mbr size:%d\n",(*(unsigned int*)(cleartext+0x94) + *(unsigned int*)(cleartext+0x90))<<9 );
			is_first_chunk = 0;
		}

		fwrite(cleartext,CHUNK_SIZE - strm.avail_out,1,fp);
		
	}while(ret != Z_STREAM_END);

	inflateEnd(&strm);

	printf("decompressed len:%ld\n",strm.total_out);

	if (ret == Z_STREAM_END) {
        fprintf(stderr, "\nDecompression complete.\n");
        return 0;
    } else {
        fprintf(stderr, "\nDecompression failed.\n");
    	return -1;
    }
}

int main(int argc,char *argv[])
{
	if(argc != 3){
		printf("usage: %s <FIRMWARE NAME> <DECRYPT OUT FILE>\n",argv[0]);
		return 0;
	}
	int fd = open(argv[1], O_RDONLY);
	char *out_file_name = argv[2];
	if(fd == -1){
		perror("Failed to open file");
		return -1;
	}

	struct stat file_stat;
	if(fstat(fd,&file_stat) == -1){
		perror("Failed to get file size");
		close(fd);
		return -1;
	}

	printf("file size: %ld\n",file_stat.st_size);
	
	size_t file_size = file_stat.st_size - 256;//skip signature
	char *buffer = malloc(file_size);
    	if (!buffer) {
        	perror("Failed to allocate memory");
        	close(fd);
        	return -1;
    	}

	size_t bytes_read = 0;
    	while (bytes_read < file_size) {
		ssize_t result = read(fd, buffer + bytes_read, file_size - bytes_read);
        	if (result < 0) {
            		perror("Failed to read file");
            		free(buffer);
            		close(fd);
            		return -1;
        	}
        	bytes_read += result;
    	}
	close(fd);
	
	size_t gz_header_len = check_gz_header(buffer,file_size);
	printf("gz header len  : %ld\n",gz_header_len);
	printf("compressed len : %ld\n",file_size - gz_header_len);
	decompress(buffer + gz_header_len ,file_size - gz_header_len,out_file_name);
	
	free(buffer);
	return 0;
}
```





# 参考资料

Breaking Fortinet Firmware Encryption

https://bishopfox.com/blog/breaking-fortinet-firmware-encryption