```
FortiGate-100D login: admin
Password: *****
Welcome!

FortiGate-100D # execute restore image tftp image.out 192.168.1.110
This operation will replace the current firmware version!
Do you want to continue? (y/n)y

Please wait...

Connect to tftp server 192.168.1.110 ...
#########################################################

Get image from tftp server OK.
The new image does not have a valid RSA signature.

Checking new firmware integrity ... pass

Please wait for system to restart.


Firmware upgrade in progress ...
Error : Boot image on disk: /dev/sdb1 is corrupted, please try to update the firmware again !
 Bad upgrade image. Abort.
Done.


The system is going down NOW !!

Please stand by while rebooting the system.
Restarting system.
FortiGate-100D (17:36-08.07.2014)
Ver:05000006
Serial number:FG100D3G17803968
RAM activation
CPU(00:000106ca bfebfbff): MP initialization
CPU(01:000106ca bfebfbff): MP initialization
CPU(02:000106ca bfebfbff): MP initialization
CPU(03:000106ca bfebfbff): MP initialization
Total RAM: 4096MB
Enabling cache...Done.
Scanning PCI bus...Done.
Allocating PCI resources...Done.
Enabling PCI resources...Done.
Zeroing IRQ settings...Done.
Verifying PIRQ tables...Done.
Boot up, boot device capacity: 15272MB.
Press any key to display configuration menu...
......

Reading boot image 2721475 bytes.
Initializing firewall...
System is starting...
Starting system maintenance...
Scanning /dev/sdb2... (100%)   
Scanning /dev/sdb3... (100%)   
Detected failed upgrade on backup partition


FortiGate-100D login: admin
Password: *****
Welcome!
```

# 固件格式分析

通过字符串：

```
.rodata:0000000003417E28	0000001F	C	Get image from tftp server OK.
```

可以找到固件格式检查代码：

```c
__int64 __fastcall sub_239E780(int a1, const char **a2)
{
  char *v3; // r12
  char *v4; // r13
  __int64 v5; // r12
  unsigned int v6; // er13
  void *v8; // rsi
  int v9; // ebx
  int v10; // eax
  int *v11; // rax
  __int64 v12; // rax
  __int64 v13; // r12
  __int64 v14; // rbx
  char *s2; // [rsp+8h] [rbp-168h] BYREF
  __int64 v16; // [rsp+12h] [rbp-15Eh] BYREF
  int v17; // [rsp+1Ah] [rbp-156h]
  __int16 v18; // [rsp+1Eh] [rbp-152h]
  char s1[32]; // [rsp+20h] [rbp-150h] BYREF
  char nptr[128]; // [rsp+40h] [rbp-130h] BYREF
  char v21[136]; // [rsp+C0h] [rbp-B0h] BYREF
  unsigned __int64 v22; // [rsp+148h] [rbp-28h]

  v22 = __readfsqword(0x28u);
  v18 = 0;
  s2 = 0LL;
  v16 = 0LL;
  v17 = 0;
  if ( a1 <= 0 )
  {
    LODWORD(v5) = 0;
    fwrite("Incomplete command.\n", 1uLL, 0x14uLL, stderr);
    putchar(10);
    sub_90A8C0("disk_erase_help");
    sub_908AC0();
    return (unsigned int)v5;
  }
  s1[0] = 0;
  sub_2814F20((__int64)&s2, 0LL);
  v3 = s2;
  if ( !s2 )
  {
    LODWORD(v5) = 1;
    fwrite("Boot disk not found.\n", 1uLL, 0x15uLL, stderr);
    return (unsigned int)v5;
  }
  v4 = (char *)*a2;
  if ( !strcmp(*a2, "boot") )
  {
    sub_292B4D0(s1, v3, 0x20uLL);
  }
  else
  {
    s1[0] = 0;
    v8 = (void *)sub_9078F0(v4);
    if ( v8 )
      sub_292B4D0(s1, v8, 0x20uLL);
  }
  if ( !s1[0] || (LODWORD(v5) = sub_28330F0(s1), (_DWORD)v5) )
  {
    LODWORD(v5) = -56;
    fprintf(stderr, "Disk [%s] not found.\n", *a2);
    return (unsigned int)v5;
  }
  if ( !strcmp(s1, s2) )
  {
    v6 = 1;
    if ( (unsigned int)sub_239E690() )
    {
      fwrite("Cannot erase boot device on this Fortigate.\n", 1uLL, 0x2CuLL, stderr);
      return (unsigned int)v5;
    }
  }
  else
  {
    v6 = 0;
  }
  if ( !(unsigned int)sub_2091410(
                        "\n"
                        "WARNING\n"
                        "This will permanently erase all data from the storage media.\n"
                        "(This may take as short as a few minutes or over an hour depending on the size\n"
                        "of the disk and the number of times you wish to overwrite the disk.)\n"
                        "WARNING\n"
                        "\n") )
    return (unsigned int)v5;
  if ( !(unsigned int)sub_2090E00("How many times do you wish to overwrite the media? ", 0LL) )
    return (unsigned int)v5;
  v9 = strtol(nptr, 0LL, 10);
  if ( v9 <= 0 )
    return (unsigned int)v5;
  if ( !v6 )
  {
LABEL_27:
    v12 = sub_44B1E0();
    v13 = v12;
    if ( v12 )
    {
      v14 = (unsigned int)sub_44B1F0(v12, s1, (unsigned int)v9, v6);
      sub_44B220(v13, v14);
      v5 = (_DWORD)v14 != 0;
    }
    else
    {
      LODWORD(v5) = -24;
    }
    return (unsigned int)v5;
  }
  if ( !(unsigned int)sub_2091410("Restore the image after erasing.\n") )
  {
    if ( !(unsigned int)sub_2091410("Erasing boot disk will make VM unbootable.\n") )
      return (unsigned int)v5;
    goto LABEL_27;
  }
  if ( (unsigned int)sub_2090E00("TFTP server: ", 0LL)
    && (unsigned int)sub_2090E00("TFTP file: ", 0LL)
    && !(unsigned int)sub_239E5F0(v21, nptr, "/tmp/uploadxxxx") )//从TFTP下载固件
  {
    v10 = sub_27CDBD0("/tmp/uploadxxxx", (__int64)&v16, 1);//固件格式检查
    if ( v10 < 0 )
    {
      LODWORD(v5) = 0;
      fwrite("Invalid image.\n", 1uLL, 0xFuLL, stderr);
      unlink("/tmp/uploadxxxx");
      return (unsigned int)v5;
    }
    if ( (unsigned int)sub_23E8050(&v16, v10 == 1) || (unsigned int)sub_27CD0B0("/tmp/uploadxxxx", 0) )//固件signature检查，最后的256字节为signature，该函数也会将最后的signature去掉 。 "Low-Encryption(LENC) mode don't support image verification, skipped."
    {
      LODWORD(v5) = 0;
      unlink("/tmp/uploadxxxx");
      return (unsigned int)v5;
    }
    if ( rename("/tmp/uploadxxxx", "/tmp/upfile") )
    {
      v11 = __errno_location();
      fprintf(stderr, "Rename image error:%d.\n", (unsigned int)*v11);
    }
    goto LABEL_27;
  }
  return (unsigned int)v5;
}
```



sub_239E780 --> sub_27CDBD0 固件格式检查



```c
__int64 __fastcall sub_27CDBD0(char *filename, __int64 a2, int a3)
{
  unsigned int v3; // er12
  int v4; // er15
  int v5; // er15
  int v6; // eax
  int v8; // er15
  int v9; // er15
  int v10; // er15
  int v11; // er15
  int v12; // er15
  int v13; // er15
  int v14; // er15
  __int64 v16; // [rsp+14h] [rbp-16Ch] BYREF
  int v17; // [rsp+1Ch] [rbp-164h]
  __int16 v18; // [rsp+20h] [rbp-160h]
  char dest[7]; // [rsp+22h] [rbp-15Eh] BYREF
  char s2[7]; // [rsp+29h] [rbp-157h] BYREF
  char v21[16]; // [rsp+30h] [rbp-150h] BYREF
  __m128i v22[16]; // [rsp+40h] [rbp-140h] BYREF
  unsigned __int64 v23; // [rsp+148h] [rbp-38h]

  v23 = __readfsqword(0x28u);
  v18 = 0;
  v16 = 0LL;
  v17 = 0;
  if ( (int)sub_27CD190(filename, (__int64)&v16, v22) < 0 )
    return (unsigned int)-1;
  if ( (_WORD)v16 == 5 && !BYTE4(v16) && WORD1(v16) == 271 )
    BYTE4(v16) = 7;
  strncpy(dest, &v22[0].m128i_i8[10], 6uLL);    // model
  dest[6] = 0;
  sub_27CD940(s2, 7LL);
  v3 = sub_27CDA30(s2, dest);
  if ( v3 )
    return (unsigned int)-1;
  v4 = (unsigned __int8)v16;
  if ( v4 < (int)strtol("7", 0LL, 10)
    || (v8 = (unsigned __int8)v16, v8 <= (int)strtol("7", 0LL, 10))
    && (BYTE1(v16) <= 1u || BYTE1(v16) == 2 && WORD1(v16) <= 0x484u) )
  {
    v5 = (unsigned __int8)v16;
    if ( v5 < (int)strtol("2", 0LL, 10)
      || (v9 = (unsigned __int8)v16, v9 == (unsigned int)strtol("2", 0LL, 10))
      && (v14 = BYTE1(v16), v14 < (int)strtol("80", 0LL, 10))
      || (v10 = (unsigned __int8)v16, v10 == (unsigned int)strtol("2", 0LL, 10))
      && (v12 = BYTE1(v16), v12 == (unsigned int)strtol("80", 0LL, 10))
      && (v13 = WORD1(v16), v13 < (int)strtol("71", 0LL, 10)) )
    {
      v3 = 2;
    }
    else
    {
      v11 = (unsigned __int8)v16;
      if ( v11 == (unsigned int)strtol("3", 0LL, 10) )
        v3 = 3;
    }
  }
  else
  {
    v3 = 1;
  }
  if ( a2 )
  {
    *(_QWORD *)a2 = v16;
    *(_DWORD *)(a2 + 8) = v17;
    *(_WORD *)(a2 + 12) = v18;
  }
  v6 = sub_27CB990(filename);
  if ( v6 < 0 )
    return (unsigned int)v6;
  if ( a3 && (unsigned int)sub_1FCAFF0(filename, "/tmp/sig.dat", (__int64)v21) )
    sub_1FD3EF0((__int64)v21);
  return v3;
}
```

对于函数sub_239E780 --> sub_27CDBD0 --> sub_27CD190，该逻辑为：
```c
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
int main(void)
{
	char *file_name = "FGT_100D-v6-build1319-FORTINET.out";
	FILE *fp = fopen(file_name,"rb");
	char header_buf[256] = {0};
	char model[7] = {0};
	char major_version_number[2] = {0};
	char minor_version_number[3] = {0};
	char *build_str_pointer = NULL;
	char build_version[6] = {0};
	char *tmp_ptr = NULL;
	char patch_version[3] = {0};

	if(fp == NULL){
		printf("fopen %s error ( %s )\n",file_name,strerror(errno));
		return -1;
	}
	
	if(fread(header_buf,1,0x100,fp)!=0x100)
	{
		printf("fread header error (%s)\n",strerror(errno));
		return -1;
	}
	
	strncpy(model,header_buf+10,6);
	printf("model:%s\n",model);
	
	strncpy(major_version_number,header_buf+0x11,1);
	printf("major version number: %s\n",major_version_number);
	
	strncpy(minor_version_number,header_buf+0x13,2);
	printf("minor version number: %s\n",minor_version_number);
	
	build_str_pointer = strstr(header_buf+10,"build");
	if(build_str_pointer == NULL){
		printf("not found build str\n");
		return -1;
	}
	
	tmp_ptr = strchr(build_str_pointer,'-');
	if(tmp_ptr == NULL){
		printf("not found '-' str\n");
		return -1;
	}
	
	int len = tmp_ptr - (build_str_pointer+5);
	
	strncpy(build_version,build_str_pointer+5,len);
	printf("build version: %s\n",build_version);

	tmp_ptr = strstr(header_buf+10,"patch");
	strncpy(patch_version,tmp_ptr+5,2);
	printf("patch version: %s\n",patch_version);

	return 0;
}
```

output:

```
model:FG100D
major version number: 6
minor version number: 02
build version: 1319
patch version: 12
```



对于函数sub_239E780 --> sub_27CDBD0 --> sub_27CB990：

```c
__int64 __fastcall sub_27CB990(char *filename)
{
  unsigned int v1; // ebx
  FILE *v2; // rax
  FILE *v3; // r14
  int v4; // eax
  int v5; // er12
  int v6; // eax
  unsigned int v7; // eax
  unsigned int v8; // eax
  __int64 v9; // rdx
  unsigned int v11; // edx
  __int64 v12; // rsi
  __int64 v13; // rsi
  __int64 v14; // rdx
  unsigned int v15; // eax
  __int64 v16; // rcx
  int *v17; // rax
  int v18; // [rsp+8h] [rbp-2358h]
  unsigned int v19; // [rsp+Ch] [rbp-2354h]
  __int64 v20[14]; // [rsp+10h] [rbp-2350h] BYREF
  struct stat stat_buf; // [rsp+80h] [rbp-22E0h] BYREF
  __int64 v22; // [rsp+118h] [rbp-2248h] BYREF
  char v23[512]; // [rsp+120h] [rbp-2240h] BYREF
  char ptr[8200]; // [rsp+320h] [rbp-2040h] BYREF
  unsigned __int64 v25; // [rsp+2328h] [rbp-38h]

  v25 = __readfsqword(0x28u);
  v1 = crc32(0LL, 0LL, 0LL);
  if ( __xstat(1, filename, &stat_buf) || (v2 = fopen(filename, "r"), (v3 = v2) == 0LL) )
  {
    message((__int64)"Cannot open file %s\n", filename);
    return (unsigned int)-1;
  }
  v4 = fread(ptr, 1uLL, 0x2000uLL, v2);
  v5 = v4;
  if ( v4 < 0 )
  {
    message((__int64)"Cannot read from file %s\n", filename);
    v19 = -1;
    goto LABEL_15;
  }
  v6 = sub_27CB880(ptr, (unsigned int)v4);
  if ( v6 < 0 )
  {
    v17 = __errno_location();
    message((__int64)"check_gz_header() failed (%d)\n", (unsigned int)*v17);
    v19 = -1;
    goto LABEL_15;
  }
  v18 = v6;
  memset(v20, 0, sizeof(v20));
  v7 = inflateInit2_(v20, 4294967281LL, "1.2.11", 112LL);
  v19 = v7;
  if ( v7 )
  {
    message((__int64)"inflateInit2() error: %d\n", v7);
    v19 = -1;
    goto LABEL_15;
  }
  if ( !v5 )
    goto LABEL_17;
  LODWORD(v20[1]) = v5 - v18;
  for ( v20[0] = (__int64)&ptr[v18]; ; v20[0] = (__int64)ptr )
  {
    do
    {
      v20[3] = (__int64)v23;
      LODWORD(v20[4]) = 512;
      v8 = inflate(v20, 0LL);
      v9 = (unsigned int)(512 - LODWORD(v20[4]));
      if ( v8 == 2 || v8 == -3 || v8 == -4 )
      {
        message((__int64)"inflate() error: %d\n", v8);
        v19 = -1;
        goto LABEL_14;
      }
      if ( v8 == 1 )
      {
        if ( (_DWORD)v9 )
          v1 = crc32(v1, v23, v9);
        v11 = v20[1];
        v12 = v20[0];
        if ( LODWORD(v20[1]) <= 7 )
        {
          if ( LODWORD(v20[1]) )
          {
            v15 = 0;
            do
            {
              v16 = v15++;
              *((_BYTE *)&v22 + v16) = *(_BYTE *)(v12 + v16);
            }
            while ( v15 < v11 );
          }
          if ( (fread((char *)&v22 + v11, 1uLL, 8 - v11, v3) & 0x80000000) != 0LL )
          {
            message((__int64)"Cannot read from file %s\n", filename);
LABEL_27:
            v19 = -1;
            goto LABEL_14;
          }
        }
        else
        {
          v22 = *(_QWORD *)v20[0];
        }
        v13 = (BYTE1(v22) << 8) + (BYTE2(v22) << 16) + (unsigned __int8)v22 + (BYTE3(v22) << 24);
        v14 = (HIBYTE(v22) << 24) + (BYTE5(v22) << 8) + (BYTE6(v22) << 16) + (unsigned int)BYTE4(v22);
        if ( v20[5] == v14 )
        {
          if ( v1 == (_DWORD)v13 )
            goto LABEL_14;
          message((__int64)"gzfile: CRC32 doesn't match!\n", v13, v14);
        }
        else
        {
          message((__int64)"gzfile: ISIZE doesn't match! %lu, %u\n", v20[5], v14);
        }
        goto LABEL_27;
      }
      v1 = crc32(v1, v23, v9);
    }
    while ( !LODWORD(v20[4]) );
LABEL_17:
    LODWORD(v20[1]) = fread(ptr, 1uLL, 0x2000uLL, v3);
    if ( ferror(v3) )
      goto LABEL_27;
    if ( !LODWORD(v20[1]) )
      break;
  }
  v19 = 0;
LABEL_14:
  inflateEnd(v20);
LABEL_15:
  fclose(v3);
  return v19;
}
```

该函数的逻辑为：

- 先判断是否是一个合格的gzip header
- 使用 `inflateInit2_()` 和 `inflate()` 对文件数据进行解压
- 使用 CRC32 校验解压后的数据。
- 验证文件尾部的 ISIZE（解压后数据的大小）是否与计算结果一致。

GZIP 文件的尾部包含 8 字节：

- CRC32 校验值（4 字节）。
- ISIZE 值（4 字节），表示解压后数据的大小（取模 2³²）。



对应的代码为：

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

#define CHUNK_SIZE 512
#define GZ_INVALID_HEADER 0xFFFFFFFF

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
uint64_t check_gz_header(const uint8_t *buffer, size_t buffer_size)
{
    if (!buffer || buffer_size < 10)
    {
        return GZ_INVALID_HEADER; // 缓冲区无效或长度不足
    }

    // 检查 GZIP 标识符
    if (buffer[0] != 0x1F || buffer[1] != 0x8B)
    {
        return GZ_INVALID_HEADER; // ID1 和 ID2 不匹配
    }

    // 检查压缩方法（CM）是否为 DEFLATE，以及标志字节（FLG）
    if (buffer[2] != 8 || (buffer[3] & 0xE0) != 0)
    {
        return GZ_INVALID_HEADER; // 非 DEFLATE 或标志字节非法
    }

    size_t header_length = 10; // 基本头部长度
    uint8_t flags = buffer[3]; // 标志字节

    // 处理 FEXTRA（扩展字段）
    if (flags & 0x04)
    {
        if (header_length + 2 > buffer_size)
        {
            return GZ_INVALID_HEADER; // 缓冲区不足
        }
        size_t extra_length = buffer[header_length] | (buffer[header_length + 1] << 8);
        header_length += 2 + extra_length;
        if (header_length > buffer_size)
        {
            return GZ_INVALID_HEADER; // 缓冲区不足
        }
    }

    // 处理 FNAME（文件名）
    if (flags & 0x08)
    {
        while (header_length < buffer_size && buffer[header_length] != '\0')
        {
            header_length++;
        }
        if (header_length >= buffer_size)
        {
            return GZ_INVALID_HEADER; // 缓冲区不足
        }
        header_length++; // 跳过 '\0'
    }

    // 处理 FCOMMENT（注释）
    if (flags & 0x10)
    {
        while (header_length < buffer_size && buffer[header_length] != '\0')
        {
            header_length++;
        }
        if (header_length >= buffer_size)
        {
            return GZ_INVALID_HEADER; // 缓冲区不足
        }
        header_length++; // 跳过 '\0'
    }

    // 处理 FHCRC（头部校验）
    if (flags & 0x02)
    {
        header_length += 2;
        if (header_length > buffer_size)
        {
            return GZ_INVALID_HEADER; // 缓冲区不足
        }
    }

    // 最终检查头部长度
    if (header_length > buffer_size)
    {
        return GZ_INVALID_HEADER; // 缓冲区不足
    }

    return header_length; // 返回头部长度
}

int check_firmware_gz_file_format_valid(uint8_t *input_data, size_t input_data_size)
{
    z_stream strm;
    unsigned char out_buffer[CHUNK_SIZE];
    int ret;
    memset(&strm, 0, sizeof(z_stream));
    unsigned int crc = crc32(0L, Z_NULL, 0); // 初始化 CRC32

    if (inflateInit2_(&strm, 4294967281, "1.2.11", sizeof(strm)) != Z_OK)
    {
        printf("inflate Init error\n");
        return -1;
    }

    strm.next_in = input_data;
    strm.avail_in = input_data_size;

    do
    {
        strm.next_out = out_buffer;
        strm.avail_out = CHUNK_SIZE;
        ret = inflate(&strm, Z_NO_FLUSH);
        switch (ret)
        {
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

        size_t have = CHUNK_SIZE - strm.avail_out;
        crc = crc32(crc, out_buffer, have);
    } while (ret != Z_STREAM_END);

    inflateEnd(&strm);

    printf("decompressed len:%ld\n", strm.total_out);

    unsigned int file_crc = *(unsigned int *)(input_data + input_data_size - strm.avail_in);      // 前4字节为 CRC32
    unsigned int file_size = *(unsigned int *)(input_data + input_data_size - strm.avail_in + 4); // 后4字节为 ISIZE

    printf("strm.avail_in: %u\n", strm.avail_in);

    if (crc != file_crc)
    {
        printf("CRC32 mismatch! Calculated: %u, Expected: %u\n", crc, file_crc);
    }
    else
    {
        printf("CRC32 match   ! Calculated: %u, Expected: %u\n", crc, file_crc);
    }

    if (strm.total_out != file_size)
    {
        printf("ISIZE mismatch! Calculated: %lu, Expected: %u\n", strm.total_out, file_size);
    }
    else
    {
        printf("ISIZE match   ! Calculated: %lu, Expected: %u\n", strm.total_out, file_size);
    }

    if (ret == Z_STREAM_END)
    {
        fprintf(stderr, "\nDecompression complete.\n");
        return 0;
    }
    else
    {
        fprintf(stderr, "\nDecompression failed.\n");
        return -1;
    }
}

int check_firmware_gz_name_valid(char *header_buf)
{
    char model[7] = {0};
    char major_version_number[2] = {0};
    char minor_version_number[3] = {0};
    char *build_str_pointer = NULL;
    char build_version[6] = {0};
    char *tmp_ptr = NULL;
    char patch_version[3] = {0};

    strncpy(model, header_buf + 10, 6);
    printf("model:%s\n", model);

    strncpy(major_version_number, header_buf + 0x11, 1);
    printf("major version number: %s\n", major_version_number);

    strncpy(minor_version_number, header_buf + 0x13, 2);
    printf("minor version number: %s\n", minor_version_number);

    build_str_pointer = strstr(header_buf + 10, "build");
    if (build_str_pointer == NULL)
    {
        printf("not found build str\n");
        return -1;
    }

    tmp_ptr = strchr(build_str_pointer, '-');
    if (tmp_ptr == NULL)
    {
        printf("not found '-' str\n");
        return -1;
    }

    int len = tmp_ptr - (build_str_pointer + 5);

    strncpy(build_version, build_str_pointer + 5, len);
    printf("build version: %s\n", build_version);

    tmp_ptr = strstr(header_buf + 10, "patch");
    strncpy(patch_version, tmp_ptr + 5, 2);
    printf("patch version: %s\n", patch_version);

    return 0;
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        printf("usage: %s <FIRMWARE NAME>\n", argv[0]);
        return 0;
    }
    int fd = open(argv[1], O_RDONLY);
    if (fd == -1)
    {
        perror("Failed to open file");
        return -1;
    }

    struct stat file_stat;
    if (fstat(fd, &file_stat) == -1)
    {
        perror("Failed to get file size");
        close(fd);
        return -1;
    }

    printf("file size: %ld\n", file_stat.st_size);

    size_t file_size = file_stat.st_size;
    char *buffer = malloc(file_size);
    if (!buffer)
    {
        perror("Failed to allocate memory");
        close(fd);
        return -1;
    }

    size_t bytes_read = 0;
    while (bytes_read < file_size)
    {
        ssize_t result = read(fd, buffer + bytes_read, file_size - bytes_read);
        if (result < 0)
        {
            perror("Failed to read file");
            free(buffer);
            close(fd);
            return -1;
        }
        bytes_read += result;
    }
    close(fd);

    if (check_firmware_gz_name_valid(buffer) == -1)
    {
        printf("check_firmware_gz_name_invalid\n");
        free(buffer);
        close(fd);
        return -1;
    }

    size_t gz_header_len = check_gz_header(buffer, file_size);
    printf("gz header len  : %ld\n", gz_header_len);
    printf("compressed len : %ld\n", file_size - gz_header_len);
    check_firmware_gz_file_format_valid(buffer + gz_header_len, file_size - gz_header_len);

    free(buffer);
    return 0;
}
```

Output:

```
sysirq@sysirq-machine:~/Work/Fortinet/FortiGate_6_2_12$ ./check_firmware FGT_100D-v6-build1319-FORTINET.out
file size: 60581933
model:FG100D
major version number: 6
minor version number: 02
build version: 1319
patch version: 12
gz header len  : 50
compressed len : 60581883
decompressed len:268435968
strm.avail_in: 2086
CRC32 match   ! Calculated: 2226910769, Expected: 2226910769
ISIZE match   ! Calculated: 268435968, Expected: 268435968

Decompression complete.
```





# 固件解密代码逆向分析

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
      sub_20C0800(buf, 512LL, 0LL);//解密函数
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
- 跳过512字节的MBR，将后续的256MB写入磁盘，256MB数据写入磁盘完毕后，才写入MBR

```c
void __fastcall sub_20C0800(__int64 a1, int a2, int a3)//a3 控制是加密，还是解密，解密时a3为0
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
            *(_BYTE *)(a1 + v7++) = (v10 ^ v9 ^ v8) - v11;//解密逻辑
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

解压解密代码：

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

#define CHUNK_SIZE 512
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
	NULL};

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
uint64_t check_gz_header(const uint8_t *buffer, size_t buffer_size)
{
	if (!buffer || buffer_size < 10)
	{
		return GZ_INVALID_HEADER; // 缓冲区无效或长度不足
	}

	// 检查 GZIP 标识符
	if (buffer[0] != 0x1F || buffer[1] != 0x8B)
	{
		return GZ_INVALID_HEADER; // ID1 和 ID2 不匹配
	}

	// 检查压缩方法（CM）是否为 DEFLATE，以及标志字节（FLG）
	if (buffer[2] != 8 || (buffer[3] & 0xE0) != 0)
	{
		return GZ_INVALID_HEADER; // 非 DEFLATE 或标志字节非法
	}

	size_t header_length = 10; // 基本头部长度
	uint8_t flags = buffer[3]; // 标志字节

	// 处理 FEXTRA（扩展字段）
	if (flags & 0x04)
	{
		if (header_length + 2 > buffer_size)
		{
			return GZ_INVALID_HEADER; // 缓冲区不足
		}
		size_t extra_length = buffer[header_length] | (buffer[header_length + 1] << 8);
		header_length += 2 + extra_length;
		if (header_length > buffer_size)
		{
			return GZ_INVALID_HEADER; // 缓冲区不足
		}
	}

	// 处理 FNAME（文件名）
	if (flags & 0x08)
	{
		while (header_length < buffer_size && buffer[header_length] != '\0')
		{
			header_length++;
		}
		if (header_length >= buffer_size)
		{
			return GZ_INVALID_HEADER; // 缓冲区不足
		}
		header_length++; // 跳过 '\0'
	}

	// 处理 FCOMMENT（注释）
	if (flags & 0x10)
	{
		while (header_length < buffer_size && buffer[header_length] != '\0')
		{
			header_length++;
		}
		if (header_length >= buffer_size)
		{
			return GZ_INVALID_HEADER; // 缓冲区不足
		}
		header_length++; // 跳过 '\0'
	}

	// 处理 FHCRC（头部校验）
	if (flags & 0x02)
	{
		header_length += 2;
		if (header_length > buffer_size)
		{
			return GZ_INVALID_HEADER; // 缓冲区不足
		}
	}

	// 最终检查头部长度
	if (header_length > buffer_size)
	{
		return GZ_INVALID_HEADER; // 缓冲区不足
	}

	return header_length; // 返回头部长度
}

// ciphertext 长度一定为512字节，如果不为的话表示有问题， key 长度为 32字节
int decrypt(uint8_t *ciphertext, uint8_t *cleartext, uint8_t *key)
{
	size_t block_offset = 0;
	size_t key_offset = 0;
	uint8_t previous_ciphertext_byte = 0xFF;
	uint8_t xor = 0;

	while (block_offset < CHUNK_SIZE)
	{
		xor = (key[key_offset] ^ (ciphertext[block_offset]) ^ previous_ciphertext_byte) - (block_offset & 0x1F);
		previous_ciphertext_byte = ciphertext[block_offset];
		cleartext[block_offset] = xor;
		key_offset = (key_offset + 1) & 0x1f;
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

typedef struct
{
	uint8_t boot_flag;		  // 启动标志
	uint8_t start_chs[3];	  // 起始CHS地址
	uint8_t partition_type;	  // 分区类型
	uint8_t end_chs[3];		  // 结束CHS地址
	uint32_t start_lba;		  // 起始LBA地址
	uint32_t size_in_sectors; // 分区大小（扇区数）
} PartitionEntry;

int check_valid_mbr(uint8_t *mbr)
{
	uint16_t signature = *(uint16_t *)(mbr + SIGNATURE_OFFSET);
	uint8_t *partition_table = mbr + PARTITION_TABLE_OFFSET;
	uint32_t previous_lba_end = 0;
	if (signature != MBR_SIGNATURE)
		return -1;
	for (int i = 0; i < 4; i++)
	{
		PartitionEntry *entry = (PartitionEntry *)(partition_table + i * PARTITION_ENTRY_SIZE);
		if (entry->partition_type != 0x00)
		{
			if (entry->boot_flag != 0x00 && entry->boot_flag != 0x80)
			{ // 0x00: 非活动分区 , 0x80: 活动分区（最多一个）。
				return -1;
			}

			if (entry->size_in_sectors == 0)
			{
				return -1;
			}

			if (previous_lba_end != 0)
			{
				if (previous_lba_end != entry->start_lba)
					return -1;
				if (previous_lba_end > entry->start_lba)
					return -1;
			}

			previous_lba_end = entry->start_lba + entry->size_in_sectors;
		}
	}
	return 0;
}

int print_mbr_info(uint8_t *mbr)
{
	uint8_t *partition_table = mbr + PARTITION_TABLE_OFFSET;
	for (int i = 0; i < 4; i++)
	{
		PartitionEntry *entry = (PartitionEntry *)(partition_table + i * PARTITION_ENTRY_SIZE);

		if (entry->partition_type != 0x00)
		{
			if (entry->boot_flag != 0x00 && entry->boot_flag != 0x80)
			{
				return -1;
			}

			printf("分区 %d: 类型 0x%02X,分区标志 %x, 起始 LBA %u, 大小 %u 扇区\n",
				   i + 1, entry->partition_type, entry->boot_flag, entry->start_lba, entry->size_in_sectors);
		}
	}
	return 0;
}

int decompress(uint8_t *input_data, size_t input_data_size, char *out_file_name)
{
	z_stream strm;
	char *key = NULL;
	unsigned char out_buffer[CHUNK_SIZE];
	unsigned char cleartext[CHUNK_SIZE];
	int ret;
	FILE *fp;
	memset(&strm, 0, sizeof(z_stream));
	int is_first_chunk = 1;

	fp = fopen(out_file_name, "wb");
	if (fp == NULL)
	{
		printf("open out file error\n");
		return -1;
	}

	if (inflateInit2_(&strm, 4294967281, "1.2.11", sizeof(strm)) != Z_OK)
	{
		printf("inflate Init error\n");
		fclose(fp);
		return -1;
	}

	strm.next_in = input_data;
	strm.avail_in = input_data_size;

	do
	{
		strm.next_out = out_buffer;
		strm.avail_out = CHUNK_SIZE;
		ret = inflate(&strm, Z_NO_FLUSH);

		if(CHUNK_SIZE - strm.avail_out != CHUNK_SIZE){
			fprintf(stderr, "inflate out size not equ CHUNK_SIZE\n");
			inflateEnd(&strm);
			fclose(fp);
			return -1;
		}

		switch (ret)
		{
		case Z_STREAM_ERROR:
			fprintf(stderr, "inflate failed: Z_STREAM_ERROR\n");
			inflateEnd(&strm);
			fclose(fp);
			return -1;
		case Z_MEM_ERROR:
			fprintf(stderr, "inflate failed: Z_MEM_ERROR\n");
			inflateEnd(&strm);
			fclose(fp);
			return -1;
		case Z_DATA_ERROR:
			fprintf(stderr, "inflate failed: Z_DATA_ERROR\n");
			inflateEnd(&strm);
			fclose(fp);
			return -1;
		}

		if (key == NULL)
		{
			int i = 0;
			while (keys[i] != NULL)
			{
				decrypt(out_buffer, cleartext, keys[i]);
				if (check_valid_mbr(cleartext) == 0)
				{
					key = keys[i];
					printf("found key for decrypt:%s\n", key);
					break;
				}
				i++;
			}

			if (key == NULL)
			{
				printf("not found valid key for firmware decrypt\n");
				inflateEnd(&strm);
				fclose(fp);
				return -1;
			}
		}

		decrypt(out_buffer, cleartext, key);

		if (is_first_chunk == 1)
		{
			print_mbr_info(cleartext);
			printf("mbr size:%d\n", (*(unsigned int *)(cleartext + 0x94) + *(unsigned int *)(cleartext + 0x90)) << 9);
			is_first_chunk = 0;
		}

		fwrite(cleartext, CHUNK_SIZE - strm.avail_out, 1, fp);

	} while (ret != Z_STREAM_END);

	inflateEnd(&strm);
	fclose(fp);

	printf("decompressed len:%ld\n", strm.total_out);

	if (ret == Z_STREAM_END)
	{
		fprintf(stderr, "\nDecompression complete.\n");
		return 0;
	}
	else
	{
		fprintf(stderr, "\nDecompression failed.\n");
		return -1;
	}
}

int main(int argc, char *argv[])
{
	if (argc != 3)
	{
		printf("usage: %s <FIRMWARE NAME> <DECRYPT OUT FILE>\n", argv[0]);
		return 0;
	}
	int fd = open(argv[1], O_RDONLY);
	char *out_file_name = argv[2];
	if (fd == -1)
	{
		perror("Failed to open file");
		return -1;
	}

	struct stat file_stat;
	if (fstat(fd, &file_stat) == -1)
	{
		perror("Failed to get file size");
		close(fd);
		return -1;
	}

	printf("file size: %ld\n", file_stat.st_size);

	size_t file_size = file_stat.st_size - 256; // skip signature
	char *buffer = malloc(file_size);
	if (!buffer)
	{
		perror("Failed to allocate memory");
		close(fd);
		return -1;
	}

	size_t bytes_read = 0;
	while (bytes_read < file_size)
	{
		ssize_t result = read(fd, buffer + bytes_read, file_size - bytes_read);
		if (result < 0)
		{
			perror("Failed to read file");
			free(buffer);
			close(fd);
			return -1;
		}
		bytes_read += result;
	}
	close(fd);

	size_t gz_header_len = check_gz_header(buffer, file_size);
	printf("gz header len  : %ld\n", gz_header_len);
	printf("compressed len : %ld\n", file_size - gz_header_len);
	decompress(buffer + gz_header_len, file_size - gz_header_len, out_file_name);

	free(buffer);
	return 0;
}
```

output:

```
sysirq@sysirq-machine:~/Work/Fortinet/FortiGate_6_2_12$ ./decompress FGT_100D-v6-build1319-FORTINET.out FGT_ORIG
file size: 60581933
gz header len  : 50
compressed len : 60581627
found key for decrypt:oAbBIcDde7FfgGHhiIjJ7KlLmsnN3OPP
分区 1: 类型 0x83,分区标志 80, 起始 LBA 1, 大小 524288 扇区
分区 2: 类型 0x83,分区标志 0, 起始 LBA 524289, 大小 524288 扇区
分区 3: 类型 0x83,分区标志 0, 起始 LBA 1048577, 大小 524288 扇区
mbr size:512
decompressed len:268435968

Decompression complete.
```

分析发现，解压后的大小为：

```
512字节的MBR + 256MB == 512 + 268435456 == 268435968 == decompressed len
```



# 固件加密压缩

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

#define CHUNK_SIZE 512

#pragma pack(push, 1)
typedef struct {
    uint8_t id1;         // 固定为 0x1F
    uint8_t id2;         // 固定为 0x8B
    uint8_t compression; // 压缩方法（0x08 表示 DEFLATE）
    uint8_t flags;       // 标志位
    uint32_t mtime;      // 修改时间
    uint8_t xflags;      // 额外标志
    uint8_t os;          // 操作系统类型
} GzipHeader;
#pragma pack(pop)

// cleartext 长度一定为512字节，如果不为的话表示有问题， key 长度为 32字节
int encrypt( uint8_t *cleartext, uint8_t *key)
{
	size_t block_offset = 0;
	size_t key_offset = 0;
	uint8_t previous_ciphertext_byte = 0xFF;
	uint8_t xor = 0;

	while (block_offset < CHUNK_SIZE)
	{
        xor = (cleartext[block_offset] + (block_offset & 0x1F)) ^ key[key_offset] ^ previous_ciphertext_byte;
        previous_ciphertext_byte = xor;
        cleartext[block_offset] = xor;
        key_offset = (key_offset + 1) & 0x1f;
		block_offset++;
	}

	return 0;
}

int firmware_compress(uint8_t *input_data, size_t input_data_size, char *key, char *out_file_name)
{
    z_stream stream;
    int ret;
    unsigned char ciphertext[CHUNK_SIZE];
    FILE *fp;
    memset(&stream, 0, sizeof(stream));
    char *compress_buf = NULL;
    char *gz_header = NULL;
    GzipHeader header = {
        .id1 = 0x1F,
        .id2 = 0x8B,
        .compression = 0x08,  // 使用 DEFLATE 压缩
        .flags = 0x08,        // 表示包含文件名（FNAME）
        .mtime = 0,           // 修改时间设为 0
        .xflags = 0,          // 无额外标志
        .os = 0x03            // Unix 系统
    };
    size_t gz_header_len = 0;
    size_t compress_out = 0;
    size_t input_data_offset = 0;
    unsigned int crc = crc32(0L, Z_NULL, 0); // 初始化 CRC32
    uint8_t garbage_data[2078] = {0};

    if(input_data_size % CHUNK_SIZE != 0){
        
        printf("input_data_size %% CHUNK_SIZE != 0");
        return -1;
    }

    //encrypt
    while(input_data_offset < input_data_size){
        encrypt(input_data + input_data_offset,key);

        crc = crc32(crc, input_data + input_data_offset, CHUNK_SIZE);
        input_data_offset += CHUNK_SIZE;
    }

    printf("crc: %u\n",crc);

    compress_buf = malloc(input_data_size);
    if (compress_buf == NULL)
    {
        printf("alloc compress buf error\n");
        return -1;
    }

    fp = fopen(out_file_name, "wb");
    if (fp == NULL)
    {
        printf("open out file error\n");
        free(compress_buf);
        return -1;
    }

    ret = deflateInit2_(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY, "1.2.11", sizeof(stream));;
    if (ret != Z_OK)
    {
        fprintf(stderr, "deflateInit failed: %d\n", ret);
        fclose(fp);
        free(compress_buf);
        return ret;
    }

    stream.next_in = input_data;
    stream.avail_in = input_data_size;

    stream.next_out = compress_buf;
    stream.avail_out = input_data_size;

    ret = deflate(&stream, Z_FINISH);
    if (ret != Z_STREAM_END) {
        fprintf(stderr, "deflate failed: %d\n", ret);
        deflateEnd(&stream);
        fclose(fp);
        free(compress_buf);
        return -1;
    }

    compress_out = stream.total_out;
    printf("compressed out:%lu\n",compress_out);

    //create gz header
    gz_header_len = sizeof(header)+strlen(out_file_name)+1;
    gz_header = malloc(gz_header_len);
    if(gz_header == NULL){
        printf("malloc gzip header buff error\n");
        deflateEnd(&stream);
        fclose(fp);
        free(compress_buf);
        return -1;
    }

    memset(gz_header,0,gz_header_len);
    memcpy(gz_header,&header,sizeof(header));
    memcpy(gz_header + sizeof(header),out_file_name,strlen(out_file_name));
    
    printf("sizeof(GzipHeader):%lu\n",sizeof(GzipHeader));
    printf("gz header len:%lu\n",gz_header_len);

    //write result to file
    fwrite(gz_header,1,gz_header_len,fp);
    fwrite(compress_buf,1,compress_out,fp);
    fwrite(&crc,1,4,fp);
    fwrite(&input_data_size,1,4,fp);
    fwrite(garbage_data,1,sizeof(garbage_data),fp);

    free(gz_header);
    deflateEnd(&stream);
    fclose(fp);
    free(compress_buf);
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        printf("usage: %s <FIRMWARE NAME> <ENCRYPT OUT FILE> <KEY>\n", argv[0]);
        return 0;
    }
    int fd = open(argv[1], O_RDONLY);
    char *out_file_name = argv[2];
    char *key = argv[3];
    if (fd == -1)
    {
        perror("Failed to open file");
        return -1;
    }

    struct stat file_stat;
    if (fstat(fd, &file_stat) == -1)
    {
        perror("Failed to get file size");
        close(fd);
        return -1;
    }

    printf("file size: %ld\n", file_stat.st_size);

    size_t file_size = file_stat.st_size;
    if( (file_size % CHUNK_SIZE) != 0 ){
        printf("Not valid firmware: file_size %% CHUNK_SIZE != 0\n");
        close(fd);
        return -1;
    }

    char *buffer = malloc(file_size);
    if (!buffer)
    {
        perror("Failed to allocate memory");
        close(fd);
        return -1;
    }



    size_t bytes_read = 0;
    while (bytes_read < file_size)
    {
        ssize_t result = read(fd, buffer + bytes_read, file_size - bytes_read);
        if (result < 0)
        {
            perror("Failed to read file");
            free(buffer);
            close(fd);
            return -1;
        }
        bytes_read += result;
    }
    close(fd);

    firmware_compress(buffer, file_size, key, out_file_name);

    free(buffer);
    return 0;
}
```

out:

```
sysirq@sysirq-machine:~/Work/Fortinet/FortiGate_6_2_12$ gcc compress_firmware.c -lz -o compress_firmware
sysirq@sysirq-machine:~/Work/Fortinet/FortiGate_6_2_12$ ./compress_firmware FGTOUT FG100D-6.02-FW-build1319-221102-patch12 oAbBIcDde7FfgGHhiIjJ7KlLmsnN3OPP
file size: 268435968
crc: 2226910769
compressed out:60576114
sizeof(GzipHeader):10
gz header len:50
sysirq@sysirq-machine:~/Work/Fortinet/FortiGate_6_2_12$ ./check_firmware FG100D-6.02-FW-build1319-221102-patch12
file size: 60578250
model:FG100D
major version number: 6
minor version number: 02
build version: 1319
patch version: 12
gz header len  : 50
compressed len : 60578200
decompressed len:268435968
strm.avail_in: 2086
CRC32 match   ! Calculated: 2226910769, Expected: 2226910769
ISIZE match   ! Calculated: 268435968, Expected: 268435968

Decompression complete.
sysirq@sysirq-machine:~/Work/Fortinet/FortiGate_6_2_12$ ./check_firmware FGT_100D-v6-build1319-FORTINET.out
file size: 60581933
model:FG100D
major version number: 6
minor version number: 02
build version: 1319
patch version: 12
gz header len  : 50
compressed len : 60581883
decompressed len:268435968
strm.avail_in: 2086
CRC32 match   ! Calculated: 2226910769, Expected: 2226910769
ISIZE match   ! Calculated: 268435968, Expected: 268435968

Decompression complete.
```


# 挂载并修改

```
sysirq@sysirq-machine:~/Work/Fortinet/FortiGate_6_2_12$ fdisk -l disk.img 
Disk disk.img: 256 MiB, 268435968 bytes, 524289 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0x00000000

Device     Boot   Start     End Sectors  Size Id Type
disk.img1  *          1  524288  524288  256M 83 Linux
disk.img2        524289 1048576  524288  256M 83 Linux
disk.img3       1048577 1572864  524288  256M 83 Linux
```

镜像文件的分区通常不是直接可挂载的。需要通过偏移量计算分区起始位置。

计算偏移量:

- 每个扇区大小是 512 字节，起始位置是 1 扇区，因此偏移量为：

```
1 * 512 = 512 字节
```

- 使用mount挂载

```
sudo mount -o loop,offset=512 disk.img mnt
```

# 参考资料

Breaking Fortinet Firmware Encryption

https://bishopfox.com/blog/breaking-fortinet-firmware-encryption