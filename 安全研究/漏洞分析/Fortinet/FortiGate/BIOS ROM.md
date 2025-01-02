对于固件的kernel格式显示为:

```
sysirq@sysirq-machine:~/Work/Fortinet/FortiGate_6_2_12/kernel$ file flatkc 
flatkc: BIOS (ia32) ROM Ext. (-86*512)
```

```
sysirq@sysirq-machine:~/Work/Fortinet/FortiGate_6_2_12/kernel$ xxd -l 1024 flatkc 
00000000: 55aa aa55 b000 0000 0002 0000 0000 0000  U..U............
00000010: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 1000 0000 0000 0000 0000 0000 0000  ................
00000040: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000050: 0000 0000 0000 0000 5400 0000 726f 2070  ........T...ro p
00000060: 616e 6963 3d35 2063 6f6e 736f 6c65 3d74  anic=5 console=t
00000070: 7479 5330 2c39 3630 3020 656e 6462 6173  tyS0,9600 endbas
00000080: 653d 3078 4130 3030 3020 6e6d 695f 7761  e=0xA0000 nmi_wa
00000090: 7463 6864 6f67 3d31 2072 6f6f 743d 2f64  tchdog=1 root=/d
000000a0: 6576 2f72 616d 3020 6e6f 2d68 6c74 2000  ev/ram0 no-hlt .
000000b0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000c0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000d0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000e0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000000f0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000100: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000110: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000120: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000130: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000140: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000150: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000160: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000170: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000180: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000190: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000001a0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000001b0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000001c0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000001d0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000001e0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
000001f0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000200: 1f8b 0808 b2e5 6263 0403 666f 7274 696b  ......bc..fortik
00000210: 6572 6e65 6c2e 6f75 7400 ecfd 7b7c 54d5  ernel.out...{|T.
00000220: d9ff 8dcf 2419 4820 b8a3 120c 1635 68b0  ....$.H .....5h.
00000230: a0a2 4441 4921 9281 807b 7050 5454 14f5  ..DAI!...{pPTT..
00000240: 4623 947a 449d 013c e184 c910 b69b 41d4  F#.zD..<......A.
00000250: 7a68 ab15 4f15 b555 5b15 026a 4808 64c0  zh..O..U[..jH.d.
00000260: 6380 aa78 2420 e21e 460e 6a1b 1084 793e  c..x$ ..F.j...y>
00000270: d75a 3393 04ed ddef f7f7 7b3d cf5f 1f5a  .Z3.......{=._.Z
00000280: 337b afbd f63a bcd7 e95a d7ba d6da 7545  3{...:...Z....uE
00000290: 2e97 6bc1 c605 0d0b 5a0c 77a1 cb28 7095  ..k.....Z.w..(p.
000002a0: 3684 d714 1bc7 b7ae 70b9 8a70 b30c 7f5d  6.......p..p...]
000002b0: 3fbc a8ee a2b5 5d0b 5c2e abeb 0a57 4191  ?.....].\....WA.
000002c0: 4bdf 2ccb c1fb 5657 8f0b 0fc2 b15c 5ff0  K.,...VW.....\_.
000002d0: 8715 aee2 2257 5dd8 ed72 2d73 e5ea 67ae  ...."W]..r-s..g.
000002e0: e2d4 b33a 09d3 387e e3b2 90cb d560 9c6e  ...:..8~.....`.n
000002f0: 2c77 728d 4175 f01a 328e 6fd8 eeca 2a90  ,wr.Au..2.o...*.
00000300: 60f8 efff 4302 a50d baf0 17b4 2e70 0c57  `...C........p.W
00000310: 4b5d 31e2 365c 1be3 5b0f 18ff 1fa6 8251  K]1.6\..[......Q
00000320: 9100 0990 0009 9000 0990 0009 9000 0990  ................
00000330: c0ff fb04 4e73 b9c6 dfec 5ac8 7f24 4002  ....Ns....Z..$@.
00000340: 2440 0224 4002 2440 0224 4002 2440 0224  $@.$@.$@.$@.$@.$
00000350: 4002 2440 0224 4002 2440 0224 4002 2440  @.$@.$@.$@.$@.$@
00000360: 0224 4002 2440 0224 4002 2440 0224 4002  .$@.$@.$@.$@.$@.
00000370: 2440 0224 4002 2440 0224 4002 2440 0224  $@.$@.$@.$@.$@.$
00000380: 4002 2440 0224 4002 2440 0224 4002 2440  @.$@.$@.$@.$@.$@
00000390: 0224 4002 2440 0224 4002 2440 0224 4002  .$@.$@.$@.$@.$@.
000003a0: 2440 0224 4002 2440 0224 4002 2440 0224  $@.$@.$@.$@.$@.$
000003b0: 4002 2440 0224 4002 2440 0224 4002 2440  @.$@.$@.$@.$@.$@
000003c0: 0224 4002 2440 0224 4002 2440 0224 4002  .$@.$@.$@.$@.$@.
000003d0: 2440 0224 4002 2440 0224 4002 2440 0224  $@.$@.$@.$@.$@.$
000003e0: 4002 2440 0224 4002 2440 0224 4002 2440  @.$@.$@.$@.$@.$@
000003f0: 0224 4002 2440 0224 4002 2440 0224 4002  .$@.$@.$@.$@.$@.
```


- Two bytes indicate the beginning of an extension code section: 055h followed by 0AAh.
- Immediately following the two-byte preamble bytes is a third byte that gives the length of the additional BIOS. The number represents the amount of blocks 512 bytes long, needed to hold the extra code.


# 内核提取

```
dd if=flatkc of=fortikernel.out bs=1 skip=512
```

# 内核检查

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

int check_kernel_valid(uint8_t *input_data, size_t input_data_size)
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

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        printf("usage: %s <KERNEL NAME>\n", argv[0]);
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

    size_t gz_header_len = check_gz_header(buffer, file_size);
    printf("gz header len  : %ld\n", gz_header_len);
    printf("compressed len : %ld\n", file_size - gz_header_len);
    check_kernel_valid(buffer + gz_header_len, file_size - gz_header_len);

    free(buffer);
    return 0;
}
```

output:

```
sysirq@sysirq-machine:~/Work/Fortinet/FortiGate_6_2_12/kernel$ ../../Tools/check_kernel fortikernel.out 
file size: 2720963
gz header len  : 26
compressed len : 2720937
decompressed len:6606848
strm.avail_in: 8
CRC32 match   ! Calculated: 1930918917, Expected: 1930918917
ISIZE match   ! Calculated: 6606848, Expected: 6606848

Decompression complete.
```

# 内核解压

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

int decompress(uint8_t *input_data, size_t input_data_size, char *out_file_name)
{
	z_stream strm;
	unsigned char out_buffer[CHUNK_SIZE];
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

		fwrite(out_buffer, CHUNK_SIZE - strm.avail_out, 1, fp);

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
		printf("usage: %s <KERNEL NAME> <OUT FILE>\n", argv[0]);
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

	size_t gz_header_len = check_gz_header(buffer, file_size);
	printf("gz header len  : %ld\n", gz_header_len);
	printf("compressed len : %ld\n", file_size - gz_header_len);
	decompress(buffer + gz_header_len, file_size - gz_header_len, out_file_name);

	free(buffer);
	return 0;
}
```

# 资料

BIOS Extension

https://flint.cs.yale.edu/feng/cos/resources/BIOS/biosextension.htm

Topic: updated rom-x86.trid.xml for BIOS ROM Extension (IA-32) + variants  (Read 1836 times)

https://mark0.net/forum/index.php?topic=883.0

Some Notes on ROM Extensions

https://www.rigacci.org/docs/biblio/online/firmware/romext.htm#:~:text=A%20ROM%20extension%20is%20a,which%20resides%20at%20C000%2DC7FF.

BIOS Articles

https://sites.google.com/site/pinczakko/bios-articles