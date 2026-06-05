# uboot启动分析

rom （CPU内部固化代码）--> bl1（初始化最基础硬件） --> bl2 （始化DDR、加载后续固件） --> bl31（建立安全世界） --> bl32（建立安全世界） --> u-boot


uboot代码分析：

- `u- boot --> arch/arm/lib/vectors.S: _start` 跳转到reset
- `arch/arm/cpu/armv7/start.S: reset`主要做了：save_boot_params、关中断、切 CPU mode、设置 VBAR、cpu_init_cp15、cpu_init_crit，然后跳转到_main
- `arch/arm/lib/crt0.S:_main`  解决“怎么把 C 运行环境、重定位和 U-Boot 主流程真正搭起来” , 调用了两个比较重要的函数board_init_f（继续板级/架构级早期初始化、探测内存、计算后续重定位地址、决定新的栈位置、GD 位置等）、board_init_r(重定位之后的执行函数)
- `common/board_r.c:board_init_r`核心就是跑一组后期初始化表 init_sequence_r,这一步之后会一路进入 main_loop，最后到 U-Boot 命令行。

# uboot borad kconfig分析

eg：
board/amlogic/txl_p321_v1/Kconfig: 
```kconfig
if TARGET_MESON_GXTV

config SYS_CPU
	string
	default "armv8"

config SYS_BOARD
	string
	default "txl_p321_v1"

config SYS_VENDOR
	string
	default "amlogic"

config SYS_SOC
	string
	default "txl"

config SYS_CONFIG_NAME
	default "txl_p321_v1"

endif
```

从SYS_CPU与SYS_SOC，可以知道特定的soc目录为：arch/arm/cpu/armv8/txl/

SYS_BOARD 指定 board_init 等函数的源码名称为: txl_p321_v1.c

SYS_CONFIG_NAME 指定配置文件为 txl_p321_v1.h



# khadas vim3 u-boot 制作

### 构建

Arm GNU Toolchain Downloads：https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads

```sh
git clone https://github.com/u-boot/u-boot.git
cd uboot
export PATH=$PATH:~/tools/arm-gnu-toolchain-15.2.rel1-x86_64-aarch64-none-elf/bin/
export CROSS_COMPILE=aarch64-none-elf-
make khadas-vim3_defconfig
make
```

### 签名

```sh
git clone https://github.com/LibreELEC/amlogic-boot-fip --depth=1
cd amlogic-boot-fip
mkdir my-output-dir
./build-fip.sh khadas-vim3 ../mainline-u-boot/u-boot.bin my-output-dir
```

```sh
ls my-output-dir/
u-boot.bin  u-boot.bin.sd.bin  u-boot.bin.usb.bl2  u-boot.bin.usb.tpl
```

### 写入

SD:

```sh
dd if=fip/u-boot.bin.sd.bin of=$DEV conv=fsync,notrunc bs=512 skip=1 seek=1
```

emmc:

```sh
dd if=fip/u-boot.bin.sd.bin of=$DEV conv=fsync,notrunc bs=1 count=440
```

# 内核启动

### booti(cmd/booti.c)

doc/usage/cmd/booti.rst

Image / Image.gz / 压缩 Image，用 booti

```sh
booti $kernel_addr_r $ramdisk_addr_r:$filesize $fdt_addr_r
```

### bootm(cmd/bootm.c)

doc/usage/cmd/bootm.rst

```sh
bootm $fit_addr#conf-1
bootm <fit_addr>:kernel-1 <fit_addr>:ramdisk-1 <fit_addr>:fdt-1
bootm $kernel_uimage_addr $ramdisk_addr $fdt_addr
```

- 启动默认配置：bootm <fit>
- 启动指定配置：bootm <fit>#<conf>
- 启动配置并叠加 overlay：bootm <fit>#<conf>#<extra-conf>
- 直接指定 kernel：bootm <fit>:<kernel>
- 指定 kernel + ramdisk + fdt：bootm <fit>:<kernel> <fit>:<ramdisk> <fit>:<fdt>
- 没有 ramdisk：bootm <fit>:<kernel> - <fit>:<fdt>

### bootm_run_states函数

bootm_run_states 是 U-Boot 启动框架的核心状态机执行器，它根据 states 位掩码按固定顺序推进启动流程，包括初始化上下文、查找 OS 镜像、查找 ramdisk/FDT、加载或解压内核、重定位附属镜像、处理 bootargs、执行 OS 启动前准备以及最终跳转进入 OS。它不是 bootm 独占的实现，而是 bootm、bootz、booti 共用的公共骨架。bootm 通过它执行完整启动流程，booti 和 bootz 则复用其公共阶段，只在各自特有的镜像准备逻辑上做补充。它的核心价值在于：把复杂启动过程拆成可组合、可复用、可单步调试的多个阶段，并清晰地分离了通用启动逻辑和 OS 专属启动逻辑。

```
1.合并状态到 images.state
2.如果请求 START，就执行 bootm_start：初始化全局启动上下文
3.如果请求 PRE_LOAD，就执行 bootm_pre_load：
4.如果请求 FINDOS，就执行 bootm_find_os：找到内核，识别格式、架构、入口、load 地址
5.如果请求 FINDOTHER，就执行 bootm_find_other：找到 initrd、FDT、loadables
6.如果请求 MEASURE，就执行 bootm_measure
7.如果请求 LOADOS，就关中断并执行 bootm_load_os：解压或搬移内核到目标位置
8.如果请求 RAMDISK，就重定位 initrd：重定位配套数据
9.如果请求 FDT，就重定位设备树：重定位配套数据
10.根据 images.os.os 选择具体 OS 的 boot_fn
11.如果请求 OS_CMDLINE，就调用 boot_fn 对应阶段
12.如果请求 OS_BD_T，就调用 boot_fn 对应阶段
13.如果请求 OS_PREP，就先处理 bootargs，再调用 boot_fn
14.如果请求 OS_FAKE_GO，就执行假启动逻辑
15.如果请求 OS_GO，就真正调用 boot_selected_os 进入内核：真正进入 OS
16.收尾处理错误、中断恢复、必要时复位

bootm_run_states
-> 记录 states 到 images.state
-> START: bootm_start()
-> PRE_LOAD: bootm_pre_load()
-> FINDOS: bootm_find_os()
-> FINDOTHER: bootm_find_other()
-> MEASURE: bootm_measure()
-> LOADOS: 关中断 -> bootm_load_os()
-> RAMDISK: boot_ramdisk_high()
-> FDT: boot_relocate_fdt()
-> 获取 boot_fn
-> OS_CMDLINE: boot_fn(OS_CMDLINE)
-> OS_BD_T: boot_fn(OS_BD_T)
-> OS_PREP: bootm_process_cmdline_env() -> boot_fn(OS_PREP)
-> OS_FAKE_GO: boot_selected_os(FAKE_GO)
-> OS_GO: boot_selected_os(OS_GO)
-> err 收尾:
   -> 必要时恢复中断
   -> 处理 UNIMPLEMENTED / RESET
   -> 返回 ret
```

### uImage 数据结构

uImage 是 U-Boot 早期最经典的镜像格式，由 mkimage 工具生成。它本质上是：

```
+------------------+
| image_header_t   | 64字节头部
+------------------+
| Kernel Data      | 内核/ramdisk/dtb等数据
+------------------+
```

```c
#define IH_MAGIC	0x27051956	/* Image Magic Number		*/
/*
 * Legacy format image header,
 * all data in network byte order (aka natural aka bigendian).
 */
struct legacy_img_hdr {
	uint32_t	ih_magic;	/* Image Header Magic Number	*/
	uint32_t	ih_hcrc;	/* Image Header CRC Checksum	*/
	uint32_t	ih_time;	/* Image Creation Timestamp	*/
	uint32_t	ih_size;	/* Image Data Size		*/
	uint32_t	ih_load;	/* Data	 Load  Address		*/
	uint32_t	ih_ep;		/* Entry Point Address		*/
	uint32_t	ih_dcrc;	/* Image Data CRC Checksum	*/
	uint8_t		ih_os;		/* Operating System		*/
	uint8_t		ih_arch;	/* CPU architecture		*/
	uint8_t		ih_type;	/* Image Type			*/
	uint8_t		ih_comp;	/* Compression Type		*/
	uint8_t		ih_name[IH_NMLEN];	/* Image Name		*/
};

enum image_type_t {
	IH_TYPE_INVALID		= 0,	/* Invalid Image		*/
	IH_TYPE_STANDALONE,		/* Standalone Program		*/
	IH_TYPE_KERNEL,			/* OS Kernel Image		*/
	IH_TYPE_RAMDISK,		/* RAMDisk Image		*/
	IH_TYPE_MULTI,			/* Multi-File Image		*/
	IH_TYPE_FIRMWARE,		/* Firmware Image		*/
	............
};
```

### android boot image

include/android_image.h

```c
/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * This is from the Android Project,
 * Repository: https://android.googlesource.com/platform/system/tools/mkbootimg
 * File: include/bootimg/bootimg.h
 * Commit: cce5b1923e3cd2fcb765b512610bdc5c42bc501d
 *
 * Copyright (C) 2007 The Android Open Source Project
 */

#ifndef _ANDROID_IMAGE_H_
#define _ANDROID_IMAGE_H_

#include <linux/compiler.h>
#include <linux/types.h>

#define ANDR_GKI_PAGE_SIZE 4096
#define ANDR_BOOT_MAGIC "ANDROID!"
#define ANDR_BOOT_MAGIC_SIZE 8
#define ANDR_BOOT_NAME_SIZE 16
#define ANDR_BOOT_ARGS_SIZE 512
#define ANDR_BOOT_EXTRA_ARGS_SIZE 1024
#define VENDOR_BOOT_MAGIC "VNDRBOOT"
#define ANDR_VENDOR_BOOT_V3_SIZE 2112 /* sz(andr_vnd_boot_img_hdr) - sz(vendor_ramdisk_table*) */
#define ANDR_VENDOR_BOOT_V4_SIZE 2128 /* sz(andr_vnd_boot_img_hdr) */
#define ANDR_VENDOR_BOOT_MAGIC_SIZE 8
#define ANDR_VENDOR_BOOT_ARGS_SIZE 2048
#define ANDR_VENDOR_BOOT_NAME_SIZE 16

#define BOOTCONFIG_MAGIC "#BOOTCONFIG\n"
#define BOOTCONFIG_MAGIC_SIZE 12
#define BOOTCONFIG_SIZE_SIZE 4
#define BOOTCONFIG_CHECKSUM_SIZE 4
#define BOOTCONFIG_TRAILER_SIZE BOOTCONFIG_MAGIC_SIZE + \
				BOOTCONFIG_SIZE_SIZE + \
				BOOTCONFIG_CHECKSUM_SIZE

struct andr_boot_img_hdr_v3 {
	u8 magic[ANDR_BOOT_MAGIC_SIZE];

	u32 kernel_size;    /* size in bytes */
	u32 ramdisk_size;   /* size in bytes */

	u32 os_version;

	u32 header_size;    /* size of boot image header in bytes */
	u32 reserved[4];
	u32 header_version; /* offset remains constant for version check */

	u8 cmdline[ANDR_BOOT_ARGS_SIZE + ANDR_BOOT_EXTRA_ARGS_SIZE];
	/* for boot image header v4 only */
	u32 signature_size; /* size in bytes */
};

struct andr_vnd_boot_img_hdr {
	u8 magic[ANDR_VENDOR_BOOT_MAGIC_SIZE];
	u32 header_version;
	u32 page_size;           /* flash page size we assume */

	u32 kernel_addr;         /* physical load addr */
	u32 ramdisk_addr;        /* physical load addr */

	u32 vendor_ramdisk_size; /* size in bytes */

	u8 cmdline[ANDR_VENDOR_BOOT_ARGS_SIZE];

	u32 tags_addr;           /* physical addr for kernel tags */

	u8 name[ANDR_VENDOR_BOOT_NAME_SIZE]; /* asciiz product name */
	u32 header_size;         /* size of vendor boot image header in bytes */
	u32 dtb_size;            /* size of dtb image */
	u64 dtb_addr;            /* physical load address */
	/* for boot image header v4 only */
	u32 vendor_ramdisk_table_size; /* size in bytes for the vendor ramdisk table */
	u32 vendor_ramdisk_table_entry_num; /* number of entries in the vendor ramdisk table */
	u32 vendor_ramdisk_table_entry_size; /* size in bytes for a vendor ramdisk table entry */
	u32 bootconfig_size; /* size in bytes for the bootconfig section */
};

/* The bootloader expects the structure of andr_boot_img_hdr_v0 with header
 * version 0 to be as follows: */
struct andr_boot_img_hdr_v0 {
    /* Must be ANDR_BOOT_MAGIC. */
    char magic[ANDR_BOOT_MAGIC_SIZE];

    u32 kernel_size; /* size in bytes */
    u32 kernel_addr; /* physical load addr */

    u32 ramdisk_size; /* size in bytes */
    u32 ramdisk_addr; /* physical load addr */

    u32 second_size; /* size in bytes */
    u32 second_addr; /* physical load addr */

    u32 tags_addr; /* physical addr for kernel tags */
    u32 page_size; /* flash page size we assume */

    /* Version of the boot image header. */
    u32 header_version;

    /* Operating system version and security patch level.
     * For version "A.B.C" and patch level "Y-M-D":
     *   (7 bits for each of A, B, C; 7 bits for (Y-2000), 4 bits for M)
     *   os_version = A[31:25] B[24:18] C[17:11] (Y-2000)[10:4] M[3:0] */
    u32 os_version;

    char name[ANDR_BOOT_NAME_SIZE]; /* asciiz product name */

    char cmdline[ANDR_BOOT_ARGS_SIZE];

    u32 id[8]; /* timestamp / checksum / sha1 / etc */

    /* Supplemental command line data; kept here to maintain
     * binary compatibility with older versions of mkbootimg. */
    char extra_cmdline[ANDR_BOOT_EXTRA_ARGS_SIZE];

    /* Fields in boot_img_hdr_v1 and newer. */
    u32 recovery_dtbo_size;   /* size in bytes for recovery DTBO/ACPIO image */
    u64 recovery_dtbo_offset; /* offset to recovery dtbo/acpio in boot image */
    u32 header_size;

    /* Fields in boot_img_hdr_v2 and newer. */
    u32 dtb_size; /* size in bytes for DTB image */
    u64 dtb_addr; /* physical load address for DTB image */
} __attribute__((packed));

/* When a boot header is of version 0, the structure of boot image is as
 * follows:
 *
 * +-----------------+
 * | boot header     | 1 page
 * +-----------------+
 * | kernel          | n pages
 * +-----------------+
 * | ramdisk         | m pages
 * +-----------------+
 * | second stage    | o pages
 * +-----------------+
 *
 * n = (kernel_size + page_size - 1) / page_size
 * m = (ramdisk_size + page_size - 1) / page_size
 * o = (second_size + page_size - 1) / page_size
 *
 * 0. all entities are page_size aligned in flash
 * 1. kernel and ramdisk are required (size != 0)
 * 2. second is optional (second_size == 0 -> no second)
 * 3. load each element (kernel, ramdisk, second) at
 *    the specified physical address (kernel_addr, etc)
 * 4. prepare tags at tag_addr.  kernel_args[] is
 *    appended to the kernel commandline in the tags.
 * 5. r0 = 0, r1 = MACHINE_TYPE, r2 = tags_addr
 * 6. if second_size != 0: jump to second_addr
 *    else: jump to kernel_addr
 */

/* When the boot image header has a version of 2, the structure of the boot
 * image is as follows:
 *
 * +---------------------+
 * | boot header         | 1 page
 * +---------------------+
 * | kernel              | n pages
 * +---------------------+
 * | ramdisk             | m pages
 * +---------------------+
 * | second stage        | o pages
 * +---------------------+
 * | recovery dtbo/acpio | p pages
 * +---------------------+
 * | dtb                 | q pages
 * +---------------------+
 *
 * n = (kernel_size + page_size - 1) / page_size
 * m = (ramdisk_size + page_size - 1) / page_size
 * o = (second_size + page_size - 1) / page_size
 * p = (recovery_dtbo_size + page_size - 1) / page_size
 * q = (dtb_size + page_size - 1) / page_size
 *
 * 0. all entities are page_size aligned in flash
 * 1. kernel, ramdisk and DTB are required (size != 0)
 * 2. recovery_dtbo/recovery_acpio is required for recovery.img in non-A/B
 *    devices(recovery_dtbo_size != 0)
 * 3. second is optional (second_size == 0 -> no second)
 * 4. load each element (kernel, ramdisk, second, dtb) at
 *    the specified physical address (kernel_addr, etc)
 * 5. If booting to recovery mode in a non-A/B device, extract recovery
 *    dtbo/acpio and apply the correct set of overlays on the base device tree
 *    depending on the hardware/product revision.
 * 6. prepare tags at tag_addr.  kernel_args[] is
 *    appended to the kernel commandline in the tags.
 * 7. r0 = 0, r1 = MACHINE_TYPE, r2 = tags_addr
 * 8. if second_size != 0: jump to second_addr
 *    else: jump to kernel_addr
 */

/* When the boot image header has a version of 3, the structure of the boot
 * image is as follows:
 *
 * +---------------------+
 * | boot header         | 4096 bytes
 * +---------------------+
 * | kernel              | m pages
 * +---------------------+
 * | ramdisk             | n pages
 * +---------------------+
 *
 * m = (kernel_size + 4096 - 1) / 4096
 * n = (ramdisk_size + 4096 - 1) / 4096
 *
 * Note that in version 3 of the boot image header, page size is fixed at 4096 bytes.
 *
 * The structure of the vendor boot image (introduced with version 3 and
 * required to be present when a v3 boot image is used) is as follows:
 *
 * +---------------------+
 * | vendor boot header  | o pages
 * +---------------------+
 * | vendor ramdisk      | p pages
 * +---------------------+
 * | dtb                 | q pages
 * +---------------------+
 * o = (2112 + page_size - 1) / page_size
 * p = (vendor_ramdisk_size + page_size - 1) / page_size
 * q = (dtb_size + page_size - 1) / page_size
 *
 * 0. all entities in the boot image are 4096-byte aligned in flash, all
 *    entities in the vendor boot image are page_size (determined by the vendor
 *    and specified in the vendor boot image header) aligned in flash
 * 1. kernel, ramdisk, vendor ramdisk, and DTB are required (size != 0)
 * 2. load the kernel and DTB at the specified physical address (kernel_addr,
 *    dtb_addr)
 * 3. load the vendor ramdisk at ramdisk_addr
 * 4. load the generic ramdisk immediately following the vendor ramdisk in
 *    memory
 * 5. set up registers for kernel entry as required by your architecture
 * 6. if the platform has a second stage bootloader jump to it (must be
 *    contained outside boot and vendor boot partitions), otherwise
 *    jump to kernel_addr
 */

/* When the boot image header has a version of 4, the structure of the boot
 * image is as follows:
 *
 * +---------------------+
 * | boot header         | 4096 bytes
 * +---------------------+
 * | kernel              | m pages
 * +---------------------+
 * | ramdisk             | n pages
 * +---------------------+
 * | boot signature      | g pages
 * +---------------------+
 *
 * m = (kernel_size + 4096 - 1) / 4096
 * n = (ramdisk_size + 4096 - 1) / 4096
 * g = (signature_size + 4096 - 1) / 4096
 *
 * Note that in version 4 of the boot image header, page size is fixed at 4096
 * bytes.
 *
 * The structure of the vendor boot image version 4, which is required to be
 * present when a version 4 boot image is used, is as follows:
 *
 * +------------------------+
 * | vendor boot header     | o pages
 * +------------------------+
 * | vendor ramdisk section | p pages
 * +------------------------+
 * | dtb                    | q pages
 * +------------------------+
 * | vendor ramdisk table   | r pages
 * +------------------------+
 * | bootconfig             | s pages
 * +------------------------+
 *
 * o = (2128 + page_size - 1) / page_size
 * p = (vendor_ramdisk_size + page_size - 1) / page_size
 * q = (dtb_size + page_size - 1) / page_size
 * r = (vendor_ramdisk_table_size + page_size - 1) / page_size
 * s = (vendor_bootconfig_size + page_size - 1) / page_size
 *
 * Note that in version 4 of the vendor boot image, multiple vendor ramdisks can
 * be included in the vendor boot image. The bootloader can select a subset of
 * ramdisks to load at runtime. To help the bootloader select the ramdisks, each
 * ramdisk is tagged with a type tag and a set of hardware identifiers
 * describing the board, soc or platform that this ramdisk is intended for.
 *
 * The vendor ramdisk section is consist of multiple ramdisk images concatenated
 * one after another, and vendor_ramdisk_size is the size of the section, which
 * is the total size of all the ramdisks included in the vendor boot image.
 *
 * The vendor ramdisk table holds the size, offset, type, name and hardware
 * identifiers of each ramdisk. The type field denotes the type of its content.
 * The vendor ramdisk names are unique. The hardware identifiers are specified
 * in the board_id field in each table entry. The board_id field is consist of a
 * vector of unsigned integer words, and the encoding scheme is defined by the
 * hardware vendor.
 *
 * For the different type of ramdisks, there are:
 *    - VENDOR_RAMDISK_TYPE_NONE indicates the value is unspecified.
 *    - VENDOR_RAMDISK_TYPE_PLATFORM ramdisks contain platform specific bits, so
 *      the bootloader should always load these into memory.
 *    - VENDOR_RAMDISK_TYPE_RECOVERY ramdisks contain recovery resources, so
 *      the bootloader should load these when booting into recovery.
 *    - VENDOR_RAMDISK_TYPE_DLKM ramdisks contain dynamic loadable kernel
 *      modules.
 *
 * Version 4 of the vendor boot image also adds a bootconfig section to the end
 * of the image. This section contains Boot Configuration parameters known at
 * build time. The bootloader is responsible for placing this section directly
 * after the generic ramdisk, followed by the bootconfig trailer, before
 * entering the kernel.
 *
 * 0. all entities in the boot image are 4096-byte aligned in flash, all
 *    entities in the vendor boot image are page_size (determined by the vendor
 *    and specified in the vendor boot image header) aligned in flash
 * 1. kernel, ramdisk, and DTB are required (size != 0)
 * 2. load the kernel and DTB at the specified physical address (kernel_addr,
 *    dtb_addr)
 * 3. load the vendor ramdisks at ramdisk_addr
 * 4. load the generic ramdisk immediately following the vendor ramdisk in
 *    memory
 * 5. load the bootconfig immediately following the generic ramdisk. Add
 *    additional bootconfig parameters followed by the bootconfig trailer.
 * 6. set up registers for kernel entry as required by your architecture
 * 7. if the platform has a second stage bootloader jump to it (must be
 *    contained outside boot and vendor boot partitions), otherwise
 *    jump to kernel_addr
 */

/* Private struct */
struct andr_image_data {
	ulong kernel_ptr;  /* kernel address */
	u32 kernel_size;  /* size in bytes */
	u32 ramdisk_size;  /* size in bytes */
	ulong vendor_ramdisk_ptr;  /* vendor ramdisk address */
	u32 vendor_ramdisk_size;  /* vendor ramdisk size*/
	u32 boot_ramdisk_size;  /* size in bytes */
	ulong second_ptr;  /* secondary bootloader address */
	u32 second_size;  /* secondary bootloader size */
	ulong dtb_ptr;  /* address of dtb image */
	u32 dtb_size;  /* size of dtb image */
	ulong recovery_dtbo_ptr;  /* size in bytes for recovery DTBO/ACPIO image */
	u32 recovery_dtbo_size;  /* offset to recovery dtbo/acpio in boot image */

	const char *kcmdline;  /* boot kernel cmdline */
	const char *kcmdline_extra;  /* vendor-boot extra kernel cmdline */
	const char *image_name;  /* asciiz product name */

	ulong bootconfig_addr;  /* bootconfig image address */
	ulong bootconfig_size;  /* bootconfig image size */

	ulong kernel_addr;  /* physical load addr */
	ulong ramdisk_addr;  /* physical load addr */
	ulong ramdisk_ptr;  /* ramdisk address */
	ulong dtb_load_addr;  /* physical load address for DTB image */
	ulong tags_addr;  /* physical addr for kernel tags */
	u32 header_version;  /* version of the boot image header */
	u32 boot_img_total_size;  /* boot image size */
	u32 vendor_boot_img_total_size;  /* vendor boot image size */
};

#endif

```

```c
	if (((struct andr_boot_img_hdr_v0 *)hdr)->header_version <= 2)
		android_boot_image_v0_v1_v2_parse_hdr(hdr, &data);
	else
		android_boot_image_v3_v4_parse_hdr(hdr, &data);
```

# bootstd 分析

**以下多少材料来自AI，请自行判断正确性：**

- bootstd：标准启动框架的顶层设备（对应 UCLASS_BOOTSTD），其私有数据 struct bootstd_priv 保存全局配置和扫描列表。bootstd 设备默认由驱动模型自动创建（即使设备树中未显式定义），并负责协调所有 bootdev 和 bootmeth 的操作。
- bootdev：引导设备，即可提供引导介质访问的设备（通常是存储或网络硬件）。每个 bootdev 驱动与一个底层“媒体”设备相关联（例如 mmc_bootdev 属于对应的 MMC 设备），通过遍历该介质的分区和文件系统来寻找引导文件。
- bootmeth：引导方法，实现特定格式的引导逻辑（如从 extlinux.conf、PXE、Android boot.img、U-Boot 脚本等加载内核）。每个 bootmeth 驱动包含查找和验证 bootflow 的代码片段。例如 u-boot,extlinux 驱动寻找 /extlinux/extlinux.conf，u-boot,script 驱动寻找 boot.scr.uimg/boot.scr，u-boot,android 驱动负责 Android 分区布局。
- bootflow：具体的引导流程实例，包含操作系统映像的位置、参数等信息。bootflow 由 bootdev+bootmeth 组合查找生成，可能源自 BLS/extlinux 格式的文件或 Android Boot Image 等。


bootflow_scan_first() 内部做了什么：

```c
bootflow_scan_first()
  │
  ├─ bootmeth_setup_iter_order(iter, ...)
  │    → 读取 bootmeths="android" 环境变量
  │    → iter->method_order[] = [bootmeth_android]  只有一个
  │    → iter->method = bootmeth_android
  │
  ├─ bootdev_setup_iter(iter, ...)
  │    → 找 mmc bootdev，按优先级排序
  │    → VIM3: mmc2(eMMC) 优先级最高
  │    → iter->dev = mmc2_bootdev
  │
  └─ bootflow_check(iter, bflow)      ← 对这个 dev+method 组合做检查

do_bootflow_scan()                       cmd/bootflow.c
  └─ bootflow_scan_first()               boot/bootflow.c
       ├─ bootmeth_setup_iter_order()    → method = bootmeth_android
       ├─ bootdev_setup_iter()           → dev = mmc2
       └─ bootflow_check()
            └─ bootdev_get_bootflow()
                 └─ bootmeth_read_bootflow()
                      └─ android_read_bootflow()  ← 这里读 BCB、验证分区 magic
                           → bflow.state = BOOTFLOWST_READY
                           → ret = 0（成功）
  └─ bootflow_run_boot()                 找到了，立刻启动
       └─ bootmeth_boot()
            └─ android_boot()            boot/bootmeth_android.c
                 └─ boot_android_normal()
                      └─ bootm_boot_start()
```

bootflow_scan_first/next 是迭代器，逐一枚举设备和方法的组合。每次枚举都调用 bootflow_check → android_read_bootflow，一旦成功（bflow.err == 0）就立刻 bootflow_run_boot 启动。

来自u-boot官方描述：

```c
while (get next bootdev)
   while (get next bootmeth)
       while (get next bootflow)
           try to boot it
```

# Android 启动阶段分析(A/B分区)

### misc 分区

一共4KB，u-boot中的表示方法为:

```c
struct bootloader_message_ab {
    struct bootloader_message message;  // 2048 字节
    char slot_suffix[32];               // 32 字节
    char update_channel[128];           // 128 字节
    char reserved[1888];                // 填充至 4096 字节
};
```

message 字段是 bootloader 与 Android 系统/recovery 之间通信的消息通道

其中slot_suffix用于存放struct bootloader_control：

```c
/* Bootloader Control AB
 *
 * This struct can be used to manage A/B metadata. It is designed to
 * be put in the 'slot_suffix' field of the 'bootloader_message'
 * structure described above. It is encouraged to use the
 * 'bootloader_control' structure to store the A/B metadata, but not
 * mandatory.
 */
struct bootloader_control {
    // NUL terminated active slot suffix.
    char slot_suffix[4];
    // Bootloader Control AB magic number (see BOOT_CTRL_MAGIC).
    uint32_t magic;
    // Version of struct being used (see BOOT_CTRL_VERSION).
    uint8_t version;
    // Number of slots being managed.
    uint8_t nb_slot : 3;
    // Number of times left attempting to boot recovery.
    uint8_t recovery_tries_remaining : 3;
    // Ensure 4-bytes alignment for slot_info field.
    uint8_t reserved0[2];
    // Per-slot information.  Up to 4 slots.
    struct slot_metadata slot_info[4];
    // Reserved for further use.
    uint8_t reserved1[8];
    // CRC32 of all 28 bytes preceding this field (little endian
    // format).
    uint32_t crc32_le;
} __attribute__((packed));
```

用于控制从那个slot中启动（具体实现函数为：ab_select_slot）

### vbmeta header

AvbVBMetaImageHeader

```c
typedef struct AvbVBMetaImageHeader {
  /*   0: Four bytes equal to "AVB0" (AVB_MAGIC). */
  uint8_t magic[AVB_MAGIC_LEN];

  /*   4: The major version of libavb required for this header. */
  uint32_t required_libavb_version_major;
  /*   8: The minor version of libavb required for this header. */
  uint32_t required_libavb_version_minor;

  /*  12: The size of the signature block. */
  uint64_t authentication_data_block_size;
  /*  20: The size of the auxiliary data block. */
  uint64_t auxiliary_data_block_size;

  /*  28: The verification algorithm used, see |AvbAlgorithmType| enum. */
  uint32_t algorithm_type;

  /*  32: Offset into the "Authentication data" block of hash data. */
  uint64_t hash_offset;
  /*  40: Length of the hash data. */
  uint64_t hash_size;

  /*  48: Offset into the "Authentication data" block of signature data. */
  uint64_t signature_offset;
  /*  56: Length of the signature data. */
  uint64_t signature_size;

  /*  64: Offset into the "Auxiliary data" block of public key data. */
  uint64_t public_key_offset;
  /*  72: Length of the public key data. */
  uint64_t public_key_size;

  /*  80: Offset into the "Auxiliary data" block of public key metadata. */
  uint64_t public_key_metadata_offset;
  /*  88: Length of the public key metadata. Must be set to zero if there
   *  is no public key metadata.
   */
  uint64_t public_key_metadata_size;

  /*  96: Offset into the "Auxiliary data" block of descriptor data. */
  uint64_t descriptors_offset;
  /* 104: Length of descriptor data. */
  uint64_t descriptors_size;

  /* 112: The rollback index which can be used to prevent rollback to
   *  older versions.
   */
  uint64_t rollback_index;

  /* 120: Flags from the AvbVBMetaImageFlags enumeration. This must be
   * set to zero if the vbmeta image is not a top-level image.
   */
  uint32_t flags;

  /* 124: Reserved to ensure |release_string| start on a 16-byte
   * boundary. Must be set to zeroes.
   */
  uint8_t reserved0[4];

  /* 128: The release string from avbtool, e.g. "avbtool 1.0.0" or
   * "avbtool 1.0.0 xyz_board Git-234abde89". Is guaranteed to be NUL
   * terminated. Applications must not make assumptions about how this
   * string is formatted.
   */
  uint8_t release_string[AVB_RELEASE_STRING_SIZE];

  /* 176: Padding to ensure struct is size AVB_VBMETA_IMAGE_HEADER_SIZE
   * bytes. This must be set to zeroes.
   */
  uint8_t reserved[80];
} AVB_ATTR_PACKED AvbVBMetaImageHeader;
```

```
字节偏移   字段                              大小    说明
─────────────────────────────────────────────────────────────────
  0 ~  3   magic[4]                          4B    固定 "AVB0"
  4 ~  7   required_libavb_version_major     4B    主版本（必须精确匹配）
  8 ~ 11   required_libavb_version_minor     4B    次版本（不能超过运行时）
─────────────────────────────────────────────────────────────────
 12 ~ 19   authentication_data_block_size    8B    认证块大小（64的倍数）
 20 ~ 27   auxiliary_data_block_size         8B    辅助块大小（64的倍数）
─────────────────────────────────────────────────────────────────
 28 ~ 31   algorithm_type                    4B    签名算法枚举
─────────────────────────────────────────────────────────────────
 32 ~ 39   hash_offset                       8B    ┐ hash 在认证块内的位置
 40 ~ 47   hash_size                         8B    ┘
 48 ~ 55   signature_offset                  8B    ┐ 签名在认证块内的位置
 56 ~ 63   signature_size                    8B    ┘
─────────────────────────────────────────────────────────────────
 64 ~ 71   public_key_offset                 8B    ┐ 公钥在辅助块内的位置
 72 ~ 79   public_key_size                   8B    ┘
 80 ~ 87   public_key_metadata_offset        8B    ┐ 公钥元数据（可选）
 88 ~ 95   public_key_metadata_size          8B    ┘ 为0表示无元数据
 96 ~103   descriptors_offset                8B    ┐ 描述符在辅助块内的位置
104 ~111   descriptors_size                  8B    ┘
─────────────────────────────────────────────────────────────────
112 ~119   rollback_index                    8B    防回滚版本号
120 ~123   flags                             4B    AvbVBMetaImageFlags
124 ~127   reserved0[4]                      4B    填充对齐，必须为0
─────────────────────────────────────────────────────────────────
128 ~175   release_string[48]               48B    如 "avbtool 1.0.0"，NUL结尾
176 ~255   reserved[80]                     80B    填充至256字节，必须为0
─────────────────────────────────────────────────────────────────
总计：256 字节 = AVB_VBMETA_IMAGE_HEADER_SIZE
```

```
磁盘/内存中 vbmeta 完整镜像:
┌──────────────────────────────────┐ ← data[0]
│  Header Block (256B 固定)         │  magic + 版本 + 所有偏移量和大小描述
└──────────────────────────────────┘
┌──────────────────────────────────┐ ← data + 256
│  Authentication Block            │  大小 = authentication_data_block_size
│  ┌────────────────────────────┐  │
│  │ hash   (hash_offset起)     │  │  SHA256/SHA512(Header||Auxiliary)
│  ├────────────────────────────┤  │
│  │ signature (sig_offset起)   │  │  RSA签名(上面的hash)
│  └────────────────────────────┘  │
└──────────────────────────────────┘
┌──────────────────────────────────┐ ← data + 256 + auth_block_size
│  Auxiliary Block                 │  大小 = auxiliary_data_block_size
│  ┌────────────────────────────┐  │
│  │ public_key (pubkey_offset) │  │  ← out_public_key_data 指向这里
│  ├────────────────────────────┤  │
│  │ public_key_metadata        │  │  可选，size=0时不存在
│  ├────────────────────────────┤  │
│  │ descriptors (desc_offset)  │  │  HASH/HASHTREE/CHAIN/CMDLINE 描述符
│  └────────────────────────────┘  │
```

其中descriptors的结构体为:

```c
/* The header for a serialized descriptor.
 *
 * A descriptor always have two fields, a |tag| (denoting its type,
 * see the |AvbDescriptorTag| enumeration) and the size of the bytes
 * following, |num_bytes_following|.
 *
 * For padding, |num_bytes_following| is always a multiple of 8.
 */
typedef struct AvbDescriptor {
  uint64_t tag;
  uint64_t num_bytes_following;
} AVB_ATTR_PACKED AvbDescriptor;
```

tag的值为:

```c
/* Well-known descriptor tags.
 *
 * AVB_DESCRIPTOR_TAG_PROPERTY: see |AvbPropertyDescriptor| struct.
 * AVB_DESCRIPTOR_TAG_HASHTREE: see |AvbHashtreeDescriptor| struct.
 * AVB_DESCRIPTOR_TAG_HASH: see |AvbHashDescriptor| struct.
 * AVB_DESCRIPTOR_TAG_KERNEL_CMDLINE: see |AvbKernelCmdlineDescriptor| struct.
 * AVB_DESCRIPTOR_TAG_CHAIN_PARTITION: see |AvbChainPartitionDescriptor| struct.
 */
typedef enum {
  AVB_DESCRIPTOR_TAG_PROPERTY,
  AVB_DESCRIPTOR_TAG_HASHTREE,
  AVB_DESCRIPTOR_TAG_HASH,
  AVB_DESCRIPTOR_TAG_KERNEL_CMDLINE,
  AVB_DESCRIPTOR_TAG_CHAIN_PARTITION,
} AvbDescriptorTag;
```

所有 Descriptor 以 AvbDescriptor（tag + num_bytes_following）为基础，派生出：

- AVB_DESCRIPTOR_TAG_HASH：用于 boot/recovery 等整分区哈希校验
- AVB_DESCRIPTOR_TAG_HASHTREE：用于 system/vendor 等 dm-verity 哈希树
- AVB_DESCRIPTOR_TAG_KERNEL_CMDLINE：向内核传递 cmdline 参数
- AVB_DESCRIPTOR_TAG_CHAIN_PARTITION：链式 vbmeta（chained partition）
- AVB_DESCRIPTOR_TAG_PROPERTY：键值对属性

### avb启动验证流程

```c
run_avb_verification()
  │
  ├─ avb_ops_alloc()           ← 初始化平台 IO 操作
  ├─ read_is_device_unlocked() ← 检查设备锁定状态
  │
  └─ avb_slot_verify()
       │
       ├─ 读取 vbmeta_a/vbmeta_b 分区
       ├─ avb_vbmeta_image_verify()
       │    ├─ 校验 magic、版本
       │    ├─ 计算 SHA256/SHA512 哈希，与 auth block 比对
       │    └─ RSA 验签（auth block 中的签名 vs aux block 中的公钥）
       │
       ├─ validate_vbmeta_public_key() ← 校验公钥是否是 OEM 内置信任公钥
       ├─ read_rollback_index()        ← 防回滚检查
       │
       ├─ 遍历 Descriptors
       │    ├─ HashDescriptor → 加载分区，计算哈希并比对（boot、vendor_boot）
       │    ├─ HashtreeDescriptor → 生成 dm-verity 参数写入 cmdline（system、vendor）
       │    └─ KernelCmdlineDescriptor → 追加 cmdline 参数
       │
       └─ 输出 AvbSlotVerifyData（cmdline、rollback_indexes 等）
```

# 参考资料

**U-Boot** 源代码分析 源代码分析 源代码分析 源代码分析

https://people.umass.edu/tongping/book/ubootframework.pdf

uboot之源码分析

https://draapho.github.io/2017/08/25/1720-uboot-source/

The U-Boot Documentation

https://docs.u-boot.org/en/latest/

U-Boot移植与调试指南

https://openvela.csdn.net/69c4b45054b52172bc648ca5.html

u-boot启动流程

https://github.com/zhaojh329/U-boot-1/blob/master/第1章-U-boot启动流程.md

U-Boot 深度解析：从原理到实践

https://www.cnblogs.com/clnchanpin/p/19393470

amlogic-u-boot-scripts

https://github.com/FauthD/amlogic-u-boot-scripts

Board-specific doc / Amlogic

https://docs.u-boot.org/en/latest/board/amlogic/index.html

ARM的安全启动—ATF/TF-A以及它与UEFI的互动

https://zhuanlan.zhihu.com/p/391101179

ARM Trusted Firmware-A && RISC-V OpenSBI

https://www.cnblogs.com/Avalon-Nausica/p/18574664

Standard Boot

https://docs.u-boot.org/en/stable/develop/bootstd/index.html