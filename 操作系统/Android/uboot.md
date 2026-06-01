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
