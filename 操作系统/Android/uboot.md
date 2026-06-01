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
bootm $kernel_uimage_addr $ramdisk_addr $fdt_addr
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
