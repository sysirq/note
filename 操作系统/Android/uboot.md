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