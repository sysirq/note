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