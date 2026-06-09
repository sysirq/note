# VIM3

VIM3/3L Setup Serial Debug Console

https://docs.khadas.com/products/sbc/vim3/development/setup-serial-tool#tab__mac-os

### 串行调试控制台

| **Serial tools pin** | GPIO **board header pin** |
| -------------------- | ------------------------- |
| GND                  | 17                        |
| TXD                  | 18                        |
| RXD                  | 19                        |


# 硬件控制

### LED 控制

“系统开机状态”的 LED控制：
```
i2c mw 0x18 0x28 3 1 # LED_HEARTBEAT_MODE
i2c mw 0x18 0x28 2 1 # LED_BREATHE_MODE
i2c mw 0x18 0x28 1 1 # LED_ON_MODE
i2c mw 0x18 0x28 0 1 # LED_OFF_MODE
```

“系统关机状态”的 LED控制：
```
i2c mw 0x18 0x29 3 1 # LED_HEARTBEAT_MODE
i2c mw 0x18 0x29 2 1 # LED_BREATHE_MODE
i2c mw 0x18 0x29 1 1 # LED_ON_MODE
i2c mw 0x18 0x29 0 1 # LED_OFF_MODE
```

# Android 9 32位源码编译

### Build U-Boot

```shell
$ cd PATH_YOUR_PROJECT
$ cd bootloader/uboot
$ ./mk TARGET
```

### Build Linux Kernel

```shell
$ source build/envsetup.sh 
$ lunch kvim3-userdebug
$ make bootimage
```

对应的makefile解析:

```
bootimage (phony)
└── out/.../boot.img                  [Makefile:812]
      ├── mkbootimg (host tool)       [config.mk:651]
      ├── out/.../kernel              [Makefile:677] ← 叶节点(预编译)
      └── out/.../ramdisk.img         [Makefile:692]
            ├── mkbootfs (host tool)  [config.mk:647]
            ├── minigzip (host tool)  [config.mk:648]  order-only
            └── INTERNAL_RAMDISK_FILES                 [Makefile:684]
                  = filter(root/%, ALL_DEFAULT_INSTALLED_MODULES)
                  └── ALL_DEFAULT_INSTALLED_MODULES    [main.mk:1018]
                        ├── PRODUCT_COPY_FILES 安装文件  [Makefile:40]
                        │     (init.rc, fstab.*, ueventd.rc ...)
                        ├── default.prop / build.prop   [Makefile:145]
                        └── modules_to_install          [main.mk:951]
                              = PRODUCT_PACKAGES 各模块的 INSTALLED 路径
                              └── ALL_MODULES.xxx.INSTALLED [base_rules.mk:643]
                                    (每个模块在 Android.mk 编译时注册)
```

kernel对应的makefile为：device/khadas/kvim3/Kernel.mk

### Build Android

```sh
$ cd PATH_YOUR_PROJECT
$ source build/envsetup.sh
$ lunch TARGET_LUNCH
$ make -jN otapackage
```

# 手动启动boot.img(内核)

```sh
=> mmc dev 2
switch to partitions #0, OK
mmc2(part 0) is current device
=> mmc read 0x1080000 0x3E000 0x5000
MMC read: dev # 2, block # 253952, count 20480 ... 20480 blocks read: OK
=> bootm start 0x1080000
## Booting Android Image at 0x01080000 ...
Kernel load addr 0x01080000 size 9264 KiB
Kernel command line: androidboot.dtbo_idx=0 --cmdline root=/dev/mmcblk0p18 buildvariant=userdebug
Error: header_version must be >= 2 to get dtb
second address is 0x198c800
Working FDT set to 198c800
=> bootm loados
   Loading Kernel Image to 1080000
=> bootm fdt
   Loading Device Tree to 000000007ffe5000, end 000000007ffff818 ... OK
Working FDT set to 7ffe5000
=> fdt chosen
=> fdt set /chosen bootargs "root=/dev/mmcblk0p18 rw console=ttyS0,115200 earlycon=aml_uart,0xff803000 rootwait initcall_debug androidboot.console=ttyS0 loglevel=8"
=> fdt set /chosen stdout-path "/soc/aobus@ff800000/serial@3000"
=> fdt print /chosen
chosen {
        stdout-path = "/soc/aobus@ff800000/serial@3000";
        smbios3-entrypoint = <0x00000000 0xeaf3b000>;
        u-boot,version = "2026.07-rc3-00031-g9b1f6ba072a5-dirty";
        bootargs = "root=/dev/mmcblk0p18 rw console=ttyS0,115200 earlycon=aml_uart,0xff803000 rootwait initcall_debug androidboot.console=ttyS0 loglevel=8";
        kaslr-seed = <0xb028fd10 0xea5cf5c8>;
};
=> bootm go

Starting kernel ...

   FDT blob at 0x7ffe5000, size 108569 bytes
   IH_ARCH_DEFAULT is 22, images->os.arch is 0
[    0.000000@0] Booting Linux on physical CPU 0x0
[    0.000000@0] Linux version 4.9.113 (root@c6fcd1183ec2) (gcc version 6.3.1 20170109 (Linaro GCC 6.3-2017.02) ) #1 SMP PREEMPT Mon Jun 8 18:07:09 CST 2026
[    0.000000@0] CPU: cpu_v7_name [410fd034] revision 4 (ARMv7), cr=10c5383d
[    0.000000@0] CPU: div instructions available: patching division code
[    0.000000@0] CPU: PIPT / VIPT nonaliasing data cache, VIPT aliasing instruction cache
[    0.000000@0] Machine model: Khadas
[    0.000000@0] earlycon: aml_uart0 at MMIO 0xff803000 (options '')
[    0.000000@0] bootconsole [aml_uart0] enabled
[    0.000000@0]        07400000 - 07500000,     1024 KB, ramoops@0x07400000
[    0.000000@0] failed to allocate memory for node linux,secmon, size:4 MB
[    0.000000@0] failed to allocate memory for node linux,meson-fb, size:8 MB
[    0.000000@0] failed to allocate memory for node linux,ion-dev, size:128 MB
[    0.000000@0] failed to allocate memory for node linux,di_cma, size:40 MB
[    0.000000@0] failed to allocate memory for node linux,ppmgr, size:0 MB
[    0.000000@0] failed to allocate memory for node linux,codec_mm_cma, size:308 MB
[    0.000000@0] failed to allocate memory for node linux,codec_mm_reserved, size:0 MB
[    0.000000@0] failed to allocate memory for node linux,vdin0_cma, size:64 MB
[    0.000000@0] failed to allocate memory for node linux,vdin1_cma, size:64 MB
[    0.000000@0] failed to allocate memory for node linux,galcore, size:16 MB
[    0.000000@0] failed to allocate memory for node linux,isp_cma, size:128 MB
[    0.000000@0] failed to allocate memory for node linux,adapt_cma, size:24 MB
[    0.000000@0] cma: Failed to reserve 8 MiB
[    0.000000@0] Memory policy: Data cache writealloc
```

# 参考资料

Khadas VIM1

https://docs.khadas.com/products/sbc/vim1/start?redirect=1#Krescue-Khadas-Rescue-OS

android_device_khadas

https://github.com/khadas/android_device_khadas/tree/Vim

Le Potato

https://libre.computer/products/aml-s905x-cc/#

Libre Computer Project

https://github.com/libre-computer-project

Linux for Amlogic

https://linux-meson.com

Bootflow and configuration on Amlogic device / Amlogic设备上的启动流程和配置

https://7ji.github.io/embedded/2022/11/11/amlogic-booting.html

Installation of ArchLinux ARM on an out-of-tree Amlogic device / 在不被官方支持的Amlogic设备上安装ArchLinux ARM

https://7ji.github.io/embedded/2022/11/08/alarm-install.html

Partitioning on Amlogic's proprietary eMMC partition table with ampart / 使用ampart在Amlogic专有的eMMC分区表上分区

https://7ji.github.io/embedded/2022/11/11/ept-with-ampart.html

VIM3/3L Build Android

https://docs.khadas.com/products/sbc/vim3/development/android/build-android#vim33l-build-android