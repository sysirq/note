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

### Build Android

```sh
$ cd PATH_YOUR_PROJECT
$ source build/envsetup.sh
$ lunch TARGET_LUNCH
$ make -jN otapackage
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