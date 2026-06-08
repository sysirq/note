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
$ make bootimage
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