# aosp版本

android-6.0.1_r81

# 源代码修改追踪

对某些项目建立本地分支:

```
repo start <newbranchname> <project>
```

对所有项目创建分支:

```
repo start <newbranchname> --all
```

查看现有分支的列表:

```
repo branches
```

查看修改:

```
repo diff
```

删除repo分支:

```
 repo abandon [--all | <branchname>] [<project>...]
```

# 添加新设备

### 创建目录结构

```
cd aosp-6.0.1/
mkdir -p device/mycorp/mydevice
cd device/mycorp/mydevice
```

### 核心配置文件

##### AndroidProducts.mk

起着入口索引的作用。它告诉构建系统：“在这个厂商目录下，存在哪些可以被编译的产品，以及它们的具体配置文件在哪里

它的主要任务是定义两个变量：

- PRODUCT_MAKEFILES: 指向具体产品定义文件（通常是 full_xxx.mk）的路径。这个变量是**必选**的。它列出了该厂商目录下所有可用的产品配置文件（`.mk`）。
- COMMON_LUNCH_CHOICES: 定义在 lunch 菜单中直接显示的选项。这个变量用于将常用的编译组合（产品名-编译类型）预设到 `lunch` 列表中。

eg:

```makefile
#
# Copyright (C) 2014 The Android Open-Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

PRODUCT_MAKEFILES := \
    $(LOCAL_DIR)/my_device.mk

COMMON_LUNCH_CHOICES := \
	my_device-userdebug \
	my_device-eng
```

##### vendorsetup.sh

仅适用于 Android 9 及更低版本,创建一个 vendorsetup.sh 文件，以将您的产品（“lunch combo”）以及用破折号分隔的构建变体添加到构建中。例如

```sh
add_lunch_combo <product-name>-userdebug
```

但在现代 AOSP 中，Google 推荐并强制使用 AndroidProducts.mk 中的 COMMON_LUNCH_CHOICES。

##### device.mk

产品配置文件是整个构建系统的“指挥棒”。它决定了 Android 系统镜像中包含哪些功能、哪些应用、以及针对什么硬件进行优化。通常这个文件会被 AndroidProducts.mk 引用，它的核心任务是填充以 PRODUCT_ 开头的系统变量。

一个完整的产品配置文件通常分为三个部分：继承基础配置、定义设备参数、声明包含组件。



- 1、继承基础配置 (Inherit)

你不需要从零开始写一个 Android 系统。通过 inherit-product 函数，你可以复用 Google 已经写好的通用配置。

```makefile
$(call inherit-product, device/generic/x86_64/mini_x86_64.mk)

$(call inherit-product, device/generic/mini-emulator-armv7-a-neon/mini_emulator_common.mk)
```

- 2、定义设备参数

这些信息会写入到系统的 /system/build.prop 文件中，应用通过 android.os.Build 类读取。

```makefile
PRODUCT_NAME := my_device_model      # 关键：必须与 lunch 选项一致
PRODUCT_DEVICE := my_codename       # 对应 device/vendor/codename 目录名
PRODUCT_BRAND := MyBrand            # 品牌名
PRODUCT_MODEL := Awesome Pad Pro    # 最终在“关于手机”里显示的名字
PRODUCT_MANUFACTURER := MyFactory   # 制造商
```

- 3、定义包含的软件包 (PRODUCT_PACKAGES)

这是最常用的变量，用于指定哪些模块（APK、动态库、可执行文件）要打包进镜像。

```makefile
PRODUCT_PACKAGES += \
    MyCustomLauncher \
    libcustom_hardware_jni \
    ScreenRecorder
```

**常用高级变量说明**：

- PRODUCT_COPY_FILES

将源码树中的文件拷贝到镜像指定路径。常用于配置文件。eg: path/to/init.rc:vendor/etc/init/init.rc

- PRODUCT_PROPERTY_OVERRIDES

设置默认的系统属性（build.prop）。eg: ro.config.low_ram=false

- PRODUCT_CHARACTERISTICS

定义设备形态（手机、平板、手表、电视）,tablet 或 nosdcard,watch


##### BoardConfig.mk

主要负责配置与特定硬件架构、内核、编译器参数以及分区结构相关的变量。

- 1、定义硬件架构

```makefile
TARGET_ARCH := arm64							# 基础架构（如 arm64, x86_64）。
TARGET_ARCH_VARIANT := armv8-a    # 架构变体（如 armv8-a, armv8-2a）。
```

- 2、内核与引导配置

TARGET_NO_BOOTLOADER: 是否在 AOSP 中编译 Bootloader（通常为 true，因为 Bootloader 多由厂商单独提供）。

BOARD_KERNEL_CMDLINE: 传递给内核的启动参数（如串口打印、根分区位置）

BOARD_KERNEL_BASE: 内核加载的基地址。

BOARD_KERNEL_PAGESIZE: 内核页大小（通常是 2048 或 4096）。

- 3、存储与分区定义 (Storage & Partitions)


BOARD_XXXXXIMAGE_PARTITION_SIZE： 定义各分区的字节大小。

BOARD_XXXXXIMAGE_FILE_SYSTEM_TYPE：定义文件系统格式（如 `ext4`, `f2fs`, `erofs`）

# 自定义模块

### 目录结构

```
/home/sysirq/aosp-6.0.1/device/tvbox

└── test_module
    ├── Android.mk
    └── hello_aosp.c
```

Android.mk:

```makefile
# 获取当前目录路径
LOCAL_PATH := $(call my-dir)

# 清空之前的变量环境（必须）
include $(CLEAR_VARS)         

# 模块名，这就是你加到 PRODUCT_PACKAGES 的名字
LOCAL_MODULE := hello_aosp
# 源码文件路径
LOCAL_SRC_FILES := hello_aosp.c 
# 编译选项
LOCAL_CFLAGS := -Werror       

# 告诉系统：编译成一个可执行文件
include $(BUILD_EXECUTABLE)   
```

hello_aosp.c

```c
#include <stdio.h>

int main(void)
{
	printf("Hello,world\n");
	return 0;
}
```

### 模块最终被安装到镜像的哪个路径

- include $(BUILD_EXECUTABLE): 默认安装到 /system/bin/
- include $(BUILD_PACKAGE): 默认安装到 /system/app/ 或 /system/priv-app/
- include $(BUILD_SHARED_LIBRARY): 默认安装到 /system/lib/ (或 lib64)

自定义路径变量：

LOCAL_MODULE_PATH: 最高优先级。如果你手动设置了这个变量，模块会无视默认规则，强行去往该路径。

e g: LOCAL_MODULE_PATH := $(TARGET_OUT_ETC)/my_config  → 安装到 /system/etc/my_config/


# 资料

添加新设备

https://source.android.com/docs/setup/create/new-device?hl=zh-cn

使用 Android 模拟器虚拟设备

https://source.android.com/docs/setup/test/avd?hl=zh-cn

Soong

https://android.googlesource.com/platform/build/soong/+/refs/heads/main/README.md

Android.mk

https://developer.android.com/ndk/guides/android_mk?hl=zh-cn

针对 AOSP 进行开发 (5.0 - 8.0)的Dockerfile

https://android.googlesource.com/platform/build/+/main/tools/docker

