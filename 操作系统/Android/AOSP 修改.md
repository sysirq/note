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

##### vendorsetup.sh

仅适用于 Android 9 及更低版本,创建一个 vendorsetup.sh 文件，以将您的产品（“lunch combo”）以及用破折号分隔的构建变体添加到构建中。例如

```
add_lunch_combo <product-name>-userdebug
```

但在现代 AOSP 中，Google 推荐并强制使用 AndroidProducts.mk 中的 COMMON_LUNCH_CHOICES。

##### device.mk


##### BoardConfig.mk




# 资料

添加新设备

https://source.android.com/docs/setup/create/new-device?hl=zh-cn

使用 Android 模拟器虚拟设备

https://source.android.com/docs/setup/test/avd?hl=zh-cn

从命令行启动模拟器

https://developer.android.com/studio/run/emulator-commandline?hl=zh-cn#startup-options

Soong

https://android.googlesource.com/platform/build/soong/+/refs/heads/main/README.md

Android.mk

https://developer.android.com/ndk/guides/android_mk?hl=zh-cn