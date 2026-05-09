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

###### AndroidProducts.mk


###### device.mk


###### BoardConfig.mk


###### vendorsetup.sh

仅适用于 Android 9 及更低版本,创建一个 vendorsetup.sh 文件，以将您的产品（“lunch combo”）以及用破折号分隔的构建变体添加到构建中。例如

```
add_lunch_combo <product-name>-userdebug
```

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