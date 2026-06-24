# adb 小知识

android设备添加adb认证时使用的公钥文件

```sh
mkdir -p /data/misc/adb
cat /sdcard/adbkey.pub >> /data/misc/adb/adb_keys
```

连接时，使用的私钥：

```sh
~/.android/adbkey        # 私钥文件
~/.android/adbkey.pub    # 公钥文件
```

# 有用的命令

| 命令      | 全称                  | 对应服务                        | 作用                            |
| ------- | ------------------- | --------------------------- | ----------------------------- |
| pm      | Package Manager     | PackageManagerService(PMS)  | 应用安装、卸载、查询                    |
| am      | Activity Manager    | ActivityManagerService(AMS) | 启动 Activity/Service/Broadcast |
| dumpsys | Dump System Service | 所有 System Service           | 查看系统运行状态和调试信息                 |


### pm

- pm list packages: 查看所有应用
- pm path com.kartina.tv.daydream:查看APK路径

### am

- am start -n com.android.settings: 启动Activity
- am start -a android.settings.WIFI_SETTINGS

### dumpsys

- dumpsys -l : 查看所有服务
- dumpsys package com.demo.app：查看指定应用

# 资料

APK加固原理详解

https://www.jianshu.com/p/89dee4891f70

AndroidStudio生成aar包和如何使用aar包

https://blog.csdn.net/feikudai8460/article/details/120727645

引导加载程序

https://source.android.com/docs/core/architecture/bootloader?hl=zh-cn