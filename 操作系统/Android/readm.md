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

