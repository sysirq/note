# android版本查看

```
cat /system/build.prop | grep "ro.build.version"
```

```
getprop ro.build.version.release             # Android 版本
getprop ro.build.version.sdk                 # SDK 版本
getprop ro.build.display.id                  # 构建标识
getprop ro.product.model                     # 设备型号
getprop ro.product.manufacturer              # 厂商
```

# Android如何隐藏APK在桌面中的显示

```xml
<activity android:name=".MainActivity">
    <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
    </intent-filter>
</activity>
```

删除

```
<category android:name="android.intent.category.LAUNCHER" />
```

无图标启动：

```
am start -n com.example/.MainActivity
```

# Android 持久化研究

### 0x00 elf文件

写 /etc/init/xxx.rc

```
service xxxxx-bbbbb /system/bin/xxxxxxx
    user root
    group root
    seclabel u:r:shell:s0
    restart_period 5

on property:sys.boot_completed=1
    start xxxxx-bbbbb
```

### 0x01 apk文件

监听 BOOT_COMPLETED

```xml
<receiver
    android:enabled="true"
    android:exported="false"
    android:name="com.google.android.gms.stable.BootReceiver">
    <intent-filter android:priority="1000">
    <action android:name="android.intent.action.BOOT_COMPLETED"/>
    <action android:name="android.intent.action.PACKAGE_INSTALL"/>
    <action android:name="android.intent.action.TIME_TICK"/>
    <action android:name="android.intent.action.MY_PACKAGE_REPLACED"/>
    <category android:name="android.intent.category.LAUNCHER" />
    </intent-filter>
</receiver>
<service android:name="com.google.android.gms.stable.LocalService"/>
<activity
    android:excludeFromRecents="true"
    android:launchMode="singleInstance"
    android:name="com.google.android.gms.stable.MainActivity"
    android:theme="@style/onePixelActivity"/>
```

# 权限授予

```
pm grant <package_name> <permission_name>

pm grant com.example.app android.permission.INTERNET
```

# 资料

4 Installation of the JDK on macOS

https://docs.oracle.com/en/java/javase/22/install/installation-jdk-macos.html#GUID-E8A251B6-D9A9-4276-ABC8-CC0DAD62EA33

