# 启动调试

```xml
<application
    android:debuggable="true"  <!-- 强制启用调试模式 -->
    android:allowBackup="true"
    android:icon="@mipmap/ic_launcher"
    android:label="@string/app_name"
    android:theme="@style/AppTheme">
    ...
</application>
```

# 快速定位程序关键点

### 代码注入法

插入log函数，输出调试信息。

```smali
const-string v0,"TAG"
const-string v1,"info"
invoke-static {v0,v1},Landroid/util/log;->v(Ljava/lang/String;Ljava/lang/String;)I
```

然后使用logcat 输出信息:

```bash
logcat -s TAG:V
```

TAG 为 log 的第一个参数，V为等级

### 栈跟踪法

通过调用:new Exception("Print stack").printStackTrace();来显示某个函数是什么时候被调用的。

```smali
new-instance v0,Ljava/lang/Exception;
const-string v1,"print stack"
invoke-direct {v0,v1},Ljava/lang/Exception;-><init>(Ljava/lang/String;)V
invoke-virtual {v0},Ljava/lang/Exception;->printStackTrace()V
```

然后利用 logcat 输出信息:

```bash
logcat -s System.err:V*:W
```

### Method Profiling

利用Android SDK 自带的

DDMS（位置:AndroidSDK\tools\lib\monitor-x86_64）

也可以利用Android SDK 提供的函数，实现特定代码段的Method Profiling:

```java
android.os.Debug.startMethodTracing("123");
a();
android.os.Debug.stopMethodTracing();
```

该代码会在sd卡的根目录生成名123的trace文件。然后利用Android sdk 提供的 traceview 打开该文件.

# 质料：

[原创]安卓APP动态调试技术--以IDA为例：https://bbs.pediy.com/thread-217612.htm