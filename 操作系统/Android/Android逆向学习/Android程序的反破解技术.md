Android 程序的破解一般步骤如下：反编译、静态分析、动态调试、重编译。我们可以从这几个步骤着手反破解

# 反编译
我们可以查找反编译器的漏洞，从而使反编译器无法正确解析APK文件

# 静态分析
- 对java代码进行混淆
- 对NDK编写的Native 程序进行加壳

# 动态调式
### 可以判断程序是否可被调试

```java
if((getApplicationInfo().flag &= ApplicationInfo.FLAG_DEBUGGABLE)!=0){
    //程序被调试
}
```

或使用SDK提供的方法检查调试器是否连接

```java
android.os.Debug.isBebuggerCoonected();
```
### 判断是否在模拟器中

# 重编译

### 进行签名检查

原理：由于重编译，会导致软件的签名被改变。所以
可以查看软件的签名是否改变来检查软件是否被修改。

```java
public int getSignature(String packageName){
    PackageManager pm = this.getPackageManager();
    PackageInfo pi = null;
    int sig = 0;
    try{
        pi = pm.getPackageInfo(packageName,PackageManager.GET_SIGNATURES);
        Signature[] s = pi.signatures;
        sig = s[0].hashCode();
    }
    catch(Exception e){
        sig = 0;
        e.printStackTrace();
    }
    return sig;
}
```

### 对重编译的class.dex文件进行校验

原理：对代码进行修改，然后重编译会导致classes.dex文件的hash被改变

```java
private boolean checkCRC(){
    boolean beModified = false;
    long src = long.parseLong(getString(R.string.crc));
    
    ZipFile zf;
    try{
        
        zf = new ZipFile(getApplicationContext().getPackageCodePath());
        ZipEntry ze = zf.getEntry("classes.dex");
        if(ze.getCrc == crc){
            bemodified = true;
        }
    }
    catch(IOException e){
        e.printStackTrace();
        beModified = false;
    }
    return beModified;
}
```