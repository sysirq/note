# Activity
### 启动Activity的两种方法
1. startActivity
2. startActivityForResult  (可以通过intent获取返回结果)

Android Manifest文件中含有如下过滤器的Activity组件为默认启动类当程序启动时系统自动调用它
```
<intent-filter>
       <action android:name="android.intent.action.MAIN" />
       <category android:name="android.intent.category.LAUNCHER" />
</intent-filter>
```

生命周期讲解：http://blog.csdn.net/android_tutor/article/details/5772285

# Service
一共有三种使用service的方式:
1. 直接startService
2. 通过BindService
3. 先startService 然后在bind

详细讲解质料:
http://blog.csdn.net/guolin_blog/article/details/11952435

# BroadCast
分动态注册于静态注册

# ContentPrivoder
用于提供数据.
ContentResolve用于提供器的CRUD

详细讲解质料:
http://blog.csdn.net/carson_ho/article/details/76101093

SQLite 质料:
https://www.jianshu.com/p/8e3f294e2828
# Intent
分为显式Intent和隐式Intent

# 参考质料
1. http://www.runoob.com/w3cnote/android-tutorial-service-1.html
2. http://www.cnblogs.com/bravestarrhu/archive/2012/05/02/2479461.html