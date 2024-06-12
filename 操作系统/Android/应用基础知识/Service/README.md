服务基本上包含两种状态 

- Started：Android的应用程序组件，如活动，通过startService()启动了服务，则服务是Started状态。一旦启动，服务可以在后台无限期运行，即使启动它的组件已经被销毁。
- Bound：当Android的应用程序组件通过bindService()绑定了服务，则服务是Bound状态。Bound状态的服务提供了一个客户服务器接口来允许组件与服务进行交互，如发送请求，获取结果，甚至通过IPC来进行跨进程通信。

![图片](images/services.jpg)

要创建服务，你需要创建一个继承自Service基类或者它的已知子类的Java类。Service基类定义了不同的回调方法和多数重要方法。

- onStartCommand()：其他组件(如活动)通过调用startService()来请求启动服务时，系统调用该方法。如果你实现该方法，你有责任在工作完成时通过stopSelf()或者stopService()方法来停止服务。
- onBind：当其他组件想要通过bindService()来绑定服务时，系统调用该方法。如果你实现该方法，你需要返回IBinder对象来提供一个接口，以便客户来与服务通信。你必须实现该方法，如果你不允许绑定，则直接返回null。
- onUnbind()：当客户中断所有服务发布的特殊接口时，系统调用该方法。
- onRebind()：当新的客户端与服务连接，且此前它已经通过onUnbind(Intent)通知断开连接时，系统调用该方法。
- onCreate()：当服务通过onStartCommand()和onBind()被第一次创建的时候，系统调用该方法。该调用要求执行一次性安装。
- onDestroy()：当服务不再有用或者被销毁时，系统调用该方法。你的服务需要实现该方法来清理任何资源，如线程，已注册的监听器，接收器等。

通过在AndroidManifest.xml文件中添加

```xml
 <service android:name=".MyService" />
```

来包含我们的服务

# 资料

Android 服务（Service）

https://www.runoob.com/android/android-services.html

关于Android Service真正的完全详解，你需要知道的一切

https://blog.csdn.net/javazejian/article/details/52709857