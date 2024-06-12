# 创建广播接收器

广播接收器需要实现为BroadcastReceiver类的子类，并重写onReceive()方法来接收以Intent对象为参数的消息。

```java
public class MyReceiver extends BroadcastReceiver {
   @Override
   public void onReceive(Context context, Intent intent) {
      Toast.makeText(context, "Intent Detected.", Toast.LENGTH_LONG).show();
   }
}
```

# 注册广播接收器

应用程序通过在AndroidManifest.xml中注册广播接收器来监听制定的广播意图。假设我们将要注册MyReceiver来监听系统产生的ACTION_BOOT_COMPLETED事件。该事件由Android系统的启动进程完成时发出。

```xml
<application
   android:icon="@drawable/ic_launcher"
   android:label="@string/app_name"
   android:theme="@style/AppTheme" >
   <receiver android:name="MyReceiver">

      <intent-filter>
         <action android:name="android.intent.action.BOOT_COMPLETED">
         </action>
      </intent-filter>

   </receiver>
</application>
```

现在，无论什么时候Android设备被启动，都将被广播接收器MyReceiver所拦截，并且在onReceive()中实现的逻辑将被执行。

# 广播自定义意图

如果你想要应用程序中生成并发送自定义意图，你需要在活动类中通过sendBroadcast()来创建并发送这些意图。

```java
public void broadcastIntent(View view)
{
   Intent intent = new Intent();
   intent.setAction("com.example.CUSTOM_INTENT");
  intent.setPackage("com.example.myapplication");
   sendBroadcast(intent);
}
```

com.example.CUSTOM_INTENT的意图可以像之前我们注册系统产生的意图一样被注册。

```xml
<application
   android:icon="@drawable/ic_launcher"
   android:label="@string/app_name"
   android:theme="@style/AppTheme" >
   <receiver android:name="MyReceiver">

      <intent-filter>
         <action android:name="com.example.CUSTOM_INTENT">
         </action>
      </intent-filter>

   </receiver>
</application>
```