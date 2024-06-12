内容提供者被实现为类 ContentProvider 类的子类。需要实现一系列标准的 API，以便其他的应用程序来执行事务。

```java
public class MyApplication extends  ContentProvider {

}
```

# 内容URI

要查询内容提供者，你需要以如下格式的URI的形式来指定查询字符串：

```url
<prefix>://<authority>/<data_type>/<id>
```

# 创建流程

- 首先，你需要继承类 ContentProvider 来创建一个内容提供者类。
- 其次，你需要定义你的内容提供者URI地址。
- 接下来，你需要创建数据库来保存内容。通常，Android 使用 SQLite 数据库，并在框架中重写 onCreate() 方法来使用 SQLiteOpenHelper 的方法创建或者打开提供者的数据库。当你的应用程序被启动，它的每个内容提供者的 onCreate() 方法将在应用程序主线程中被调用。
- 最后，使用<provider.../>标签在 AndroidManifest.xml 中注册内容提供者。

你需要在类 ContentProvider 中重写的一些方法：

- onCreate():当提供者被启动时调用。
- query():该方法从客户端接受请求。结果是返回指针(Cursor)对象。
- insert():该方法向内容提供者插入新的记录。
- delete():该方法从内容提供者中删除已存在的记录。
- update():该方法更新内容提供者中已存在的记录。
- getType():该方法为给定的URI返回元数据类型。
