# Activity的概念

Activity 提供窗口供应用在其中绘制界面。此窗口通常会填满屏幕，但也可能比屏幕小，并浮动在其他窗口上面。通常，一个 Activity 实现应用中的一个屏幕。例如，应用中的一个 Activity 实现“偏好设置”屏幕，而另一个 Activity 实现“选择照片”屏幕。

大多数应用包含多个屏幕，这意味着它们包含多个 Activity。通常，应用中的一个 Activity 会被指定为主 Activity，这是用户启动应用时出现的第一个屏幕。然后，每个 Activity 可以启动另一个 Activity，以执行不同的操作。例如，一个简单的电子邮件应用中的主 Activity 可能会提供显示电子邮件收件箱的屏幕。主 Activity 可能会从该屏幕启动其他 Activity，以提供执行写邮件和打开邮件这类任务的屏幕。

虽然应用中的各个 Activity 协同工作形成统一的用户体验，但每个 Activity 与其他 Activity 之间只存在松散的关联，应用内不同 Activity 之间的依赖关系通常很小。事实上，Activity 经常会启动属于其他应用的 Activity。例如，浏览器应用可能会启动社交媒体应用的“分享”Activity。

# 配置清单

### 声明Activity

要声明 Activity，请打开清单文件，并添加 <activity> 元素作为 <application> 元素的子元素

此元素唯一的必要属性是 android:name，该属性用于指定 Activity 的类名称。您也可以添加用于定义标签、图标或界面主题等 Activity 特征的属性。

### 声明intent过滤器

Intent 过滤器是 Android 平台的一项非常强大的功能。借助这项功能，您不但可以根据显式请求启动 Activity，还可以根据隐式请求启动 Activity。例如，显式请求可能会告诉系统“在 Gmail 应用中启动‘发送电子邮件’Activity”，而隐式请求可能会告诉系统“在任何能够完成此工作的 Activity 中启动‘发送电子邮件’屏幕”。当系统界面询问用户使用哪个应用来执行任务时，这就是 intent 过滤器在起作用。

要使用此功能，您需要在 <activity> 元素中声明 <intent-filter> 属性。此元素的定义包括 <action> 元素，以及可选的 <category> 元素和/或 <data> 元素。这些元素组合在一起，可以指定 Activity 能够响应的 intent 类型。

### 声明权限

您可以使用清单的 <activity> 标记来控制哪些应用可以启动某个 Activity。父 Activity 和子 Activity 必须在其清单中具有相同的权限，前者才能启动后者。如果您为父 Activity 声明了 <uses-permission> 元素，则每个子 Activity 都必须具有匹配的 <uses-permission>元素。

# 管理Activity生命周期

### OnCreate()

您必须实现此回调，它会在系统创建您的 Activity 时触发。您的实现应该初始化 Activity 的基本组件：例如，您的应用应该在此处创建视图并将数据绑定到列表。最重要的是，您必须在此处调用 setContentView() 来定义 Activity 界面的布局。

onCreate() 完成后，下一个回调将是 onStart()。

### OnStart()

onCreate() 退出后，Activity 将进入“已启动”状态，并对用户可见。此回调包含 Activity 进入前台与用户进行互动之前的最后准备工作。

### OnResume()

系统会在 Activity 开始与用户互动之前调用此回调。此时，该 Activity 位于 Activity 堆栈的顶部，并会捕获所有用户输入。应用的大部分核心功能都是在 onResume() 方法中实现的。

onResume() 回调后面总是跟着 onPause() 回调。

### OnPause()

当 Activity 失去焦点并进入“已暂停”状态时，系统就会调用 onPause()。例如，当用户点按“返回”或“最近使用的应用”按钮时，就会出现此状态。当系统为您的 Activity 调用 onPause() 时，从技术上来说，这意味着您的 Activity 仍然部分可见，但大多数情况下，这表明用户正在离开该 Activity，该 Activity 很快将进入“已停止”或“已恢复”状态。

如果用户希望界面继续更新，则处于“已暂停”状态的 Activity 也可以继续更新界面。例如，显示导航地图屏幕或播放媒体播放器的 Activity 就属于此类 Activity。即使此类 Activity 失去了焦点，用户仍希望其界面继续更新。

您不应使用 onPause() 来保存应用或用户数据、进行网络呼叫或执行数据库事务。有关保存数据的信息，请参阅保存和恢复 Activity 状态。

onPause() 执行完毕后，下一个回调为 onStop()或 onResume()，具体取决于 Activity 进入“已暂停”状态后发生的情况。

### OnStop()

当 Activity 对用户不再可见时，系统会调用 onStop()。出现这种情况的原因可能是 Activity 被销毁，新的 Activity 启动，或者现有的 Activity 正在进入“已恢复”状态并覆盖了已停止的 Activity。在所有这些情况下，停止的 Activity 都将完全不再可见。

系统调用的下一个回调将是 onRestart()（如果 Activity 重新与用户互动）或者 onDestroy()（如果 Activity 彻底终止）。

### OnRestart()

当处于“已停止”状态的 Activity 即将重启时，系统就会调用此回调。onRestart() 会从 Activity 停止时的状态恢复 Activity。

此回调后面总是跟着 onStart()。

### OnDestroy()

此回调是 Activity 接收的最后一个回调。通常，实现 onDestroy() 是为了确保在销毁 Activity 或包含该 Activity 的进程时释放该 Activity 的所有资源。