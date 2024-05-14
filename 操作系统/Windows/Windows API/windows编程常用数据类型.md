Windows数据类型:

   

    WORD：16位无符号整形数据

　　DWORD：32位无符号整型数据（DWORD32）

　　DWORD64：64位无符号整型数据

　　INT：32位有符号整型数据类型

　　INT_PTR：指向INT数据类型的指针类型

　　INT32：32位符号整型

　　int64：64位符号整型

　　UINT：无符号INT

   

    PVOID:普通指针

　　LONG：32位符号整型（LONG32）

　　ULONG：无符号LONG

　　LONGLONG：64位符号整型（LONG64）

　　SHORT：无符号短整型（16位）

　　LPARAM：消息的L参数

　　WPARAM：消息的W参数

　　HANDLE：对象的句柄，最基本的句柄类型

　　HICON：图标的句柄

　　HINSTANCE：程序实例的句柄

　　HKEY：注册表键的句柄

　　HMODULE：模块的句柄

　　HWND：窗口的句柄

　　LPSTR：字符指针，也就是字符串变量

　　LPCSTR：字符串常量

　　LPCTSTR：根据环境配置，如果定义了UNICODE宏，则是LPCWSTR类型，否则则为LPCSTR类型

　　LPCWSTR：UNICODE字符串常量

　　LPDWORD：指向DWORD类型数据的指针

　　CHAR：8比特字节

　　TCHAR：如果定义了UNICODE，则为WCHAR，否则为CHAR

　　UCHAR：无符号CHAR

　　WCHAR：16位Unicode字符

　　BOOL：布尔型变量

　　BYTE：字节类型（8位）

　　CONST：常量

　　FLOAT：浮点数据类型

　　SIZE_T：表示内存大小，以字节为单位，其最大值是CPU最大寻址范围

　　VOID：无类型，相当于标准C语言中的void

 

 - Windows数据类型命名规律 　　

    基本数据类型包括：BYTE、CHAR、WORD、SHORT、INT等。

　　指针类型的命令方式一般是在其指向的数据类型前加“LP”或“P”，比如指向DWORD的指针类型为“LPDWORD”和“PDWORD”

　　各种句柄类型的命名方式一般都是在对象名前加“H”，比如位图（BITMAP）对应的句柄类型为“HBITMAP”。

　　无符号类型一般是以“U”开头，比如“INT”是符号类型，“UINT”是无符号类型

　　根据这些命名规律以及自己的经验看到一些没见过的数据类型也就能知道它的代表的意思

Windows数据类型 - Windows数据类型与标准C数据类型的关系 　　

  

    C数据类型经过类型重定义得到的。如DWORD实质上就是 unsigned long 数据类型，32位无符号整型。

    而经常要用到的HANDLE类型实质上是无类型指针void,HANDLE定义为：

　　typedof PVOID HANDLE;

　　HANDLE实际上就是一个PVOID，那PVOID又是什么呢？

　　Typeof void *PVOID;

　　PVOID就是指向void的指针。