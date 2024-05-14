```c
BOOL CreateProcess(
    PCTSTR pszApplicationName,
    PTSTR pszCommandLine,
    PSECURITY_ATTRIBUTES psaProcess,
    PSECURITY_ATTRIBUTES psaThread,
    BOOL bInheritHandles,
    DWORD fdwCreate,
    PVOID pvEnvironment,
    PCTSTR pszCurDir,
    PSTARTUPINFO psiStartInfo,
    PPROCESS_INFORMATION ppiProcInfo
);
```

当一个线程调用CreateProcess时，系统就会创建一个进程内核对象，其初始使用计数是1。该进程内核对象不是进程本身，而是操作系统管理进程时使用的一个较小的数据结构。然后，系统为新进程创建一个虚拟地址空间，并将可执行文件或任何必要的DLL文件的代码和数据加载到该进程的地址空间中。然后，系统为新进程的主线程创建一个线程内核对象。

# pszApplicationName和pszCommandLine

程序路径和命令行

# psaProcess、psaThread 和 binheritHandles

若要创建一个新进程，系统必须创建一个进程内核对象和一个线程内核对象。可以使用psaProcess和psaThread 参数分别设定进程对象和线程对象需要的安全性

# fdwCreate

决定新进程如何被创建。

CREATE_SUSPENDED

# pvEnviroment

指向包含新进程将要使用的环境字符串。可设置为NULL。

# pszCurDir

设置子进程的当前驱动器和目录。可设置为NULL

# psiStartInfo 用于指向一个STARTUPINFO结构

```c
STARTUPINFO si = {sizeof(si)};

CreateProcess(...,&si,...);
```

# ppiProcInfo


```c
typedef struct __PROCESS_INFORMATION {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD dwProcessId;
    DWORD dwThreadId;
}PROCESS_INFORMATION;
```

CreateProcess在返回之前对该结构成员进行初始化。

```c
#include <stdio.h>
#include <Windows.h>
#include <winerror.h>

#pragma warning(disable: 4996)

int main(int argc, char* argv[])
{
	wchar_t szCommandLine[] = L"calc";
	STARTUPINFO si = { sizeof(si) };
	PROCESS_INFORMATION pi;
	si.dwFlags = STARTF_USESHOWWINDOW; //制定wShowWindow成员
	si.wShowWindow = TRUE; //为真，显示进程的主窗口
	BOOL bRet = ::CreateProcess(
		NULL,//不在此指定可执行文件的文件名
		szCommandLine, //命令行参数
		NULL,//默认进程的安全性
		NULL,//默认线程的安全性
		FALSE,//指定当前进程内的句柄不可以被子进程继承
		CREATE_NEW_CONSOLE,//为新进程创建一个新的控制台窗口
		NULL,//使用本进程的环境变量
		NULL,//使用本进程的驱动器和目录
		&si,
		&pi);
	if (bRet)
	{
		//既然我们不使用两个句柄，最好是立刻将他们关闭
		::CloseHandle(pi.hThread);
		::CloseHandle(pi.hProcess);
		printf("新的进程的进程ID号：%d\n", pi.dwProcessId);
		printf("新进程的主线程ID号：%d\n", pi.dwThreadId);
	}
	return 0;
}
```