# 使用CreateRemoteThread函数对运行中的进程注入dll

从根本上说，dll注入技术要求目标进程中的一个线程调用LoadLibrary函数来载入我们想要注入的 dll。

```c
HANDLE WINAPI CreateRemoteThread(
  _In_  HANDLE                 hProcess,
  _In_  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
  _In_  SIZE_T                 dwStackSize,
  _In_  LPTHREAD_START_ROUTINE lpStartAddress,
  _In_  LPVOID                 lpParameter,
  _In_  DWORD                  dwCreationFlags,
  _Out_ LPDWORD                lpThreadId
);
```

### 流程

- (1).用VirtualAllocEx函数在目标进程的地址空间中分配一块足够大的内存用于保存被注入的dll的路径。
- (2).用WriteProcessMemory函数把本进程中保存dll路径的内存中的数据拷贝到第(1)步得到的目标进程的内存中。
- (3).用GetProcAddress函数获得LoadLibraryW函数的起始地址。LoadLibraryW函数位于Kernel32.dll中。
- (4).用CreateRemoteThread函数让目标进程执行LoadLibraryW来加载被注入的dll。函数结束将返回载入dll后的模块句柄。
- (5).用VirtualFreeEx释放第(1)步开辟的内存。

在需要卸载dll时我们可以在上述第(5)步的基础上继续执行以下步骤:

- 用GetProcAddress函数获得FreeLibrary函数的起始地址。FreeLibrary函数位于Kernel32.dll中。
- 用CreateRemoteThread函数让目标进程执行FreeLibrary来卸载被注入的dll。(其参数是第(4)步返回的模块句柄)。

```c
#include "windows.h"
#include "stdio.h"
#include "tlhelp32.h"
#include "io.h"
#include "tchar.h"

//判断某模块(dll)是否在相应的进程中
//dwPID         进程的PID
//szDllPath     查询的dll的完整路径
BOOL CheckDllInProcess(DWORD dwPID, LPCTSTR szDllPath)
{
    BOOL                    bMore = FALSE;
    HANDLE                  hSnapshot = INVALID_HANDLE_VALUE;
    MODULEENTRY32           me = { sizeof(me), };

    if (INVALID_HANDLE_VALUE ==
        (hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID)))//获得进程的快照
    {
        _tprintf(L"CheckDllInProcess() : CreateToolhelp32Snapshot(%d) failed!!! [%d]\n",
            dwPID, GetLastError());
        return FALSE;
    }
    bMore = Module32First(hSnapshot, &me);//遍历进程内得的所有模块
    for (; bMore; bMore = Module32Next(hSnapshot, &me))
    {
        if (!_tcsicmp(me.szModule, szDllPath) || !_tcsicmp(me.szExePath, szDllPath))//模块名或含路径的名相符
        {
            CloseHandle(hSnapshot);
            return TRUE;
        }
    }
    CloseHandle(hSnapshot);
    return FALSE;
}

//向指定的进程注入相应的模块
//dwPID         目标进程的PID
//szDllPath     被注入的dll的完整路径
BOOL InjectDll(DWORD dwPID, LPCTSTR szDllPath)
{
    HANDLE                  hProcess = NULL;//保存目标进程的句柄
    LPVOID                  pRemoteBuf = NULL;//目标进程开辟的内存的起始地址
    DWORD                   dwBufSize = (DWORD)(_tcslen(szDllPath) + 1) * sizeof(TCHAR);//开辟的内存的大小
    LPTHREAD_START_ROUTINE  pThreadProc = NULL;//loadLibreayW函数的起始地址
    HMODULE                 hMod = NULL;//kernel32.dll模块的句柄
    BOOL                    bRet = FALSE;
    if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)))//打开目标进程，获得句柄
    {
        _tprintf(L"InjectDll() : OpenProcess(%d) failed!!! [%d]\n",
            dwPID, GetLastError());
        goto INJECTDLL_EXIT;
    }
    pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize,
        MEM_COMMIT, PAGE_READWRITE);//在目标进程空间开辟一块内存
    if (pRemoteBuf == NULL)
    {
        _tprintf(L"InjectDll() : VirtualAllocEx() failed!!! [%d]\n",
            GetLastError());
        goto INJECTDLL_EXIT;
    }
    if (!WriteProcessMemory(hProcess, pRemoteBuf,
        (LPVOID)szDllPath, dwBufSize, NULL))//向开辟的内存复制dll的路径
    {
        _tprintf(L"InjectDll() : WriteProcessMemory() failed!!! [%d]\n",
            GetLastError());
        goto INJECTDLL_EXIT;
    }
    hMod = GetModuleHandle(L"kernel32.dll");//获得本进程kernel32.dll的模块句柄
    if (hMod == NULL)
    {
        _tprintf(L"InjectDll() : GetModuleHandle(\"kernel32.dll\") failed!!! [%d]\n",
            GetLastError());
        goto INJECTDLL_EXIT;
    }
    pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryW");//获得LoadLibraryW函数的起始地址
    if (pThreadProc == NULL)
    {
        _tprintf(L"InjectDll() : GetProcAddress(\"LoadLibraryW\") failed!!! [%d]\n",
            GetLastError());
        goto INJECTDLL_EXIT;
    }
    if (!CreateRemoteThread(hProcess, NULL, 0, pThreadProc, pRemoteBuf, 0, NULL))//执行远程线程
    {
        _tprintf(L"InjectDll() : MyCreateRemoteThread() failed!!!\n");
        goto INJECTDLL_EXIT;
    }
INJECTDLL_EXIT:
    bRet = CheckDllInProcess(dwPID, szDllPath);//确认结果
    if (pRemoteBuf)
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);
    if (hProcess)
        CloseHandle(hProcess);
    return bRet;
}

//让指定的进程卸载相应的模块
//dwPID         目标进程的PID
//szDllPath     被注入的dll的完整路径,注意：路径不要用“/”来代替“\\”
BOOL EjectDll(DWORD dwPID, LPCTSTR szDllPath)
{
    BOOL                    bMore = FALSE, bFound = FALSE, bRet = FALSE;
    HANDLE                  hSnapshot = INVALID_HANDLE_VALUE;
    HANDLE                  hProcess = NULL;
    MODULEENTRY32           me = { sizeof(me), };
    LPTHREAD_START_ROUTINE  pThreadProc = NULL;
    HMODULE                 hMod = NULL;
    TCHAR                   szProcName[MAX_PATH] = { 0, };
    if (INVALID_HANDLE_VALUE == (hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID)))
    {
        _tprintf(L"EjectDll() : CreateToolhelp32Snapshot(%d) failed!!! [%d]\n",
            dwPID, GetLastError());
        goto EJECTDLL_EXIT;
    }
    bMore = Module32First(hSnapshot, &me);
    for (; bMore; bMore = Module32Next(hSnapshot, &me))//查找模块句柄
    {
        if (!_tcsicmp(me.szModule, szDllPath) ||
            !_tcsicmp(me.szExePath, szDllPath))
        {
            bFound = TRUE;
            break;
        }
    }
    if (!bFound)
    {
        _tprintf(L"EjectDll() : There is not %s module in process(%d) memory!!!\n",
            szDllPath, dwPID);
        goto EJECTDLL_EXIT;
    }
    if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)))
    {
        _tprintf(L"EjectDll() : OpenProcess(%d) failed!!! [%d]\n",
            dwPID, GetLastError());
        goto EJECTDLL_EXIT;
    }
    hMod = GetModuleHandle(L"kernel32.dll");
    if (hMod == NULL)
    {
        _tprintf(L"EjectDll() : GetModuleHandle(\"kernel32.dll\") failed!!! [%d]\n",
            GetLastError());
        goto EJECTDLL_EXIT;
    }
    pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "FreeLibrary");
    if (pThreadProc == NULL)
    {
        _tprintf(L"EjectDll() : GetProcAddress(\"FreeLibrary\") failed!!! [%d]\n",
            GetLastError());
        goto EJECTDLL_EXIT;
    }
    if (!CreateRemoteThread(hProcess, NULL, 0, pThreadProc, me.modBaseAddr, 0, NULL))
    {
        _tprintf(L"EjectDll() : MyCreateRemoteThread() failed!!!\n");
        goto EJECTDLL_EXIT;
    }
    bRet = TRUE;
EJECTDLL_EXIT:
    if (hProcess)
        CloseHandle(hProcess);
    if (hSnapshot != INVALID_HANDLE_VALUE)
        CloseHandle(hSnapshot);
    return bRet;
}

int main()
{
    //InjectDll(6836, L"C:\\a.dll");
    //EjectDll(6836, L"C:\\a.dll");
    return 0;
}
```

# 用CreateProcess对子进程注入dll

- 1.保存所有寄存器的值；
- 2.将dll路径首地址压栈；
- 3.调用LoadLibrary函数；
- 4.恢复所有寄存器的值；
- 5.跳转到原先EIP位置，让程序继续执行，好像什么都没发生。

```c
#include <windows.h>
#include <stdio.h>
#pragma warning(disable : 4996) 

//在子进程创建挂起时注入dll
//hProcess      被创建时挂起的进程句柄
//hThread       进程中被挂起的线程句柄
//szDllPath     被注入的dll的完整路径
BOOL StartHook(HANDLE hProcess, HANDLE hThread, TCHAR* szDllPath)
{
    BYTE ShellCode[30 + MAX_PATH * sizeof(TCHAR)] =
    {
        0x60,               //pushad
        0x9c,               //pushfd
        0x68,0xaa,0xbb,0xcc,0xdd,   //push xxxxxxxx(xxxxxxxx的偏移为3)
        0xff,0x15,0xdd,0xcc,0xbb,0xaa,  //call [addr]([addr]的偏移为9)
        0x9d,               //popfd
        0x61,               //popad
        0xff,0x25,0xaa,0xbb,0xcc,0xdd,  //jmp [eip]([eip]的偏移为17)
        0xaa,0xaa,0xaa,0xaa,        //保存loadlibraryW函数的地址(偏移为21)
        0xaa,0xaa,0xaa,0xaa,        //保存创建进程时被挂起的线程EIP(偏移为25)
        0,              //保存dll路径字符串(偏移为29)
    };
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_ALL;
    if (!GetThreadContext(hThread, &ctx))
    {
        printf("GetThreadContext() ErrorCode:[0x%08x]\n", GetLastError());
        return FALSE;
    }
    //在目标进程内存空间调拨一块可执行的内存
    LPVOID LpAddr = VirtualAllocEx(hProcess, NULL, 30 + MAX_PATH * sizeof(TCHAR), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (LpAddr == NULL)
    {
        printf("VirtualAllocEx() ErrorCode:[0x%08x]\n", GetLastError());
        return FALSE;
    }
    //获得LoadLibraryW函数的地址
    DWORD LoadDllAAddr = (DWORD)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
    if (LoadDllAAddr == NULL)
    {
        printf("GetProcAddress() ErrorCode:[0x%08x]\n", GetLastError());
        return FALSE;
    }
    printf("原始EIP=0x%08x\n", ctx.Eip);
    //写入dllpath
    memcpy((char*)(ShellCode + 29), szDllPath, MAX_PATH);
    //写入push xxxxxxxx
    *(DWORD*)(ShellCode + 3) = (DWORD)LpAddr + 29;
    //写入loadlibraryA地址
    *(DWORD*)(ShellCode + 21) = LoadDllAAddr;
    //写入call [addr]的[addr]
    *(DWORD*)(ShellCode + 9) = (DWORD)LpAddr + 21;
    //写入原始eip
    *(DWORD*)(ShellCode + 25) = ctx.Eip;
    //写入jmp [eip]的[eip]
    *(DWORD*)(ShellCode + 17) = (DWORD)LpAddr + 25;
    //把shellcode写入目标进程
    if (!WriteProcessMemory(hProcess, LpAddr, ShellCode, 30 + MAX_PATH * sizeof(TCHAR), NULL))
    {
        printf("WriteProcessMemory() ErrorCode:[0x%08x]\n", GetLastError());
        return FALSE;
    }
    //修改目标进程的EIP，执行被注入的代码
    ctx.Eip = (DWORD)LpAddr;
    if (!SetThreadContext(hThread, &ctx))
    {
        printf("SetThreadContext() ErrorCode:[0x%08x]\n", GetLastError());
        return FALSE;
    }
    printf("修改后EIP=0x%08x\n", ctx.Eip);
    return TRUE;
};

int main()
{
    STARTUPINFO sti;
    PROCESS_INFORMATION proci;
    memset(&sti, 0, sizeof(STARTUPINFO));
    memset(&proci, 0, sizeof(PROCESS_INFORMATION));
    sti.cb = sizeof(STARTUPINFO);
    wchar_t ExeName[MAX_PATH] = L"C:\\aimprocess.exe";//子进程的名字及启动参数
    wchar_t DllName[MAX_PATH] = L"C:\\hookdll2.dll";//被注入的dll的完整路径
    if (CreateProcess(NULL, ExeName, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &sti, &proci) == NULL)
    {
        printf("CreateProcess() ErrorCode:[0x%08x]\n", GetLastError());
        getchar();
        return 0;
    }
    if (!StartHook(proci.hProcess, proci.hThread, DllName))
    {
        TerminateProcess(proci.hProcess, 0);
        printf("Terminated Process\n");
        getchar();
        return 0;
    }
    ResumeThread(proci.hThread);
    CloseHandle(proci.hProcess);
    CloseHandle(proci.hThread);
    return 0;
}
```

# 资料

Windows系统的dll注入

https://www.cnblogs.com/wf751620780/p/10730013.html

Dllmain的作用

https://www.cnblogs.com/xiangtingshen/p/11465002.html