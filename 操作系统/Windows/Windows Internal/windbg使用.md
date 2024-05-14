# windbg 基本命令

`.help`：显示WinDbg命令的帮助信息。

`.cls`：清除WinDbg窗口中的内容。

`.reload`：重新加载符号文件。这在调试期间经常需要，特别是在加载新模块时。

`.symfix`：设置符号文件路径。这允许WinDbg在调试时自动查找并加载符号文件。

`.sympath`：显示或设置符号文件路径。使用这个命令可以查看或修改符号文件的搜索路径。

`.load`：加载调试扩展。这允许您加载自定义的调试扩展，以扩展WinDbg的功能。

`.unload`：卸载调试扩展。

`.chain`：显示已加载的调试扩展。

`.lm`：列出加载的模块。这将显示所有已加载的模块及其基址、大小、符号状态等信息。

`.reload /f`：强制重新加载符号文件。有时候符号文件可能已经加载但不正确，使用此命令可以强制重新加载。

`.ecxr`：显示当前异常上下文记录（Exception Context Record）。

`.exr`：显示当前异常记录（Exception Record）。

`.thread`：显示或更改当前线程上下文。

`.process`：显示或更改当前进程上下文。

`.bp`：设置断点。

`.bl`：列出断点。

`.bc`：清除断点。

`.g`：继续执行程序（继续执行）。

`.k`：显示调用堆栈。

`.lmf`：列出模块的基本信息及文件版本。

# 扩展命令

`!analyze`：自动分析当前的崩溃或异常情况，并提供关于问题的详细信息和建议。

`!threads`：显示当前进程中所有线程的信息，包括线程ID、当前指令指针和堆栈信息。

`!process`：显示或更改当前进程的信息，如进程ID、父进程ID、进程启动时间等。

`!peb`：显示当前进程环境块（PEB）的信息，包括进程参数、模块列表等。

`!teb`：显示特定线程环境块（TEB）的信息，包括线程ID、堆栈基址等。

`!handle`：显示当前进程的句柄信息，包括句柄值、类型、对象等。

`!heap`：显示当前进程的堆信息，包括堆的大小、空闲块、已分配的内存等。

`!pool`：显示内核内存池的信息，包括已分配和空闲的内存块。

`!locks`：显示当前进程中的锁定信息，包括临界区、互斥体等。

`!drivers`：显示已加载的驱动程序信息，包括驱动名称、基址、大小等。

`!sos`：用于与.NET应用程序的调试。它提供了一系列与.NET相关的命令，如查看.NET堆栈、对象、线程等。

`!clrstack`：显示托管代码的堆栈信息。

`!dumpheap`：以各种方式显示.NET堆上的对象。

`!dumpobj`：显示.NET对象的详细信息。

`!ready`: “This command displays the thread or list of threads that are ready to run at each priority level.”

`!pcr`:PCR is short for processor control region.!pcr takes a single numeric argument, which is the number of the CPU whose PCR is to be displayed.

`!vm`:The !vm extension displays summary information about virtual memory use statistics on the target system

`!poolused`:The !poolused extension displays memory use summaries, based on the tag used for each pool allocation.

`!lookaside`:The !lookaside extension displays information about look-aside lists, resets the counters of look-aside lists, or modifies the depth of a look-aside list.

`!heap`:The !heap extension displays heap usage information, controls breakpoints in the heap manager, detects leaked heap blocks, searches for heap blocks, or displays page heap information.

`!dp`: This is similar to the dq command , but lets us examine memory by physical rather than virtual address.
