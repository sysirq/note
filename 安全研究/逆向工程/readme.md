# 插件

### keypatch

- 进入IDA python 文件 eg: D:\Program Files (x86)\IDA_Pro_v8.3_Portable\python311
- 执行命令：./python.exe -m pip install keystone-engine
- 执行命令：./python.exe -m pip install six
- 拷贝 keypatch.py 到 IDA Plugin 文件，eg：D:\Program Files (x86)\IDA_Pro_v8.3_Portable\plugins

地址：https://github.com/keystone-engine/keypatch

### mips 反汇编插件 -- retdec

- 复制plugin中的两个dll到DA所在目录的plugins下去
- 为设置retdec_decompiler.py地址，IDA --》Options --〉RetDec Plugin Settings（需要下载地址1中的东西）

地址：
- https://github.com/avast/retdec
- https://github.com/avast/retdec-idaplugin

# 资料

跟羽夏学 Ghidra

https://www.cnblogs.com/wingsummer/p/16678277.html

NSA开源逆向工具Ghidra入门使用教程

https://www.secrss.com/articles/8829