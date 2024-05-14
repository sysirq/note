# VCS 产生Verdi波形

波形文件格式为.fsdb

vcs 需要加 -fsdb选项编译

编译后运行，然后得到波形文件

### tb中加入相应的系统函数

```verilog
initial begin
    $fsdbDumpfile("fifo.fsdb");
    $fsdbFumpvars(0);
end
```

# 资料

Verdi 基础教程

https://blog.csdn.net/qq_21842097/article/details/116144372