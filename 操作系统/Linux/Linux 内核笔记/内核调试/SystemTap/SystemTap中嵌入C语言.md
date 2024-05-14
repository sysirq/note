eg:

```stap
function getprocname:string(task:long)
%{
    struct task_struct *task = (struct task_struct *)STAP_ARG_task;
    snprintf(STAP_RETVALUE, MAXSTRINGLEN, "pid: %d, comm: %s", task->pid, task->comm);
%}

function getprocid:long(task:long)
%{
    struct task_struct *task = (struct task_struct *)STAP_ARG_task;
    STAP_RETURN(task->pid);
%}

probe kernel.function("copy_process").return
{
    printf("copy_process return: %p, pid: %d, getprocname: %s, getprocid: %d\n", $return, $return->pid, getprocname($return), getprocid($return));
}
```

- SystemTap脚本里面嵌入C语言代码需要在每个大括号前面加%号。（猜测应该与yacc和lex有关）

- 获取脚本参数要用STAP_ARG_前缀

- 一般long等返回值用STAP_RETURN，而string类型返回值要用snprintf、strncat等方式把字符串复制到STAP_RETVALUE里面

- 内嵌C语言模式需要-g选项

- SystemTap函数和probe都是在关闭中断下执行，所以在所有嵌入的C代码中不能睡眠