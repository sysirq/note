```c
#include <stdio.h>

void please_hook_me(int a,int b)
{
    printf("please hook me: %d\n",a + b);
}

int print_self_maps(void);

int main(void)
{

    printf("main function addr:%p\n",main);
    printf("hook function addr:%p\n",please_hook_me);
    printf("func:%s\n",__func__);
    print_self_maps();
    please_hook_me(1,3);
    please_hook_me(3,4);
    please_hook_me(5,6);
    return 0;
}
```

