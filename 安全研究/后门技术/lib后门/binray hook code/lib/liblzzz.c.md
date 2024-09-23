```c
#include <stdio.h>
#include <stdlib.h>
#include "just4fun.h"

void __attribute__((constructor)) ___init___() 
{
    init_function();
}

int print_self_maps(void)
{
    return 0;
    char line[256];
    FILE *fp = fopen("/proc/self/maps", "r");
    if (fp == NULL) {
        perror("fopen");
        return -1;
    }
        
    while (fgets(line, sizeof(line), fp) != NULL) {
        printf("%s", line);
    }

    fclose(fp);

    return 0;
}

void hello() {
    printf("Hello, Dynamic Library!\n");
}

```