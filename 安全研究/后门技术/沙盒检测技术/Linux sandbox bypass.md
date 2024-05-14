```c
#include <sys/sysinfo.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <x86intrin.h>
#include <unistd.h>
#include "debug.h"


static uint64_t rdtsc() 
{
    __asm__ __volatile__("":::"memory");
    uint64_t r = __rdtsc();
    __asm__ __volatile__("":::"memory");
    return r;
}


//
static uint64_t get_system_uptime_minutes(void)
{
    struct sysinfo info;

    if (sysinfo(&info) != 0) {
        DLX(0,printf("\tsysinfo call error:%s\n",strerror(errno))); 
        return 1;
    }

    // 获取系统启动时间（以秒为单位）
    uint64_t uptime = info.uptime;

    uint64_t minutes = uptime / 60;

    return minutes;
}

//MHz , 
static uint64_t get_cpu_frequency()
{
    FILE *fp;
    char line[4096];
    float cpu_freq = 0.0;

    fp = fopen("/proc/cpuinfo", "r");
    if (fp == NULL) {
        perror("Error opening /proc/cpuinfo");
        return 1;
    }

    while (fgets(line, 4096, fp) != NULL) {
        if (strstr(line, "cpu MHz") != NULL) {
            sscanf(line, "cpu MHz : %f", &cpu_freq);
        }
    }

    fclose(fp);

    // 输出 CPU 频率
    if (cpu_freq > 0.0) {
        return cpu_freq;
    } else {
        return 0;
    }
}

//0 for true
static int is_time_accelerate()
{
    int time_to_sleep = 60;

    uint64_t cpu_frequency = get_cpu_frequency();
    if (cpu_frequency != 0){

        uint64_t start_tsc = rdtsc();
        sleep(time_to_sleep);
        uint64_t stop_tsc = rdtsc();

        uint64_t real_run_time = (stop_tsc - start_tsc)/(cpu_frequency*1E6);

        if(real_run_time + 10 < time_to_sleep){
            return 0;
        }
    }

    return -1;
}

//return 0 for true
int is_in_sandbox(void)
{
    if(get_system_uptime_minutes() < 30){ //system start time
        DLX(0,printf("\tSystem uptime < 30\n")); 
        return 0;
    }
    
    if(is_time_accelerate() == 0){
        DLX(0,printf("\tChecked time accelerate\n")); 
        return 0;
    }
    
    return -1;
}
```