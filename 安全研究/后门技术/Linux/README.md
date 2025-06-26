# 双守护

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <signal.h>
#include <sys/wait.h>
#include <errno.h>
#include <string.h>

#define SHM_KEY 12345  
#define SHM_SIZE sizeof(pid_t) * 2  

int is_process_alive(pid_t pid) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d", pid);
    return access(path, F_OK) == 0; 
}

int resurrect_process(pid_t *pid, char *program_path, char *arg) {
    pid_t new_pid;

    new_pid = fork();
    if (new_pid == -1){
        return -1;
    }

    if(new_pid){//parent
        return new_pid;
    }

    new_pid = fork();
    if (new_pid == 0) {
        execlp(program_path, program_path, arg, (char *)NULL);
        perror("execlp failed");
        exit(1);
    } else if (new_pid > 0) {
        *pid = new_pid; 
        printf("Process with PID %d resurrected\n", new_pid);
        exit(0);
    } else {
        perror("fork failed");
        exit(-1);
    }
}

int main(int argc, char *argv[]) {
    key_t key = SHM_KEY;
    int shmid;
    pid_t *shm_ptr;

    shmid = shmget(key, SHM_SIZE, IPC_CREAT | 0666);
    if (shmid < 0) {
        perror("shmget failed");
        exit(1);
    }

    shm_ptr = (pid_t *)shmat(shmid, NULL, 0);
    if ((void *)shm_ptr == (void *)-1) {
        perror("shmat failed");
        exit(1);
    }

    if (argc == 2 && strcmp(argv[1], "start") == 0) {
        pid_t pid = getpid();
        shm_ptr[0] = pid; 
        printf("Process 1 started with PID: %d\n", pid);
    } else if (argc == 2 && strcmp(argv[1], "start2") == 0) {
        pid_t pid = getpid();
        shm_ptr[1] = pid;
        printf("Process 2 started with PID: %d\n", pid);
    } else {
        fprintf(stderr, "Usage: %s [start|start2]\n", argv[0]);
        exit(1);
    }

    while (1) {
        if (shm_ptr[0] != 0 && !is_process_alive(shm_ptr[0])) {
            printf("Process 1 has died. Resurrecting...\n");
            pid_t pid = resurrect_process(&shm_ptr[0], argv[0], "start");
            if(pid != -1){
                waitpid(pid, NULL, 0);
            }
        }

        if (shm_ptr[1] != 0 && !is_process_alive(shm_ptr[1])) {
            printf("Process 2 has died. Resurrecting...\n");
            pid_t pid = resurrect_process(&shm_ptr[1], argv[0], "start2");
            if(pid != -1){
                waitpid(pid, NULL, 0);
            }
        }

        sleep(1); 
    }

    shmdt(shm_ptr);

    return 0;
}
```

# 资料

双头龙(RotaJakiro)，一个至少潜伏了3年的后门木马

https://blog.netlab.360.com/stealth_rotajakiro_backdoor_cn/