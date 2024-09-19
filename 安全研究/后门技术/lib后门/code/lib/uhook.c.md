```c
/*
* only support x86_64
*/

#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include "debug.h"
#include "uhook.h"
#include "insn.h"


static uhook_t* uhooks = NULL;
static unsigned long uhooks_max_count =  1024;

/*
_start:
	mov rax,0x7f7f7f7f7f7f7f7f
	jmp rax
	jmp 0x7f7f

objdump -d 

*0000000000000000 <_start>:
   0:	48 b8 7f 7f 7f 7f 7f 	movabs $0x7f7f7f7f7f7f7f7f,%rax
   7:	7f 7f 7f 
   a:	ff e0                	jmpq   *%rax
*/
static char trampoline_code[] = {0x48,0xb8,0x7f,0x7f,0x7f,0x7f,0x7f,0x7f,0x7f,0x7f,0xff,0xe0};

static inline int uhook_get_insn_length(void *p)
{
    struct insn insn;
    int is_x86_64 = 1;

    insn_init(&insn,p,15,is_x86_64);

    insn_get_length(&insn);

    return insn.length;
}

static inline int change_mm_protect_to_rwx(unsigned long addr,int len)
{
    size_t page_size = sysconf(_SC_PAGESIZE);
    unsigned long first_page  = addr & (~((unsigned long) (page_size-1)));
    unsigned long second_page = (addr+len) & (~((unsigned long)(page_size-1)));

    if(first_page == second_page){
        mprotect((void*)(first_page), page_size, PROT_READ|PROT_WRITE|PROT_EXEC);
    }else{
        mprotect((void*)(first_page), page_size, PROT_READ|PROT_WRITE|PROT_EXEC);
        mprotect((void*)(second_page), page_size, PROT_READ|PROT_WRITE|PROT_EXEC);
    }
}

static inline int change_mm_protect_to_rx(unsigned long addr,int len)
{
    size_t page_size = sysconf(_SC_PAGESIZE);
    unsigned long first_page  = addr & (~((unsigned long) (page_size-1)));
    unsigned long second_page = (addr+len) & (~((unsigned long)(page_size-1)));

    if(first_page == second_page){
        mprotect((void*)(first_page), page_size, PROT_READ|PROT_EXEC);
    }else{
        mprotect((void*)(first_page), page_size, PROT_READ|PROT_EXEC);
        mprotect((void*)(second_page), page_size, PROT_READ|PROT_EXEC);
    }
}

uhook_t *find_uhook(char *func_name)
{
    int i = 0;
    uhook_t *hook = NULL;
    for(i = 0;i<uhooks_max_count;i++){
        if( (uhooks[i].is_used == 1) && strcmp(func_name,uhooks[i].name) == 0){
            hook = uhooks+i;
            break;
        }
    }

    return hook;
}

int temp_close_hook(uhook_t *hook)
{
    change_mm_protect_to_rwx((unsigned long)hook->func_addr,hook->nbytes);
    
    memcpy((void*)hook->func_addr,hook->func_code,hook->nbytes);

    change_mm_protect_to_rx((unsigned long)hook->func_addr,hook->nbytes);
}

int enable_temp_close_hook(uhook_t *hook)
{
    change_mm_protect_to_rwx((unsigned long)hook->func_addr,hook->nbytes);
    
    memcpy((void*)hook->func_addr,hook->trampoline_code,hook->nbytes);

    change_mm_protect_to_rx((unsigned long)hook->func_addr,hook->nbytes);
}

int close_hook(uhook_t *hook)
{
    change_mm_protect_to_rwx((unsigned long)hook->func_addr,hook->nbytes);
    
    memcpy((void*)hook->func_addr,hook->func_code,hook->nbytes);

    change_mm_protect_to_rx((unsigned long)hook->func_addr,hook->nbytes);

    hook->is_used = 0;
}

int uhook(char *func_name,unsigned long func_start_addr,unsigned long func_end_addr,void *handle_addr)
{
    uhook_t *hook = NULL;
    unsigned long *temp;

    int i = 0;
    if(func_start_addr == 0){
        DLX(0,printf("%s start addr error",func_name));
        return -1;
    }

    if(func_end_addr == 0){
        DLX(0,printf("%s end addr error",func_name));
        return -1;
    }

    for(i = 0;i<uhooks_max_count;i++){
        if(uhooks[i].is_used == 0){
            hook = uhooks+i;
            break;
        }
    }

    if(hook == NULL){
        DLX(0,printf("not found usable uhook for function: %s\n",func_name));
        return -1;
    }

    
    hook->nbytes = 0;
    while(hook->nbytes < sizeof(trampoline_code)){
        hook->nbytes += uhook_get_insn_length((void*)(func_start_addr + hook->nbytes));
    }
    
    DLX(0,printf("\thook->nbytes: %d\n",hook->nbytes));

    if(hook->nbytes + func_start_addr >= func_end_addr){
        DLX(0,printf("\tno space to place trampoline_code in %s function\n",func_name));
        return -1;
    }

    //save orignal code
    memcpy(hook->func_code,(void*)func_start_addr,hook->nbytes);

    //fix hook function addr
    change_mm_protect_to_rwx(func_start_addr,hook->nbytes);
    memcpy((void*)func_start_addr,trampoline_code,sizeof(trampoline_code));
    temp = (unsigned long*)(func_start_addr  + 2);
    *temp = (unsigned long)handle_addr;
    change_mm_protect_to_rx(func_start_addr,hook->nbytes);
    
    //save trampoline code
    memcpy(hook->trampoline_code,(void*)func_start_addr,hook->nbytes);


    hook->name = func_name;
    hook->handler_addr = handle_addr;
    hook->func_addr = (void*)func_start_addr;
    hook->is_used = 1;
    return 0;
}

int uhook_init()
{

    uhooks = mmap(NULL, sizeof(uhook_t) * uhooks_max_count, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (uhooks == MAP_FAILED) {
        DLX(0,perror("mmap failed"));
        return -1;
    }
    memset(uhooks,0,sizeof(uhook_t) * uhooks_max_count);
    return 0;
}

void hook_exit()
{
    uhook_t *hook;
    int i = 0;
    for(i = 0;i<uhooks_max_count;i++){
        if(uhooks[i].is_used == 1){
            hook = uhooks+i;
            close_hook(hook);
        }
    }
    munmap(uhooks, sizeof(uhook_t) * uhooks_max_count);
}
```