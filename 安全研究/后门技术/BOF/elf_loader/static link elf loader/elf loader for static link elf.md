```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <dlfcn.h>
#include "loader.h"

#define STACK_SIZE (1024*1024*32)

#ifdef DEBUG
int dbug_level_ = 2;
#endif

#define ARRAY_SIZE(a) (sizeof((a))/sizeof((a[0])))
#define PAGE_SIZE	0x1000
#define ALIGN		(PAGE_SIZE - 1)
#define ROUND_PG(x)	(((x) + (ALIGN)) & ~(ALIGN))
#define TRUNC_PG(x)	((x) & ~(ALIGN))
#define PFLAGS(x)	((((x) & PF_R) ? PROT_READ : 0) | \
			 (((x) & PF_W) ? PROT_WRITE : 0) | \
			 (((x) & PF_X) ? PROT_EXEC : 0))

static void* load_segments(char *elf_format_data,unsigned long *map_size,unsigned long *entry_addr)
{
    ELFInfo_t elfinfo;
    int counter = 0;
    int tempOffsetCounter = 0;
    int c2 = 0;
    unsigned long minva = (unsigned long)-1;
    unsigned long maxva = 0;
    unsigned long total_size = 0;
    unsigned long entry_offset = 0;
    char **argv = {NULL};
    unsigned long entry;
    void *base_addr = NULL;


    memset(&elfinfo,0,sizeof(elfinfo));
    elfinfo.Header = (Elf_Ehdr*)elf_format_data;

    // vertify that the data is an elf file
    if( elf_format_data[0] != '\x7f' || elf_format_data[1] != 'E' || elf_format_data[2] != 'L' || elf_format_data[3] != 'F' ){
        DLX(0,printf("\tnot an elf file\n"));
        goto cleanup;
    }
    DLX(0,printf("\tvalid elf file magic number\n"));

    if(elfinfo.Header->e_type != ET_DYN){ //ET_DYN
        DLX(0,printf("\tELF Type isn't Shared object file type\n"));
        goto cleanup;
    }
    //.so .elf(pie)
    DLX(0,printf("\tELF Object Data: %p\n", elf_format_data));
    DLX(0,printf("\tELF Type: %d\n", elfinfo.Header->e_type));
    DLX(0,printf("\tELF Machine: %d\n", elfinfo.Header->e_machine));
    DLX(0,printf("\tELF Version: %d\n", elfinfo.Header->e_version));
    DLX(0,printf("\tELF Entry: 0x%lx\n", elfinfo.Header->e_entry));
    DLX(0,printf("\tELF ProgramHeaderOffset: 0x%lx\n", elfinfo.Header->e_phoff));
    DLX(0,printf("\tELF SectionHeaderOffset: 0x%lx\n", elfinfo.Header->e_shoff));
    DLX(0,printf("\tELF Flags: 0x%x\n", elfinfo.Header->e_flags));
    DLX(0,printf("\tELF Header Size: %d\n", elfinfo.Header->e_ehsize));
    DLX(0,printf("\tELF Program Header Entry Size: %d\n", elfinfo.Header->e_phentsize));
    DLX(0,printf("\tELF Program Header Entry Count: %d\n", elfinfo.Header->e_phnum));
    DLX(0,printf("\tELF Section Header Entry Size: %d\n", elfinfo.Header->e_shentsize));
    DLX(0,printf("\tELF Section Header Entry Count: %d\n", elfinfo.Header->e_shnum));
    DLX(0,printf("\tELF Section Header Table Index Entry: %d\n", elfinfo.Header->e_shstrndx));

    /* Set all the headers and sizes */
    elfinfo.progHeader = (Elf_Phdr*)(elf_format_data + elfinfo.Header->e_phoff);
    elfinfo.sectHeader = (Elf_Shdr*)(elf_format_data + elfinfo.Header->e_shoff);
    elfinfo.progHeaderNum = elfinfo.Header->e_phnum;
    elfinfo.sectHeaderNum = elfinfo.Header->e_shnum;

    /* calc minva maxva */
    DLX(0,printf("\tWorking with program headers, Count: %d\n", elfinfo.progHeaderNum));
    for (counter = 0; counter < elfinfo.progHeaderNum; counter++){
        switch (elfinfo.progHeader[counter].p_type)
        {
        case PT_LOAD:
            if(minva > elfinfo.progHeader[counter].p_vaddr){
                minva = elfinfo.progHeader[counter].p_vaddr;
            }
            if(maxva  < (elfinfo.progHeader[counter].p_vaddr + elfinfo.progHeader[counter].p_memsz) ){
                maxva  = (elfinfo.progHeader[counter].p_vaddr + elfinfo.progHeader[counter].p_memsz);
            }
            break;
        default:
            break;
        }
    }

    minva = TRUNC_PG(minva);
    maxva = ROUND_PG(maxva);

    *map_size = total_size = maxva - minva;
    base_addr = mmap(NULL,total_size,PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memset(base_addr,0,total_size);//init .bss

    if(base_addr == NULL || base_addr ==MAP_FAILED){
        DLX(0,printf("\tmmap error\n"));
        goto cleanup;
    }

    entry_offset = elfinfo.Header->e_entry - minva;
    *entry_addr = entry = (unsigned long)(base_addr + entry_offset);

    DLX(0,printf("\tbase_addr: %p\n",  base_addr));
    DLX(0,printf("\tminva: 0x%lX\n",minva));
    DLX(0,printf("\tmaxva: 0x%lX\n",  maxva));
    DLX(0,printf("\ttotal_size: 0x%lX\n",  total_size));
    DLX(0,printf("\tentry_offset: 0x%lX\n",  entry_offset));
    DLX(0,printf("\tentry: 0x%lx\n",  entry));

    //mmap
    for (counter = 0; counter < elfinfo.progHeaderNum; counter++){
        switch (elfinfo.progHeader[counter].p_type)
        {
        case PT_LOAD:
            memcpy(base_addr+(elfinfo.progHeader[counter].p_vaddr - minva),elf_format_data+elfinfo.progHeader[counter].p_offset,elfinfo.progHeader[counter].p_filesz);
            break;
        }
    }

    return base_addr;
cleanup:
    if(base_addr != NULL && base_addr != MAP_FAILED){
        munmap(base_addr,total_size);
    }
    return NULL;
}

static void* init_stack(int exec_argc, char *exec_argv[], char **exec_environ,void *base_addr)
{
    ELFInfo_t elfinfo;
    void *stack = mmap(NULL,STACK_SIZE,PROT_READ | PROT_WRITE,MAP_PRIVATE | MAP_ANONYMOUS,-1,0);
    if(stack == NULL || stack == MAP_FAILED){
        return NULL;
    }

    memset(&elfinfo,0,sizeof(elfinfo));
    elfinfo.Header = (Elf_Ehdr*)base_addr;

    unsigned long *sp = (unsigned long*)((unsigned long)(stack) + STACK_SIZE - 4*PAGE_SIZE);
    //point to top stack
    void *res = (void*)sp;

    //argv init
    *sp++ = exec_argc;
    for(int i = 0; exec_argv[i]; ++i) {
        *sp++ = (unsigned long)exec_argv[i];
    }
    *sp++ = 0;

    //environ init
    int environ_idx = 0;
    for(; exec_environ[environ_idx]; ++environ_idx) {
        if(strchr(exec_environ[environ_idx], '_') != exec_environ[environ_idx]) { 
            *sp++ = (unsigned long)exec_environ[environ_idx]; 
        } else {
            char *environ = (char*)malloc(strlen(exec_argv[0] + 3));
            sprintf(environ, "_=%s", exec_argv[0]);
            *sp++ = (unsigned long)environ;
        }
    }
    *sp++ = 0;

    //auxiliary vector entries
    *((Elf_auxv_t*)sp) = (Elf_auxv_t){ .a_type = AT_RANDOM, .a_un.a_val = (unsigned long)(stack) + STACK_SIZE - 16};
    sp = (unsigned long*)((Elf_auxv_t*)sp + 1);
    *((Elf_auxv_t*)sp) = (Elf_auxv_t){ .a_type = AT_PAGESZ, .a_un.a_val = PAGE_SIZE};
    sp = (unsigned long*)((Elf_auxv_t*)sp + 1);
    *((Elf_auxv_t*)sp) = (Elf_auxv_t){ .a_type = AT_PHDR,   .a_un.a_val = (unsigned long)(base_addr) + elfinfo.Header->e_phoff};
    sp = (unsigned long*)((Elf_auxv_t*)sp + 1);
    *((Elf_auxv_t*)sp) = (Elf_auxv_t){ .a_type = AT_PHENT,  .a_un.a_val = elfinfo.Header->e_phentsize};
    sp = (unsigned long*)((Elf_auxv_t*)sp + 1);
    *((Elf_auxv_t*)sp) = (Elf_auxv_t){ .a_type = AT_PHNUM,  .a_un.a_val = elfinfo.Header->e_phnum};
    sp = (unsigned long*)((Elf_auxv_t*)sp + 1);
    *((Elf_auxv_t*)sp) = (Elf_auxv_t){ .a_type = AT_NULL};

    int argc = *(unsigned long*)res, i;
    char **argv;
    char **environ;
    Elf_auxv_t* elf_auxv_t;
    DLX(0,printf("\tstack => %p\n", res));
    DLX(0,printf("\targc => %d\n", argc));

    argv = ((char**)res) + 1;
    for(i = 0; i < argc; ++i) {
        DLX(0,printf("\targv[%d] = %s\n", i, argv[i])); 
    }

    environ = argv + argc + 1;
    for(i = 0; environ[i]; ++i) { 
        DLX(0,printf("\tenviron[%d] = %s\n", i, environ[i])); 
    }

    elf_auxv_t = (Elf_auxv_t*)(environ + i + 1);
    for(i = 0; elf_auxv_t[i].a_type != AT_NULL; ++i) { 
        DLX(0,printf("\tauxiliary[%d].a_type = %#lx, auxiliary[%d].a_un.a_val = %#lx\n", i, elf_auxv_t[i].a_type, i, elf_auxv_t[i].a_un.a_val)); 
    }

    return res;
}

static void init_registers(unsigned long entry, void *stack){
    __asm__ volatile(
        "mov %0, %%rsp;"
        "xor %%rdx, %%rdx;"
        "jmp *%1"
        :
        : "r"(stack), "r"(entry)
        : "rdx"
    );
}

int main(int argc,char **argv,char **env)
{
    FILE *file;
    long file_size;
    unsigned long total_size;
    unsigned long entry_addr;
    char *buffer;
    void *base_addr;
    void *stack;

    file = fopen("../go/hello/hello", "rb");
    //file = fopen("/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", "rb");
    if (file == NULL) {
        perror("Error opening file");
        return 1;
    }

    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    rewind(file);

    buffer = (char *)malloc(file_size);
    if (buffer == NULL) {
        perror("Error allocating memory");
        fclose(file);
        return 2;
    }

    fread(buffer, 1, file_size, file);

    base_addr = load_segments(buffer,&total_size,&entry_addr);
    free(buffer);
    fclose(file);

    stack = init_stack(argc,argv,env,base_addr);
    
    init_registers(entry_addr,stack);

    return 0;
}
```

