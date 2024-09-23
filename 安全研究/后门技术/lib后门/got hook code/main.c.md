```c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <unistd.h>
#include "my_elf.h"
#include "debug.h"

#ifdef DEBUG
int dbug_level_ = 0;
#endif

// a_type:
//   AT_NULL (0)：结束标志。
//   AT_PHDR (3)：程序头表地址。
//   AT_PHENT (4)：程序头表条目大小。
//   AT_PHNUM (5)：程序头表的条目数量。
//   AT_PAGESZ (6)：系统页面大小
//   AT_BASE (7)：动态链接器的基地址。
//   AT_FLAGS (8)：进程的标志。
//   AT_ENTRY (9)：程序入口点。
//   AT_UID (11)：真实用户 ID。
//   AT_EUID (12)：有效用户 ID。
//   AT_GID (13)：真实组 ID。
//   AT_EGID (14)：有效组 ID。
//   AT_CLKTCK (17)：时钟周期数。
static int get_auxv_value(long int a_type, long int *value)
{
    Elf64_auxv_t auxv;
    ssize_t read_bytes;

    int fd = open("/proc/self/auxv", O_RDONLY);

    if (fd == -1)
    {
        DLX(0, perror("Failed to open /proc/self/auxv"));
        return -1;
    }

    while ((read_bytes = read(fd, &auxv, sizeof(Elf64_auxv_t))) == sizeof(Elf64_auxv_t))
    {
        if (auxv.a_type == a_type)
        {
            *value = auxv.a_un.a_val;
            close(fd);
            return 0;
        }
        if (auxv.a_type == AT_NULL)
        {
            break;
        }
    }

    if (read_bytes == -1)
    {
        DLX(0, perror("Error reading /proc/self/auxv"));
        close(fd);
        return -1;
    }
    close(fd);

    return -1;
}

static unsigned long read_self_exe_entry(void)
{
    struct stat st;
    int fd = open("/proc/self/exe", O_RDONLY); // 打开文件
    if (fd < 0)
    {
        DLX(0, perror("open"));
        return -1;
    }

    if (fstat(fd, &st) != 0)
    {
        DLX(0, perror("fstat"));
        close(fd);
        return -1;
    }

    char *buffer = malloc(st.st_size + 1);
    if (!buffer)
    {
        DLX(0, perror("malloc"));
        close(fd);
        return -1;
    }

    ssize_t bytes_read = read(fd, buffer, st.st_size);
    if (bytes_read != st.st_size)
    {
        DLX(0, perror("read"));
        free(buffer);
        close(fd);
        return -1;
    }

    close(fd);

    Elf_Ehdr *ehdr = (Elf_Ehdr *)buffer;
    unsigned long entry = ehdr->e_entry;
    free(buffer);

    return entry;
}

unsigned long get_prog_load_offset()
{
    unsigned long self_prog_entry;
    int retcode;

    unsigned long self_exe_entry = read_self_exe_entry();
    if (self_exe_entry == -1)
    {
        DLX(0, printf("\tself_exe_entry error\n"));
        return -1;
    }

    retcode = get_auxv_value(AT_ENTRY, &self_prog_entry);
    if (retcode == -1)
    {
        DLX(0, printf("\tget_auxv_value AT_ENTRY error\n"));
        return -1;
    }

    return self_prog_entry - self_exe_entry;
}

static void update_got_entry(unsigned long addr,unsigned long entry)
{
    size_t page_size = sysconf(_SC_PAGESIZE);
    unsigned long first_page  = addr & (~((unsigned long) (page_size-1)));
    unsigned long second_page = (addr+sizeof(entry)) & (~((unsigned long)(page_size-1)));

    if(first_page == second_page){
        mprotect((void*)(first_page), page_size, PROT_READ|PROT_WRITE);
    }else{
        mprotect((void*)(first_page), page_size, PROT_READ|PROT_WRITE);
        mprotect((void*)(second_page), page_size, PROT_READ|PROT_WRITE);
    }

    *(unsigned long*)(addr) = entry;
}

int got_hook(char *func_name,unsigned long func_addr)
{
    Elf_Phdr *phdr = NULL;
    Elf_Phdr *ph_dyn = NULL;
    Elf_Dyn *dyn;
    unsigned long int phnum = 0;
    unsigned long load_offset;
    int retcode = -1;
    int i;
    unsigned long plt_relocs_addr = 0;
    unsigned long str_tab_addr = 0;
    unsigned long sym_tab_addr = 0;
    unsigned long plt_relocs_size = 0;
    unsigned long plt_reloc_type = 0;
    Elf_Rela *rel_table;

    load_offset = get_prog_load_offset();
    if (load_offset == -1)
    {
        DLX(0, printf("\tget_prog_load_offset error\n"));
        return -1;
    }

    DLX(0, printf("\tprog load offset:0x%lx\n", load_offset));

    retcode = get_auxv_value(AT_PHDR, (long *)(&phdr));
    if (retcode != 0)
    {
        DLX(0, printf("\tget_auxv_value AT_PHDR error\n"));
        return -1;
    }

    retcode = get_auxv_value(AT_PHNUM, &phnum);
    if (retcode != 0)
    {
        DLX(0, printf("\tget_auxv_value AT_PHNUM error\n"));
        return -1;
    }

    DLX(0, printf("\tPHDR addr:%p , PHDR num:%ld\n", phdr, phnum));

    for (i = 0; i < phnum; i++)
    {
        if (phdr[i].p_type == PT_DYNAMIC)
        {
            ph_dyn = phdr + i;
            break;
        }
    }

    if (ph_dyn == NULL)
    {
        DLX(0, printf("\tnot found PT_DYNAMIC\n"));
        return -1;
    }

    dyn = (void*)(load_offset + ph_dyn->p_vaddr);

    while (dyn->d_tag != DT_NULL)
    {
        switch (dyn->d_tag)
        {
            case DT_JMPREL:
                plt_relocs_addr = dyn->d_un.d_ptr;
                break;
            case DT_STRTAB:
                str_tab_addr = dyn->d_un.d_ptr;
                break;
            case DT_PLTRELSZ:
                plt_relocs_size = dyn->d_un.d_val;
                break;
            case DT_SYMTAB:
                sym_tab_addr = dyn->d_un.d_ptr;
                break;
            case DT_PLTREL:
                plt_reloc_type = dyn->d_un.d_val;
                break;
        }
        dyn++;
    }

    if(plt_relocs_addr == 0){
        DLX(0,printf("\tget DT_JMPREL error\n"));
        return -1;
    }
    if(str_tab_addr == 0){
        DLX(0,printf("\tget DT_STRTAB error\n"));
        return -1;
    }
    if(plt_relocs_size == 0){
        DLX(0,printf("\tget DT_PLTRELSZ error\n"));
        return -1;
    }
    if(sym_tab_addr == 0){
        DLX(0,printf("\tget DT_SYMTAB error\n"));
        return -1;
    }
    if(plt_reloc_type == 0){
        DLX(0,printf("\tget DT_PLTREL error\n"));
        return -1;
    }

    if( plt_reloc_type != DT_RELA ){
        DLX(0,printf("\tonly support  Elf32_Rela (or Elf64_Rela)\n"));
        return -1;
    }

    rel_table = (Elf_Rela*)(plt_relocs_addr);

    for(i = 0;i<(plt_relocs_size/sizeof(Elf_Rela));i++){
        int sym_idx = ELF_R_SYM(rel_table[i].r_info);
        Elf_Sym *sym = (Elf_Sym*)( sym_idx*sizeof(Elf_Sym) + sym_tab_addr );
        char *name = (char*)(str_tab_addr + sym->st_name);
        
        if(strcmp(name,func_name) == 0){
            update_got_entry(load_offset + rel_table[i].r_offset,func_addr);
            return 0;
        }
    }

    return -1;
}

static int my_puts (char *__s)
{
    int (*func_ptr) (char *__s);

    func_ptr = dlsym(NULL,"puts");

    return func_ptr("miaomiaomiao");
}

int main(void)
{
    got_hook("puts",(unsigned long)my_puts);
    puts("Please hook me");
    return 0;
}
```

