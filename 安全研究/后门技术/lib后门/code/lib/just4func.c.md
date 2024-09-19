```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <elf.h>
#include <errno.h>
#include <string.h>
#include <lzma.h>
#include "debug.h"
#include "my_elf.h"
#include "just4fun.h"
#include "uhook.h"

int dbug_level_ = 0;

//a_type:
//  AT_NULL (0)：结束标志。
//  AT_PHDR (3)：程序头表地址。
//  AT_PHENT (4)：程序头表条目大小。
//  AT_PHNUM (5)：程序头表的条目数量。
//  AT_PAGESZ (6)：系统页面大小
//  AT_BASE (7)：动态链接器的基地址。
//  AT_FLAGS (8)：进程的标志。
//  AT_ENTRY (9)：程序入口点。
//  AT_UID (11)：真实用户 ID。
//  AT_EUID (12)：有效用户 ID。
//  AT_GID (13)：真实组 ID。
//  AT_EGID (14)：有效组 ID。
//  AT_CLKTCK (17)：时钟周期数。
static int get_auxv_value(long int a_type,long int* value){
    Elf64_auxv_t auxv;
    ssize_t read_bytes;
    
    int fd = open("/proc/self/auxv", O_RDONLY);
    
    if (fd == -1) {
        DLX(0,perror("Failed to open /proc/self/auxv"));
        return -1;
    }

    while ((read_bytes = read(fd, &auxv, sizeof(Elf64_auxv_t))) == sizeof(Elf64_auxv_t)) {
        if (auxv.a_type == a_type){
            *value = auxv.a_un.a_val;
            close(fd);
            return 0;
        }
        if (auxv.a_type == AT_NULL) {
            break;
        }
    }

    if (read_bytes == -1) {
        DLX(0,perror("Error reading /proc/self/auxv"));
        close(fd);
        return -1;
    }
    close(fd);

    return -1;
}

static int decompress_xz(char *input, size_t input_size, char **output, size_t *output_size) {
    lzma_stream strm = LZMA_STREAM_INIT;
    lzma_ret ret;
    size_t buf_size = 8*1024*1024;//最大
    *output = malloc(buf_size);

    if (*output == NULL) {
        DLX(0,perror("malloc"));
        return -1;
    }

    // Initialize decompression
    ret = lzma_stream_decoder(&strm, UINT64_MAX, LZMA_CONCATENATED);
    if (ret != LZMA_OK) {
        DLX(0,fprintf(stderr, "lzma_stream_decoder failed\n"));
        free(*output);
        return -1;
    }

    strm.next_in = input;
    strm.avail_in = input_size;
    strm.next_out = *output;
    strm.avail_out = buf_size;

    // Decompress data
    ret = lzma_code(&strm, LZMA_FINISH);
    if (ret == LZMA_OK || ret == LZMA_STREAM_END) {
        *output_size = buf_size - strm.avail_out;
        lzma_end(&strm);
        return 0;
    } else {
        DLX(0,fprintf(stderr, "lzma_code failed\n"));
        free(*output);
        lzma_end(&strm);
        return -1;
    }
}

static char* read_self_exe(void)
{
    struct stat st;
    int fd = open("/proc/self/exe", O_RDONLY);  // 打开文件
    if (fd < 0) {
        DLX(0,perror("open"));
        return NULL;
    }

    if (fstat(fd, &st) != 0) {
        DLX(0,perror("fstat"));
        close(fd);
        return NULL;
    }

    char *buffer = malloc(st.st_size + 1);
    if (!buffer) {
        DLX(0,perror("malloc"));
        close(fd);
        return NULL;
    }

    ssize_t bytes_read = read(fd, buffer, st.st_size);
    if (bytes_read != st.st_size) {
        DLX(0,perror("read"));
        free(buffer);
        close(fd);
        return NULL;
    }

    close(fd);
    return buffer;
}

static void* get_gnu_debugdata(size_t *out_size)
{
    int retcode = 0;
    int counter = 0;
    ELFInfo_t elfinfo;
    char *elf_format_data = read_self_exe();
    
    char *gnu_debugdata_compressed = NULL;
    size_t gnu_debugdata_compressed_size = 0;

    char *gnu_debugdata = NULL;
    size_t gnu_debugdata_size = 0;
    
    elfinfo.Header = (Elf_Ehdr*)elf_format_data;

    if(elf_format_data == NULL){
        return NULL;
    }

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

    // Set all the headers and sizes 
    elfinfo.progHeader = (Elf_Phdr*)(elf_format_data + elfinfo.Header->e_phoff);
    elfinfo.sectHeader = (Elf_Shdr*)(elf_format_data + elfinfo.Header->e_shoff);
    elfinfo.progHeaderNum = elfinfo.Header->e_phnum;
    elfinfo.sectHeaderNum = elfinfo.Header->e_shnum;
    elfinfo.shstrtab_hdr = &elfinfo.sectHeader[elfinfo.Header->e_shstrndx];
    elfinfo.shstrtab = (char*)(elf_format_data + elfinfo.shstrtab_hdr->sh_offset);

    for (counter = 0; counter < elfinfo.sectHeaderNum; counter++){
        char *section_name = &elfinfo.shstrtab[elfinfo.sectHeader[counter].sh_name];
        if(strcmp(section_name,".gnu_debugdata") == 0){
            gnu_debugdata_compressed = elf_format_data + elfinfo.sectHeader[counter].sh_offset;
            gnu_debugdata_compressed_size = elfinfo.sectHeader[counter].sh_size;
            break;
        }
    }

    if(gnu_debugdata_compressed == NULL){

        free(elf_format_data);
        return NULL;
    }

    DLX(0,printf("\tgnu_debugdata_compressed: %p\n",gnu_debugdata_compressed));
    DLX(0,printf("\tgnu_debugdata_compressed_size: %ld\n",gnu_debugdata_compressed_size));
    DLX(0,printf("\tgnu_debugdata_compressed[0]: 0x%x , gnu_debugdata_compressed[1]: 0x%x \n",(unsigned char)gnu_debugdata_compressed[0],(unsigned char)gnu_debugdata_compressed[1]));


    retcode = decompress_xz(gnu_debugdata_compressed,gnu_debugdata_compressed_size,&gnu_debugdata,&gnu_debugdata_size);
    if(retcode != 0){
        free(elf_format_data);
        return NULL;
    }

    *out_size = gnu_debugdata_size;

    DLX(0,printf("\tgnu_debugdata:%p\n",gnu_debugdata));
    DLX(0,printf("\tgnu_debugdata_size:%ld\n",gnu_debugdata_size));

    free(elf_format_data);
    return gnu_debugdata;
}

static int parse_gnu_debugdata(char *elf_format_data,ELFInfo_t *elfinfo)
{
    int counter = 0;
    int i;
    int j;
    Elf_Sym temp;
    elfinfo->Header = (Elf_Ehdr*)elf_format_data;
    
    // varify that the data is an elf file
    if( elf_format_data[0] != '\x7f' || elf_format_data[1] != 'E' || elf_format_data[2] != 'L' || elf_format_data[3] != 'F' ){
        DLX(0,printf("\tnot an elf file\n"));
        return -1;
    }
    DLX(0,printf("\tvalid elf file magic number\n"));

    DLX(0,printf("\tELF Object Data: %p\n", elf_format_data));
    DLX(0,printf("\tELF Type: %d\n", elfinfo->Header->e_type));
    DLX(0,printf("\tELF Machine: %d\n", elfinfo->Header->e_machine));
    DLX(0,printf("\tELF Version: %d\n", elfinfo->Header->e_version));
    DLX(0,printf("\tELF Entry: 0x%lx\n", elfinfo->Header->e_entry));
    DLX(0,printf("\tELF ProgramHeaderOffset: 0x%lx\n", elfinfo->Header->e_phoff));
    DLX(0,printf("\tELF SectionHeaderOffset: 0x%lx\n", elfinfo->Header->e_shoff));
    DLX(0,printf("\tELF Flags: 0x%x\n", elfinfo->Header->e_flags));
    DLX(0,printf("\tELF Header Size: %d\n", elfinfo->Header->e_ehsize));
    DLX(0,printf("\tELF Program Header Entry Size: %d\n", elfinfo->Header->e_phentsize));
    DLX(0,printf("\tELF Program Header Entry Count: %d\n", elfinfo->Header->e_phnum));
    DLX(0,printf("\tELF Section Header Entry Size: %d\n", elfinfo->Header->e_shentsize));
    DLX(0,printf("\tELF Section Header Entry Count: %d\n", elfinfo->Header->e_shnum));
    DLX(0,printf("\tELF Section Header Table Index Entry: %d\n", elfinfo->Header->e_shstrndx));

    /* Set all the headers and sizes */
    elfinfo->progHeader = (Elf_Phdr*)(elf_format_data + elfinfo->Header->e_phoff);
    elfinfo->sectHeader = (Elf_Shdr*)(elf_format_data + elfinfo->Header->e_shoff);
    elfinfo->progHeaderNum = elfinfo->Header->e_phnum;
    elfinfo->sectHeaderNum = elfinfo->Header->e_shnum;

    // get sym_tab and sym_str_tab
    for (counter = 0; counter < elfinfo->sectHeaderNum; counter++){
        switch (elfinfo->sectHeader[counter].sh_type){
            case SHT_SYMTAB:
                DLX(0,printf("\t\tSymbol Table\n"));
                elfinfo->symbolTable = (Elf_Sym*)(elf_format_data + elfinfo->sectHeader[counter].sh_offset);
                elfinfo->symStringTable = (char*)(elf_format_data + elfinfo->sectHeader[elfinfo->sectHeader[counter].sh_link].sh_offset);
                elfinfo->symbolsNum = elfinfo->sectHeader[counter].sh_size / (sizeof(Elf_Sym));

                DLX(0,printf("\t\tSymbolTable: %p\n", elfinfo->symbolTable));
                DLX(0,printf("\t\tsymStringTable: %p\n", elfinfo->symStringTable));
                DLX(0,printf("\t\tsymbolsNum: %d\n", elfinfo->symbolsNum));
                break;
        }
    }

    if( elfinfo->symbolTable == NULL || elfinfo->symStringTable == NULL){
        return -1;
    }

    //Bubble Sort
    for(i = 0;i<elfinfo->symbolsNum -1 ;i++){
        for(j = 0;j < elfinfo->symbolsNum -i -1;j++){
            if(elfinfo->symbolTable[j].st_value > elfinfo->symbolTable[j+1].st_value){
                temp = elfinfo->symbolTable[j];
                elfinfo->symbolTable[j] = elfinfo->symbolTable[j+1];
                elfinfo->symbolTable[j+1] = temp;
            }
        }
    }

    return 0;
}

static unsigned long get_func_start_addr(char *func_name,ELFInfo_t *elfinfo)
{
    int i;
    int found = 0;
    Elf_Sym sym;
    unsigned long start_addr = 0;
    unsigned long symbol_addr = 0;
    unsigned long entry;
    int retcode;

    retcode = get_auxv_value(AT_ENTRY,&entry);
    if(retcode != 0){
        DLX(0,printf("\tget_auxv_value AT_ENTRY error\n"));
        return 0;
    }

    for(i = 0;i<elfinfo->symbolsNum;i++){
        if(elfinfo->symbolTable[i].st_name!=0){
            const char *name = &elfinfo->symStringTable[elfinfo->symbolTable[i].st_name];

            if(strcmp(name,"_start") == 0){
                sym = elfinfo->symbolTable[i];
                found = 1;
            }
        }
    }
    if(found == 0){
        DLX(0,printf("\tget _start symbol addr error\n"));
        return 0;
    }

    start_addr = sym.st_value;

    found = 0;
    for(i = 0;i<elfinfo->symbolsNum;i++){
        if(elfinfo->symbolTable[i].st_name!=0){
            const char *name = &elfinfo->symStringTable[elfinfo->symbolTable[i].st_name];

            if(strcmp(name,func_name) == 0){
                sym = elfinfo->symbolTable[i];
                found = 1;
            }
        }
    }

    if(found == 0)
    {
        return 0;
    }

    if(start_addr > sym.st_value){
        symbol_addr = entry - (start_addr -  sym.st_value);
    }else{
        symbol_addr = entry + (sym.st_value - start_addr );
    }

    DLX(0,printf("\tsymbol name: %s , start_addr:0x%lx\n",func_name,symbol_addr));

    return symbol_addr;
}

static unsigned long get_func_end_addr(char *func_name,ELFInfo_t *elfinfo)
{
    int i;
    int found = 0;
    Elf_Sym sym;
    unsigned long start_addr = 0;
    unsigned long symbol_addr = 0;
    unsigned long entry;
    unsigned long index = 0;
    int retcode;

    retcode = get_auxv_value(AT_ENTRY,&entry);
    if(retcode != 0){
        DLX(0,printf("\tget_auxv_value AT_ENTRY error\n"));
        return 0;
    }

    for(i = 0;i<elfinfo->symbolsNum;i++){
        if(elfinfo->symbolTable[i].st_name!=0){
            const char *name = &elfinfo->symStringTable[elfinfo->symbolTable[i].st_name];

            if(strcmp(name,"_start") == 0){
                sym = elfinfo->symbolTable[i];
                found = 1;
            }
        }
    }
    if(found == 0){
        DLX(0,printf("\tget _start symbol addr error\n"));
        return 0;
    }

    start_addr = sym.st_value;

    found = 0;
    for(i = 0;i<elfinfo->symbolsNum;i++){
        if(elfinfo->symbolTable[i].st_name!=0){
            const char *name = &elfinfo->symStringTable[elfinfo->symbolTable[i].st_name];

            if(strcmp(name,func_name) == 0){
                index = i;
                found = 1;
            }
        }
    }

    if(found == 0)
    {
        return 0;
    }

    if(index + 1 >= elfinfo->symbolsNum){
        return 0;
    }

    sym = elfinfo->symbolTable[index + 1];

    if(start_addr > sym.st_value){
        symbol_addr = entry - (start_addr -  sym.st_value);
    }else{
        symbol_addr = entry + (sym.st_value - start_addr );
    }

    DLX(0,printf("\tsymbol name: %s , end_addr:0x%lx\n",func_name,symbol_addr));

    return symbol_addr;
}

static my_hook(int a,int b)
{
    void (*func_ptr)(int a,int b);
    uhook_t* hook = find_uhook("please_hook_me");

    printf("this is my hook\n");
    printf("\t argument a:%d\n",a);
    printf("\t argument b:%d\n",b);

    temp_close_hook(hook);

    func_ptr = hook->func_addr;

    func_ptr(5,5);
    enable_temp_close_hook(hook);

}

int init_function()
{
    char *gnu_debugdata = NULL;
    size_t gnu_debugdata_size;
    ELFInfo_t elfinfo = {};
    int retcode;

    gnu_debugdata = get_gnu_debugdata(&gnu_debugdata_size);
    if(gnu_debugdata == NULL){
        DLX(0,printf("\tget gnu_debugdata error\n"));
        goto cleanup;
    }

    retcode = parse_gnu_debugdata(gnu_debugdata,&elfinfo);
    if(retcode != 0){
        DLX(0,printf("parse_gnu_debugdata error"));
        goto cleanup;
    }

    retcode = uhook_init();
    if(retcode != 0){
        DLX(0,printf("uhook init error"));
        goto cleanup;
    }

    uhook("please_hook_me",get_func_start_addr("please_hook_me",&elfinfo),get_func_end_addr("please_hook_me",&elfinfo),my_hook);

cleanup:
    if(gnu_debugdata != NULL){
        memset(gnu_debugdata,0,gnu_debugdata_size);
    }
    return;
}
```