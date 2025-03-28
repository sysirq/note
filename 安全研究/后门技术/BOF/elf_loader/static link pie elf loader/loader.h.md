```c
#ifndef __INCLUDE_LOADER_H__
#define __INCLUDE_LOADER_H__

#include <elf.h>
#include <sys/mman.h>
#include "debug.h"

#define PAGE_SIZE 0x1000

/*Defines to map Elf_Phdr to Elf32_Phdr and whatnot*/
#if UINTPTR_MAX == 0xffffffff
#define Elf_Ehdr Elf32_Ehdr
#define Elf_Phdr Elf32_Phdr
#define Elf_Sym Elf32_Sym
#define Elf_Rel Elf32_Rel
#define Elf_Shdr    Elf32_Shdr
#define Elf_Dyn Elf32_Dyn
#define ELF_R_TYPE(i)   ELF32_R_TYPE(x)
#define ELF_R_SYM(x)    ELF32_R_SYM(x)
#define SHT_REL_TYPE    SHT_REL
#define DT_REL_TYPE     DT_REL
#define DT_RELSZ_TYPE   DT_RELSZ
#define DT_RELENT_TYPE  DT_RELENT
#define Elf_auxv_t Elf32_auxv_t
#define X86
#else
#define Elf_Ehdr Elf64_Ehdr
#define Elf_Phdr Elf64_Phdr
#define Elf_Sym Elf64_Sym
#define Elf_Rel Elf64_Rela
#define Elf_Shdr Elf64_Shdr
#define Elf_Dyn Elf64_Dyn
#define ELF_R_TYPE(i)   ELF64_R_TYPE(i)
#define ELF_R_SYM(x)    ELF64_R_SYM(i)
#define SHT_REL_TYPE    SHT_RELA
#define DT_REL_TYPE     DT_RELA
#define DT_RELSZ_TYPE   DT_RELASZ
#define DT_RELENT_TYPE  DT_RELAENT
#define Elf_auxv_t Elf64_auxv_t
#endif

typedef struct ELFInfo {
    Elf_Ehdr *Header;
    Elf_Phdr *progHeader;
    int progHeaderNum;
    Elf_Shdr *sectHeader;
    int sectHeaderNum;
    unsigned char* execPtr;
    Elf_Sym *symbolTable;
    char* stringTable;
    char* sectionStringTable;
    unsigned char** sectionMappings;
    int* sectionMappingProts;
    unsigned char* tempOffsetTable;
    int tempOffsetCounter;
} ELFInfo_t;

#endif
```

