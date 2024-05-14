```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <dlfcn.h>
#include "loader.h"

#ifdef DEBUG
int dbug_level_ = 2;
#endif

#define ARRAY_SIZE(a) (sizeof((a))/sizeof((a[0])))

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
#define INTERNAL_DEFAULT_LIBRARY ((void*) -2)
#else
#define INTERNAL_DEFAULT_LIBRARY NULL //RTLD_DEFAULT
#endif

typedef struct beacon_function{
    char* functionName;
    void* function;
} beacon_function_t;

int BeaconPrint(void *str)
{
    printf("BeaconPrint:%s\n",(char*)str);
    return 0;
}

beacon_function_t BeaconInternalMapping[] = {
    {"BeaconPrint", (void*)BeaconPrint},
};

void* internalFunctionLookup(char* symbolName){
    void* functionaddress = NULL;
    int tempcounter = 0;
    for (tempcounter = 0; tempcounter < ARRAY_SIZE(BeaconInternalMapping); tempcounter++){
        if (strcmp(symbolName, BeaconInternalMapping[tempcounter].functionName) == 0){
            DLX(0,printf("\t\t\t\tInternalFunction: %s\n", symbolName));
            functionaddress = BeaconInternalMapping[tempcounter].function;
            return functionaddress;
        }
    }
    /* If not an internal function, then its an external one */
    if (functionaddress == NULL){
        functionaddress = dlsym(INTERNAL_DEFAULT_LIBRARY, symbolName);
    }
    return functionaddress;
}

static int elf_parse(char *elf_format_data,char *func_name)
{
    ELFInfo_t elfinfo;
    int retcode = 0;
    int counter = 0;
    int tempOffsetCounter = 0;
    int c2 = 0;

    int (*ptr)(void) = (int (*)(void))NULL;

    memset(&elfinfo,0,sizeof(elfinfo));
    elfinfo.Header = (Elf_Ehdr*)elf_format_data;

    // varify that the data is an elf file
    if( elf_format_data[0] != '\x7f' || elf_format_data[1] != 'E' || elf_format_data[2] != 'L' || elf_format_data[3] != 'F' ){
        DLX(0,printf("\tnot an elf file\n"));
        retcode = -1;
        goto cleanup;
    }
    DLX(0,printf("\tvalid elf file magic number\n"));

    if(elfinfo.Header->e_type != ET_REL){ //ET_DYN
        DLX(0,printf("\tELF Type isn't Shared object file type\n"));
        retcode = -1;
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

    DLX(0,printf("\tWorking with program headers, Count: %d\n", elfinfo.progHeaderNum));
    for (counter = 0; counter < elfinfo.progHeaderNum; counter++){
        DLX(0,printf("\t\tProgram Header Entry Counter: %d\n", counter));
        DLX(0,printf("\t\tOffset: 0x%lx\n", elfinfo.progHeader[counter].p_offset));
    }

    elfinfo.sectionMappings = calloc(elfinfo.sectHeaderNum*sizeof(char*), 1);
    elfinfo.sectionMappingProts = calloc(elfinfo.sectHeaderNum*sizeof(int), 1);
    if (elfinfo.sectionMappings == NULL || elfinfo.sectionMappingProts == NULL){
        DLX(0,printf("Failed to setup sectionMappings\n"));
        retcode = -1;
        goto cleanup;
    }
    elfinfo.tempOffsetTable = mmap(NULL, 255*ThunkTrampolineSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    tempOffsetCounter += 0x5000;
    elfinfo.tempOffsetCounter = 0;
    if (elfinfo.tempOffsetTable == NULL || elfinfo.tempOffsetTable == (void*)-1){
        DLX(0,printf("Failed to allocate the hacky GOT/Thunk function table.\n"));
        retcode = -1;
        goto cleanup;
    }

    DLX(0,printf("\tWorking over section headers, Count: %d\n", elfinfo.sectHeaderNum));
    for (counter = 0; counter < elfinfo.sectHeaderNum; counter++){
        int sectionProts = PROT_READ | PROT_WRITE;

        DLX(0,printf("\tSection Header Entry Counter: %d\n", counter));
        DLX(0,printf("\t\tName is %d\n", elfinfo.sectHeader[counter].sh_name));
        DLX(0,printf("\t\tType is 0x%x\n", elfinfo.sectHeader[counter].sh_type));
        DLX(0,printf("\t\tFlags are 0x%lx\n", elfinfo.sectHeader[counter].sh_flags));
        
        /* Identify the memory permissions here */
        if (elfinfo.sectHeader[counter].sh_flags & SHF_WRITE){
            DLX(0,printf("\t\tWriteable Section\n"));
            sectionProts = PROT_READ | PROT_WRITE;
        }
        if (elfinfo.sectHeader[counter].sh_flags & SHF_EXECINSTR){
            DLX(0,printf("\t\tExecutable Section\n"));
            sectionProts = PROT_READ | PROT_EXEC;
        }
        if (elfinfo.sectHeader[counter].sh_size > 0 && elfinfo.sectHeader[counter].sh_type == SHT_PROGBITS){
            elfinfo.sectionMappings[counter] = mmap(elfinfo.tempOffsetTable+tempOffsetCounter, elfinfo.sectHeader[counter].sh_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            tempOffsetCounter += 0x5000;
            if (elfinfo.sectionMappings[counter] == NULL || elfinfo.sectionMappings[counter] == (void*)-1){
                DLX(0,printf("\t\tFailed to allocate memory for section\n"));
                retcode = -1;
                goto cleanup;
            }
            memcpy(elfinfo.sectionMappings[counter], elf_format_data+elfinfo.sectHeader[counter].sh_offset, elfinfo.sectHeader[counter].sh_size);
        }else{
        /* Not allocating memory because the section isn't needed for the program to run, just used to link. */
            DLX(0,printf("\t\tNot allocating memory for section\n"));
            elfinfo.sectionMappings[counter] = NULL;
        }
        elfinfo.sectionMappingProts[counter] = sectionProts;

        DLX(0,printf("\t\tAddr is 0x%lx\n", elfinfo.sectHeader[counter].sh_addr));
        DLX(0,printf("\t\tOffset is 0x%lx\n", elfinfo.sectHeader[counter].sh_offset));
        DLX(0,printf("\t\tSize is %ld\n", elfinfo.sectHeader[counter].sh_size));
        DLX(0,printf("\t\tLink is %d\n", elfinfo.sectHeader[counter].sh_link));
        DLX(0,printf("\t\tInfo is %d\n", elfinfo.sectHeader[counter].sh_info));
        DLX(0,printf("\t\tAddrAlign is %ld\n", elfinfo.sectHeader[counter].sh_addralign));
        DLX(0,printf("\t\tEntSize is %ld\n", elfinfo.sectHeader[counter].sh_entsize));

        /* Locate the sections that we want to keep track to */
        switch (elfinfo.sectHeader[counter].sh_type){
            case SHT_SYMTAB:
                DLX(0,printf("\t\tSymbol Table\n"));
                elfinfo.symbolTable = (Elf_Sym*)(elf_format_data + elfinfo.sectHeader[counter].sh_offset);
                elfinfo.stringTable = (char*)(elf_format_data + elfinfo.sectHeader[elfinfo.sectHeader[counter].sh_link].sh_offset);
                DLX(0,printf("\t\tSymbolTable: %p\n", elfinfo.symbolTable));
                DLX(0,printf("\t\tStringTable: %p\n", elfinfo.stringTable));
                break;
            case SHT_STRTAB:
                DLX(0,printf("\t\tString Table\n"));
                elfinfo.sectionStringTable = (char*)(elf_format_data + elfinfo.sectHeader[counter].sh_offset);
                break;
            default:
                DLX(0,printf("\t\tCase Not Handled\n"));
                break;
        }
    }

    DLX(0,printf("\tWorking over section headers, Round 2, Count: %d\n", elfinfo.sectHeaderNum));
    for (counter = 0; counter < elfinfo.sectHeaderNum; counter++){
        DLX(0,printf("\tSection Header Entry Counter: %d\n", counter));
        char* sym = elfinfo.sectionStringTable + elfinfo.sectHeader[counter].sh_name;
        DLX(0,printf("\t\tName is %s\n", sym));
        Elf_Rel* rel = (Elf_Rel*)(elf_format_data + elfinfo.sectHeader[counter].sh_offset);
        DLX(0,printf("\t\tType is 0x%x\n", elfinfo.sectHeader[counter].sh_type));
        DLX(0,printf("\t\tFlags are 0x%lx\n", elfinfo.sectHeader[counter].sh_flags));
        DLX(0,printf("\t\tAddr is 0x%lx\n", elfinfo.sectHeader[counter].sh_addr));
        DLX(0,printf("\t\tOffset is 0x%lx\n", elfinfo.sectHeader[counter].sh_offset));
        DLX(0,printf("\t\tSize is %ld\n", elfinfo.sectHeader[counter].sh_size));
        DLX(0,printf("\t\tLink is %d\n", elfinfo.sectHeader[counter].sh_link));
        DLX(0,printf("\t\tInfo is %d\n", elfinfo.sectHeader[counter].sh_info));
        DLX(0,printf("\t\tAddrAlign is %ld\n", elfinfo.sectHeader[counter].sh_addralign));
        DLX(0,printf("\t\tEntSize is %ld\n", elfinfo.sectHeader[counter].sh_entsize));

        /* Handle the relocations here */
        if (elfinfo.sectHeader[counter].sh_type == SHT_REL_TYPE){
            DLX(0,printf("\t\tRelocation Entries:\n"));
            for (c2 = 0; c2 < elfinfo.sectHeader[counter].sh_size / sizeof(Elf_Rel); c2++){
                char* relocStr = elfinfo.stringTable + elfinfo.symbolTable[ELF_R_SYM(rel[c2].r_info)].st_name;
                char WorkingTrampoline[ThunkTrampolineSize];
                memcpy(WorkingTrampoline, ThunkTrampoline, ThunkTrampolineSize);
                DLX(0,printf("\t\t\tSymbol: %s\n", relocStr));
                DLX(0,printf("\t\t\tType: 0x%lx\n", ELF_R_TYPE(rel[c2].r_info)));
                DLX(0,printf("\t\t\tSymbolValue: 0x%lx\n", elfinfo.symbolTable[ELF_R_SYM(rel[c2].r_info)].st_value));
                /* This is the section number where the relocation lives in at x + offset, if its 0 then its a symbol to get
                 * so get the address, store the address, increase the symbol count, and then continue */
                DLX(0,printf("\t\t\tShndx: 0x%x\n", elfinfo.symbolTable[ELF_R_SYM(rel[c2].r_info)].st_shndx));
                if (elfinfo.symbolTable[ELF_R_SYM(rel[c2].r_info)].st_shndx == 0){
                    /* This function is a function not defined in the object file, so if we can't resolve it then bail. */
                    void* symaddress = NULL;
                    int32_t relativeOffsetFunc = 0;
                    symaddress = internalFunctionLookup(relocStr);
                    if (symaddress == NULL){
                        DLX(0,printf("\t\t\t\tFailed to find a function!!!!!\n"));
                        retcode = -1;
                        goto cleanup;
                    }
                    DLX(0,printf("\t\t\t\tFound Function Address: %p\n", symaddress));
                    /* Copy over the symaddress to the location of the trampoline */
                    memcpy(WorkingTrampoline+THUNKOFFSET, &symaddress, sizeof(void*));
                    /* Copy the trampoline bytes over to the tempOffsetTable so relocations work */
                    DLX(0,printf("\t\t\t\tTempOffsetCounter: %d\n", elfinfo.tempOffsetCounter));
                    memcpy(elfinfo.tempOffsetTable+(elfinfo.tempOffsetCounter*ThunkTrampolineSize), WorkingTrampoline, ThunkTrampolineSize);
                    /* Calculate the relative offset of the function trampoline */
                    /* The logic to handle x86_64 is different then x86, so ifdef'ing these out for now */
                   #if defined(__amd64__) || defined(__x86_64__)
                    relativeOffsetFunc = (elfinfo.tempOffsetTable + (elfinfo.tempOffsetCounter *ThunkTrampolineSize))-(elfinfo.sectionMappings[elfinfo.sectHeader[counter].sh_info]+rel[c2].r_offset)+rel[c2].r_addend;
                    DLX(0,printf("\t\t\t\tRelativeOffsetFunc: 0x%x\n", relativeOffsetFunc));
                    /* Copy over the relative offset to the trampoline table */
                    memcpy(elfinfo.sectionMappings[elfinfo.sectHeader[counter].sh_info]+rel[c2].r_offset, &relativeOffsetFunc, 4);
                    #elif defined(__i386__)
                    /* Need to correct this for x86 and 32 bit arm targets, think its good now. */
                    memcpy(&relativeOffsetFunc, elfinfo.sectionMappings[elfinfo.sectHeader[counter].sh_info]+rel[c2].r_offset, 4);
                    relativeOffsetFunc += (elfinfo.tempOffsetTable + (elfinfo.tempOffsetCounter *ThunkTrampolineSize))-(elfinfo.sectionMappings[elfinfo.sectHeader[counter].sh_info]+rel[c2].r_offset);
                    memcpy(elfinfo.sectionMappings[elfinfo.sectHeader[counter].sh_info]+rel[c2].r_offset, &relativeOffsetFunc, 4);
                    #else
                    DLX(0,printf("\t\t\t\tTERROR: Not configured for this architecture\n"));
                    #endif
                    /* Once set increment the Thunk Trampoline counter to the next one */
                    elfinfo.tempOffsetCounter+=1;
                }
                else if (elfinfo.sectHeader[counter].sh_flags== SHF_INFO_LINK){/* `sh_info' contains SHT index */
                    /* Handle the relocations for values and functions included in the object file */
                    /* NOTE: If sh_flags == 0x40, then sh_info contains the section the relocation applies too */
                    #if defined(__amd64__) || defined(__x86_64__)
                    int32_t relativeOffset = (elfinfo.sectionMappings[elfinfo.symbolTable[ELF_R_SYM(rel[c2].r_info)].st_shndx])-(elfinfo.sectionMappings[elfinfo.sectHeader[counter].sh_info]+rel[c2].r_offset)+rel[c2].r_addend + elfinfo.symbolTable[ELF_R_SYM(rel[c2].r_info)].st_value;
                    #elif defined(__i386__)
                    int32_t relativeOffset = 0;
                    if (ELF_R_TYPE(rel[c2].r_info) == R_386_32){
                        DLX(0,printf("\t\t\t\t32bit Direct\n"));
                        memcpy(&relativeOffset, elfinfo.sectionMappings[elfinfo.sectHeader[counter].sh_info]+rel[c2].r_offset, 4);
                        //relativeOffset = (elfinfo.sectionMappings[elfinfo.symbolTable[ELF_R_SYM(rel[c2].r_info)].st_shndx])-(elfinfo.sectionMappings[elfinfo.sectHeader[counter].sh_info]+rel[c2].r_offset)+relativeOffset + elfinfo.symbolTable[ELF_R_SYM(rel[c2].r_info)].st_value;
                        relativeOffset += elfinfo.symbolTable[ELF_R_SYM(rel[c2].r_info)].st_value;
                        relativeOffset += (int32_t)(elfinfo.sectionMappings[elfinfo.symbolTable[ELF_R_SYM(rel[c2].r_info)].st_shndx]);
                    }
                    else if (ELF_R_TYPE(rel[c2].r_info) == R_386_PC32){
                        DLX(0,printf("\t\t\t\tPC relative Address\n"));
                        memcpy(&relativeOffset, elfinfo.sectionMappings[elfinfo.sectHeader[counter].sh_info]+rel[c2].r_offset, 4);
                        relativeOffset = (elfinfo.sectionMappings[elfinfo.symbolTable[ELF_R_SYM(rel[c2].r_info)].st_shndx])-(elfinfo.sectionMappings[elfinfo.sectHeader[counter].sh_info]+rel[c2].r_offset)+relativeOffset + elfinfo.symbolTable[ELF_R_SYM(rel[c2].r_info)].st_value;
                    }
                    #else
                    int32_t relativeOffset = 0;
                    #endif
                    DLX(0,printf("\t\t\t\tFirstAddress(NoAddend): %p\n", (elfinfo.sectionMappings[elfinfo.symbolTable[ELF_R_SYM(rel[c2].r_info)].st_shndx])));

                    #if defined(__amd64__) || defined(__x86_64__)
                    DLX(0,printf("\t\t\t\tFirstAddress: %p\n", (elfinfo.sectionMappings[elfinfo.symbolTable[ELF_R_SYM(rel[c2].r_info)].st_shndx]+rel[c2].r_addend)));
                    #endif
                    DLX(0,printf("\t\t\t\tSecondAddress(NoOffset): %p\n", (elfinfo.sectionMappings[elfinfo.sectHeader[counter].sh_info])));
                    DLX(0,printf("\t\t\t\tSecondAddress: %p\n", (elfinfo.sectionMappings[elfinfo.sectHeader[counter].sh_info]+rel[c2].r_offset)));
                    DLX(0,printf("\t\t\t\tRelativeOffset: 0x%x\n", relativeOffset));
                    /* Copy over the relative offset of the value to the section+offset */
                    memcpy(elfinfo.sectionMappings[elfinfo.sectHeader[counter].sh_info]+rel[c2].r_offset, &relativeOffset, 4);
                }
                DLX(0,printf("\t\t\tOffset: 0x%lx\n", rel[c2].r_offset));
                #if defined(__amd64__) || defined(__x86_64__)
                DLX(0,printf("\t\t\tAddend: 0x%lx\n", rel[c2].r_addend));
                #endif
                DLX(0,printf("\t\t\t----------------------------------------------------------\n"));
            }
        }
        /* Handle the symbols here, get the entry points and all that */
        if (elfinfo.sectHeader[counter].sh_type == SHT_SYMTAB){
            for (c2 = 0; c2 < elfinfo.sectHeader[counter].sh_size / sizeof(Elf_Sym); c2 += 1) {
                Elf_Sym* syms = (Elf_Sym*)(elf_format_data + elfinfo.sectHeader[counter].sh_offset);
                //DLX(0,printf("\t\t\t0x%x\n", syms[c2].st_name));
                DLX(0,printf("\t\t\tSymbolName: %s\n", elfinfo.stringTable + syms[c2].st_name));
                if (strcmp(func_name, elfinfo.stringTable + syms[c2].st_name) == 0){
                    DLX(0,printf("\t\t\tFOUND GO!\n"));
                    ptr = (int (*)(void))elfinfo.sectionMappings[syms[c2].st_shndx] + syms[c2].st_value;
                }
                DLX(0,printf("\t\t\tSymbolSectionIndex: %d\n", syms[c2].st_shndx));
                if (elfinfo.sectionMappings != NULL && syms[c2].st_shndx < elfinfo.sectHeaderNum && syms[c2].st_shndx != 0){
                    DLX(0,printf("\t\t\tSymbolAddress(real): %p\n", elfinfo.sectionMappings[syms[c2].st_shndx] + syms[c2].st_value));
                }
            }
        }
    }
    DLX(0,printf("\tTempOffsetTable: %p\n", elfinfo.tempOffsetTable));
    if (mprotect(elfinfo.tempOffsetTable, 255*ThunkTrampolineSize, PROT_READ | PROT_EXEC) != 0){
        DLX(0,printf("\tFailed to mprotect the thunk table\n"));
    }
    
    for (counter = 0; counter < elfinfo.sectHeaderNum; counter++){
        DLX(0,printf("\tSection #%d mapped at %p\n", counter, elfinfo.sectionMappings[counter]));
        if (elfinfo.sectionMappings[counter] != NULL){
            if (mprotect(elfinfo.sectionMappings[counter], elfinfo.sectHeader[counter].sh_size, elfinfo.sectionMappingProts[counter]) != 0){
                DLX(0,printf("\tFailed to protect memory\n"));
            }
        }
    }

    if(ptr != NULL){
        DLX(0,printf("\tTrying to run ptr......\n"));
            /* NOTE: Change this to pass in arguments for ones that use it */
        (void)ptr();
        DLX(0,printf("\tReturned from ptr\n"));
    }else{
        DLX(0,printf("\tNot found ptr\n"));
    }

cleanup:
    DLX(0,printf("\tCleaning up...\n"));
    for (counter = 0; counter < elfinfo.sectHeaderNum; counter++){
        DLX(0,printf("\tFreeing Section #%d\n", counter));
        if (elfinfo.sectionMappings != NULL){
            if (elfinfo.sectionMappings[counter] != NULL){
                if (munmap(elfinfo.sectionMappings[counter], elfinfo.sectHeader[counter].sh_size)  != 0){
                    DLX(0,printf("\tFailed to unmap memory\n"));
                }
            }
        }
    }
    if (elfinfo.tempOffsetTable){
        munmap(elfinfo.tempOffsetTable, 255*ThunkTrampolineSize);
    }

    if (elfinfo.sectionMappings){
        free(elfinfo.sectionMappings);
    }
    if (elfinfo.sectionMappingProts){
        free(elfinfo.sectionMappingProts);
    }

    DLX(0,printf("\tReturning\n"));
    return retcode;
}

int main(void)
{
    FILE *file;
    long file_size;
    char *buffer;

    file = fopen("hello", "rb");
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

    elf_parse(buffer,"print_hello");

    free(buffer);
    fclose(file);

    return 0;
}
```

