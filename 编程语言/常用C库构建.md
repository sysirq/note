# libcurl

```
./configure --prefix=$(pwd)/build --disable-shared --enable-static --without-libidn --without-ssl --without-librtmp --without-gnutls --without-nss --without-libssh2 --without-zlib --without-winidn --disable-rtsp --disable-ldap --disable-ldaps --disable-ipv6
```

linux静态编译libcurl出.a文件，连接到自己的项目中

https://zhuanlan.zhihu.com/p/86307842

libcurl 静态编译及初步使用（Linux环境）

https://blog.csdn.net/u012467749/article/details/50740006

eg

```c
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include "curl/curl.h"
#include "LzmaLib.h"

// 回调函数，用于将下载的数据写入文件
size_t write_data(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    size_t written = fwrite(ptr, size, nmemb, stream);
    return written;
}

int test_curl()
{
    // 初始化libcurl
    CURL *curl = curl_easy_init();
    
    if (curl) {
        // 设置下载的URL
        const char *url = "http://www.example.com/file-to-download.txt";
        curl_easy_setopt(curl, CURLOPT_URL, url);

        // 设置回调函数，将数据写入文件
        FILE *fp = fopen("downloaded_file.txt", "wb");
        if (!fp) {
            fprintf(stderr, "Error opening file.\n");
            return 1;
        }
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);

        // 执行HTTP请求
        CURLcode res = curl_easy_perform(curl);
        
        // 检查请求是否成功
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }

        // 关闭文件
        fclose(fp);

        // 清理资源
        curl_easy_cleanup(curl);
    }
    return 0;
}
```

# 7zip

sdk从官网下载

cmake中引入

```cmake
# adding sources
file(GLOB 7Z_SOURCE "../common/lzma2301/C/*.c")

set( MAIN_SOURCE
        src/main.c
)

# add compiled demons
add_executable( ${PROJECT_NAME} ${MAIN_SOURCE} ${7Z_SOURCE})
```

eg:

```c
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include "curl/curl.h"
#include "LzmaLib.h"


void Usage()
{
    fputs(
        "Usage:\n"
        "LZMAComp <command> <input> <output>\n"
        "Command:\n"
        "  -c: Compress a single file <input> into <output>.\n"
        "  -d: Decompress a single file <input> into <output>.\n",stderr);
}


int CompressFile(FILE*fpOut,FILE*fpIn,unsigned long InSize);
int DecompressFile(FILE*fpOut,FILE*fpIn);

int main(int argc,char**argv)
{
    if(argc<4)
    {
        Usage();
        return 1;
    }
    if(!strncmp(argv[1],"-c",2))//压缩一个文件
    {
        FILE*fp=fopen(argv[2],"rb");
        FILE*fpout=fopen(argv[3],"wb");
        int iRet;
        unsigned long fLen;
        if(!fp)
        {
            fprintf(stderr,"Unable to open %s\n",argv[2]);
            return 2;
        }
        if(!fpout)
        {
            fprintf(stderr,"Unable to write %s\n",argv[3]);
            return 2;
        }
        fseek(fp,0,SEEK_END);
        fLen=ftell(fp);
        fseek(fp,0,SEEK_SET);
        printf("Input file size=%u\n",fLen);
        iRet=CompressFile(fpout,fp,fLen);
        if(iRet)
            fprintf(stderr,"Error:%d\n",iRet);
        fclose(fpout);
        fclose(fp);
        if(iRet)
            unlink(argv[3]);
        return iRet;
    }
    if(!strncmp(argv[1],"-d",2))//解压一个文件
    {
        FILE*fp=fopen(argv[2],"rb");
        FILE*fpout=fopen(argv[3],"wb");
        int iRet;
        if(!fp)
        {
            fprintf(stderr,"Unable to open %s\n",argv[2]);
            return 2;
        }
        if(!fpout)
        {
            fprintf(stderr,"Unable to write %s\n",argv[3]);
            return 2;
        }
        iRet=DecompressFile(fpout,fp);
        if(iRet)
            fprintf(stderr,"Error:%d\n",iRet);
        fclose(fpout);
        fclose(fp);
        if(iRet)
            unlink(argv[3]);
        return iRet;
    }
    Usage();
    return 1;
}

int CompressFile(FILE*fpOut,FILE*fpIn,unsigned long InSize)
{
    void*pInBuffer;//输入缓冲区
    void*pOutBuffer;//输出缓冲区
    unsigned long OutSize;//输出缓冲区大小

    unsigned char Props[LZMA_PROPS_SIZE];//属性
    size_t PropsSize=LZMA_PROPS_SIZE;//属性大小

    pInBuffer=malloc(InSize);//缓冲区分配内存
    pOutBuffer=malloc(OutSize=InSize);//输出缓冲区分配和输入缓冲区一样大的内存
    if(!pInBuffer||!pOutBuffer)
    {
        free(pInBuffer);
        free(pOutBuffer);
        return 2;
    }

    fread(pInBuffer,1,InSize,fpIn);//读取文件

    switch(LzmaCompress(//开始压缩
        pOutBuffer,&OutSize,//输出缓冲区，大小
        pInBuffer,InSize,//输入缓冲区，大小
        Props,&PropsSize,//属性，属性大小
        9,0,-1,-1,-1,-1,-1))//压缩比最大。其余全部取默认
    {
    case SZ_OK://成功完成
        fwrite(&InSize,1,sizeof(InSize),fpOut);//写入原数据大小
        fwrite(&OutSize,1,sizeof(OutSize),fpOut);//写入解压后的数据大小
        fwrite(Props,1,PropsSize,fpOut);//写入属性
        fwrite(pOutBuffer,1,OutSize,fpOut);//写入缓冲区
        free(pInBuffer);//释放内存
        free(pOutBuffer);
        return 0;
    case SZ_ERROR_PARAM://参数错误
        free(pInBuffer);
        free(pOutBuffer);
        return 1;
    default:
    case SZ_ERROR_MEM://内存分配错误
    case SZ_ERROR_THREAD://线程错误
        free(pInBuffer);
        free(pOutBuffer);
        return 2;
    case SZ_ERROR_OUTPUT_EOF://缓冲区过小
        free(pInBuffer);
        free(pOutBuffer);
        return 3;
    }
}

int DecompressFile(FILE*fpOut,FILE*fpIn)
{
    void*pSrcBuffer;
    size_t InSize;

    void*pDestBuffer;
    size_t OutSize;

    unsigned char Props[LZMA_PROPS_SIZE];

    fread(&OutSize,1,sizeof(OutSize),fpIn);//读取原数据大小
    fread(&InSize,1,sizeof(InSize),fpIn);//读取压缩后的数据大小

    printf("Outsize:0x%lX Insize:0x%lX\n",OutSize,InSize);

    pDestBuffer=malloc(OutSize);//分配内存
    pSrcBuffer=malloc(InSize);//分配内存
    if(!pSrcBuffer||!pDestBuffer)//内存不足
    {
        free(pSrcBuffer);
        free(pDestBuffer);
        return 2;
    }

    fread(Props,1,sizeof(Props),fpIn);
    fread(pSrcBuffer,1,InSize,fpIn);

    switch(LzmaUncompress(pDestBuffer,&OutSize,pSrcBuffer,&InSize,Props,sizeof(Props)))
    {
    case SZ_OK:
        fwrite(pDestBuffer,1,OutSize,fpOut);
        free(pDestBuffer);
        free(pSrcBuffer);
        return 0;
    case SZ_ERROR_DATA:
    case SZ_ERROR_UNSUPPORTED:
    case SZ_ERROR_INPUT_EOF:
        free(pDestBuffer);
        free(pSrcBuffer);
        return 1;
    default:
    case SZ_ERROR_MEM:
        free(pDestBuffer);
        free(pSrcBuffer);
        return 2;
    }
}

```

从文件中解压7z

```c
#include "7zCrc.h"
#include "7zFile.h"
#include "7zVersion.h"
#include "7zTypes.h"
#include "7z.h"
#include "7zAlloc.h"

int extract_from_file(int numargs, char *args[])
{
    char *archivePath = NULL;
    CSzArEx db;
    CFileInStream archiveStream;
    CLookToRead2 lookStream;
    SRes res;
    ISzAlloc allocImp;
    ISzAlloc allocTempImp;
    size_t tempSize = 0;
    UInt32 blockIndex = 0xFFFFFFFF; /* it can have any value before first call (if outBuffer = 0) */
    Byte *outBuffer = 0; /* it must be 0 before first call for each new archive. */
    size_t outBufferSize = 0;  /* it can have any value before first call (if outBuffer = 0) */
    size_t offset = 0;
    size_t outSizeProcessed = 0;

    archivePath = "SILENT_NURSE.7z";
    
    allocImp = g_Alloc;
    allocTempImp = g_Alloc;
    // 初始化7-Zip库
    SzArEx_Init(&db);

    // 打开存档文件
    if (InFile_Open(&archiveStream.file, archivePath))
    {
#ifdef DEBUG
        printf("InFile Open:%s\n",archivePath);
#endif
        return 1;
    }

    FileInStream_CreateVTable(&archiveStream);
    archiveStream.wres = 0;
    LookToRead2_CreateVTable(&lookStream, False);
    lookStream.buf = NULL;

    lookStream.buf = (Byte *)ISzAlloc_Alloc(&allocImp, kInputBufSize);
    if(lookStream.buf  == NULL){
#ifdef DEBUG
        printf("malloc kInputBufSize error\n");
#endif
        return -1;
    }
    
    lookStream.bufSize = kInputBufSize;
    lookStream.realStream = &archiveStream.vt;
    LookToRead2_INIT(&lookStream)

    CrcGenerateTable();
    SzArEx_Init(&db);  

    res = SzArEx_Open(&db, &lookStream.vt, &allocImp, &allocTempImp);
    if (res != SZ_OK)
    {
#ifdef DEBUG
        printf("SzArEx_Open error\n");
#endif
        return -1;
    }

    if(db.NumFiles != 1){
#ifdef DEBUG
        printf("error file number\n");
#endif
        return -1;
    }

    UInt64 fileSize;
    fileSize = SzArEx_GetFileSize(&db, 0);
    printf("%lu\n",fileSize);

    SzArEx_Extract(&db, &lookStream.vt, 0,
              &blockIndex, &outBuffer, &outBufferSize,
              &offset, &outSizeProcessed,
              &allocImp, &allocTempImp);

    printf("%lu\n",outBufferSize);

    FILE *file = fopen("example.txt", "wb");
    if (file == NULL) {
#ifdef DEBUG
        perror("Error opening file");
#endif
        return 1;
    }
    fwrite(outBuffer,outBufferSize,1,file);
    fclose(file);

    SzArEx_Free(&db, &allocImp);
    ISzAlloc_Free(&allocImp, lookStream.buf);
    File_Close(&archiveStream.file);
    ISzAlloc_Free(&allocImp, outBuffer);
  
    return 0;
}
```

从内存中解压7z

```c
#include "extract_7z_data.h"

#define kInputBufSize ((size_t)1 << 18)
static const ISzAlloc g_Alloc = { SzAlloc, SzFree };

static char *p7zip_data = NULL;
static Int64 p7zip_data_len = 0;
static Int64 p7zip_data_pos = 0;

static SRes InStreamWrap_Read(ISeekInStreamPtr p, void *buf, size_t *size)
{
    size_t real_copy = 0;
    size_t originalSize = *size;
    
    if( (originalSize + p7zip_data_pos) > p7zip_data_len){
        real_copy = p7zip_data_len - p7zip_data_pos;
    }else{
        real_copy = originalSize;
    }
    memcpy(buf,p7zip_data + p7zip_data_pos,real_copy);

    *size = real_copy;
    p7zip_data_pos += real_copy;

    return SZ_OK;
}

static SRes InStreamWrap_Seek(ISeekInStreamPtr p, Int64 *offset, ESzSeek origin)
{
    switch ((int)origin)
    {
        case SZ_SEEK_SET: 
            p7zip_data_pos = *offset; 
            break;
        case SZ_SEEK_CUR: 
            p7zip_data_pos = p7zip_data_pos + *offset; 
            break;
        case SZ_SEEK_END: 
            p7zip_data_pos = p7zip_data_len + *offset; 
            break;
        default: 
            return SZ_ERROR_PARAM;
    }
    *offset = p7zip_data_pos;

    return SZ_OK;
}

static ISeekInStream vt = {
    .Read = InStreamWrap_Read,
    .Seek = InStreamWrap_Seek,
};

int extract_7z_data_from_mem(char *inBuf,size_t inBufSize,char *outBuf,size_t *outBufsize)
{
    CLookToRead2 lookStream;
    CSzArEx db;
    SRes res;
    ISzAlloc allocImp;
    ISzAlloc allocTempImp;
    
    UInt64 fileSize;
    UInt32 blockIndex = 0xFFFFFFFF; /* it can have any value before first call (if outBuffer = 0) */
    Byte *outBuffer = 0; /* it must be 0 before first call for each new archive. */
    size_t outBufferSize = 0;  /* it can have any value before first call (if outBuffer = 0) */
    size_t offset = 0;
    size_t outSizeProcessed = 0;

    allocImp = g_Alloc;
    allocTempImp = g_Alloc;

    p7zip_data = inBuf;
    p7zip_data_len = inBufSize;
    p7zip_data_pos = 0;

    LookToRead2_CreateVTable(&lookStream, False);
    lookStream.buf = NULL;

    lookStream.buf = (Byte *)ISzAlloc_Alloc(&allocImp, kInputBufSize);
    if(lookStream.buf  == NULL){
        printf("\tISzAlloc_Alloc error...\n");
        return -1;
    }

    lookStream.bufSize = kInputBufSize;
    lookStream.realStream = &vt;
    LookToRead2_INIT(&lookStream);

    CrcGenerateTable();
    SzArEx_Init(&db);

    res = SzArEx_Open(&db, &lookStream.vt, &allocImp, &allocTempImp);
    if (res != SZ_OK)
    {
         printf("\tSzArEx_Open error...\n");
        return -1;
    }

    printf("\tdb.NumFiles: %d...\n",db.NumFiles);
    if(db.NumFiles != 1)
    {
        printf("\terror db.NumFiles...\n");
        return -1;
    }

    fileSize = SzArEx_GetFileSize(&db, 0);
     printf("\tSzArEx_GetFileSize: %ld...\n",fileSize);

    if(fileSize > *outBufsize){
        printf("\tfileSize > outBufsize...\n");
        ISzAlloc_Free(&allocImp, lookStream.buf);
        SzArEx_Free(&db, &allocImp);
        return -1;
    }

    SzArEx_Extract(&db, &lookStream.vt, 0,
              &blockIndex, &outBuffer, &outBufferSize,
              &offset, &outSizeProcessed,
              &allocImp, &allocTempImp);
    printf("\toutBufferSize: %ld...\n",outBufferSize);

    memcpy(outBuf,outBuffer,outBufferSize);
    *outBufsize = outBufferSize;

    ISzAlloc_Free(&allocImp, lookStream.buf);
    SzArEx_Free(&db, &allocImp);
    ISzAlloc_Free(&allocImp, outBuffer);
    return 0;
}
```

https://www.0xaa55.com/thread-514-1-1.html