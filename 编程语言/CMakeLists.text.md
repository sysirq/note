# 构建命令

```
cd build
cmake ../
```

# 依赖解决

可以用add_dependencies，指定依赖关系，

eg:

``` 
add_executable( ${PROJECT_NAME} ${MAIN_SOURCE})
add_dependencies( ${PROJECT_NAME} libcurl )

target_link_libraries(
  ${PROJECT_NAME} libcurl.a
)
```

add_dependencies中所填写的名字应该是其他CMAKE生成目标的名字。

# 目录结构

```
r1ng0@r1ng0-virtual-machine ~/Work/Demo/payload$ tree -L 3 
.
├── common
│   └── mbedtls
│       ├── 3rdparty
│       ├── BRANCHES.md
│       ├── BUGS.md
│       ├── ChangeLog
│       ├── ChangeLog.d
│       ├── cmake
│       ├── CMakeLists.txt
│       ├── configs
│       ├── CONTRIBUTING.md
│       ├── DartConfiguration.tcl
│       ├── dco.txt
│       ├── docs
│       ├── doxygen
│       ├── include
│       ├── library
│       ├── LICENSE
│       ├── Makefile
│       ├── programs
│       ├── README.md
│       ├── scripts
│       ├── SECURITY.md
│       ├── SUPPORT.md
│       ├── tests
│       └── visualc
└── sources-linux
    ├── build
    │   ├── beacon
    │   ├── CMAKE_BINARY_DIR
    │   ├── CMakeCache.txt
    │   ├── CMakeFiles
    │   ├── cmake_install.cmake
    │   ├── linux_server64
    │   ├── Makefile
    │   └── mbedtls
    ├── CMakeCache.txt
    ├── CMakeFiles
    │   ├── 3.22.1
    │   ├── cmake.check_cache
    │   ├── CMakeOutput.log
    │   └── CMakeTmp
    ├── CMakeLists.txt
    ├── include
    │   ├── beacon.h
    │   ├── common.h
    │   ├── debug.h
    │   └── threads.h
    └── src
        ├── beacon.c
        ├── debug.c
        ├── main.c
        └── threads.c


```

# CMakeLists.txt

```
cmake_minimum_required(VERSION 3.19)
project(beacon)
set( PROJECT_NAME beacon )

# set compiler settings
set( CMAKE_C_FLAGS "--pie" )

# Disable in-source builds to prevent source tree corruption.
if(" ${CMAKE_SOURCE_DIR}" STREQUAL " ${CMAKE_BINARY_DIR}")
  message(FATAL_ERROR "
FATAL: In-source builds are not allowed.
       You should create a separate directory for build files.
")
endif()

# common library
add_subdirectory(../common/mbedtls/ ${CMAKE_BINARY_DIR}/mbedtls)

include_directories( include )
include_directories( ${CMAKE_BINARY_DIR}/mbedtls/include )
link_directories( ${CMAKE_BINARY_DIR}/mbedtls/library )

# adding sources

set( MAIN_SOURCE
        src/main.c
        src/beacon.c
        src/debug.c
        src/threads.c
)

# preprocessor flags
add_compile_definitions( DEBUG )

# add compiled demons
add_executable( ${PROJECT_NAME} ${MAIN_SOURCE} )


target_link_libraries(${PROJECT_NAME} libmbedtls.a libmbedcrypto.a libmbedx509.a)
```

# CMakeLists.txt

```
cmake_minimum_required(VERSION 3.19)
project(linux_loader)
set( PROJECT_NAME linux_loader )

# set compiler settings
# set( CMAKE_C_FLAGS "--pie -O3 -s -fno-unwind-tables -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections -Wl,-gc-sections -fno-stack-protector" )
set( CMAKE_C_FLAGS "-g" )

# Disable in-source builds to prevent source tree corruption.
if(" ${CMAKE_SOURCE_DIR}" STREQUAL " ${CMAKE_BINARY_DIR}")
  message(FATAL_ERROR "
FATAL: In-source builds are not allowed.
       You should create a separate directory for build files.
")
endif()

# common library
set(HTTP_ONLY ON)
set(CURL_ENABLE_SSL OFF)
set(BUILD_STATIC_LIBS ON)
set(BUILD_CURL_EXE OFF)
set(BUILD_SHARED_LIBS OFF)
set(CURL_ENABLE_SSL OFF)
set(ENABLE_IPV6 OFF)
set(HAVE_ATOMIC OFF)
set(USE_UNIX_SOCKETS OFF)
set(CURL_DISABLE_ALTSVC ON)
set(USE_WIN32_LARGE_FILES OFF)
set(CURL_DISABLE_HSTS ON)
set(ENABLE_THREADED_RESOLVER OFF)
add_subdirectory(../common/tiny-curl-8.4.0  ${CMAKE_BINARY_DIR}/tiny-curl-8.4.0 )

# include dir
include_directories( ../common/lzma2301/C )
include_directories( include )
include_directories( ../common/tiny-curl-8.4.0/include/ )

# link dir
link_directories( ${CMAKE_BINARY_DIR}/tiny-curl-8.4.0/lib/ )

# adding sources
file(GLOB 7Z_SOURCE "../common/lzma2301/C/*.c")

set( MAIN_SOURCE
        src/main.c
        src/extract_7z_data.c
        src/get_payload_from_server.c
        src/exec_payload.c
        src/elf_loader.c
)

# preprocessor flags
add_compile_definitions( DEBUG )

# add compiled demons
add_executable( ${PROJECT_NAME} ${MAIN_SOURCE} ${7Z_SOURCE})
add_dependencies( ${PROJECT_NAME} libcurl )

target_link_libraries(
  ${PROJECT_NAME} libcurl.a
)
```
# 小技巧


```
1.动态库去掉前缀

SET(CMAKE_SHARED_LIBRARY_PREFIX "")

2.去掉RPATH

SET(CMAKE_SKIP_BUILD_RPATH TRUE)
```

可以到CMakeFiles/xxx.dir/link.txt 查看最终的编译命令

# 使libcurl库使用mbedtls并启用CJSON

```
cmake_minimum_required(VERSION 3.19)
project(beacon)
set( PROJECT_NAME beacon )

# set compiler settings
set(CMAKE_C_FLAGS "-static-pie -O3 -s -fno-unwind-tables -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections -Wl,-gc-sections -fno-stack-protector" )
set(CMAKE_SKIP_BUILD_RPATH TRUE)
set(CMAKE_LINK_SEARCH_START_STATIC TRUE)

# Disable in-source builds to prevent source tree corruption.
if(" ${CMAKE_SOURCE_DIR}" STREQUAL " ${CMAKE_BINARY_DIR}")
  message(FATAL_ERROR "
FATAL: In-source builds are not allowed.
       You should create a separate directory for build files.
")
endif()



include_directories( include )
include_directories( ${CMAKE_SOURCE_DIR}/lib/curl-8.10.1/include )
include_directories( ${CMAKE_SOURCE_DIR}/lib/mbedtls-3.6.2/include )
include_directories( ${CMAKE_SOURCE_DIR}/lib/cJSON-1.7.18 )

# common library
set(HTTP_ONLY ON)
set(NGHTTP2 OFF)
set(USE_LIBIDN2 OFF)
set(CURL_USE_LIBPSL OFF)
set(CURL_USE_LIBSSH2 OFF)
set(HAVE_LIBZ OFF)
set(ZLIB_FOUND OFF)
set(CURL_DISABLE_WEBSOCKETS ON)
set(BUILD_TESTING OFF)
set(BUILD_STATIC_LIBS ON)
set(BUILD_CURL_EXE OFF)
set(BUILD_SHARED_LIBS OFF)
set(ENABLE_IPV6 OFF)
set(HAVE_ATOMIC OFF)
set(USE_UNIX_SOCKETS OFF)
set(CURL_DISABLE_ALTSVC ON)
set(USE_WIN32_LARGE_FILES OFF)
set(CURL_DISABLE_HSTS ON)
set(ENABLE_THREADED_RESOLVER OFF)
set(CURL_DISABLE_IMAPS ON)
set(CURL_ENABLE_SSL OFF)
set(USE_MBEDTLS ON)
set(_ssl_enabled ON)
set(CURL_USE_mbedTLS ON)
set(mbedTLS_LIBRARIES mbedx509 mbedcrypto mbedtls)
set(mbedTLS_INCLUDE_DIRS ${CMAKE_SOURCE_DIR}/lib/mbedtls-3.6.2/include)
add_subdirectory(${CMAKE_SOURCE_DIR}/lib/curl-8.10.1/  ${CMAKE_BINARY_DIR}/curl)

set(ENABLE_TESTING OFF)
set(mbedTLS_AS_SUBPROJECT ON)
set(ENABLE_PROGRAMS OFF)
set(USE_STATIC_mbedTLS_LIBRARY ON)
set(USE_SHARED_mbedTLS_LIBRARY OFF)
add_subdirectory(${CMAKE_SOURCE_DIR}/lib/mbedtls-3.6.2/ ${CMAKE_BINARY_DIR}/mbedtls)

set(ENABLE_PUBLIC_SYMBOLS OFF)
set(ENABLE_CJSON_VERSION_SO OFF)
set(ENABLE_CJSON_TEST OFF)
set(ENABLE_CJSON_UNINSTALL OFF)
set(ENABLE_LOCALES OFF)
set(CJSON_OVERRIDE_BUILD_SHARED_LIBS OFF)
set(CJSON_BUILD_SHARED_LIBS OFF)
set(BUILD_SHARED_LIBS OFF)
add_subdirectory(${CMAKE_SOURCE_DIR}/lib/cJSON-1.7.18/ ${CMAKE_BINARY_DIR}/cJSON)

link_directories( ${CMAKE_BINARY_DIR}/curl/lib/ )
link_directories( ${CMAKE_BINARY_DIR}/mbedtls/library )

# adding sources
set( MAIN_SOURCE
        src/main.c
)

# preprocessor flags
add_compile_definitions( DEBUG )

# add compiled demons
add_executable( ${PROJECT_NAME} ${MAIN_SOURCE} )

add_dependencies(${PROJECT_NAME} libcurl mbedtls mbedx509 mbedcrypto cjson)

target_link_libraries(${PROJECT_NAME} curl mbedx509 mbedcrypto mbedtls cjson)

```

main.c

```c
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include "mbedtls/aes.h"
#include "curl/curl.h"
#include "debug.h"
#include "cJSON.h"

#define INFO_FILE_NAME "downloaded_file.txt"

#ifdef DEBUG
int dbug_level_ = 1;
#endif

size_t write_data(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    size_t written = fwrite(ptr, size, nmemb, stream);
    return written;
}

int get_ip_info()
{
    // 初始化libcurl
    CURL *curl = curl_easy_init();
    
    if (curl) {
        // 设置下载的URL
        const char *url = "https://ipinfo.io";
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);

        // 设置回调函数，将数据写入文件
        FILE *fp = fopen(INFO_FILE_NAME, "wb");
        if (!fp) {
            fprintf(stderr, "Error opening file.\n");
            curl_easy_cleanup(curl);
            return 1;
        }
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);

        // 执行HTTP请求
        CURLcode res = curl_easy_perform(curl);
        
        // 检查请求是否成功
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            fclose(fp);
            curl_easy_cleanup(curl);
            return -1;
        }

        // 关闭文件
        fclose(fp);

        // 清理资源
        curl_easy_cleanup(curl);
        return 0;
    }
    return -1;
}

int main(void)
{
    FILE *file;
    long file_size;
    char *buffer;
    cJSON* cjson_test = NULL;
    cJSON* cjson_country = NULL;

    if(get_ip_info()!=0){
        printf("get ip info error\n");
        return -1;
    }

    file = fopen(INFO_FILE_NAME, "rb");
    if (file == NULL) {
        perror("Error opening file");
        return -1;
    }

    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    rewind(file);

    buffer = malloc(file_size + 1);
    if (buffer == NULL) {
        perror("Memory allocation failed");
        fclose(file);
        return -1;
    }

    // 读取文件内容
    fread(buffer, 1, file_size, file);
    buffer[file_size] = '\0'; // 以空字符结束字符串

    // JSON解析
    // printf("%s", buffer);
    cjson_test = cJSON_Parse(buffer);
    if(cjson_test == NULL){
        printf("parse fail.");
        
        free(buffer);
        fclose(file);
        return -1;
    }

    cjson_country = cJSON_GetObjectItem(cjson_test,"country");

    printf("country:%s\n",cjson_country->valuestring);

    cJSON_Delete(cjson_test);
    // 清理
    free(buffer);
    fclose(file);

    return 0;
}
```

其中 需要修改 curl 目录中的CMakeLists.txt

- 注释掉optional_dependency(ZLIB)
- 注释掉find_package(MbedTLS REQUIRED)

# 资料

cmake 引入第三方库（头文件目录、库目录、库文件）

https://blog.csdn.net/challenglistic/article/details/129093434

libcurl with mbedtls

https://git.vikingsoftware.com/blog/libcurl-with-mbedtls