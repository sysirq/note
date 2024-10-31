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

# 资料

cmake 引入第三方库（头文件目录、库目录、库文件）

https://blog.csdn.net/challenglistic/article/details/129093434