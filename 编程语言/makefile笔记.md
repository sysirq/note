# Makefile 基本语法

```
目标:依赖
    命令
```

# Makefile 中的变量

### 系统变量

```
$*  #不包括扩展名的目标文件名称
$+  #所有的依赖文件，以空格分隔
$<  #表示规则中的第一个条件
$?  #所有时间戳比目标文件晚的依赖文件，以空格分隔
$@  #目标文件的完整名称
$^  #所有不重复的依赖文件，以空格分隔
$%  #如果目标是归档成员，则该变量表示目标的归档成员名称
```

### 自定义变量

```
定义：变量名=变量值
使用：$(变量名)/${变量名}
```

### eg

```c
CC = musl-gcc
CFLAGS = --static -O3 -s -fno-unwind-tables -fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections -Wl,-gc-sections -fno-stack-protector
INCLUDES = -I./include -I./lib/lzma2301
SOURCES = src/compression.c \
		src/hidden.c \
		src/loader.c \
		src/payload.c \
		src/sandbox_check.c \
		$(wildcard lib/lzma2301/*.c)  # Get all .c files in the src directory

OBJECTS = $(SOURCES:.c=.o)
TARGET=loader

all: $(TARGET)

$(TARGET):$(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^
%.o:%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -rf $(TARGET) $(OBJECTS)
```

# Makefile 定义命令

eg

```Makefile
ENABLE_DEBUG = 1
ENABLE_SANDBOX_CHECK = 0
SANDBOX_CHECK_UPTIME = 0
SANDBOX_CHECK_TIME_TO_SLEEP = 10
EVIL_PROCESS_NAME=\"\"
ENABLE_PRELOAD_ROOTKIT=0

ifeq ($(ENABLE_DEBUG), 1)
    # Commands for enabling feature A
    CFLAGS += -DDEBUG
endif

ifeq ($(ENABLE_SANDBOX_CHECK), 1)
    # Commands for enabling feature B
    CFLAGS += -DSANDBOX_CHECK
endif

ifeq ($(ENABLE_PRELOAD_ROOTKIT), 1)
    # Commands for enabling feature B
    CFLAGS += -DPRELOAD_ROOTKIT
endif
```

命令行调用Makefile
```shell
make target ENABLE_DEBUG=$enable_debug \
     ENABLE_SANDBOX_CHECK=$enable_sandbox_check \
     SANDBOX_CHECK_UPTIME=$sandbox_check_uptime \
     SANDBOX_CHECK_TIME_TO_SLEEP=$sandbox_check_time_to_sleep \
     EVIL_PROCESS_NAME=$evil_process_name \
     ENABLE_PRELOAD_ROOTKIT=$enable_preload_rootkit \
```

# 资料

Makefile入门

https://blog.csdn.net/zhexiangsi/article/details/129914471

Linux学习笔记——例说makefile 头文件查找路径

https://blog.csdn.net/xukai871105/article/details/36476793