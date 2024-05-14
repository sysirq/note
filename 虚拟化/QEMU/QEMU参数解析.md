# vm_config_groups

总的选项分类（目前QEMU一共支持48个选项）

eg:qemu_find_opts("machine")

# QemuOptsList

通过qemu_find_opts("machine")找到对应的QemuOptsList

# QemuOpts

QemuOptsList中的元素

# QemuOpt

QemuOpts中的元素，保存真正的选项（key,value）

# 数据结构

```c
struct QemuOptsList {
    const char *name;
    const char *implied_opt_name;
    bool merge_lists;  /* Merge multiple uses of option into a single list? */
    QTAILQ_HEAD(, QemuOpts) head;
    QemuOptDesc desc[];
};

struct QemuOpts {
    char *id;
    QemuOptsList *list;
    Location loc;
    QTAILQ_HEAD(, QemuOpt) head;
    QTAILQ_ENTRY(QemuOpts) next;
};

struct QemuOpt {
    char *name;
    char *str;

    const QemuOptDesc *desc;
    union {
        bool boolean;
        uint64_t uint;
    } value;

    QemuOpts     *opts;
    QTAILQ_ENTRY(QemuOpt) next;
};
```

# 资料

QEMU参数解析

http://terenceli.github.io/%E6%8A%80%E6%9C%AF/2015/09/26/qemu-options