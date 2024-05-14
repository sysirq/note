首先是一个大类来包含下面的选项：

```c
struct QemuOptsList {
    const char *name;
    const char *implied_opt_name;
    bool merge_lists;  /* Merge multiple uses of option into a single list? */
    QTAILQ_HEAD(, QemuOpts) head;
    QemuOptDesc desc[];
};
```

eg:

```c
static QemuOptsList qemu_machine_opts = {
    .name = "machine",
    .implied_opt_name = "type",
    .merge_lists = true,
    .head = QTAILQ_HEAD_INITIALIZER(qemu_machine_opts.head),
    .desc = {
        /*
         * no elements => accept any
         * sanity checking will happen later
         * when setting machine properties
         */
        { }
    },
};
```

然后QemuOptsList中的head链表根据id不同，连接不同id选项的QemuOpts

```c
struct QemuOpts {
    char *id;
    QemuOptsList *list;
    Location loc;
    QTAILQ_HEAD(, QemuOpt) head;
    QTAILQ_ENTRY(QemuOpts) next;
};
```


最后QemuOpts中的head链表，连接正真的选项信息

```c
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

eg:

```c
opt	QemuOpt *	0x5555567ecec0	
	name	char *	0x5555567ecf00 "accel"	
	str	char *	0x5555567ecea0 "kvm"	
	desc	const QemuOptDesc *	0x0	
	value	union {...}	{...}	
		boolean	_Bool	false	
		uint	uint64_t	0	
	opts	QemuOpts *	0x5555567ecb70	
	next	union {...}	{...}	

```

# eg

比如选项: -netdev user,id=mynet
 
 ```
 ret	QemuOptsList *	0x55555672da80 <qemu_netdev_opts>	
	name	const char *	0x555555fc02e0 "netdev"	
	implied_opt_name	const char *	0x555555fc0056 "type"	
	merge_lists	_Bool	false	
	head	union {...}	{...}	
	desc	QemuOptDesc []	0x55555672daa8 <qemu_netdev_opts+40>	

opts	QemuOpts *	0x5555567ecc00	
	id	char *	0x5555567ecc50 "mynet"	
	list	QemuOptsList *	0x55555672da80 <qemu_netdev_opts>	
	loc	Location	{...}	
	head	union {...}	{...}	
	next	union {...}	{...}	


opt	QemuOpt *	0x5555567ecc90	
	name	char *	0x5555567eccd0 "type"	
	str	char *	0x5555567ecc70 "user"	
	desc	const QemuOptDesc *	0x0	
	value	union {...}	{...}	
	opts	QemuOpts *	0x5555567ecc00	
	next	union {...}	{...}	

 ```
 
 其中 id=mynet 会转化为QemuOpts