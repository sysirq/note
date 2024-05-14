#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/fs.h>        // for basic filesystem
#include <linux/proc_fs.h>    // for the proc filesystem
#include <linux/seq_file.h>    // for sequence files
#include <linux/string.h>

static struct proc_dir_entry* jif_file;

static void *nowCacheAddr = NULL;

inline void cflush(volatile int *p){
	 __asm__ __volatile__("clflush (%0)"::"r"(p));
}


static int jif_show(struct seq_file *m, void *v)
{
    return 0;
}

static int jif_open(struct inode *inode, struct file *file)
{
     return single_open(file, jif_show, NULL);
}

static ssize_t jif_read(struct file * file,char *data,size_t len,loff_t *off){
	if(len < sizeof(nowCacheAddr)){
		return -1;
	}
	memcpy(data,&nowCacheAddr,sizeof(nowCacheAddr));
	return sizeof(nowCacheAddr);
}

static ssize_t jif_write(struct file * file,const char *data,size_t len,loff_t *off){

	if(len > sizeof(nowCacheAddr)){
		return -1;
	}
	memcpy(&nowCacheAddr,data,sizeof(nowCacheAddr));
	return len;

}

static const struct file_operations jif_fops = {
    .owner    = THIS_MODULE,
    .open    = jif_open,
    .read    = jif_read,
    .write   = jif_write,
    .llseek    = seq_lseek,
    .release    = single_release,
};


static int __init jif_init(void)
{
    jif_file = proc_create("jif", 0666, NULL, &jif_fops);

    if (!jif_file) {
        return -ENOMEM;
    }

    return 0;
}

static void __exit jif_exit(void)
{
    remove_proc_entry("jif", NULL);
}

module_init(jif_init);
module_exit(jif_exit);

MODULE_LICENSE("GPL");
