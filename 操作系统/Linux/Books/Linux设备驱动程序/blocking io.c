#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/kdev_t.h>
#include <linux/cdev.h>
#include <linux/semaphore.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/uaccess.h>

#define dev_name "hanhan"
#define BUFSIZE 1024

dev_t my_dev_num;
struct cdev *my_cdev;

struct buff{
	int r_pos,w_pos;
	char *data;
	struct semaphore sem;
	wait_queue_head_t readq;
	wait_queue_head_t writeq;
};

int my_open(struct inode *inode,struct file *filep)
{
	struct buff *pbuff = kmalloc(sizeof(struct buff),GFP_KERNEL);
	if(pbuff == NULL){
		printk("struct buff malloc error\n");
		return -ENOMEM;
	}
	
	memset(pbuff,0,sizeof(struct buff));
	
	pbuff->data = kmalloc(BUFSIZE,GFP_KERNEL);
	if(pbuff->data == NULL){
		printk("buff->data malloc error\n");
		return -ENOMEM;
	}

	memset(pbuff->data,0,BUFSIZE);
	
	pbuff->r_pos = pbuff->w_pos = 0;

	sema_init(&pbuff->sem,1);
	
	init_waitqueue_head(&pbuff->readq);
	init_waitqueue_head(&pbuff->writeq);

	filep->private_data = pbuff;
		
	return 0;
}

int my_release(struct inode *inode,struct file *filep)
{
	struct buff *pbuff = filep->private_data;
	kfree(pbuff->data);
	kfree(pbuff);
	return 0;
}

ssize_t my_read(struct file *filp,char __user *buf,size_t count,loff_t *offp)
{
	int realcount = 0;
	int retcount = 0;
	int i = 0,j = 0;
	struct buff *pbuff = filp->private_data;
	if(down_interruptible(&pbuff->sem)){
		return -ERESTARTSYS;
	}

	while(pbuff->r_pos == pbuff->w_pos){
		up(&pbuff->sem);
		
		if(filp->f_flags & O_NONBLOCK){
			return -EAGAIN;
		}

		if(wait_event_interruptible(pbuff->readq,(pbuff->r_pos != pbuff->w_pos))){
			return -ERESTARTSYS;
		}
		if(down_interruptible(&pbuff->sem)){
			return -ERESTARTSYS;
		}

	}
	
	realcount = (pbuff->w_pos - pbuff->r_pos + BUFSIZE)%BUFSIZE;
	if(realcount > count){
		retcount = count;
	}
	else{
		retcount = realcount;
	}

	if(pbuff->w_pos > pbuff->r_pos){
		copy_to_user(buf,pbuff->data+pbuff->r_pos,retcount);
		pbuff->r_pos += retcount;
	}
	else{
		if( BUFSIZE - pbuff->r_pos > retcount ){
			copy_to_user(buf,pbuff->data+pbuff->r_pos,retcount);
			pbuff->r_pos += retcount;
		}
		else{
			j = BUFSIZE - pbuff->r_pos;
			copy_to_user(buf,pbuff->data+pbuff->r_pos,j);

			i = retcount - j;
			copy_to_user(buf+j,pbuff->data,i);

			pbuff->r_pos = i;

		}
	}
	
	up(&pbuff->sem);
	wake_up_interruptible(&pbuff->writeq);

	return retcount;
}

ssize_t my_write(struct file *filp,const char __user *buf,size_t count,loff_t *offp)
{
	int realcount = 0;
	int retcount = 0;
	int i = 0,j = 0;
	struct buff *pbuff = filp->private_data;
	if(down_interruptible(&pbuff->sem)){
		return -ERESTARTSYS;
	}

	while( (pbuff->w_pos + 1)%BUFSIZE == pbuff->r_pos ){
		up(&pbuff->sem);
		
		if(filp->f_flags & O_NONBLOCK){
			return -EAGAIN;
		}

		if(wait_event_interruptible(pbuff->writeq,(pbuff->w_pos+1)%BUFSIZE != pbuff->r_pos)){
			return -ERESTARTSYS;
		}
		if(down_interruptible(&pbuff->sem)){
			return -ERESTARTSYS;
		}
	
	}
	
	realcount = BUFSIZE - (pbuff->w_pos - pbuff->r_pos + BUFSIZE)%BUFSIZE - 1;

	if(realcount > count){
		retcount = count;
	}
	else{
		retcount = realcount;
	}

	if(pbuff->w_pos < pbuff->r_pos){
		copy_from_user(pbuff->data+pbuff->w_pos,buf,retcount);
		pbuff->w_pos += retcount;
	}
	else{
		if(BUFSIZE - pbuff->w_pos > retcount){
			copy_from_user(pbuff->data+pbuff->w_pos,buf,retcount);
			pbuff->w_pos += retcount;
		}
		else{
			j = BUFSIZE - pbuff->w_pos;
			copy_from_user(pbuff->data+pbuff->w_pos,buf,j);
			i = retcount - j;
			copy_from_user(pbuff->data,buf+j,i);
			pbuff->w_pos = i;
		}
	
	}
	up(&pbuff->sem);
	wake_up_interruptible(&pbuff->readq);

	return retcount;
}

struct file_operations my_ops = {
	.open = my_open,
	.release = my_release,
	.read = my_read,
	.write = my_write,
};

static int __init hello_init(void)
{
	int ret = 0;
	
	ret = alloc_chrdev_region(&my_dev_num,0,1,dev_name);
	if(ret < 0){
		printk("alloc chrdev region error\n");
		return -1;	
	}
	
	my_cdev = cdev_alloc();
	my_cdev->ops = &my_ops;
	
	ret = cdev_add(my_cdev,my_dev_num,1);
	if( ret != 0 ){
		printk("cdev_add error\n");
		return -1;
	}

	printk("hello module init\n");
	printk("major:%d,minor:%d\n",MAJOR(my_dev_num),MINOR(my_dev_num));
	return 0;
}

static void __exit hello_exit(void)
{
	cdev_del(my_cdev);
	unregister_chrdev_region(my_dev_num,1);
	printk("hello module exit\n");
}

module_init(hello_init);
module_exit(hello_exit);
MODULE_LICENSE("GPL");
