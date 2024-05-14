# The Internal Representation of Device Numbers

Within the kernel,the dev_t type(defined in       linux/types.h ) is used to hold device numbers---both the major and minor parts.

it should,instead,make use of a set of macros found in linux/kdev_t.h.To obtain the major or minor parts of a dev_t,use:

```c
MAJOR(dev_t dev);
MINOR(dev_t dev);
```

If,instead,you have the major and minor numbers and need to turn them into a dev_t,use:

```c
MKDEV(int major,int minor);
```

# Allocating and Freeing Device Numbers

one of the first things your driver will need to do when setting up a char device is to obtain one or more device numbers to work with.

declared in linux/fs.h:

```c
//static alloc device number
int register_chrdev_region(dev_t first,unsigned int count,char *name);


//dynamic alloc
int alloc_chrdev_region(dev_t *dev,unsigned int firstminor,unsigned int count,char *name);//retval < 0 :error

//free device number
void unregister_chrdev_region(dev_t first,unsigned int count);
```

# Some Important Data Structures

#### File Operations

Each open file(represented internally by a file structrue)is associated with its own set of functions(by including a field called f_op that points to a file_operations structure)

We can consider the file to be an "object" and the functions operating on it to be its "method"(object-oriented programming)

#### The file Structure

The file structure represents an open file.

#### The inode Structure

The inode structure is used by the kernel internally to represent files.

There can be numerous file structures representing multiple open descriptors on a single file,but all point to a single inode structure.

# Char Device Registration

Before the kernel invokes your device's operations,you must allocate and register one or more of type struct cdev(linux/cdev.h).

There are two ways of allocating and initializing one of these structures.

```c
struct cdev *my_cdev = cdev_alloc();
my_cdev->ops = &my_fops;
//or
void cdev_init(struct cdev *cdev,struct file_operations *fops);
```

```c
int cdev_add(struct cdev *dev,dev_t num,unsigned int count);//retval != 0 ,error
```

```c
void cdev_del(struct cdev *dev);
```

# The open Method

```c
int (*open)(struct inode * inode,struct file *filp);
```

# The release Method

```c
int (*release)(struct inode * inode,struct file *filp);
```

# read and write

prototype:

```c
ssize_t read(struct file *filp,char __user *buf,size_t count,loff_t *offp);

ssize_t write(struct file *filp,const char __user *buf,size_t count,loff_t *offp);
```

copy a whole segment of data to or from the user address space.(linux/uaccess.h)

```c
unsigned long copy_to_user(void __user *to,const void *from,unsigned long count);

unsigned long copy_from_user(void *to,const void __user * from,unsigend long count);
```