# Kernel Modules Versus Applications

Kernel modules programming is similar to event driven programming.

the task of the module's initialization function is to perpare for later invocation of the module's functions;it's as though the module were saying,"Here I am,and this is what I can do."The module's exit function gets invoked just before the module is unloaded.it should tell the kernel,"I'm not there anymore;don't ask me to do anything else".

A module,is linked only to the kernel,and the only functions it can call are the ones exported by the kernel

# Concurrency in the kernel

- interrupt handlers
- symmetric multiprocessor(SMP)
- kernel code has been made preemptible

As a result,Linux kernel code,including driver code,must be reentrant.

# A Few Other Details

Kernel code cannot do floating point arithmetic.

Kernel has very small stack.

Often,as you look at the kernel API,you will encounter function name starting with a double undersore(__).Essentially,it says to the programmer:"if you call this function,be sure you know what you are doing"

# Compiling Modules

```makefile
obj-m := hello.o

hello-objs := main.o add.o

all:
    make -C /usr/src/XXX/ M=`pwd` modules

clean:
    make -C /usr/src/XXX/ M=`pwd` clean
```

# Loading and Unloading Modules

```bash
insmod
```

The program loads the module code and data into the kernel,which,in turn,performs a function similar to the of ld,in that it links any unresolved symbol in the module to the symbol table of the kernel

```bash
modprobe
```

like insmod,load a module into the kernel.It differs in that it will look at the module to be loaded to see whether it references any symbols that are not currently defined in the kernel.If any such references are found,modprobe looks for other modules in the current module search path that define the relevant symbols.When modprobe finds those modules,it loads them into the kernel as well.

# The kernel symbol table

EXPORT_SYMBOL(name)
EXPORT_SYMBOL_GPL(name)

# Module Parameters

```shell
insmod hello.ko howmany=10 whom="Mom"
```

Parameters are declared with the module_param macro,which is defined in moduleparam.h .module_param takes three parameters: the name of the variable,its type , and a permissions mask to be used for an accompanying sysfs entry.
eg:

```c
static char *whom="world";
static int howmany=1;
module_param(howmany,int,S_IRUGO);
module_param(whom,charp,S_IRUGO);
```