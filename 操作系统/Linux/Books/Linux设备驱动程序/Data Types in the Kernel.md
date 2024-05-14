Data types used by kernel data are divided into three main classes:standard C types such as int,explicitly sized type such as u32, and types used for specific kernel objects,such as pid_t.

# Use of Standard C Types

The kernel treats physical memory like huge array,and a memory address is just an index into the array.Therefore,generic memory addresses in the kernel are usually unsigned long.

# Assigning an Explicit Size to Data Items

```
#include <linux/types.h>
u8;
u16;
u32;
u64;
```

The corresponding signed type exist,but are rarely needed;just replace u with s in the name if you need them.

# Interface-Specific Types

# Other Portability Issues

### Iume Intervals

use HZ

### Page Size

use PAGE_SIZE PAGE_SHIFT macros (asm/page.h)

### Byte Order

### Data Alignment

### Pointers and Error Values

# Linked Listss

To use the list mechanism,your driver must include the file <linux/list.h>.This file defines a simple structure of type list_head:

```c
struct list_head{
    struct list_head *next,*prev;  
};
```

To use the Linux list facility in your code,you need only embed a list_head inside the structures that make up the list.

eg:

```
struct todo_struct{
    struct list_head list;
    int index;
};
```

List heads must be initialized prior to use with the INIT_LIST_HEAD macro.

```
list_add(struct list_head *new,struct list_head *head);
    Adds the new entry immediately after the list head

list_add_tail(struct list_head *new,struct list_head *head);
    Adds the new entry just before the given list head

list_del(struct list_head *entry);
list_del_init(struct list_head *entry);
    The given entry is removed from the list.
    
list_move(struct list_head *entry, struct list_head *head);
list_move_tail(struct list_head *entry, struct list_head *head);
    The given entry is removed from its current list and added to the beginning of head. To put the entry at the end of the new list, use list_move_tail instead.
    
list_empty(struct list_head *head);
    Returns a nonzero value if the given list is empty.
    
list_splice(struct list_head *list, struct list_head *head);
    Joins two lists by inserting list immediately after head.

list_for_each(struct list_head *cursor, struct list_head *list)
    This macro creates a for loop that executes once with cursor pointing at each successive entry in the list. Be careful about changing the list while iterating through it.
list_for_each_prev(struct list_head *cursor, struct list_head *list)
    This version iterates backward through the list.
    
list_for_each_safe(struct list_head *cursor, struct list_head *next, struct  list_head *list)
    If your loop may delete entries in the list, use this version. It simply stores the next entry in the list in next at the beginning of the loop, so it does not get confused if the entry pointed to by cursor is deleted.

list_for_each_entry(type *cursor, struct list_head *list, member)
list_for_each_entry_safe(type *cursor, type *next, struct list_head *list,  member)
    These macros ease the process of dealing with a list containing a given type of structure. Here,cursor is a pointer to the containing structure type, and member is the name of the list_head structure within the containing structure. With these macros, there is no need to put list_entry calls inside the loop.
```