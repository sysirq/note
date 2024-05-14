# The Memory Map and Struct Page

struct page(defined in <linux/mm.h>).This data structure is used to keep track of just about everything the kernel needs to know about physical memory.there is one struct page for each physical page on the system.

Some of the fields of this structure include the following:

- atomic_t count;
    The number of references there are to this page.
- void *virtual;
    The kernel virtual address of the page
- unsigned long flags
    A set of bit flags describing the status of the page.

Some functions and macros are defined for translating between struct page pointers and virtual addresses:

```c
struct page *virt_to_page(void *kaddr);/*
This macro,defined
in <asm/page.h>,takes a kernel logical address and 
returns its associated struct page pointer.Since it 
requires a logical address,it does not work with 
memory from vmalloc or high memory
*/


struct page *pfn_to_page(int pfn)/*
Returns the struct page pointer for the given page 
frame number.If necessary,it checks a page frame 
number for validity with pfn_valid before passing it 
to pfn_to_page
*/

void *page_address(struct page*page);/*
Return the kernel virtual address of this page,if 
such an address exists.For high memory,that address 
exists only if the page has been mapped.
*/

#include <linux/highmem.h>
void *kmap(struct page *page);
void kunmap(struct page *page);
/*kmap returns a kernel virtual address for any page 
in the system. For low-mem-ory pages, it just returns the logical address of the page; for high-memory 
pages,kmap creates a special mapping in a dedicated 
part of the kernel address space.Mappings created 
with kmap should always be freed with kunmap; a 
limited number of such mappings is available, so it 
is better not to hold on to them for too 
long.kmap calls maintain a counter, so if two or more functions both call kmap on the same page, the right 
thing happens. Note also that kmap can sleep if no 
mappings are available*/
```

#### Virtual Memory Areas

Each field in /proc/*/maps(except the image name) corresponds to a field in struct vm_area_struct:

start、end、perm、offset、major、minor、inode、image

#### The vm_area_struct structure

