# flag

PG_locked:表示页面已经上锁

PG_error:表示页面操作过程中发生错误时会设置该位

PG_referenced和PG_active:用于控制页面的活跃程度

PG_uptodate:表示页面的数据已经从块设备成功读取

PG_dirty:表示页面内容发生改变

PG_lru:表示页面加入了LRU链表中

PG_slab:表示页面用于slab分配

PG_writeback:表示页面的内容正在向块设备进行回写

PG_swapcache:表示页面处于交换缓存

PG_swapbacked:表示页面具有swap缓存功能

PG_reclaim:表示这个页面马上要被回收

PG_unevictable:表示页面不可被回收

PG_mlocked:表示页面对应的VMA处于mlocked状态。

PageXXX：如PageLRU用于检查PG_lru标志位是否置位

SetPageXXX:如SetPageLRU用于设置PG_lru位

ClearPageXXX:用于无条件的清除某个特定的标志位

注意：伙伴系统分配好的页面_count初始值为1，_count为0时表示页面已经被释放掉了。_mapcount==-1，表示没有pte映射到该页面。


