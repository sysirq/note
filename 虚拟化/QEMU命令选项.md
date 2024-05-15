# 磁盘

The most explicit way to describe disks is to use a combination of **-device** to specify the hardware device and **-blockdev** to describe the backend. **The device defines what the  guest  sees  and  the backend describes how QEMU handles the data**. **It is the only guaranteed stable interface for describing block devices** and as such is recommended for management tools and scripting.

