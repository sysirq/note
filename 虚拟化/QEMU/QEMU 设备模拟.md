# 概念

### 系统总线（System Bus）

系统总线是用来连接计算机硬件系统中若干主要部件（如：CPU、主存、I/O模块）的总线。Intel公司新推出的芯片组中，对系统总线赋予了特定的含义，把CPU连接到北桥芯片的总线称为系统总线，也称为处理器总线，或叫前端总线（Front Side Bus）。CPU通过前端总线（FSB）连接到北桥芯片，进而通过北桥芯片和内存、显卡交换数据。在系统总线上传输的有数据、地址和控制信息（控制信息包括：命令/定时/总线请求/总线允许/中断请求/中断允许/……等）。所以把系统总线也分成三组传输线：数据线、地址线、控制线。有时也把它们分别称为：数据总线、地址总线、控制总线。


# 数据结构

### Memory Control hub

设置MMCONFIG区域

DeviceClass --- DeviceState --- device_type_info

PCIDeviceClass --- PCIDevice --- pci_device_type_info

nullptr --- MCHPCIState --- mch_info

### 北桥

DeviceClass --- DeviceState --- device_type_info

SysBusDeviceClass --- SysBusDevice --- sysbus_device_type_info

PCIHostBridgeClass --- PCIHostState --- pci_host_type_info

nullptr --- PCIExpressHost --- pcie_host_type_info

nullptr --- Q35PCIHost --- q35_host_info

其中 main_system_bus 是系统总线，在pc_q35_init中初始化的q35_host是北桥芯片

北桥芯片连接内存、显存等高速缓存

### 总线

BusClass --- BusState --- bus_info

PCIBusClass --- PCIBus --- pci_bus_info

nullptr --- nullptr --- pcie_bus_info

### 设备

DeviceClass --- DeviceState --- device_type_info

PCIDeviceClass --- PCIDevice --- pci_device_type_info

### 桥

DeviceClass --- DeviceState --- device_type_info

PCIDeviceClass --- PCIDevice --- pci_device_type_info

nullptr --- PCIBridge --- pci_bridge_type_info


### PCIE

##### PCI Express Root Port

DeviceClass --- DeviceState --- device_type_info

PCIDeviceClass --- PCIDevice --- pci_device_type_info

nullptr --- PCIBridge --- pci_bridge_type_info

nullptr --- PCIEPort --- pcie_port_type_info

nullptr --- PCIESlot --- pcie_slot_type_info

PCIERootPortClass --- nullptr --- rp_info           # 设置配置空间写函数为rp_write_config，PCIDeviceClass的realize为rp_realize

nullptr --- nullptr --- ioh3420_info    # 设置厂商标识

##### PCI Upstream Port 

DeviceClass --- DeviceState --- device_type_info

PCIDeviceClass --- PCIDevice --- pci_device_type_info

nullptr --- PCIBridge --- pci_bridge_type_info

nullptr --- PCIEPort --- pcie_port_type_info

nullptr --- nullptr --- xio3130_upstream_info # 设置厂商标识，设置配置空间写函数为xio3130_upstream_write_config，PCIDeviceClass的realize为xio3130_upstream_realize

##### PCI Downstream Port

DeviceClass --- DeviceState --- device_type_info

PCIDeviceClass --- PCIDevice --- pci_device_type_info

nullptr --- PCIBridge --- pci_bridge_type_info

nullptr --- PCIEPort --- pcie_port_type_info

nullptr --- PCIESlot --- pcie_slot_type_info

nullptr --- nullptr --- xio3130_downstream_info # 设置厂商标识，设置配置空间写函数为xio3130_downstream_write_config，PCIDeviceClass的realize为xio3130_downstream_realize

# 函数分析

```c
PCIDevice *pci_create_simple_multifunction(PCIBus *bus, int devfn,
                                           bool multifunction,
                                           const char *name);
在bus上挂载为name的设备

devfn为设备的功能号（可以为负数，表示总线自动分配），一般通过如下宏计算：

#define PCI_DEVFN(slot, func)   ((((slot) & 0x1f) << 3) | ((func) & 0x07))

因此通过该宏算出的 devfn 是一个8bit的数字，高5bit为slot号，低3bit位func号

```

pci 设备初始化过程，先调用pci_qdev_realize（DeviceClass中的realize），，在调用PCIDeviceClass中的realize

先调用pci_qdev_realize:主要是建立分配配置空间，以及设备的配置空间默认读写函数:pci_default_read_config、pci_default_write_config

PCIDeviceClass中的realize主要是（以网卡为例:e1000e_pci_realize）：调用pci_register_bar关联配置空间中的BAR与MemoryRegion(地址空间)

对配置空间的操作是通过0xcf8 和 0xcfc 端口实现的。0xcf8指定地址，0xcfc指定读取或写入的值

这两个地址的映射是通过

```c
static void q35_host_realize(DeviceState *dev, Error **errp)
{
    sysbus_add_io(sbd, MCH_HOST_BRIDGE_CONFIG_ADDR, &pci->conf_mem);
    sysbus_init_ioports(sbd, MCH_HOST_BRIDGE_CONFIG_ADDR, 4);

    sysbus_add_io(sbd, MCH_HOST_BRIDGE_CONFIG_DATA, &pci->data_mem);
    sysbus_init_ioports(sbd, MCH_HOST_BRIDGE_CONFIG_DATA, 4);
}
```

和 

```c
static void q35_host_initfn(Object *obj)
{
    memory_region_init_io(&phb->conf_mem, obj, &pci_host_conf_le_ops, phb,
                          "pci-conf-idx", 4);
    memory_region_init_io(&phb->data_mem, obj, &pci_host_data_le_ops, phb,
                          "pci-conf-data", 4);
}
```

其指定了对应端口的操作集合:pci_host_conf_le_ops、pci_host_data_le_ops

### mmconfig的设置

PCIE总线是通过内存访问PCIE设备的配置地址空间的，这段地址空间的开始是MMCONFIG。可以通过 cat /proc/iomem 找到该地址的开始地址，然后ioremap/unremap，访问。

在QEMU中，实现是通过MCH，映射到的。首先在TYPE_PCIE_HOST_BRIDGE中的对象初始函数pcie_host_init初始化MMCONFIG这段内存空间（主要是初始化该MemoryRegion的ops函数集合为pcie_mmcfg_ops，也就是该段空间的读写函数）。然后在TYPE_MCH_PCI_DEVICE中的config_write（mch_write_config）函数中，将该地址空间映射到物理地址空间。

# 自定义PCIE设备

```c
#include "qemu/osdep.h"
#include "hw/pci/msi.h"
#include "stdio.h"
#include "qemu/timer.h"

#define TYPE_MYHW "my_hw"
#define MYHW(obj) OBJECT_CHECK(MYHWState,(obj),TYPE_MYHW)

typedef struct MYHWState{
	PCIDevice parent_obj;

	MemoryRegion mmio;

	QEMUTimer my_timer;

	bool irq_raise;
}MYHWState;

static uint64_t my_hw_mmio_read(void *opaque, hwaddr addr, unsigned size)
{
	printf("my_hw_mmio_read: addr:0x%lx , size: %d\n",addr,size);
	return 0;
}

static void my_timer_func(void *opaque)
{
	MYHWState *myhw = opaque;
	printf("my_timer_func\n");
	timer_mod(&myhw->my_timer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 2000);

	if(!myhw->irq_raise){
		pci_set_irq(&myhw->parent_obj,1);
		myhw->irq_raise = true;
	}
}

static void my_hw_mmio_write(void *opaque, hwaddr addr,
                   uint64_t val, unsigned size)
{
	MYHWState *myhw = opaque;
	printf("my_hw_mmio_write: addr:0x%lx , val 0x%lx\n",addr,val);

	switch(addr){
	case 0x10:
		printf("timer run\n");
		myhw->irq_raise = false;
		timer_init_ms(&myhw->my_timer,QEMU_CLOCK_VIRTUAL,my_timer_func,myhw);
		timer_mod(&myhw->my_timer, qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + 2000);
		break;
	case 0x20:
		printf("del timer\n");
		timer_del(&myhw->my_timer);
		break;
	case 0x30:
		myhw->irq_raise = false;
		pci_set_irq(&myhw->parent_obj,0);
		break;
	default:
		printf("unkown opcode\n");
		break;
	}
}

static const MemoryRegionOps mmio_ops = {
		.read = my_hw_mmio_read,
		.write = my_hw_mmio_write,
};

static void my_hw_write_config(PCIDevice *pci_dev, uint32_t address,
                                uint32_t val, int len)
{
	pci_default_write_config(pci_dev, address, val, len);
}

static uint32_t my_hw_read_config(PCIDevice *pci_dev, uint32_t address,
                              int len)
{
	return pci_default_read_config(pci_dev,address,len);
}

static void myhw_pci_realize(PCIDevice *pci_dev,Error **errp)
{
	MYHWState *s = MYHW(pci_dev);

	pci_dev->config_write = my_hw_write_config;
	pci_dev->config_read = my_hw_read_config;

	pci_dev->config[PCI_INTERRUPT_PIN] = 1;

	memory_region_init_io(&s->mmio,OBJECT(s),&mmio_ops,s,"MY_HW-mmio",1024*1024);
	pci_register_bar(pci_dev, 0,PCI_BASE_ADDRESS_SPACE_MEMORY, &s->mmio);
}

static void myhw_class_init(ObjectClass *class,void *data)
{
	DeviceClass *dc = DEVICE_CLASS(class);
	PCIDeviceClass *c = PCI_DEVICE_CLASS(class);

	c->realize = myhw_pci_realize;
	c->vendor_id = 0x4c52;
	c->device_id = 0x6c72;
	c->revision = 0;
	c->class_id = PCI_CLASS_NOT_DEFINED;

	dc->desc = "Dundun & hanhan";
}

static void myhw_instance_init(Object *obj)
{

}

static const TypeInfo myhw_info = {
		.name = TYPE_MYHW,
		.parent = TYPE_PCI_DEVICE,
		.instance_size = sizeof(MYHWState),
		.class_init = myhw_class_init,
		.instance_init = myhw_instance_init,
	    .interfaces = (InterfaceInfo[]) {
	        { INTERFACE_PCIE_DEVICE },
	        { }
	    },
};

static void myhw_register_types(void)
{
	type_register_static(&myhw_info);
}

type_init(myhw_register_types);
```

对应的驱动程序

```c
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/init.h>

#define MY_PCI_VENDOR_ID	0x4c52
#define MY_PCI_DEVICE_ID	0x6c72
#define MY_PCI_REVISION_ID 	0x0

static struct pci_device_id ids[]={
	{ PCI_DEVICE(MY_PCI_VENDOR_ID,MY_PCI_DEVICE_ID), },
	{ 0, }
};

static struct my_pci_info{
	struct pci_dev *dev;
	void __iomem *address_io;
}pci_info;

MODULE_DEVICE_TABLE(pci,ids);

static irqreturn_t my_pci_irq_handler(int irq,void *dev_id)
{
	struct my_pci_info *pci_info = dev_id;
	
	*((uint8_t *)pci_info->address_io + 0x30) = 0x01;
	
	printk("my pci:receive irq\n");
	
	return 0;
}

//return 0 means success
static int probe(struct pci_dev *dev,const struct pci_device_id *id)
{
	int bar = 0;
	int ret;
	resource_size_t len;

	ret = pci_enable_device(dev);
	if(ret) return ret;
	
	len = pci_resource_len(dev,bar);
	pci_info.address_io = pci_iomap(dev,bar,len);
	pci_info.dev = dev;
	
	//interrupt
	ret = request_irq(dev->irq,my_pci_irq_handler,IRQF_SHARED,"my_pci",&pci_info);
	if(ret){
		printk("request IRQ failed\n");
		return 1;
	}
	

	
	*((uint8_t *)pci_info.address_io+0x10) = 0x01;

	return 0;
}

static void remove(struct pci_dev *dev)
{
	*((uint8_t *)pci_info.address_io+0x20) = 0x01;
	
	free_irq(dev->irq,&pci_info);
	
	pci_iounmap(dev,pci_info.address_io);
	
	pci_disable_device(dev);
}

static struct pci_driver pci_driver = {
	.name = "my_hw",
	.id_table = ids,
	.probe = probe,
	.remove = remove,
};

static int __init my_pci_init(void)
{
	return pci_register_driver(&pci_driver);
}

static void __exit my_pci_exit(void)
{
	pci_unregister_driver(&pci_driver);
}

MODULE_LICENSE("GPL");
module_init(my_pci_init);
module_exit(my_pci_exit);
```

可以通过lspci获得myhw的BAR地址，然后用ioremap和iounmap对该BAR指向的地址进行读写

# Tips

MMCONFIG：PCIE设备的总的配置空间位置

# 资料

Qemu X86架构的Machine Type

https://remimin.github.io/2019/07/09/qemu_machine_type/

KVM虚拟机代码揭秘——QEMU的PCI总线与设备（上）

https://blog.csdn.net/yearn520/article/details/6576875

KVM虚拟机代码揭秘——QEMU的PCI总线与设备（下）

https://blog.csdn.net/yearn520/article/details/6577988

QEMU学习笔记——Q35

https://www.binss.me/blog/qemu-note-of-Q35-machine/

PCI设备的创建与初始化

https://github.com/GiantVM/doc/blob/master/pci.md

概念术语

http://media.njude.com.cn/vclass/Courses/15201A/CourseDetail.aspx?id=4612&name=%E6%A6%82%E5%BF%B5%E6%9C%AF%E8%AF%AD

PCI EXPRESS GUIDELINES

https://github.com/qemu/qemu/blob/master/docs/pcie.txt

在qemu中增加pci设备并用linux驱动验证

https://blog.csdn.net/XscKernel/article/details/8298195

qemu PCI edu.c

https://github.com/qemu/qemu/blob/v2.7.0/hw/misc/edu.c

https://github.com/qemu/qemu/blob/v2.7.0/docs/specs/edu.txt

浅谈Linux PCI设备驱动

http://www.uml.org.cn/embeded/201205152.asp