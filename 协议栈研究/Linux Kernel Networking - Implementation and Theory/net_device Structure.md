The fields of the net_device structure can be classified into the following categories:

- Configuration
- Statistics
- Device status
- List management
- Traffic management
- Feature specific
- Generic
- Function pointers(or VFT)

# Identifiers

- int ifindex:A unique ID,assigned to each device when it is registered with call to dev_new_index.
- unsigned short dev_id:Used to differentiate devices that share the same link layer address.

# Configuration

- char name[IFNAMSIZ]:Name of the device
- unsigned long mem_start,mem_end:These fields describe the shared memory used by the device to communicate with the kernel.
- unsigned long base_addr:The beginning of the I/O memory mapped to the device's own memory.
- unsigned int irq:The interrupt number used by the device to talk to the kernel.
- unsigned char if_port:The type of port being used for this interface.
- unsigned char dma:The DMA channel used by the device.
- unsigned short flags,gflags,priv_flags:Some bits in the flag field represent capabilities of the network device and other represent changing status.
- int features:report the card's capabilities for communicating with the CPU,such as whether the card can do DMA to high memory
- unsigned mtu
- unsigned short type:The category of the devices to which it belongs
- unsigned short hard_header_len:The size of the device header in octets.The Ethernet header,for instance,is 14 octets long.
- unsigned char broadcast[MAX_ADDR_LEN]:The link layer broadcast address
- unsigned char dev_addr[MAX_ADDR_LEN]
- unsigned char addr_len

    dev_addr is the device link layer address
    
- int promiscuity

# Generic

