# VIRTUAL PROCESSOR IDENTIFIERS(VPIDS)

A logical processor may tag some cached information with a 16-bit VPID

# THE EXTENDED PAGE TABLE MACHANISM(EPT)

When EPT is in use,certain addresses that would normally be treated as physical addresses are instead treated as guest-physical addresses.Guest-physical addresses area translated by traversing a set of EPT paging structures to produce physical addresses that are used to access memory.

### EPT 转换机制

EPT转换机制仅仅使用客户机物理地址的47:0 bit.