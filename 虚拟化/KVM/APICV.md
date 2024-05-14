```c
    vmcs
    +----------------------------------+
    |guest state area                  |
    |   +------------------------------+
    |   |guest non-register state      |
    |   |   +--------------------------+
    |   |   |Guest interrupt status    |
    |   |   |   +----------------------+
    |   |   |   |Requesting virtual    |
    |   |   |   |   interrupt (RVI).   |
    |   |   |   +----------------------+
    |   |   |   |Servicing virtual     |
    |   |   |   |   interrupt (RVI).   |
    |   |   |   |                      |
    |   |   +---+----------------------+
    |   |                              |
    |   +------------------------------+
    |                                  |
    |vm-execution control              |
    |   +------------------------------+
    |   |APIC-access address           |
    |   |                              |
    |   |                              |         4K Virtual-APIC page
    |   |Virtual-APIC address      ----|-------->+-------------------------+
    |   |                              |     080H|Virtual task-priority    |
    |   |                              |         |        register (VTPR)  |
    |   |                              |     0A0H|Vrtl processor-priority  |
    |   |                              |         |        register (VPPR)  |
    |   |                              |     0B0H|Virtual end-of-interrupt |
    |   |                              |         |        register (VEOI)  |
    |   |                              |         |Virtual interrupt-service|
    |   |                              |         |        register (VISR)  |
    |   |                              |         |Virtual interrupt-request|
    |   |                              |         |        register (VIRR)  |
    |   |                              |     300H|Virtual interrupt-command|
    |   |                              |         |        register(VICR_LO)|
    |   |                              |     310H|Virtual interrupt-command|
    |   |                              |         |        register(VICR_HO)|
    |   |                              |         |                         |
    |   |                              |         +-------------------------+
    |   |                              |
    |   |                              |
    |   |TPR threshold                 |
    |   |EOI-exit bitmap               |
    |   |Posted-interrupt notification |
    |   |        vector                |
    |   |                              |
    |   |                              |    64 byte descriptor
    |   |                              |    511              255              0
    |   |Posted-interrupt descriptor   |--->+----------------+----------------+
    |   |        address               |    |                |                |
    |   |                              |    |                |                |
    |   |                              |    +----------------+----------------+
    |   |Pin-Based VM-Execution Ctrls  |
    |   |    +-------------------------+
    |   |    |Process posted interrupts|
    |   |    |                         |
    |   |    +-------------------------+
    |   |                              |
    |   |Primary Processor-Based       |
    |   |   VM-Execution Controls      |
    |   |    +-------------------------+
    |   |    |Interrupt window exiting |
    |   |    |Use TPR shadow           |
    |   |    |                         |
    |   |    +-------------------------+
    |   |                              |
    |   |Secondary Processor-Based     |
    |   |   VM-Execution Controls      |
    |   |    +-------------------------+
    |   |    |Virtualize APIC access   |
    |   |    |Virtualize x2APIC mode   |
    |   |    |APIC-register virtual    |
    |   |    |Virtual-intr delivery    |
    |   |    |                         |
    |   |    |                         |
    |   |    +-------------------------+
    |   |                              |
    |   +------------------------------+
    |                                  |
    +----------------------------------+
```

用一个特殊的中断将真正的中断注入到虚拟机

特殊中断在VMCS中的POSTED_INTR_NV字段中

# 资料

APICV

https://richardweiyang.gitbooks.io/understanding_qemu/apic/03-apicv.html