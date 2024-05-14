Controller/Bridge/Hub devices:

name "i82801b11-bridge", bus PCI

name "igd-passthrough-isa-bridge", bus PCI, desc "ISA bridge faked to support IGD PT"

name "ioh3420", bus PCI, desc "Intel IOH device id 3420 PCIE Root Port"

name "pci-bridge", bus PCI, desc "Standard PCI Bridge"

name "pci-bridge-seat", bus PCI, desc "Standard PCI Bridge (multiseat)"

name "pcie-pci-bridge", bus PCI

name "pcie-root-port", bus PCI, desc "PCI Express Root Port"

name "pxb", bus PCI, desc "PCI Expander Bridge"

name "pxb-pcie", bus PCI, desc "PCI Express Expander Bridge"

name "usb-hub", bus usb-bus

name "vfio-pci-igd-lpc-bridge", bus PCI, desc "VFIO dummy ISA/LPC bridge for IGD assignment"

name "x3130-upstream", bus PCI, desc "TI X3130 Upstream Port of PCI Express Switch"

name "xio3130-downstream", bus PCI, desc "TI X3130 Downstream Port of PCI Express Switch"



USB devices:

name "ich9-usb-ehci1", bus PCI

name "ich9-usb-ehci2", bus PCI

name "ich9-usb-uhci1", bus PCI

name "ich9-usb-uhci2", bus PCI

name "ich9-usb-uhci3", bus PCI

name "ich9-usb-uhci4", bus PCI

name "ich9-usb-uhci5", bus PCI

name "ich9-usb-uhci6", bus PCI

name "nec-usb-xhci", bus PCI

name "pci-ohci", bus PCI, desc "Apple USB Controller"

name "piix3-usb-uhci", bus PCI

name "piix4-usb-uhci", bus PCI

name "qemu-xhci", bus PCI

name "usb-ehci", bus PCI

name "vt82c686b-usb-uhci", bus PCI



Storage devices:

name "am53c974", bus PCI, desc "AMD Am53c974 PCscsi-PCI SCSI adapter"

name "dc390", bus PCI, desc "Tekram DC-390 SCSI adapter"

name "floppy", bus floppy-bus, desc "virtual floppy drive"

name "ich9-ahci", bus PCI, alias "ahci"

name "ide-cd", bus IDE, desc "virtual IDE CD-ROM"

name "ide-drive", bus IDE, desc "virtual IDE disk or CD-ROM (legacy)"

name "ide-hd", bus IDE, desc "virtual IDE disk"

name "isa-fdc", bus ISA

name "isa-ide", bus ISA

name "lsi53c810", bus PCI

name "lsi53c895a", bus PCI, alias "lsi"

name "megasas", bus PCI, desc "LSI MegaRAID SAS 1078"

name "megasas-gen2", bus PCI, desc "LSI MegaRAID SAS 2108"

name "mptsas1068", bus PCI, desc "LSI SAS 1068"

name "nvme", bus PCI, desc "Non-Volatile Memory Express"

name "piix3-ide", bus PCI

name "piix3-ide-xen", bus PCI

name "piix4-ide", bus PCI

name "pvscsi", bus PCI

name "scsi-block", bus SCSI, desc "SCSI block device passthrough"

name "scsi-cd", bus SCSI, desc "virtual SCSI CD-ROM"

name "scsi-disk", bus SCSI, desc "virtual SCSI disk or CD-ROM (legacy)"

name "scsi-generic", bus SCSI, desc "pass through generic scsi device (/dev/sg*)"

name "scsi-hd", bus SCSI, desc "virtual SCSI disk"

name "sd-card", bus sd-bus

name "sdhci-pci", bus PCI

name "usb-bot", bus usb-bus

name "usb-mtp", bus usb-bus, desc "USB Media Transfer Protocol device"

name "usb-storage", bus usb-bus

name "usb-uas", bus usb-bus

name "vhost-scsi", bus virtio-bus

name "vhost-scsi-pci", bus PCI

name "vhost-scsi-pci-non-transitional", bus PCI

name "vhost-scsi-pci-transitional", bus PCI

name "vhost-user-blk", bus virtio-bus

name "vhost-user-blk-pci", bus PCI

name "vhost-user-blk-pci-non-transitional", bus PCI

name "vhost-user-blk-pci-transitional", bus PCI

name "vhost-user-scsi", bus virtio-bus

name "vhost-user-scsi-pci", bus PCI

name "vhost-user-scsi-pci-non-transitional", bus PCI

name "vhost-user-scsi-pci-transitional", bus PCI

name "virtio-blk-device", bus virtio-bus

name "virtio-blk-pci", bus PCI, alias "virtio-blk"

name "virtio-blk-pci-non-transitional", bus PCI

name "virtio-blk-pci-transitional", bus PCI

name "virtio-scsi-device", bus virtio-bus

name "virtio-scsi-pci", bus PCI, alias "virtio-scsi"

name "virtio-scsi-pci-non-transitional", bus PCI

name "virtio-scsi-pci-transitional", bus PCI



Network devices:

name "e1000", bus PCI, alias "e1000-82540em", desc "Intel Gigabit Ethernet"

name "e1000-82544gc", bus PCI, desc "Intel Gigabit Ethernet"

name "e1000-82545em", bus PCI, desc "Intel Gigabit Ethernet"

name "e1000e", bus PCI, desc "Intel 82574L GbE Controller"

name "i82550", bus PCI, desc "Intel i82550 Ethernet"

name "i82551", bus PCI, desc "Intel i82551 Ethernet"

name "i82557a", bus PCI, desc "Intel i82557A Ethernet"

name "i82557b", bus PCI, desc "Intel i82557B Ethernet"

name "i82557c", bus PCI, desc "Intel i82557C Ethernet"

name "i82558a", bus PCI, desc "Intel i82558A Ethernet"

name "i82558b", bus PCI, desc "Intel i82558B Ethernet"

name "i82559a", bus PCI, desc "Intel i82559A Ethernet"

name "i82559b", bus PCI, desc "Intel i82559B Ethernet"

name "i82559c", bus PCI, desc "Intel i82559C Ethernet"

name "i82559er", bus PCI, desc "Intel i82559ER Ethernet"

name "i82562", bus PCI, desc "Intel i82562 Ethernet"

name "i82801", bus PCI, desc "Intel i82801 Ethernet"

name "ne2k_isa", bus ISA

name "ne2k_pci", bus PCI

name "pcnet", bus PCI

name "rocker", bus PCI, desc "Rocker Switch"

name "rtl8139", bus PCI

name "usb-bt-dongle", bus usb-bus

name "usb-net", bus usb-bus

name "virtio-net-device", bus virtio-bus

name "virtio-net-pci", bus PCI, alias "virtio-net"

name "virtio-net-pci-non-transitional", bus PCI

name "virtio-net-pci-transitional", bus PCI

name "vmxnet3", bus PCI, desc "VMWare Paravirtualized Ethernet v3"



Input devices:

name "i8042", bus ISA

name "ipoctal232", bus IndustryPack, desc "GE IP-Octal 232 8-channel RS-232 IndustryPack"

name "isa-parallel", bus ISA

name "isa-serial", bus ISA

name "pci-serial", bus PCI

name "pci-serial-2x", bus PCI

name "pci-serial-4x", bus PCI

name "tpci200", bus PCI, desc "TEWS TPCI200 IndustryPack carrier"

name "usb-braille", bus usb-bus

name "usb-ccid", bus usb-bus, desc "CCID Rev 1.1 smartcard reader"

name "usb-kbd", bus usb-bus

name "usb-mouse", bus usb-bus

name "usb-serial", bus usb-bus

name "usb-tablet", bus usb-bus

name "usb-wacom-tablet", bus usb-bus, desc "QEMU PenPartner Tablet"

name "vhost-user-input", bus virtio-bus

name "vhost-user-input-pci", bus PCI

name "virtconsole", bus virtio-serial-bus

name "virtio-input-host-device", bus virtio-bus

name "virtio-input-host-pci", bus PCI, alias "virtio-input-host"

name "virtio-keyboard-device", bus virtio-bus

name "virtio-keyboard-pci", bus PCI, alias "virtio-keyboard"

name "virtio-mouse-device", bus virtio-bus

name "virtio-mouse-pci", bus PCI, alias "virtio-mouse"

name "virtio-serial-device", bus virtio-bus

name "virtio-serial-pci", bus PCI, alias "virtio-serial"

name "virtio-serial-pci-non-transitional", bus PCI

name "virtio-serial-pci-transitional", bus PCI

name "virtio-tablet-device", bus virtio-bus

name "virtio-tablet-pci", bus PCI, alias "virtio-tablet"

name "virtserialport", bus virtio-serial-bus



Display devices:

name "ati-vga", bus PCI

name "bochs-display", bus PCI

name "cirrus-vga", bus PCI, desc "Cirrus CLGD 54xx VGA"

name "isa-cirrus-vga", bus ISA

name "isa-vga", bus ISA

name "ramfb", bus System, desc "ram framebuffer standalone device"

name "secondary-vga", bus PCI

name "sga", bus ISA, desc "Serial Graphics Adapter"

name "VGA", bus PCI

name "vhost-user-gpu", bus virtio-bus

name "vhost-user-gpu-pci", bus PCI

name "vhost-user-vga", bus PCI

name "virtio-gpu-device", bus virtio-bus

name "virtio-gpu-pci", bus PCI, alias "virtio-gpu"

name "virtio-vga", bus PCI

name "vmware-svga", bus PCI



Sound devices:

name "AC97", bus PCI, desc "Intel 82801AA AC97 Audio"

name "adlib", bus ISA, desc "Yamaha YM3812 (OPL2)"

name "cs4231a", bus ISA, desc "Crystal Semiconductor CS4231A"

name "ES1370", bus PCI, desc "ENSONIQ AudioPCI ES1370"

name "gus", bus ISA, desc "Gravis Ultrasound GF1"

name "hda-duplex", bus HDA, desc "HDA Audio Codec, duplex (line-out, line-in)"

name "hda-micro", bus HDA, desc "HDA Audio Codec, duplex (speaker, microphone)"

name "hda-output", bus HDA, desc "HDA Audio Codec, output-only (line-out)"

name "ich9-intel-hda", bus PCI, desc "Intel HD Audio Controller (ich9)"

name "intel-hda", bus PCI, desc "Intel HD Audio Controller (ich6)"

name "sb16", bus ISA, desc "Creative Sound Blaster 16"

name "usb-audio", bus usb-bus



Misc devices:

name "amd-iommu", bus System, desc "AMD IOMMU (AMD-Vi) DMA Remapping device"

name "edu", bus PCI

name "hyperv-testdev", bus ISA

name "i2c-ddc", bus i2c-bus

name "i6300esb", bus PCI

name "ib700", bus ISA

name "intel-iommu", bus System, desc "Intel IOMMU (VT-d) DMA Remapping device"

name "isa-applesmc", bus ISA

name "isa-debug-exit", bus ISA

name "isa-debugcon", bus ISA

name "ivshmem-doorbell", bus PCI, desc "Inter-VM shared memory"

name "ivshmem-plain", bus PCI, desc "Inter-VM shared memory"

name "kvaser_pci", bus PCI, desc "Kvaser PCICANx"

name "loader", desc "Generic Loader"

name "mioe3680_pci", bus PCI, desc "Mioe3680 PCICANx"

name "pc-testdev", bus ISA

name "pci-testdev", bus PCI, desc "PCI Test Device"

name "pcm3680_pci", bus PCI, desc "Pcm3680i PCICANx"

name "pvpanic", bus ISA

name "tpm-crb"

name "vfio-pci", bus PCI, desc "VFIO-based PCI device assignment"

name "vfio-pci-nohotplug", bus PCI, desc "VFIO-based PCI device assignment"

name "vhost-vsock-device", bus virtio-bus

name "vhost-vsock-pci", bus PCI

name "vhost-vsock-pci-non-transitional", bus PCI

name "vhost-vsock-pci-transitional", bus PCI

name "virtio-balloon-device", bus virtio-bus

name "virtio-balloon-pci", bus PCI, alias "virtio-balloon"

name "virtio-balloon-pci-non-transitional", bus PCI

name "virtio-balloon-pci-transitional", bus PCI

name "virtio-crypto-device", bus virtio-bus

name "virtio-crypto-pci", bus PCI

name "virtio-pmem-pci", bus PCI

name "virtio-rng-device", bus virtio-bus

name "virtio-rng-pci", bus PCI, alias "virtio-rng"

name "virtio-rng-pci-non-transitional", bus PCI

name "virtio-rng-pci-transitional", bus PCI

name "vmcoreinfo"

name "vmgenid"



CPU devices:

name "486-v1-x86_64-cpu"

name "486-x86_64-cpu"

name "athlon-v1-x86_64-cpu"

name "athlon-x86_64-cpu"

name "base-x86_64-cpu"

name "Broadwell-IBRS-x86_64-cpu"

name "Broadwell-noTSX-IBRS-x86_64-cpu"

name "Broadwell-noTSX-x86_64-cpu"

name "Broadwell-v1-x86_64-cpu"

name "Broadwell-v2-x86_64-cpu"

name "Broadwell-v3-x86_64-cpu"

name "Broadwell-v4-x86_64-cpu"

name "Broadwell-x86_64-cpu"

name "Cascadelake-Server-v1-x86_64-cpu"

name "Cascadelake-Server-v2-x86_64-cpu"

name "Cascadelake-Server-x86_64-cpu"

name "Conroe-v1-x86_64-cpu"

name "Conroe-x86_64-cpu"

name "core2duo-v1-x86_64-cpu"

name "core2duo-x86_64-cpu"

name "coreduo-v1-x86_64-cpu"

name "coreduo-x86_64-cpu"

name "Dhyana-v1-x86_64-cpu"

name "Dhyana-x86_64-cpu"

name "EPYC-IBPB-x86_64-cpu"

name "EPYC-v1-x86_64-cpu"

name "EPYC-v2-x86_64-cpu"

name "EPYC-x86_64-cpu"

name "Haswell-IBRS-x86_64-cpu"

name "Haswell-noTSX-IBRS-x86_64-cpu"

name "Haswell-noTSX-x86_64-cpu"

name "Haswell-v1-x86_64-cpu"

name "Haswell-v2-x86_64-cpu"

name "Haswell-v3-x86_64-cpu"

name "Haswell-v4-x86_64-cpu"

name "Haswell-x86_64-cpu"

name "host-x86_64-cpu"

name "Icelake-Client-v1-x86_64-cpu"

name "Icelake-Client-x86_64-cpu"

name "Icelake-Server-v1-x86_64-cpu"

name "Icelake-Server-x86_64-cpu"

name "IvyBridge-IBRS-x86_64-cpu"

name "IvyBridge-v1-x86_64-cpu"

name "IvyBridge-v2-x86_64-cpu"

name "IvyBridge-x86_64-cpu"

name "KnightsMill-v1-x86_64-cpu"

name "KnightsMill-x86_64-cpu"

name "kvm32-v1-x86_64-cpu"

name "kvm32-x86_64-cpu"

name "kvm64-v1-x86_64-cpu"

name "kvm64-x86_64-cpu"

name "max-x86_64-cpu"

name "n270-v1-x86_64-cpu"

name "n270-x86_64-cpu"

name "Nehalem-IBRS-x86_64-cpu"

name "Nehalem-v1-x86_64-cpu"

name "Nehalem-v2-x86_64-cpu"

name "Nehalem-x86_64-cpu"

name "Opteron_G1-v1-x86_64-cpu"

name "Opteron_G1-x86_64-cpu"

name "Opteron_G2-v1-x86_64-cpu"

name "Opteron_G2-x86_64-cpu"

name "Opteron_G3-v1-x86_64-cpu"

name "Opteron_G3-x86_64-cpu"

name "Opteron_G4-v1-x86_64-cpu"

name "Opteron_G4-x86_64-cpu"

name "Opteron_G5-v1-x86_64-cpu"

name "Opteron_G5-x86_64-cpu"

name "Penryn-v1-x86_64-cpu"

name "Penryn-x86_64-cpu"

name "pentium-v1-x86_64-cpu"

name "pentium-x86_64-cpu"

name "pentium2-v1-x86_64-cpu"

name "pentium2-x86_64-cpu"

name "pentium3-v1-x86_64-cpu"

name "pentium3-x86_64-cpu"

name "phenom-v1-x86_64-cpu"

name "phenom-x86_64-cpu"

name "qemu32-v1-x86_64-cpu"

name "qemu32-x86_64-cpu"

name "qemu64-v1-x86_64-cpu"

name "qemu64-x86_64-cpu"

name "SandyBridge-IBRS-x86_64-cpu"

name "SandyBridge-v1-x86_64-cpu"

name "SandyBridge-v2-x86_64-cpu"

name "SandyBridge-x86_64-cpu"

name "Skylake-Client-IBRS-x86_64-cpu"

name "Skylake-Client-v1-x86_64-cpu"

name "Skylake-Client-v2-x86_64-cpu"

name "Skylake-Client-x86_64-cpu"

name "Skylake-Server-IBRS-x86_64-cpu"

name "Skylake-Server-v1-x86_64-cpu"

name "Skylake-Server-v2-x86_64-cpu"

name "Skylake-Server-x86_64-cpu"

name "Snowridge-v1-x86_64-cpu"

name "Snowridge-x86_64-cpu"

name "Westmere-IBRS-x86_64-cpu"

name "Westmere-v1-x86_64-cpu"

name "Westmere-v2-x86_64-cpu"

name "Westmere-x86_64-cpu"



Uncategorized devices:

name "AMDVI-PCI", bus PCI

name "ipmi-bmc-extern"

name "ipmi-bmc-sim"

name "isa-ipmi-bt", bus ISA

name "isa-ipmi-kcs", bus ISA

name "my_hw", bus PCI, desc "Dundun & hanhan"

name "nvdimm", desc "DIMM memory module"

name "pc-dimm", desc "DIMM memory module"

name "tpm-tis", bus ISA

name "virtio-pmem", bus virtio-bus