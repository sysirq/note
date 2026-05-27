# USB Burn Image ---  image config

### VIM3.uboot-mainline.emmc.aml.img

```ini
[LIST_NORMAL]
file="DDR.USB"		main_type="USB"		sub_type="DDR"	file_type="normal"
file="DDR.USB"		main_type="USB"		sub_type="UBOOT"	file_type="normal"
file="aml_sdc_burn.UBOOT"		main_type="UBOOT"		sub_type="aml_sdc_burn"	file_type="normal"
file="aml_sdc_burn.ini"		main_type="ini"		sub_type="aml_sdc_burn"	file_type="normal"
file="_aml_dtb.PARTITION"		main_type="dtb"		sub_type="meson1"	file_type="normal"
file="platform.conf"		main_type="conf"		sub_type="platform"	file_type="normal"

[LIST_VERIFY]
file="_aml_dtb.PARTITION"		main_type="PARTITION"		sub_type="_aml_dtb"	file_type="normal"
file="bootloader.PARTITION"		main_type="PARTITION"		sub_type="bootloader"	file_type="normal"
```

dts /partitions 节点:

```dts
        partitions {
                parts = <0x03>;
                part-0 = <0x61>;
                part-1 = <0x62>;
                part-2 = <0x63>;
                phandle = <0x100>;

                logo {
                        pname = "logo";
                        size = <0x00 0x800000>;
                        mask = <0x01>;
                        phandle = <0x61>;
                };

                ramdisk {
                        pname = "ramdisk";
                        size = <0x00 0x2000000>;
                        mask = <0x01>;
                        phandle = <0x62>;
                };

                rootfs {
                        pname = "rootfs";
                        size = <0xffffffff 0xffffffff>;
                        mask = <0x04>;
                        phandle = <0x63>;
                };
        };
```

uboot读取emmc上的MPT分区表

```sh
=> mmc list
mmc@ffe03000: 0
mmc@ffe05000: 1
mmc@ffe07000: 2 (eMMC)
=> mmc dev 2
switch to partitions #0, OK
mmc2(part 0) is current device
=> mmc info
Device: mmc@ffe07000
Manufacturer ID: 15
OEM: 0
Name: BJTD4R
Bus Speed: 26000000
Mode: MMC High Speed (26MHz)
Rd Block Len: 512
MMC version 5.1
High Capacity: Yes
Capacity: 29.1 GiB
Bus Width: 8-bit
Erase Group Size: 512 KiB
HC WP Group Size: 8 MiB
User Capacity: 29.1 GiB WRREL
Boot Capacity: 4 MiB ENH
RPMB Capacity: 4 MiB ENH
Boot area 0 is not write protected
Boot area 1 is not write protected
=> mmc read 0x1080000 0x12000 0x20
MMC read: dev # 2, block # 73728, count 32 ... 32 blocks read: OK
=> md.b 0x1080000
01080000: 4d 50 54 00 30 31 2e 30 30 2e 30 30 00 00 00 00  MPT.01.00.00....
01080010: 06 00 00 00 32 e7 67 16 62 6f 6f 74 6c 6f 61 64  ....2.g.bootload
01080020: 65 72 00 00 00 00 00 00 00 00 40 00 00 00 00 00  er........@.....
01080030: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
```

分区表强制同步校验机制:

- 检测物理不一致： U-Boot会将此动态构建的分区映像与物理eMMC上 36MiB 偏移处的物理 EPT 逐项比对 。
- 强制覆盖策略： 如果两者发生不一致，U-Boot会默认当前的 DTB 节点配置具有最高置信度，并在对物理存储介质上的旧 EPT 进行全盘覆盖擦写后，用最新的 DTB 分区布局强行同步复写物理 EPT 结构 。
- 无节点回退模式： 只有当在当前 DTB 中完全无法寻获 /partitions 节点结构时，U-Boot 才会放弃对物理分区的重写，并允许内核直接信任并读取现存的 eMMC 物理 EPT 。

### vim3-android-11-32bit-v241024.img.xz

```ini
[LIST_NORMAL]
file="DDR.USB"		main_type="USB"		sub_type="DDR"
file="DDR.USB"		main_type="USB"		sub_type="UBOOT"
file="aml_sdc_burn.UBOOT"		main_type="UBOOT"		sub_type="aml_sdc_burn"
file="aml_sdc_burn.ini"		main_type="ini"		sub_type="aml_sdc_burn"
file="_aml_dtb.PARTITION"		main_type="dtb"		sub_type="meson1"
file="platform.conf"		main_type="conf"		sub_type="platform"

[LIST_VERIFY]
file="_aml_dtb.PARTITION"		main_type="PARTITION"		sub_type="_aml_dtb"
file="boot.PARTITION"		main_type="PARTITION"		sub_type="boot"
file="DDR.USB"		main_type="PARTITION"		sub_type="bootloader"
file="dtbo.PARTITION"		main_type="PARTITION"		sub_type="dtbo"
file="logo.PARTITION"		main_type="PARTITION"		sub_type="logo"
file="odm_ext.PARTITION"		main_type="PARTITION"		sub_type="odm_ext"
file="oem.PARTITION"		main_type="PARTITION"		sub_type="oem"
file="recovery.PARTITION"		main_type="PARTITION"		sub_type="recovery"
file="super.PARTITION"		main_type="PARTITION"		sub_type="super"
file="vbmeta.PARTITION"		main_type="PARTITION"		sub_type="vbmeta"
```

dts /partitions 节点（_aml_dtb.PARTITION 需要先gunzip，才能使用dtc）:

```dts
	partitions {
		parts = <0x11>;
		part-0 = <0x02>;
		part-1 = <0x03>;
		part-2 = <0x04>;
		part-3 = <0x05>;
		part-4 = <0x06>;
		part-5 = <0x07>;
		part-6 = <0x08>;
		part-7 = <0x09>;
		part-8 = <0x0a>;
		part-9 = <0x0b>;
		part-10 = <0x0c>;
		part-11 = <0x0d>;
		part-12 = <0x0e>;
		part-13 = <0x0f>;
		part-14 = <0x10>;
		part-15 = <0x11>;
		part-16 = <0x12>;
		phandle = <0xa1>;

		logo {
			pname = "logo";
			size = <0x00 0x800000>;
			mask = <0x01>;
			phandle = <0x02>;
		};

		recovery {
			pname = "recovery";
			size = <0x00 0x1800000>;
			mask = <0x01>;
			phandle = <0x03>;
		};

		tee {
			pname = "tee";
			size = <0x00 0x2000000>;
			mask = <0x01>;
			phandle = <0x04>;
		};

		factory {
			pname = "factory";
			size = <0x00 0x800000>;
			mask = <0x11>;
			phandle = <0x05>;
		};

		misc {
			pname = "misc";
			size = <0x00 0x200000>;
			mask = <0x01>;
			phandle = <0x06>;
		};

		dtbo {
			pname = "dtbo";
			size = <0x00 0x200000>;
			mask = <0x01>;
			phandle = <0x07>;
		};

		cri_data {
			pname = "cri_data";
			size = <0x00 0x800000>;
			mask = <0x02>;
			phandle = <0x08>;
		};

		oem {
			pname = "oem";
			size = <0x00 0x1000000>;
			mask = <0x01>;
			phandle = <0x0b>;
		};

		odm_ext {
			pname = "odm_ext";
			size = <0x00 0x1000000>;
			mask = <0x01>;
			phandle = <0x0c>;
		};

		rsv {
			pname = "rsv";
			size = <0x00 0x1000000>;
			mask = <0x01>;
			phandle = <0x0d>;
		};

		metadata {
			pname = "metadata";
			size = <0x00 0x1000000>;
			mask = <0x01>;
			phandle = <0x0e>;
		};

		vbmeta {
			pname = "vbmeta";
			size = <0x00 0x200000>;
			mask = <0x01>;
			phandle = <0x0f>;
		};

		param {
			pname = "param";
			size = <0x00 0x1000000>;
			mask = <0x02>;
			phandle = <0x09>;
		};

		boot {
			pname = "boot";
			size = <0x00 0x1000000>;
			mask = <0x01>;
			phandle = <0x0a>;
		};

		super {
			pname = "super";
			size = <0x00 0x64000000>;
			mask = <0x01>;
			phandle = <0x10>;
		};

		cache {
			pname = "cache";
			size = <0x00 0x32000000>;
			mask = <0x02>;
			phandle = <0x11>;
		};

		data {
			pname = "data";
			size = <0xffffffff 0xffffffff>;
			mask = <0x04>;
			phandle = <0x12>;
		};
	};
```

### vim3-ubuntu-24.04-gnome-linux-5.15-fenix-1.6.9-240618-emmc.img.xz

```ini
[LIST_NORMAL]
file="DDR.USB"		main_type="USB"		sub_type="DDR"
file="DDR.USB"		main_type="USB"		sub_type="UBOOT"
file="aml_sdc_burn.UBOOT"		main_type="UBOOT"		sub_type="aml_sdc_burn"
file="aml_sdc_burn.ini"		main_type="ini"		sub_type="aml_sdc_burn"
file="_aml_dtb.PARTITION"		main_type="dtb"		sub_type="meson1"
file="platform.conf"		main_type="conf"		sub_type="platform"

[LIST_VERIFY]
file="_aml_dtb.PARTITION"		main_type="PARTITION"		sub_type="_aml_dtb"
file="DDR.USB"		main_type="PARTITION"		sub_type="bootloader"
file="rootfs.PARTITION"		main_type="PARTITION"		sub_type="rootfs"
```

dts /partitions 节点（_aml_dtb.PARTITION 需要先gunzip）:

```
	partitions {
		parts = <0x01>;
		part-0 = <0x7d>;
		phandle = <0x133>;

		rootfs {
			pname = "rootfs";
			size = <0xffffffff 0xffffffff>;
			mask = <0x04>;
			phandle = <0x7d>;
		};
	};
```

