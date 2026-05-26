# USB Burn Image ---  image config

### VIM3.uboot-mainline.emmc.aml.img

```
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

### vim3-android-11-32bit-v241024.img.xz

```
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

### vim3-ubuntu-24.04-gnome-linux-5.15-fenix-1.6.9-240618-emmc.img.xz

```
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