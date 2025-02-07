# 固件提取

```shell
ubireader_extract_images ax20v3-up-all-ver1-1-2-P1\[20221016-rel75092\]_sign_2022-10-19_09.33.01.bin 

binwalk -Me img-1571203182_vol-ubi_rootfs.ubifs 
```

```
3182_vol-ubi_rootfs.ubifs.extracted/squashfs-root/etc$ ubireader_
ubireader_display_blocks  ubireader_display_info    ubireader_extract_files   ubireader_extract_images  ubireader_list_files      ubireader_utils_info
```

