# 环境 

khadas vim3 4GB内存

# 关于amlogic emmc 分区表(EPT: Emmc Partition Table)的研究

### 分区表强制同步校验机制

- 检测物理不一致： (原厂)U-Boot会将此动态构建的(dtb partitions 节点)分区映像与物理eMMC上 36MiB 偏移处的物理 EPT 逐项比对 。
- 强制覆盖策略： 如果两者发生不一致，(原厂)U-Boot会默认当前的 DTB 节点配置具有最高置信度，并在对物理存储介质上的旧 EPT 进行全盘覆盖擦写后，用最新的 DTB 分区布局强行同步复写物理 EPT 结构 。
- 无节点回退模式： 只有当在当前 DTB 中完全无法寻获 /partitions 节点结构时，(原厂)U-Boot 才会放弃对物理分区的重写，并允许内核直接信任并读取现存的 eMMC 物理 EPT 。

###  reserved partition 布局 

```c
  Global offset of reserved partition is 36MBytes
  since MMC_BOOT_PARTITION_RESERVED is 32MBytes and
  MMC_BOOT_DEVICE_SIZE is 4MBytes.
  MMC_RESERVED_SIZE is 64MBytes for now.
  layout detail inside reserved partition.
  0x000000 - 0x003fff: partition table
  0x004000 - 0x03ffff: storage key area	(16k offset & 256k size)
  0x400000 - 0x47ffff: dtb area  (4M offset & 512k size)
  0x480000 - 64MBytes: resv for other usage.
  ...
```

### 常见 SoC EPT 分区示例

| SoC           | 分区名         | 起始偏移 | 大小     | 用途/说明                                 | flags | 对齐 (MiB) |
| :------------ | :------------- | :------- | :------- | :---------------------------------------- | :---- | :--------- |
| S905/S905X    | **bootloader** | 0x0      | 4MiB     | Amlogic 内置 bootloader（二阶段、三阶段） | 0     | 4          |
|               | **(GAP)**      | 4MiB     | 32MiB    | 引导区与第一个分区间隙                    | –     | –          |
|               | **reserved**   | 36MiB    | 64MiB    | 保留区（DDR 参数、设备树、厂商配置等）    | 0     | 8          |
|               | **(GAP)**      | 100MiB   | 8MiB     | 保留空隙                                  | –     | –          |
|               | **cache**      | 108MiB   | 512MiB   | 缓存区（Android cache）                   | 2     | 8          |
|               | **(GAP)**      | 620MiB   | 8MiB     | 缓存与环境变量分区间隙                    | –     | –          |
|               | **env**        | 628MiB   | 8MiB     | U-Boot 环境变量                           | 0     | 8          |
|               | **data**       | ~636MiB  | 剩余空间 | Android 用户数据等                        | 4     | –          |
| S912          | 与 S905X 类似  | –        | –        | 实际大小视出厂固件而定                    | –     | –          |
| S905X3/SM1    | 类似 S905X     | –        | –        | 同上                                      | –     | –          |
| S922X (A311D) | bootloader     | 0x0      | 4MiB     | bootloader (BL2/BL31 等)                  | 0     | 4          |
|               | reserved       | 36MiB    | 64MiB    | 保留区 (DDR, DTB 等)                      | 0     | 8          |
|               | cache          | 108MiB   | 512MiB   | 缓存区                                    | 2     | 8          |
|               | (padding)      | 620MiB   | 8MiB     | 保留空隙                                  | –     | –          |
|               | env            | 628MiB   | 8MiB     | U-Boot 环境变量                           | 0     | 8          |
|               | data           | ~636MiB  | 剩余空间 | 用户数据分区                              | 4     | –          |

普通 eMMC 分区之间预留的固定间隔，大小是 8MB

# 有用的脚本

### rsv_partitions_parser.py

功能：解析 rsv中的partition table

```python
#!/usr/bin/env python3

import re
import struct
import sys
from typing import Iterable, List, Sequence, Tuple


MAX_PART_NAME_LEN = 16
PARTITION_STRUCT_SIZE = 40
HEADER_STRUCT = struct.Struct("<4s12sIi")
PARTITION_STRUCT = struct.Struct("<16sQQII")
MPT_VERSION_1 = b"01.00.00"
MPT_VERSION_2 = b"01.02.00"


def extract_bytes(lines: Iterable[str]) -> bytes:
    data = bytearray()
    byte_re = re.compile(r"\b[0-9A-Fa-f]{2}\b")

    for raw_line in lines:
        line = raw_line.rstrip("\n")
        if not line.strip():
            continue

        if ":" in line:
            line = line.split(":", 1)[1]

        hex_bytes: List[int] = []
        for token in byte_re.findall(line):
            hex_bytes.append(int(token, 16))
            if len(hex_bytes) == 16:
                break

        if not hex_bytes:
            continue

        data.extend(hex_bytes)

    return bytes(data)


def decode_c_string(raw: bytes) -> str:
    return raw.split(b"\0", 1)[0].decode("ascii", errors="replace")


def detect_version(raw_version: bytes) -> int:
    if raw_version.startswith(MPT_VERSION_2):
        return 2
    if raw_version.startswith(MPT_VERSION_1):
        return 1
    return -1


def calc_checksum_v1(partitions_blob: bytes, count: int) -> int:
    checksum = 0
    words_per_partition = PARTITION_STRUCT_SIZE // 4
    ints = struct.unpack("<{}I".format(len(partitions_blob) // 4), partitions_blob)

    for _ in range(count):
        for index in range(words_per_partition):
            checksum = (checksum + ints[index]) & 0xFFFFFFFF

    return checksum


def calc_checksum_v2(partitions_blob: bytes, count: int) -> int:
    ints = struct.unpack("<{}I".format((count * PARTITION_STRUCT_SIZE) // 4), partitions_blob)
    checksum = 0
    for value in ints:
        checksum = (checksum + value) & 0xFFFFFFFF
    return checksum


def parse_partitions(blob: bytes, count: int) -> Sequence[Tuple[str, int, int, int, int]]:
    partitions = []
    offset = HEADER_STRUCT.size

    for index in range(count):
        end = offset + PARTITION_STRUCT_SIZE
        if end > len(blob):
            raise ValueError(
                "input is truncated: need {} bytes for {} partitions, got {} bytes".format(
                    end, count, len(blob)
                )
            )

        name_raw, size, part_offset, mask_flags, protect_flags = PARTITION_STRUCT.unpack(
            blob[offset:end]
        )
        partitions.append((decode_c_string(name_raw), size, part_offset, mask_flags, protect_flags))
        offset = end

    return partitions


def format_size(value: int) -> str:
    mib = value / (1024 * 1024)
    if value % (1024 * 1024) == 0:
        return "{} MiB".format(int(mib))
    return "{:.3f} MiB".format(mib)


def main() -> int:
    blob = extract_bytes(sys.stdin)
    if not blob:
        print("no hex bytes found on stdin", file=sys.stderr)
        return 1

    if len(blob) < HEADER_STRUCT.size:
        print(
            "input is too short: need at least {} bytes, got {}".format(
                HEADER_STRUCT.size, len(blob)
            ),
            file=sys.stderr,
        )
        return 1

    magic_raw, version_raw, count, checksum = HEADER_STRUCT.unpack(blob[: HEADER_STRUCT.size])
    magic = decode_c_string(magic_raw)
    version = decode_c_string(version_raw)
    version_id = detect_version(version_raw)

    try:
        partitions = parse_partitions(blob, count)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    partitions_blob = blob[HEADER_STRUCT.size : HEADER_STRUCT.size + count * PARTITION_STRUCT_SIZE]
    checksum_v1 = calc_checksum_v1(partitions_blob, count)
    checksum_v2 = calc_checksum_v2(partitions_blob, count)

    print("rsv partition table")
    print("magic        : {} ({})".format(magic, magic_raw.hex()))
    print("version      : {}".format(version))
    print("count        : {}".format(count))
    print("checksum     : 0x{:08x}".format(checksum & 0xFFFFFFFF))

    if version_id == 1:
        print(
            "checksum v1  : 0x{:08x} {}".format(
                checksum_v1, "OK" if checksum_v1 == (checksum & 0xFFFFFFFF) else "MISMATCH"
            )
        )
    elif version_id == 2:
        print(
            "checksum v2  : 0x{:08x} {}".format(
                checksum_v2, "OK" if checksum_v2 == (checksum & 0xFFFFFFFF) else "MISMATCH"
            )
        )
    else:
        print("checksum v1  : 0x{:08x}".format(checksum_v1))
        print("checksum v2  : 0x{:08x}".format(checksum_v2))
        print("warning      : unknown version string, cannot choose checksum variant")

    print()
    print(
        "{:<3} {:<12} {:>12} {:>12} {:>12} {:>12}".format(
            "idx", "name", "size", "offset", "end", "gap_prev"
        )
    )
    print("-" * 71)

    previous_end = None
    for index, (name, size, part_offset, mask_flags, protect_flags) in enumerate(partitions):
        part_end = part_offset + size
        gap_from_prev = None if previous_end is None else part_offset - previous_end
        print(
            "{:<3} {:<12} {:>12} {:>12} {:>12} {:>12}".format(
                index,
                (name or "<empty>")[:12],
                "0x{:x}".format(size),
                "0x{:x}".format(part_offset),
                "0x{:x}".format(part_end),
                "-" if gap_from_prev is None else "0x{:x}".format(gap_from_prev),
            )
        )
        print(
            "    size={} offset={} end={} gap_from_prev={} mask=0x{:x} protect=0x{:x}".format(
                format_size(size),
                format_size(part_offset),
                format_size(part_end),
                "-" if gap_from_prev is None else format_size(gap_from_prev),
                mask_flags,
                protect_flags,
            )
        )
        previous_end = part_end

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

eg:

```shell
echo "01080000: 4d 50 54 00 30 31 2e 30 30 2e 30 30 00 00 00 00  MPT.01.00.00....
01080010: 06 00 00 00 32 e7 67 16 62 6f 6f 74 6c 6f 61 64  ....2.g.bootload
01080020: 65 72 00 00 00 00 00 00 00 00 40 00 00 00 00 00  er........@.....
01080030: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
01080040: 72 65 73 65 72 76 65 64 00 00 00 00 00 00 00 00  reserved........
01080050: 00 00 00 04 00 00 00 00 00 00 40 02 00 00 00 00  ..........@.....
01080060: 00 00 00 00 00 00 00 00 65 6e 76 00 00 00 00 00  ........env.....
01080070: 00 00 00 00 00 00 00 00 00 00 80 00 00 00 00 00  ................
01080080: 00 00 c0 06 00 00 00 00 00 00 00 00 00 00 00 00  ................
01080090: 6c 6f 67 6f 00 00 00 00 00 00 00 00 00 00 00 00  logo............
010800a0: 00 00 80 00 00 00 00 00 00 00 c0 07 00 00 00 00  ................
010800b0: 01 00 00 00 00 00 00 00 72 61 6d 64 69 73 6b 00  ........ramdisk.
010800c0: 00 00 00 00 00 00 00 00 00 00 00 02 00 00 00 00  ................
010800d0: 00 00 c0 08 00 00 00 00 01 00 00 00 00 00 00 00  ................
010800e0: 72 6f 6f 74 66 73 00 00 00 00 00 00 00 00 00 00  rootfs..........
010800f0: 00 00 80 3c 07 00 00 00 00 00 40 0b 00 00 00 00  ...<......@.....
01080100: 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
01080110: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
01080120: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
01080130: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
01080140: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
01080150: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
01080160: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
01080170: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
01080180: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
01080190: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
010801a0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
010801b0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................" | python3 rsv_partitions_parser.py

rsv partition table
magic        : MPT (4d505400)
version      : 01.00.00
count        : 6
checksum     : 0x1667e732
checksum v1  : 0x1667e732 OK

idx name                 size       offset          end     gap_prev
-----------------------------------------------------------------------
0   bootloader       0x400000          0x0     0x400000            -
    size=4 MiB offset=0 MiB end=4 MiB gap_from_prev=- mask=0x0 protect=0x0
1   reserved        0x4000000    0x2400000    0x6400000    0x2000000
    size=64 MiB offset=36 MiB end=100 MiB gap_from_prev=32 MiB mask=0x0 protect=0x0
2   env              0x800000    0x6c00000    0x7400000     0x800000
    size=8 MiB offset=108 MiB end=116 MiB gap_from_prev=8 MiB mask=0x0 protect=0x0
3   logo             0x800000    0x7c00000    0x8400000     0x800000
    size=8 MiB offset=124 MiB end=132 MiB gap_from_prev=8 MiB mask=0x1 protect=0x0
4   ramdisk         0x2000000    0x8c00000    0xac00000     0x800000
    size=32 MiB offset=140 MiB end=172 MiB gap_from_prev=8 MiB mask=0x1 protect=0x0
5   rootfs        0x73c800000    0xb400000  0x747c00000     0x800000
    size=29640 MiB offset=180 MiB end=29820 MiB gap_from_prev=8 MiB mask=0x4 protect=0x0

```

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

uboot读取emmc上rsv的Emmc Partition Table分区表

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

- 检测物理不一致： (原厂)U-Boot会将此动态构建的分区映像与物理eMMC上 36MiB 偏移处的物理 EPT 逐项比对 。
- 强制覆盖策略： 如果两者发生不一致，(原厂)U-Boot会默认当前的 DTB 节点配置具有最高置信度，并在对物理存储介质上的旧 EPT 进行全盘覆盖擦写后，用最新的 DTB 分区布局强行同步复写物理 EPT 结构 。
- 无节点回退模式： 只有当在当前 DTB 中完全无法寻获 /partitions 节点结构时，(原厂)U-Boot 才会放弃对物理分区的重写，并允许内核直接信任并读取现存的 eMMC 物理 EPT 。

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

# 关于修改 burn image 实现自定义分区与bootloader的研究

### 自定义bootloader

```shell
$ ./utils/aml_image_v2_packer -d VIM3.uboot-mainline.emmc.aml.img aaa
[Msg]Image package version 0x2
[Msg]Unpack item [USB         ,              DDR] to (aaa/DDR.USB) size:1329520 bytes
[Msg]Backup item [USB         ,            UBOOT] backItemId[0][USB, DDR]
[Msg]Unpack item [PARTITION   ,         _aml_dtb] to (aaa/_aml_dtb.PARTITION) size:87858 bytes
[Msg]Unpack item [UBOOT       ,     aml_sdc_burn] to (aaa/aml_sdc_burn.UBOOT) size:1330032 bytes
[Msg]Unpack item [ini         ,     aml_sdc_burn] to (aaa/aml_sdc_burn.ini) size:589 bytes
[Msg]Unpack item [PARTITION   ,       bootloader] to (aaa/bootloader.PARTITION) size:1331200 bytes
[Msg]Backup item [dtb         ,           meson1] backItemId[2][PARTITION, _aml_dtb]
[Msg]Unpack item [conf        ,         platform] to (aaa/platform.conf) size:155 bytes
[Msg]Write config file "aaa/image.cfg" OK!
Image unpack OK!
$ cd aaa/
$ cp ../amlogic-boot-fip/my-output-dir/u-boot.bin bootloader.PARTITION 
$ cd ..
$ ./utils/aml_image_v2_packer -r aaa/image.cfg aaa/ aaa.img
[Msg]Pack Item[USB         ,              DDR] from (aaa/DDR.USB),sz[0x144970]B,fileType[normal]	
[Msg]Pack Item[USB         ,            UBOOT] from (aaa/DDR.USB),Duplicated for DDR.USB

[Msg]Pack Item[PARTITION   ,         _aml_dtb] from (aaa/_aml_dtb.PARTITION),sz[0x15732]B,fileType[normal]	
[Msg]Pack Item[VERIFY      ,         _aml_dtb] from (aaa/_aml_dtb.PARTITION),vry[sha1sum 7ee07f3471bac2523c9a3f9aebc22f3ab108155b]	
[Msg]Pack Item[UBOOT       ,     aml_sdc_burn] from (aaa/aml_sdc_burn.UBOOT),sz[0x144b70]B,fileType[normal]	
[Msg]Pack Item[ini         ,     aml_sdc_burn] from (aaa/aml_sdc_burn.ini),sz[0x24d]B,fileType[normal]	
[Msg]Pack Item[PARTITION   ,       bootloader] from (aaa/bootloader.PARTITION),sz[0x1a3970]B,fileType[normal]	
[Msg]Pack Item[VERIFY      ,       bootloader] from (aaa/bootloader.PARTITION),vry[sha1sum c9f75412790a4c3369ddf616619a911098c4aeef]	
[Msg]Pack Item[dtb         ,           meson1] from (aaa/_aml_dtb.PARTITION),Duplicated for _aml_dtb.PARTITION

[Msg]Pack Item[conf        ,         platform] from (aaa/platform.conf),sz[0x9b]B,fileType[normal]	
[Msg]version:0x2 crc:0x6495db22 size:4472723 bytes[4MB]
Pack image[aaa.img] OK
```

先用USB_Burning_Tool 刷写原版VIM3.uboot-mainline.emmc.aml.img，查看version:


```
=> version
U-Boot 2021.07 (Nov 12 2021 - 11:31:01 +0800) khadas-vim3

aarch64-none-linux-gnu-gcc (GNU Toolchain for the A-profile Architecture 9.2-2019.12 (arm-9.10)) 9.2.1 20191025
GNU ld (GNU Toolchain for the A-profile Architecture 9.2-2019.12 (arm-9.10)) 2.33.1.20191209
```

然后重新刷写我们刚刚构建的aaa.img,查看version:

```
U-Boot 2026.07-rc2-00064-g38dbe637c9df (May 21 2026 - 05:32:04 -0400) khadas-vim3

aarch64-none-elf-gcc (Arm GNU Toolchain 15.2.Rel1 (Build arm-15.86)) 15.2.1 20251203
GNU ld (Arm GNU Toolchain 15.2.Rel1 (Build arm-15.86)) 2.45.1.20251203
```

替换成功

### 自定义分区

从替换u-boot后的工作目录开始。

反编译dtb:

```sh
$ cd aaa
$ dtc -I dtb -O dts -o original.dts _aml_dtb.PARTITION 
```

查看dts partitions 内容：

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

通过rsv_partitions_parser.py，解析出来的:

```
idx name                 size       offset          end     gap_prev
-----------------------------------------------------------------------
0   bootloader       0x400000          0x0     0x400000            -
    size=4 MiB offset=0 MiB end=4 MiB gap_from_prev=- mask=0x0 protect=0x0
1   reserved        0x4000000    0x2400000    0x6400000    0x2000000
    size=64 MiB offset=36 MiB end=100 MiB gap_from_prev=32 MiB mask=0x0 protect=0x0
2   env              0x800000    0x6c00000    0x7400000     0x800000
    size=8 MiB offset=108 MiB end=116 MiB gap_from_prev=8 MiB mask=0x0 protect=0x0
3   logo             0x800000    0x7c00000    0x8400000     0x800000
    size=8 MiB offset=124 MiB end=132 MiB gap_from_prev=8 MiB mask=0x1 protect=0x0
4   ramdisk         0x2000000    0x8c00000    0xac00000     0x800000
    size=32 MiB offset=140 MiB end=172 MiB gap_from_prev=8 MiB mask=0x1 protect=0x0
5   rootfs        0x73c800000    0xb400000  0x747c00000     0x800000
    size=29640 MiB offset=180 MiB end=29820 MiB gap_from_prev=8 MiB mask=0x4 protect=0x0
```

发现貌似bootloader分区、reserved分区、env分区是必须存在的，不能通过dtb修改。

删除partitions中的ramdisk、rootfs节点，修改logo的名字为justForFun，（**parts属性也记得修改**）:

```
	partitions {
		parts = <0x01>;
		part-0 = <0x61>;
		phandle = <0x100>;

		justForFun {
			pname = "justForFun";
			size = <0x00 0x800000>;
			mask = <0x01>;
			phandle = <0x61>;
		};
	};

```

删除 ```__symbols __``` 节点下rootfs、ramdisk，替换logo的名称为justForFun。

重新生成dtb

```sh
$ rm _aml_dtb.PARTITION 
$ dtc -I dts -O dtb -o _aml_dtb.PARTITION original.dts
$ ls
_aml_dtb.PARTITION  aml_sdc_burn.ini  aml_sdc_burn.UBOOT  bootloader.PARTITION  DDR.USB  image.cfg  original.dts  platform.conf
```

创建justForFun.PARTITION:

```sh
$ dd if=/dev/urandom of=justForFun.PARTITION bs=1M count=2
$ ls
_aml_dtb.PARTITION  aml_sdc_burn.ini  aml_sdc_burn.UBOOT  bootloader.PARTITION  DDR.USB  image.cfg  justForFun.PARTITION  original.dts  platform.conf
```

修改image.cfg，原文件内容为：

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

修改后为：

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
file="justForFun.PARTITION"		main_type="PARTITION"		sub_type="justForFun"	file_type="normal"
```

重打包，然后烧写:

```sh
$ ./utils/aml_image_v2_packer -r aaa/image.cfg aaa/ aaa.img
[Msg]Pack Item[USB         ,              DDR] from (aaa/DDR.USB),sz[0x144970]B,fileType[normal]	
[Msg]Pack Item[USB         ,            UBOOT] from (aaa/DDR.USB),Duplicated for DDR.USB

[Msg]Pack Item[PARTITION   ,         _aml_dtb] from (aaa/_aml_dtb.PARTITION),sz[0x15617]B,fileType[normal]	
[Msg]Pack Item[VERIFY      ,         _aml_dtb] from (aaa/_aml_dtb.PARTITION),vry[sha1sum 2d921c8dee5357cd5f32f48969327ad6db0bc719]	
[Msg]Pack Item[UBOOT       ,     aml_sdc_burn] from (aaa/aml_sdc_burn.UBOOT),sz[0x144b70]B,fileType[normal]	
[Msg]Pack Item[ini         ,     aml_sdc_burn] from (aaa/aml_sdc_burn.ini),sz[0x24d]B,fileType[normal]	
[Msg]Pack Item[PARTITION   ,       bootloader] from (aaa/bootloader.PARTITION),sz[0x145000]B,fileType[normal]	
[Msg]Pack Item[VERIFY      ,       bootloader] from (aaa/bootloader.PARTITION),vry[sha1sum c586f54a671313e7b82d9c087277af91670f7118]	
[Msg]Pack Item[PARTITION   ,       justForFun] from (aaa/justForFun.PARTITION),sz[0x200000]B,fileType[normal]	
[Msg]Pack Item[VERIFY      ,       justForFun] from (aaa/justForFun.PARTITION),vry[sha1sum 74f55372958afc218040de65f5a7bc135e8c3892]	
[Msg]Pack Item[dtb         ,           meson1] from (aaa/_aml_dtb.PARTITION),Duplicated for _aml_dtb.PARTITION

[Msg]Pack Item[conf        ,         platform] from (aaa/platform.conf),sz[0x9b]B,fileType[normal]	
[Msg]version:0x2 crc:0x8c395092 size:6183347 bytes[5MB]
Pack image[aaa.img] OK

```

通过u-boot命令读取rsv中的分区表

```
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
=> md.b  0x1080000 0x518
```

