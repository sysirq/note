# VIM3

VIM3/3L Setup Serial Debug Console

https://docs.khadas.com/products/sbc/vim3/development/setup-serial-tool#tab__mac-os

### 串行调试控制台

| **Serial tools pin** | GPIO **board header pin** |
| -------------------- | ------------------------- |
| GND                  | 17                        |
| TXD                  | 18                        |
| RXD                  | 19                        |


# 硬件控制

### LED 控制

“系统开机状态”的 LED控制：
```
i2c mw 0x18 0x28 3 1 # LED_HEARTBEAT_MODE
i2c mw 0x18 0x28 2 1 # LED_BREATHE_MODE
i2c mw 0x18 0x28 1 1 # LED_ON_MODE
i2c mw 0x18 0x28 0 1 # LED_OFF_MODE
```

“系统关机状态”的 LED控制：
```
i2c mw 0x18 0x29 3 1 # LED_HEARTBEAT_MODE
i2c mw 0x18 0x29 2 1 # LED_BREATHE_MODE
i2c mw 0x18 0x29 1 1 # LED_ON_MODE
i2c mw 0x18 0x29 0 1 # LED_OFF_MODE
```

# Android 9 32位源码编译

### Build U-Boot

```shell
$ cd PATH_YOUR_PROJECT
$ cd bootloader/uboot
$ ./mk TARGET
```

### Build Linux Kernel

```shell
$ source build/envsetup.sh 
$ lunch kvim3-userdebug
$ make bootimage
```

对应的makefile解析:

```
bootimage (phony)
└── out/.../boot.img                  [Makefile:812]
      ├── mkbootimg (host tool)       [config.mk:651]
      ├── out/.../kernel              [Makefile:677] ← 叶节点(预编译)
      └── out/.../ramdisk.img         [Makefile:692]
            ├── mkbootfs (host tool)  [config.mk:647]
            ├── minigzip (host tool)  [config.mk:648]  order-only
            └── INTERNAL_RAMDISK_FILES                 [Makefile:684]
                  = filter(root/%, ALL_DEFAULT_INSTALLED_MODULES)
                  └── ALL_DEFAULT_INSTALLED_MODULES    [main.mk:1018]
                        ├── PRODUCT_COPY_FILES 安装文件  [Makefile:40]
                        │     (init.rc, fstab.*, ueventd.rc ...)
                        ├── default.prop / build.prop   [Makefile:145]
                        └── modules_to_install          [main.mk:951]
                              = PRODUCT_PACKAGES 各模块的 INSTALLED 路径
                              └── ALL_MODULES.xxx.INSTALLED [base_rules.mk:643]
                                    (每个模块在 Android.mk 编译时注册)
```

kernel对应的makefile为：device/khadas/kvim3/Kernel.mk

### Build Android

```sh
$ cd PATH_YOUR_PROJECT
$ source build/envsetup.sh
$ lunch TARGET_LUNCH
$ make -jN otapackage
```

# 手动启动boot.img(内核)

```sh
=> setenv fdt_high 0x20000000
=> mmc dev 2
switch to partitions #0, OK
mmc2(part 0) is current device
=> mmc read 0x1080000 0x3E000 0x5000
MMC read: dev # 2, block # 253952, count 20480 ... 20480 blocks read: OK
=> bootm start 0x1080000
## Booting Android Image at 0x01080000 ...
Kernel load addr 0x01080000 size 9264 KiB
Kernel command line: androidboot.dtbo_idx=0 --cmdline root=/dev/mmcblk0p18 buildvariant=userdebug
Error: header_version must be >= 2 to get dtb
second address is 0x198c800
Working FDT set to 198c800
=> bootm loados
   Loading Kernel Image to 1080000
=> bootm fdt
   Loading Device Tree to 000000001ffe5000, end 000000001ffff818 ... OK
Working FDT set to 1ffe5000
=> fdt chosen
=> fdt set /chosen bootargs "init=/init console=ttyS0,115200 no_console_suspend earlycon=aml-uart,0xff803000 ramoops.pstore_en=1 ramoops.record_size=0x8000 ramoops.console_size=0x4000"
=> fdt set /chosen stdout-path "/soc/aobus@ff800000/serial@3000"
=> fdt print /chosen
chosen {
        stdout-path = "/soc/aobus@ff800000/serial@3000";
        smbios3-entrypoint = <0x00000000 0xeaf3b000>;
        u-boot,version = "2026.07-rc3-00031-g9b1f6ba072a5-dirty";
        bootargs = "init=/init console=ttyS0,115200 no_console_suspend earlycon=aml-uart,0xff803000 ramoops.pstore_en=1 ramoops.record_size=0x8000 ramoops.console_size=0x4000";
        kaslr-seed = <0xfc22a6fc 0x4609f865>;
};
=> fdt mknod / memory           
=> fdt set /memory device_type "memory"  
=> fdt set /memory reg <0x0 0xED800000>  
=> fdt print /memory
memory {
        reg = <0x00000000 0xed800000>;
        device_type = "memory";
};

=> bootm go

Starting kernel ...

   FDT blob at 0x7ffe5000, size 108569 bytes
   IH_ARCH_DEFAULT is 22, images->os.arch is 0
[    0.000000@0] Booting Linux on physical CPU 0x0
[    0.000000@0] Linux version 4.9.113 (root@c6fcd1183ec2) (gcc version 6.3.1 20170109 (Linaro GCC 6.3-2017.02) ) #1 SMP PREEMPT Mon Jun 8 18:07:09 CST 2026
[    0.000000@0] CPU: cpu_v7_name [410fd034] revision 4 (ARMv7), cr=10c5383d
[    0.000000@0] CPU: div instructions available: patching division code
[    0.000000@0] CPU: PIPT / VIPT nonaliasing data cache, VIPT aliasing instruction cache
[    0.000000@0] Machine model: Khadas
[    0.000000@0] earlycon: aml-uart0 at MMIO 0xff803000 (options '')
[    0.000000@0] bootconsole [aml-uart0] enabled
[    0.000000@0]        07400000 - 07500000,     1024 KB, ramoops@0x07400000
[    0.000000@0]        05000000 - 05400000,     4096 KB, linux,secmon
[    0.000000@0]        7f800000 - 80000000,     8192 KB, linux,meson-fb
[    0.000000@0]        e5800000 - ed800000,   131072 KB, linux,ion-dev
[    0.000000@0]        e3000000 - e5800000,    40960 KB, linux,di_cma
[    0.000000@0] Reserved memory: regions without no-map are not yet supported
[    0.000000@0]        cfc00000 - e3000000,   315392 KB, linux,codec_mm_cma
[    0.000000@0]        cfc00000 - cfc00000,        0 KB, linux,codec_mm_reserved
[    0.000000@0]        cbc00000 - cfc00000,    65536 KB, linux,vdin0_cma
[    0.000000@0]        c7c00000 - cbc00000,    65536 KB, linux,vdin1_cma
[    0.000000@0]        c6c00000 - c7c00000,    16384 KB, linux,galcore
[    0.000000@0]        bec00000 - c6c00000,   131072 KB, linux,isp_cma
[    0.000000@0]        bd400000 - bec00000,    24576 KB, linux,adapt_cma
[    0.000000@0] cma: Reserved 8 MiB at 0xbcc00000
[    0.000000@0] Memory policy: Data cache writealloc
[    0.000000@0] psci: probing for conduit method from DT.
[    0.000000@0] psci: PSCIv1.0 detected in firmware.
[    0.000000@0] psci: Using standard PSCI v0.2 function IDs
[    0.000000@0] psci: MIGRATE_INFO_TYPE not supported.
[    0.000000@0] psci: SMC Calling Convention v1.1
[    0.000000@0] percpu: Embedded 15 pages/cpu @ee1b0000 s32140 r8192 d21108 u61440
[    0.000000@0] Built 1 zonelists in Zone order, mobility grouping on.  Total pages: 971264
[    0.000000@0] Kernel command line: init=/init console=ttyS0,115200 no_console_suspend earlycon=aml-uart,0xff803000 ramoops.pstore_en=1 ramoops.record_size=0x8000 ramoops.console_0
[    0.000000@0] PID hash table entries: 4096 (order: 2, 16384 bytes)
[    0.000000@0] Dentry cache hash table entries: 131072 (order: 7, 524288 bytes)
[    0.000000@0] Inode-cache hash table entries: 65536 (order: 6, 262144 bytes)
[    0.000000@0] Memory: 3023984K/3891200K available (14336K kernel code, 1357K rwdata, 3408K rodata, 1024K init, 1399K bss, 56208K reserved, 811008K cma-reserved, 2297856K highmem)
[    0.000000@0] Virtual kernel memory layout:
[    0.000000@0]     vector  : 0xffff0000 - 0xffff1000   (   4 kB)
[    0.000000@0]     fixmap  : 0xffc00000 - 0xfff00000   (3072 kB)
[    0.000000@0]     vmalloc : 0xf0800000 - 0xff800000   ( 240 MB)
[    0.000000@0]     lowmem  : 0xc0000000 - 0xf0000000   ( 768 MB)
[    0.000000@0]     pkmap   : 0xbfe00000 - 0xc0000000   (   2 MB)
[    0.000000@0]     modules : 0xbc000000 - 0xbfe00000   (  62 MB)
[    0.000000@0]       .text : 0xc0108000 - 0xc1000000   (15328 kB)
[    0.000000@0]       .init : 0xc1500000 - 0xc1600000   (1024 kB)
[    0.000000@0]       .data : 0xc1600000 - 0xc17534d0   (1358 kB)
[    0.000000@0]        .bss : 0xc1755000 - 0xc18b2e44   (1400 kB)
[    0.000000@0] zone:Normal, spaned pages:196608, total:196608
[    0.000000@0] zone:HighMem, spaned pages:776192, total:972800
[    0.000000@0] page_trace_mem_init, trace buffer:edc00000, size:3b6000, used:edfb6000, end:ee000000
[    0.000000@0] SLUB: HWalign=64, Order=0-3, MinObjects=0, CPUs=6, Nodes=1
[    0.000000@0] Preemptible hierarchical RCU implementation.
[    0.000000@0]        Build-time adjustment of leaf fanout to 32.
[    0.000000@0]        RCU restricting CPUs from NR_CPUS=8 to nr_cpu_ids=6.
[    0.000000@0] RCU: Adjusting geometry for rcu_fanout_leaf=32, nr_cpu_ids=6
[    0.000000@0] NR_IRQS:16 nr_irqs:16 16
[    0.000000@0] irq_meson_gpio: 100 to 8 gpio interrupt mux initialized
[    0.000000@0] g12a_aoclkc_init: register ao clk ok!
[    0.000000@0] Meson chip version = RevB (29:B - 10:0)
[    0.000000@0] meson_g12a_sdemmc_init: register amlogic sdemmc clk
[    0.000000@0] meson_g12a_sdemmc_init: register amlogic sdemmc clk
[    0.000000@0] meson_g12a_gpu_init: register meson gpu clk
[    0.000000@0] meson_g12a_media_init: register meson media clk
[    0.000000@0] meson_g12a_misc_init: register amlogic g12a misc clks
[    0.000000@0] meson_g12a_misc_init: done.
[    0.000000@0] g12a_clkc_init initialization complete
[    0.000000@0] arm_arch_timer: Architected cp15 timer(s) running at 24.00MHz (virt).
[    0.000000@0] clocksource: arch_sys_counter: mask: 0xffffffffffffff max_cycles: 0x588fe9dc0, max_idle_ns: 440795202592 ns
[    0.000004@0] sched_clock: 56 bits at 24MHz, resolution 41ns, wraps every 4398046511097ns
[    0.008107@0] Switching to timer-based delay loop, resolution 41ns
[    0.014267@0] meson_bc_timer: mclk->mux_reg =f080c190,mclk->reg =f080e194
[    0.021698@0] Console: colour dummy device 80x30
[    0.025541@0] Calibrating delay loop (skipped), value calculated using timer frequency.. 48.00 BogoMIPS (lpj=96000)
[    0.035877@0] pid_max: default: 32768 minimum: 301
[    0.040693@0] thread_stack_cache_init, vmap:ed825a00, bitmap:ed828400, cache page:bc800
[    0.048583@0] thread_stack_cache_init, allocation vm area:ed826f00, addr:bc000000, size:3001000
[    0.057271@0] Security Framework initialized
[    0.061422@0] SELinux:  Initializing.
[    0.065092@0] Mount-cache hash table entries: 2048 (order: 1, 8192 bytes)
[    0.071777@0] Mountpoint-cache hash table entries: 2048 (order: 1, 8192 bytes)
[    0.079667@0] CPU: Testing write buffer coherency: ok
[    0.083920@0] ftrace: allocating 45851 entries in 135 pages
[    0.173154@0] sched-energy: Sched-energy-costs installed from DT
[    0.173526@0] CPU0: update cpu_capacity 631
[    0.177699@0] CPU0: thread -1, cpu 0, socket 0, mpidr 80000000
[    0.183471@0] Setting up static identity map for 0x200000 - 0x200058
[    0.238830@0] secmon: clear_range:5100000 200000
[    0.286701@1] CPU1: update cpu_capacity 631
[    0.286706@1] CPU1: thread -1, cpu 1, socket 0, mpidr 80000001
[    0.319353@2] CPU2: update cpu_capacity 1192
[    0.319358@2] CPU2: thread -1, cpu 0, socket 1, mpidr 80000100
[    0.350929@3] CPU3: update cpu_capacity 1192
[    0.350933@3] CPU3: thread -1, cpu 1, socket 1, mpidr 80000101
[    0.383014@4] CPU4: update cpu_capacity 1192
[    0.383018@4] CPU4: thread -1, cpu 2, socket 1, mpidr 80000102
[    0.415112@5] CPU5: update cpu_capacity 1192
[    0.415116@5] CPU5: thread -1, cpu 3, socket 1, mpidr 80000103
[    0.415224@0] Brought up 6 CPUs
[    0.462679@0] SMP: Total of 6 processors activated (288.00 BogoMIPS).
[    0.469071@0] CPU: All CPU(s) started in SVC mode.
[    0.475285@4] addr:bc061cce is in kernel, size fix 4096->10, data:mode=0755
[    0.480898@0] devtmpfs: initialized
[    0.502826@0] VFP support v0.3: implementor 41 architecture 3 part 40 variant 9 rev 0
[    0.505329@4] clocksource: jiffies: mask: 0xffffffff max_cycles: 0xffffffff, max_idle_ns: 7645041785100000 ns
[    0.514864@4] futex hash table entries: 2048 (order: 5, 131072 bytes)
[    0.521409@4] pinctrl core: initialized pinctrl subsystem
[    0.527570@4] NET: Registered protocol family 16
[    0.531888@4] DMA: preallocated 256 KiB pool for atomic coherent allocations
[    0.538135@4] schedtune: init normalization constants...
[    0.543402@4] schedtune: CLUSTER[0-1]      min_pwr:     0 max_pwr:    42
[    0.550036@4] schedtune: CPU[0]            min_pwr:     0 max_pwr:   279
[    0.556672@4] schedtune: CPU[1]            min_pwr:     0 max_pwr:   279
[    0.563313@4] schedtune: CLUSTER[2-5]      min_pwr:     0 max_pwr:   110
[    0.569954@4] schedtune: CPU[2]            min_pwr:     0 max_pwr:  1048
[    0.576594@4] schedtune: CPU[3]            min_pwr:     0 max_pwr:  1048
[    0.583236@4] schedtune: CPU[4]            min_pwr:     0 max_pwr:  1048
[    0.589877@4] schedtune: CPU[5]            min_pwr:     0 max_pwr:  1048
[    0.596524@4] schedtune: SYSTEM            min_pwr:     0 max_pwr:  4902
[    0.603164@4] schedtune: using normalization constants mul: 2882587190 sh1: 1 sh2: 12
[    0.610931@4] schedtune: verify normalization constants...
[    0.616358@4] schedtune: max_pwr/2^0: 4902 => norm_pwr:  1024
[    0.622056@4] schedtune: max_pwr/2^1: 2451 => norm_pwr:   512
[    0.627743@4] schedtune: max_pwr/2^2: 1225 => norm_pwr:   255
[    0.633441@4] schedtune: max_pwr/2^3:  612 => norm_pwr:   127
[    0.639128@4] schedtune: max_pwr/2^4:  306 => norm_pwr:    63
[    0.644817@4] schedtune: max_pwr/2^5:  153 => norm_pwr:    31
[    0.650511@4] schedtune: configured to support 5 boost groups
[    0.672261@0] cpuidle: using governor menu
[    0.672399@0] register canvas platform driver
[    0.675133@0] register rdma platform driver
[    0.679664@5] hw-breakpoint: found 5 (+1 reserved) breakpoint and 4 watchpoint registers.
[    0.687314@5] hw-breakpoint: maximum watchpoint size is 8 bytes.
[    0.693541@5] clkmsr: clkmsr: driver init
[    0.697207@5] codec_mm_module_init
[    0.700627@5] media_configs_system_init
[    0.704658@5] aml_watch_point_probe, in, wp:4
[    0.709204@5] pstore: using zlib compression
[    0.713407@5] console [pstore-1] enabled
[    0.716830@5] pstore: Registered ramoops as persistent store backend
[    0.723107@5] ramoops: attached 0x100000@0x7400000, ecc: 0/0
[    0.728704@5] ramoops: ramoops_io_en:0 1 old:0x0 ftrace_size:0x40000[    0.736953@5] aml_iomap: amlogic iomap probe done
[    0.740047@5] vpu: driver version: v20190329(8-g12b)
[    0.744412@5] vpu: load vpu_clk: 666666667Hz(7)
[    0.749071@5] vpu: clktree_init
[    0.752041@5] vpu: vpu_probe OK
[    0.760948@0] clkmsr: msr_clk_reg0=f09bc004,msr_clk_reg2=f09be00c
[    0.761404@0] clkmsr ffd18004.meson_clk_msr: failed to get msr ring reg0
[    0.771665@0] audio_clocks: audio_clocks_probe done
[    0.777866@0] aml_vdac_config_probe: cpu_id:4, name:meson-g12ab-vdac
[    0.779425@0] aml_vdac_probe: ok
[    0.782587@0] canvas_probe reg=ff638000,size=2000
[    0.787053@0] canvas maped reg_base =f09c2000
[    0.801922@0] rdma_probe,cpu_type:0, ver:0, len:8
[    0.802214@0] rdma_register, rdma_table_addr f09e5000 rdma_table_addr_phy bcc40000 reg_buf ed0d8000
[    0.810010@0] rdma_register success, handle 1 table_size 32768
[    0.815783@0] set_rdma_handle video rdma handle = 1.
[    0.820711@0] classs created ok
[    0.823774@0] classs file created ok
[    0.828872@2] aml_snd_reg_map[0], reg:ff640000, size:2000
[    0.832723@2] aml_snd_reg_map[1], reg:ff642000, size:2000
[    0.838030@2] aml_snd_reg_map[2], reg:ff64a000, size:2000
[    0.843367@2] aml_snd_reg_map[3], reg:ff656000, size:1800
[    0.848734@2] aml_snd_reg_map[4], reg:ffd01000, size:1000
[    0.854063@2] amlogic auge_snd_iomap probe done
[    0.861424@2] cvbs_out: cvbsout_probe, cpu_id:4,name:meson-g12b-cvbsout
[    0.865238@2] cvbs_out: find performance_pal config
[    0.869938@2] cvbs_out: clk path:0x0
[    0.873445@2] vout: vout1: register server: cvbs_vout_server
[    0.879065@2] cvbs_out: register cvbs module server ok
[    0.884157@2] vout: vout2: register server: cvbs_vout2_server
[    0.889842@2] cvbs_out: register cvbs module vout2 server ok
[    0.895456@2] cvbs_out: chrdev devno 264241152 for disp
[    0.900859@0] cvbs_out: create cdev cvbs
[    0.904530@0] cvbs_out: cvbsout_probe OK
[    0.909117@0] codec_mm codec_mm: assigned reserved memory node linux,codec_mm_cma
[    0.915921@0] codec_mm codec_mm: assigned reserved memory node linux,codec_mm_cma
[    0.923231@0] codec_mm_probe ok
[    1.178792@1] vgaarb: loaded
[    1.179222@1] khadas_hwver_probe
[    1.179632@1] SCSI subsystem initialized
[    1.183713@1] usbcore: registered new interface driver usbfs
[    1.188836@1] usbcore: registered new interface driver hub
[    1.194385@2] usbcore: registered new device driver usb
[    1.199573@2] Linux video capture interface: v2.00
[    1.204179@2] pps_core: LinuxPPS API ver. 1 registered
[    1.209207@2] pps_core: Software ver. 5.3.6 - Copyright 2005-2007 Rodolfo Giometti <giometti@linux.it>
[    1.218447@2] PTP clock support registered
[    1.223379@0] secmon: reserve_mem_size:0x300000
[    1.227071@0] secmon secmon: assigned reserved memory node linux,secmon
[    1.233818@0] secmon: get page:ee2e7000, 5000
[    1.237829@0] secmon: share in base: 0xc50fe000, share out base: 0xc50ff000
[    1.244747@0] secmon: phy_in_base: 0x50fe000, phy_out_base: 0x50ff000
[    1.253583@5] fb: osd_init_module
[    1.254754@5] fb: viu vsync irq: 59
[    1.257885@5] fb: viu2 vsync irq: 68
[    1.261435@5] 0x000000c0:Y=c0,U=0,V=0
[    1.265000@5] 0x000000c1:Y=c1,U=0,V=0
[    1.268598@5] 0x000000c2:Y=c2,U=0,V=0
[    1.272246@5] 0x000000c3:Y=c3,U=0,V=0
[    1.275843@5] 0x000000c4:Y=c4,U=0,V=0
[    1.279493@5] 0x000000c5:Y=c5,U=0,V=0
[    1.283559@5] fb: osd_rdma_enable: rdma_table p=0xbcc48000,op=0xbcc48000 , v=0xf0ad3000
[    1.291075@5] rdma_register, rdma_table_addr f0ad5000 rdma_table_addr_phy bcc49000 reg_buf edbfa000
[    1.300020@5] rdma_register success, handle 2 table_size 4096
[    1.305708@5] fb: osd_rdma_enable:osd rdma handle = 2.
[    1.310801@5] fb: mem_size: 0x800000
[    1.314310@5] fb: mem_size: 0x2000000
[    1.317944@5] fb: mem_size: 0x100000
[    1.321468@5] fb: mem_size: 0x100000
[    1.325013@5] fb: mem_size: 0x800000
[    1.328581@5] meson-fb meson-fb: assigned reserved memory node linux,meson-fb
[    1.335626@5] fb: reserved memory base:0x7f800000, size:800000
[    1.341687@5] vout: error: invalid vinfo1. current vmode is not supported
[    1.348135@5] nativeui_propname:null 
[    1.351742@5]  fb_var_set_process 
[    1.355114@5] not recovery mode set 
[    1.358642@5] fb_def_var_set 
[    1.361583@5] fb: init fbdev bpp is:32
[    1.367050@0] fb: set osd0 reverse as NONE
[    1.369380@0] vout: error: invalid vinfo1. current vmode is not supported
[    1.376116@0] fb: osd probe OK
[    1.379973@0] hdmitx: system: Ver: 20190815
[    1.383360@0] hdmitx: system: hpd irq = 52
[    1.388057@0] hdmitx: hdmitx20: Mapped PHY: 0xffd00000
[    1.392441@0] hdmitx: hdmitx20: Mapped PHY: 0xff634400
[    1.397498@0] hdmitx: hdmitx20: Mapped PHY: 0xff900000
[    1.402571@0] hdmitx: hdmitx20: Mapped PHY: 0xff800000
[    1.407654@0] hdmitx: hdmitx20: Mapped PHY: 0xff63c000
[    1.412762@0] hdmitx: hdmitx20: Mapped PHY: 0xffd00000
[    1.417831@0] hdmitx: hdmitx20: Mapped PHY: 0xff608000
[    1.422921@0] hdmitx: hdmitx20: Mapped PHY: 0xff600000
[    1.428009@0] hdmitx: hdmitx20: Mapped PHY: 0xffe01000
[    1.433120@0] hdmitx: hw: hdmitx_get_format:0x0
[    1.437579@0] hdmitx: hw: P_HHI_HDMI_CLK_CNTL :0x100
[    1.442495@0] hdmitx: hw: P_HHI_HDMI_PLL_CNTL :0xda0504f7
[    1.448066@0] hdmitx: hw: avmute set to 1
[    1.451816@0] vout: vout1: register server: hdmitx_vout_server
[    1.457589@0] vout: vout2: register server: hdmitx_vout2_server
[    1.464200@2] hdmitx: system: fmt_attr default
[    1.468464@2] lcd: driver version: 20200102(6-g12b)
[    1.472898@1] lcd: detect mode: tablet, fr_auto_policy: 0, key_valid: 0
[    1.479260@5] lcd: detect lcd_clk_path: 1
[    1.483190@5] lcd: detect resume_type: 0
[    1.487306@5] lcd: lcd_clktree_probe
[    1.490607@5] lcd: status: 0, init_flag: 0
[    1.494683@5] vout: vout1: register server: lcd_vout_server
[    1.500194@5] vout: vout2: register server: lcd_vout2_server
[    1.505820@5] lcd: lcd_tablet_probe from dts
[    1.510026@5] lcd: error: failed to get null
[    1.514256@5] lcd: , invalid, 0bit, 1440x478
[    1.518478@5] lcd: error: Out of clock range, reset to default setting
[    1.525062@5] lcd: error: lcd_debug_info_if is null
[    1.529968@0] vout: error: invalid vinfo1. current vmode is not supported
[    1.536533@0] fb: current vmode=invalid, cmd: 0x20000
[    1.541523@0] lcd: lcd_probe ok
[    1.545063@0] vout: create vout attribute OK
[    1.549079@0] vout: aml_vout_probe OK
[    1.552482@0] vout: vout1: register server: nulldisp_vout_server
[    1.558553@0] vout: tvout monitor interval:500(ms), timeout cnt:20
[    1.564562@0] vout: init mode null set ok
[    1.568495@0] vout: aml_vout_probe
[    1.571882@0] vout: refresh_tvout_mode: mode chang to invalid
[    1.577565@0] vout: vmode set to invalid
[    1.581467@0] fb: current vmode=invalid, cmd: 0x10000
[    1.586451@0] vout: new mode invalid set ok
[    1.590587@0] fb: current vmode=invalid, cmd: 0x20000
[    1.595631@0] vout: aml_vout_probe OK
[    1.600194@4] chip type:0x29
[    1.602458@4] MEMORY:[0+ed800000]
[    1.605331@4] ramdump_probe, storage device:data
[    1.609914@4] NO valid ramdump args:0 0
[    1.613698@4] ramdump_probe, set sticky to 8ed8
[    1.618582@4] Advanced Linux Sound Architecture Driver Initialized.
[    1.626405@5] Bluetooth: Core ver 2.22
[    1.628127@5] NET: Registered protocol family 31
[    1.632680@5] Bluetooth: HCI device and connection manager initialized
[    1.639150@5] Bluetooth: HCI socket layer initialized
[    1.644152@5] Bluetooth: L2CAP socket layer initialized
[    1.649362@5] Bluetooth: SCO socket layer initialized
[    1.654860@0] NetLabel: Initializing
[    1.657909@2] NetLabel:  domain hash size = 128
[    1.662330@2] NetLabel:  protocols = UNLABELED CIPSOv4
[    1.667507@2] NetLabel:  unlabeled traffic allowed by default
[    1.673978@5] clocksource: Switched to clocksource arch_sys_counter
[    1.742163@5] VFS: Disk quotas dquot_6.6.0
[    1.742251@5] VFS: Dquot-cache hash table entries: 1024 (order 0, 4096 bytes)
[    1.758925@3] dtv_dmd:[amldtvdemod..]aml_dtvdemod_init.
[    1.759494@3] NET: Registered protocol family 2
[    1.763590@3] TCP established hash table entries: 8192 (order: 3, 32768 bytes)
[    1.766417@4] clear:2a000000, free:2a000000, tick:139152 us
[    1.775766@3] TCP bind hash table entries: 8192 (order: 4, 65536 bytes)
[    1.782294@3] TCP: Hash tables configured (established 8192 bind 8192)
[    1.788773@3] UDP hash table entries: 512 (order: 2, 16384 bytes)
[    1.794769@3] UDP-Lite hash table entries: 512 (order: 2, 16384 bytes)
[    1.801389@3] NET: Registered protocol family 1
[    1.807555@3] wifi: power_on_pin_OD = 0;
[    1.809596@3] aml_wifi wifi: [wifi_dev_probe] no power_on_pin2
[    1.815464@3] aml_wifi wifi: [pwm_double_channel_conf_dt] wifi pwm dt ok
[    1.822039@3] aml_wifi wifi: [pwm_double_channel_conf] wifi pwm conf ok
[    1.828574@3] aml_wifi wifi: [wifi_dev_probe] dhd_static_buf setup
[    1.834704@3] Wifi: bcmdhd_init_wlan_mem: bcmdhd_init_wlan_mem(): 100.10.545.3
[    1.842583@3] Wifi: bcmdhd_init_wlan_mem: bcmdhd_init_wlan_mem prealloc ok
[    1.848670@3] aml_wifi wifi: [wifi_dev_probe] interrupt_pin=483
[    1.854540@3] aml_wifi wifi: [wifi_dev_probe] irq_num=0, irq_trigger_type=1
[    1.861432@3] aml_wifi wifi: [wifi_dev_probe] power_on_pin=482
[    1.867216@3] aml_wifi wifi: [wifi_dev_probe] clock_32k_pin=0
[    1.873151@0] aml_wifi wifi: [wifi_dev_probe] wifi_setup_dt
[    1.878539@0] aml_wifi wifi: [wifi_dev_probe] irq num is:(86)
[    1.884136@0] aml_wifi wifi: [wifi_dev_probe] interrupt_pin(483)
[    1.890086@0] aml_wifi wifi: [wifi_dev_probe] power_on_pin(482)
[    1.899205@0] enable_pmuserenr_all() start
[    1.899976@0] enable_pmuserenr_all() end
[    1.903904@0] hw perfevents: clusterb_enabled = 1
[    1.908527@0] hw perfevents: cpumasks 0x3, 0x3c
[    1.913042@0] hw perfevents: cluster A irq = 25
[    1.917534@0] hw perfevents: cluster B irq = 26
[    1.922073@0] hw perfevents: enabled with armv7_cortex_a15 PMU driver, 7 counters available
[    1.934800@5] audit: initializing netlink subsys (disabled)
[    1.935802@5] audit: type=2000 audit(1.712:1): initialized
[    1.942416@0] workingset: timestamp_bits=30 max_order=20 bucket_order=0
[    1.958117@0] squashfs: version 4.0 (2009/01/31) Phillip Lougher
[    1.958850@0] exFAT: Version 1.2.9
[    1.963475@0] Registering sdcardfs 0.1
[    1.965828@0] ntfs: driver 2.1.32 [Flags: R/O].
[    1.970832@0] jffs2: version 2.2. (NAND) (SUMMARY)  © 2001-2006 Red Hat, Inc.
[    1.978348@0] fuse init (API version 7.26)
[    1.988861@0] NET: Registered protocol family 38
[    1.988899@0] Key type asymmetric registered
[    1.992152@0] Asymmetric key parser 'x509' registered
[    1.997316@0] bounce: pool size: 64 pages
[    2.001333@0] Block layer SCSI generic (bsg) driver version 0.4 loaded (major 242)
[    2.008601@0] io scheduler noop registered (default)
[    2.013479@0] io scheduler deadline registered
[    2.017910@0] io scheduler cfq registered
[    2.035568@2] random: fast init done
[    2.035632@2] random: crng init done
[    2.053774@0] brd: module loaded
[    2.073930@0] loop: module loaded
[    2.075274@0] zram: Added device: zram0
[    2.075564@0] mcu_probe
[    2.077833@0] mcu_parse_dt hwver:0
[    2.082214@0] mcu version is 3
[    2.084221@0] mcu_probe
[    2.086712@0] mcu_probe,wol enable=0
[    2.092826@1] mtdoops: mtd device (mtddev=name/number) must be supplied
[    2.097884@1] libphy: Fixed MDIO Bus: probed
[    2.101386@1] tun: Universal TUN/TAP device driver, 1.6
[    2.106143@1] tun: (C) 1999-2004 Max Krasnyansky <maxk@qualcomm.com>
[    2.113396@4]  REG0:Addr = f0cfd540
[    2.115936@4]  ee eth reset:Addr = f0ea5008
[    2.120053@4] auto_cali_idx 0
[    2.123487@0] meson6-dwmac ff3f0000.ethernet: no reset control found
[    2.129266@0] stmmac - user ID: 0x11, Synopsys ID: 0x37
[    2.134455@0]  Ring mode enabled
[    2.137602@0]  DMA HW capability register supported[    2.142289@0]  Normal descriptors
[    2.145536@0]  RX Checksum Offload Engine supported
[    2.150386@0]        COE Type 2
[    2.152953@0]  TX Checksum insertion supported
[    2.157384@0]  Wake-Up On Lan supported
[    2.161225@0]  Enable RX Mitigation via HW Watchdog Timer
[    2.169782@5] libphy: stmmac: probed
[    2.170056@5] eth%d: PHY ID 001cc916 at 0 IRQ POLL (stmmac-0:00) active
[    2.176654@5] eth%d: PHY ID 001cc916 at 1 IRQ POLL (stmmac-0:01)
[    2.183883@5] PPP generic driver version 2.4.2
[    2.187155@0] PPP BSD Compression module registered
[    2.191791@0] PPP Deflate Compression module registered
[    2.196974@0] PPP MPPE Compression module registered
[    2.201895@0] NET: Registered protocol family 24
[    2.206588@0] usbcore: registered new interface driver rtl8150
[    2.212340@0] usbcore: registered new interface driver r8152
[    2.217910@0] usbcore: registered new interface driver lan78xx
[    2.223684@0] usbcore: registered new interface driver asix
[    2.229210@0] usbcore: registered new interface driver ax88179_178a
[    2.235408@0] usbcore: registered new interface driver cdc_ether
[    2.241364@0] usbcore: registered new interface driver dm9601
[    2.247048@0] usbcore: registered new interface driver sr9700
[    2.252843@2] usbcore: registered new interface driver CoreChips
[    2.258739@2] usbcore: registered new interface driver smsc75xx
[    2.264595@2] usbcore: registered new interface driver smsc95xx
[    2.270470@2] usbcore: registered new interface driver net1080
[    2.276197@2] usbcore: registered new interface driver cdc_subset
[    2.282219@2] usbcore: registered new interface driver zaurus
[    2.287925@2] usbcore: registered new interface driver cdc_ncm
[    2.293663@2] GobiNet: Quectel_Linux&Android_GobiNet_Driver_V1.6.1
[    2.299823@2] usbcore: registered new interface driver GobiNet
[    2.306119@2] ehci_hcd: USB 2.0 'Enhanced' Host Controller (EHCI) Driver
[    2.312186@2] ehci-pci: EHCI PCI platform driver
[    2.316825@2] ohci_hcd: USB 1.1 'Open' Host Controller (OHCI) Driver
[    2.323068@2] ohci-pci: OHCI PCI platform driver
[    2.328130@2] usbcore: registered new interface driver cdc_acm
[    2.333403@2] cdc_acm: USB Abstract Control Model driver for USB modems and ISDN adapters
[    2.341572@2] usbcore: registered new interface driver usb-storage
[    2.347724@2] usbcore: registered new interface driver usbserial
[    2.353630@2] usbcore: registered new interface driver option
[    2.359310@2] usbserial: USB Serial support registered for GSM modem (1-port)
[    2.366851@0] mousedev: PS/2 mouse device common for all mice
[    2.372409@3] usbcore: registered new interface driver xpad
[    2.377635@3] edt_ft5x06 3-0038: probing for EDT FT5x06 I2C
[    3.034168@0] edt_ft5x06 3-0038: touchscreen probe failed
[    3.034321@0] sensor_register_slave:kxtj3,id=0
[    3.048188@0] khadas-rtc 4-0051: rtc core: registered khadas-rtc as rtc0
[    3.049321@0] i2c /dev entries driver
[    3.053689@0] IR NEC protocol handler initialized
[    3.057548@0] IR RC5(x/sz) protocol handler initialized
[    3.062752@0] IR RC6 protocol handler initialized
[    3.067441@0] IR JVC protocol handler initialized
[    3.072055@0] IR Sony protocol handler initialized
[    3.076767@0] IR SANYO protocol handler initialized
[    3.081623@0] IR Sharp protocol handler initialized
[    3.086440@0] IR MCE Keyboard/mouse protocol handler initialized
[    3.092409@5] IR XMP protocol handler initialized
[    3.097149@5] usbcore: registered new interface driver uvcvideo
[    3.102932@5] USB Video Class driver (1.1.1)
[    3.107197@5] usbcore: registered new interface driver cx231xx
[    3.113047@5] md: linear personality registered for level -1
[    3.119135@0] device-mapper: ioctl: 4.35.0-ioctl (2016-06-23) initialised: dm-devel@redhat.com
[    3.127272@0] device-mapper: verity-avb: AVB error handler initialized with vbmeta device: 
[    3.135366@0] Bluetooth: HCI UART driver ver 2.3
[    3.139904@0] Bluetooth: HCI UART protocol H4 registered
[    3.147083@0] ledtrig-cpu: registered to indicate activity on CPUs
[    3.151911@0] hidraw: raw HID events driver (C) Jiri Kosina
[    3.157667@4] usbcore: registered new interface driver usbhid
[    3.162530@4] usbhid: USB HID core driver
[    3.166699@0] ashmem: initialized
[    3.171045@0] meson_cpufreq_init: ignor dsu clk!
[    3.174379@0] meson_cpufreq_init: ignor dsu pre parent clk!
[    3.179892@0] value of voltage_tolerance 0
[    3.183903@0] meson_cpufreq_init:don't find the node <dynamic_gp1_clk>
[    3.190374@0] value of gp1_clk_target 0
[    3.195088@0] cpu cpu0: meson_cpufreq_init: CPU 0 initialized
[    3.201290@0] meson_cpufreq_init: ignor dsu clk!
[    3.204439@0] meson_cpufreq_init: ignor dsu pre parent clk!
[    3.210032@0] value of voltage_tolerance 0
[    3.213995@0] meson_cpufreq_init:don't find the node <dynamic_gp1_clk>
[    3.220457@0] value of gp1_clk_target 0
[    3.225183@0] cpu cpu2: meson_cpufreq_init: CPU 2 initialized
[    3.231391@0] ff803000.serial: clock gate not found
[    3.234829@0] meson_uart ff803000.serial: ==uart0 reg addr = f0ea9000
[    3.241193@0] ff803000.serial: ttyS0 at MMIO 0xff803000 (irq = 40, base_baud = 1500000) is a meson_uart
[    3.255979@0] meson_uart ff803000.serial: ttyS0 use xtal(24M) 24000000 change 0 to 115200
[    3.258615@0] console [ttyS0] enabled
[    3.258615@0] console [ttyS0] enabled
[    3.265857@0] bootconsole [aml-uart0] disabled
[    3.265857@0] bootconsole [aml-uart0] disabled
[    3.275087@5] meson_uart ffd24000.serial: ==uart1 reg addr = f0eab000
[    3.281162@5] ffd24000.serial: ttyS1 at MMIO 0xffd24000 (irq = 50, base_baud = 1500000) is a meson_uart
[    3.290675@5] meson_uart ffd22000.serial: ==uart3 reg addr = f0ead000
[    3.296894@5] ffd22000.serial: ttyS3 at MMIO 0xffd22000 (irq = 51, base_baud = 1500000) is a meson_uart
[    3.307496@0] amlogic-new-usb2-v2 ffe09000.usb2phy: USB2 phy probe:phy_mem:0xffe09000, iomap phy_base:0xf0ee2000
[    3.316723@0] amlogic-new-usb3-v2 ffe09080.usb3phy: USB3 phy probe:phy_mem:0xffe09080, iomap phy_base:0xf0eed080
[    3.327757@0] Error: Driver 'meson_reset' is already registered, aborting...
[    3.334158@0] aml_dma ff63e000.aml_dma: Aml dma
[    3.339487@3] aml_aes_dma ff63e000.aml_dma:aml_aes: Aml AES_dma
[    3.344285@3] aml_tdes_dma ff63e000.aml_dma:aml_tdes: Aml TDES_dma
[    3.350555@3] aml_sha_dma ff63e000.aml_dma:aml_sha: Aml SHA1/SHA224/SHA256 dma
[    3.357514@3] gpio-keypad gpio_keypad: power key(116) registed.
[    3.363279@3] input: gpio_keypad as /devices/platform/gpio_keypad/input/input1
[    3.370603@0] meson-remote: Driver init
[    3.374398@0] meson-remote: remote_probe
[    3.378099@0] meson-remote ff808040.rc: protocol = 0x1
[    3.383207@0] meson-remote ff808040.rc: don't find the node <led_blink>
[    3.389787@0] meson-remote ff808040.rc: led_blink = 0
[    3.394823@0] meson-remote ff808040.rc: don't find the node <led_blink_frq>
[    3.401747@0] meson-remote ff808040.rc: led_blink_frq  = 100
[    3.407400@0] meson-remote ff808040.rc: platform_data irq =49
[    3.413137@0] meson-remote ff808040.rc: custom_number = 1
[    3.418490@0] meson-remote ff808040.rc: ptable->map_size = 13
[    3.424207@0] meson-remote ff808040.rc: ptable->custom_name = khadas-ir
[    3.430784@0] meson-remote ff808040.rc: ptable->custom_code = 0xff00
[    3.437108@0] meson-remote ff808040.rc: ptable->release_delay = 80
[    3.443272@0] meson-remote ff808040.rc: default protocol = 0x1 and id = 0
[    3.450021@0] meson-remote ff808040.rc: reg=0x0, val=0x1f40190
[    3.455827@0] meson-remote ff808040.rc: reg=0x4, val=0x12c00c8
[    3.461633@0] meson-remote ff808040.rc: reg=0x8, val=0x960050
[    3.467356@0] meson-remote ff808040.rc: reg=0xc, val=0x480028
[    3.473074@0] meson-remote ff808040.rc: reg=0x10, val=0x70fa0013
[    3.479054@0] meson-remote ff808040.rc: reg=0x18, val=0x8616800
[    3.484947@0] meson-remote ff808040.rc: reg=0x1c, val=0x9f00
[    3.490583@0] meson-remote ff808040.rc: reg=0x20, val=0x0
[    3.495953@0] meson-remote ff808040.rc: reg=0x24, val=0x0
[    3.501327@0] meson-remote ff808040.rc: reg=0x28, val=0x0
[    3.507176@0] input: aml_keypad as /devices/platform/ff808040.rc/input/input2
[    3.514257@0] meson-remote: IR XMP protocol handler initialized
[    3.519856@3] <<-GT9XX-INFO->> GTP Driver Version: V2.4.0.1<2016/10/26>
[    3.526306@3] <<-GT9XX-INFO->> GTP I2C Address: 0x5d
[    3.532260@1] 3-005d supply vdd_ana not found, using dummy regulator
[    3.537610@1] 3-005d supply vcc_i2c not found, using dummy regulator
[    3.545414@1] <<-GT9XX-ERROR->> I2C Read: 0x8047, 1 bytes failed, errcode: -6! Process reset.
[    3.553156@1] <<-GT9XX-INFO->> Guitar reset
[    3.662697@1] <<-GT9XX-ERROR->> I2C Write: 0x8041, 1 bytes failed, errcode: -6!
[    3.664353@1] <<-GT9XX-ERROR->> GTP i2c test failed time 1.
[    3.686695@1] <<-GT9XX-ERROR->> I2C Read: 0x8047, 1 bytes failed, errcode: -6! Process reset.
[    3.690348@1] <<-GT9XX-INFO->> Guitar reset
[    3.802695@1] <<-GT9XX-ERROR->> I2C Write: 0x8041, 1 bytes failed, errcode: -6!
[    3.804354@1] <<-GT9XX-ERROR->> GTP i2c test failed time 2.
[    3.826694@1] <<-GT9XX-ERROR->> I2C Read: 0x8047, 1 bytes failed, errcode: -6! Process reset.
[    3.830348@1] <<-GT9XX-INFO->> Guitar reset
[    3.942694@1] <<-GT9XX-ERROR->> I2C Write: 0x8041, 1 bytes failed, errcode: -6!
[    3.944355@1] <<-GT9XX-ERROR->> GTP i2c test failed time 3.
[    3.966694@1] <<-GT9XX-ERROR->> I2C Read: 0x8047, 1 bytes failed, errcode: -6! Process reset.
[    3.970347@1] <<-GT9XX-INFO->> Guitar reset
[    4.082712@1] <<-GT9XX-ERROR->> I2C Write: 0x8041, 1 bytes failed, errcode: -6!
[    4.084374@1] <<-GT9XX-ERROR->> GTP i2c test failed time 4.
[    4.106694@1] <<-GT9XX-ERROR->> I2C Read: 0x8047, 1 bytes failed, errcode: -6! Process reset.
[    4.110350@1] <<-GT9XX-INFO->> Guitar reset
[    4.222695@1] <<-GT9XX-ERROR->> I2C Write: 0x8041, 1 bytes failed, errcode: -6!
[    4.224349@1] <<-GT9XX-ERROR->> GTP i2c test failed time 5.
[    4.245990@1] <<-GT9XX-ERROR->> I2C communication ERROR!
[    4.246586@1] efuse efuse:  open efuse clk gate error!!
[    4.250970@1] efusekeynum: 1
[    4.253731@1] efusekeyname:             mac  offset:     0   size:    12
[    4.260455@1] efuse efuse: probe OK!
[    4.265921@1] ion_dev soc:ion_dev: assigned reserved memory node linux,ion-dev
[    4.271577@1] ge2d: ge2d_init_module
[    4.275103@1] ge2d: ge2d clock is 499 MHZ
[    4.278467@1] ge2d: reserved mem is not used
[    4.282710@1] ge2d: ge2d start monitor
[    4.286871@3] [tsync_pcr_init]init success.
[    4.290672@3] amvideom vsync irq: 59
[    4.294135@3] create_ge2d_work_queue video task ok
[    4.299436@0] hdmitx: hdcp: hdmitx_hdcp_init
[    4.303695@3] vout: vout2: create vout2 attribute OK
[    4.308163@0] vout: vout2: aml_vout2_probe OK
[    4.312569@0] vout: vout2: clktree_init
[    4.316221@0] vout: vout2: register server: nulldisp_vout2_server
[    4.322416@0] vout: vout2: init mode null set ok
[    4.326890@0] vout: vout2: aml_vout2_probe OK
[    4.331363@0] DI: di_module_init ok.
[    4.334956@0] DI: di_probe:
[    4.337524@0] DI: di_probe: major 508
[    4.341394@0] deinterlace deinterlace: assigned reserved memory node linux,di_cma
[    4.348637@0] di:flag_cma=1
[    4.351401@0] DI: CMA size 0x2800000.
[    4.355061@0] pre_irq:83
[    4.357547@0] post_irq:84
[    4.360159@0] DI: di_probe allocate rdma channel 0.
[    4.365060@2] di_probe: get clk vpu error.
[    4.369074@2] DI: vpu clkb <334000000, 667000000>
[    4.373797@2] get clkb rate:333333328
[    4.377394@2] DI:enable vpu clkb.
[    4.380692@2] 0x000000c9:Y=c9,U=0,V=0
[    4.384323@2] 0x000000ca:Y=ca,U=0,V=0
[    4.387962@2] 0x000000cb:Y=cb,U=0,V=0
[    4.391602@2] 0x000000cc:Y=cc,U=0,V=0
[    4.395242@2] 0x000000cd:Y=cd,U=0,V=0
[    4.398883@2] 0x000000ce:Y=ce,U=0,V=0
[    4.402522@2] 0x000000cf:Y=cf,U=0,V=0
[    4.406164@2] 0x000000d0:Y=d0,U=0,V=0
[    4.409797@2] 0x000000d1:Y=d1,U=0,V=0
[    4.413442@2] 0x000000d2:Y=d2,U=0,V=0
[    4.417086@2] 0x000000d3:Y=d3,U=0,V=0
[    4.420722@2] 0x000000d4:Y=d4,U=0,V=0
[    4.424362@2] 0x000000d5:Y=d5,U=0,V=0
[    4.428002@2] 0x000000d6:Y=d6,U=0,V=0
[    4.431644@2] 0x000000d7:Y=d7,U=0,V=0
[    4.435294@2] 0x000000d8:Y=d8,U=0,V=0
[    4.438927@2] 0x000000d9:Y=d9,U=0,V=0
[    4.442563@2] 0x000000da:Y=da,U=0,V=0
[    4.446203@2] 0x000000db:Y=db,U=0,V=0
[    4.449837@2] 0x000000dc:Y=dc,U=0,V=0
[    4.453482@2] 0x000000dd:Y=dd,U=0,V=0
[    4.457124@2] 0x000000de:Y=de,U=0,V=0
[    4.460764@2] 0x000000df:Y=df,U=0,V=0
[    4.464403@2] 0x000000e0:Y=e0,U=0,V=0
[    4.468041@2] 0x000000e1:Y=e1,U=0,V=0
[    4.471683@2] DI: support multi decoding 223~224~225.
[    4.476825@2] DI: di_probe:Di use HRTIMER
[    4.480786@3] DI: di_probe:ok
[    4.483699@3] dim:dim_module_init
[    4.487103@3] dim:dim_module_init finish
[    4.490842@3] dil:dil_init.
[    4.493703@3] dil:dil_init ok.
[    4.496664@3] vdin_drv_init: major 507
[    4.500548@3] rdma_register, rdma_table_addr f1003000 rdma_table_addr_phy bcc4a000 reg_buf cb84de00
[    4.509388@3] rdma_register success, handle 3 table_size 512
[    4.515024@3] vdin_drv_probe:vdin.0 rdma hanld 3.
[    4.519904@4] vdin vdin0: assigned reserved memory node linux,vdin0_cma
[    4.526288@4] 
[    4.526288@4]  vdin memory resource done.
[    4.531919@4] vdin0 cma_mem_size = 64 MB
[    4.535818@4] vdin0 irq: 56 rdma irq: 2
[    4.539631@4] set_canvas_manual = 0
[    4.543113@4] get fclk_div5 err
[    4.546221@4] vdin_drv_probe: vdin cannot get msr clk !!!
[    4.551606@4] vdin_drv_probe: driver initialized ok
[    4.556495@4] rdma_register, rdma_table_addr f1005000 rdma_table_addr_phy bcc4b000 reg_buf ed22fe00
[    4.565461@4] rdma_register success, handle 4 table_size 512
[    4.571094@4] vdin_drv_probe:vdin.1 rdma hanld 4.
[    4.575926@0] vdin vdin1: assigned reserved memory node linux,vdin1_cma
[    4.582372@0] 
[    4.582372@0]  vdin memory resource done.
[    4.588007@0] vdin1 cma_mem_size = 64 MB
[    4.591898@0] vdin1 irq: 57 rdma irq: 4
[    4.595719@0] set_canvas_manual = 0
[    4.599207@0] get fclk_div5 err
[    4.602312@0] vdin_drv_probe: vdin cannot get msr clk !!!
[    4.607679@0] vdin_debugfs_init only support debug vdin0 1
[    4.613138@0] vdin_drv_probe: driver initialized ok
[    4.618125@0] vdin_drv_init: vdin driver init done
[    4.622761@0] [viuin..]viuin_init_module viuin module init
[    4.628488@0] [viuin..]viuin_probe probe ok.
[    4.632822@2] [RX]-hdmirx: hdmirx_init.
[    4.636268@2] ESM HLD: Initializing...
[    4.640801@0] amvdec_csi module: init.
[    4.643769@0] amvdec_csi_init_module:major 505
[    4.648332@0] amvdec_csi module: init. ok
[    4.652159@0] amlvid:info: amlvideo_init called[    4.656470@2] amlvid:info: amlvideo_create_instance called
[    4.661930@2] amlvid:info: v4l2_dev.name=:amlvideo-000
[    4.667189@0] amlvideo-000: V4L2 device registered as video10
[    4.672763@0] amlvid:info: amlvideo_create_instance called
[    4.678228@0] amlvid:info: v4l2_dev.name=:amlvideo-001
[    4.683473@0] amlvideo-001: V4L2 device registered as video23
[    4.689257@0] amlvideo2 probe called
[    4.692614@0] amlvideo2_create_node[    4.696101@0] amlvideo2: V4L2 device registered as video11
[    4.701388@0] amlvideo2 probe called
[    4.704913@0] amlvideo2_create_node[    4.708377@0] amlvideo2: V4L2 device registered as video12
[    4.713733@0] PPMGRDRV: warn: ppmgr module init func called
[    4.719409@0] PPMGRDRV: info: ppmgr_driver_probe called
[    4.724478@0] PPMGRDRV: info: ppmgr_dev major:504
[    4.729347@0] ppmgr: probe of ppmgr failed with error -22
[    4.734828@2] ionvideo-000: V4L2 device registered as video13
[    4.740260@2] ionvideo-001: V4L2 device registered as video14
[    4.745967@2] ionvideo-002: V4L2 device registered as video15
[    4.751693@2] ionvideo-003: V4L2 device registered as video16
[    4.757424@2] ionvideo-004: V4L2 device registered as video17
[    4.763153@0] ionvideo-005: V4L2 device registered as video18
[    4.768917@0] ionvideo-006: V4L2 device registered as video19
[    4.774640@0] ionvideo-007: V4L2 device registered as video20
[    4.780345@0] ionvideo-008: V4L2 device registered as video21
[    4.785953@0] ionvid: info: Video Technology Magazine Ion Video
[    4.791858@2] ionvid: info: Capture Board ver 1.0 successfully loaded
[    4.798414@2] picdec: picdec_driver_probe called.
[    4.803080@4] picdec: probe of picdec failed with error -22
[    4.808642@0] videosync_create_instance dev_s ece35200,dev_s->dev ed112100
[    4.815331@0] videosync_create_instance reg videosync.0
[    4.820604@0] aml_vecm_init:module init
[    4.820605@2] videosync_thread started
[    4.828363@0] VECM probe start
[    4.831471@0] vlock_status_init vlock_en:1
[    4.835173@0] pixel_probe: vpp probe func error!
[    4.839785@0] request amvecm_vsync2_irq successful
[    4.844535@0] aml_vecm_probe: ok
[    4.847809@0] amdolby_vision_init:module init
[    4.852444@0] 
[    4.852444@0]  amdolby_vision probe start & ver: 20181220
[    4.859118@0] 
[    4.859118@0]  cpu_id=2 tvmode=0
[    4.864141@0] dolby_vision_init_receiver(dvel)
[    4.868379@0] dolby_vision_init_receiver: dvel
[    4.872976@0] amdolby_vision_probe: ok
[    4.876516@0] g12 dovi disable in uboot
[    4.880412@0] prime_sl module init
[    4.884117@0] reg base = f1039000
[    4.887052@0] gdc_platform_probe: reserve_mem is not used
[    4.892513@0] gdc_platform_probe: gdc core clk is 799 MHZ
[    4.897805@0] gdc_platform_probe: gdc axi clk is 799 MHZ
[    4.903071@0] gdc_wq_init: init gdc device
[    4.907129@0] gdc_wq_init: gdc start monitor
[    4.911510@0] gdc_monitor_thread: gdc workqueue monitor start
[    4.911691@2] vm_init .
[    4.912276@2] meson-mmc: mmc driver version: 3.02, 2017-05-15: New Emmc Host Controller
[    4.917549@1] meson-mmc: >>>>>>>>hostbase f1041000, dmode 
[    4.917801@1] meson-mmc: actual_clock :400000, HHI_nand: 0x80
[    4.917817@1] meson-mmc: [meson_mmc_set_ios_v3] after clock: 0x1000023c
[    4.959687@1] meson-mmc: meson_mmc_probe() : success!
[    4.962587@3] meson-mmc: >>>>>>>>hostbase f10cb000, dmode 
[    4.964571@3] meson-mmc: gpio_cd = 1ca
[    5.005570@1] meson-aml-mmc ffe07000.emmc: divider requested rate 200000000 != actual rate 199999997: ret=0
[    5.006022@0] meson-mmc: meson_mmc_probe() : success!
[    5.014721@1] meson-mmc: actual_clock :199999997, HHI_nand: 0x80
[    5.020717@1] meson-mmc: [meson_mmc_set_ios_v3] after clock: 0x10000245
[    5.027305@1] meson-mmc: Data 1 aligned delay is 0
[    5.027738@0] meson-mmc: >>>>>>>>hostbase f1155000, dmode 
[    5.028062@0] meson-mmc: actual_clock :400000, HHI_nand: 0x80
[    5.028077@0] meson-mmc: [meson_mmc_set_ios_v3] after clock: 0x1000023c
[    5.049802@1] meson-mmc: emmc: clk 199999997 tuning start
[    5.060258@1] meson-mmc: emmc: adj_win: < 1 2 3 4 >
[    5.060282@1] meson-mmc: step:4, delay1:0x4104104, delay2:0x4004104
[    5.070005@3] meson-mmc: meson_mmc_probe() : success!
[    5.071352@1] meson-mmc: emmc: adj_win: < 1 2 3 4 >
[    5.071424@3] amlogic mtd driver init
[    5.071764@4] aml_vrtc rtc: rtc core: registered aml_vrtc as rtc1
[    5.071867@4] input: aml_vkeypad as /devices/platform/rtc/input/input3
[    5.072361@5] cectx ff80023c.aocec: cec driver date:2020/04/09:fix cec a recursive call
[    5.072361@5] 
[    5.072471@3] cectx ff80023c.aocec: compatible:amlogic, aocec-g12a
[    5.072473@3] cectx ff80023c.aocec: cecb_ver:0x1
[    5.072474@3] cectx ff80023c.aocec: line_reg:0x1
[    5.072476@3] cectx ff80023c.aocec: line_bit:0x3
[    5.072478@3] cectx ff80023c.aocec: ee_to_ao:0x1
[    5.072555@3] input: cec_input as /devices/virtual/input/input4
[    5.072620@5] cectx ff80023c.aocec: not find 'port_num'
[    5.072623@5] cectx ff80023c.aocec: using cec:1
[    5.072636@5] cectx ff80023c.aocec: no hdmirx regs
[    5.072638@5] cectx ff80023c.aocec: no hhi regs
[    5.072642@5] cectx ff80023c.aocec: not find 'output'
[    5.073898@5] irq cnt:2, a:55, b54
[    5.074072@3] cectx ff80023c.aocec: wakeup_reason:0x0
[    5.074133@3] cectx ff80023c.aocec: cev val1: 0x0;val2: 0x0
[    5.074143@3] cectx ff80023c.aocec: aml_cec_probe success end
[    5.074496@3] unifykey: no efuse-version set, use default value: -1
[    5.074667@4] unifykey: aml_unifykeys_init done!
[    5.074707@4] meson ts init
[    5.074732@4] tsensor id: 0
[    5.074796@4] r1p1_tsensor_read  valid cnt is 0
[    5.074805@4] tsensor trim info: 0xfa0080e8!
[    5.074807@4] tsensor hireboot: 0xc0ff2b00
[    5.074842@4] meson ts init
[    5.074851@4] tsensor id: 1
[    5.074896@4] r1p1_tsensor_read  valid cnt is 0
[    5.074902@4] tsensor trim info: 0xfa0080e4!
[    5.074903@4] tsensor hireboot: 0xc0ff2b00
[    5.074997@4] audio_dsp: [dsp]register dsp to char divece(257)
[    5.075093@5] amaudio: amaudio: driver amaudio init!
[    5.075320@5] amaudio: amaudio_init - amaudio: driver amaudio succuess!
[    5.075630@3] amlkaraoke init success!
[    5.075727@3] sysled: module init
[    5.075875@3] meson_wdt ffd0f0d0.watchdog: start watchdog
[    5.075877@3] meson_wdt ffd0f0d0.watchdog: creat work queue for watch dog
[    5.076013@3] meson_wdt ffd0f0d0.watchdog: AML Watchdog Timer probed done
[    5.076315@4] amlogic rfkill init
[    5.076391@4] enter bt_probe of_node
[    5.076401@4] not get gpio_en
[    5.076405@4] not get gpio_btwakeup
[    5.076409@4] power on valid level is high
[    5.076409@4] bt: power_on_pin_OD = 0;
[    5.076410@4] bt: power_off_flag = 1;
[    5.076411@4] dis power down = 0;
[    5.102035@4] request_irq error ret=-22
[    5.102058@4] dev_pm_set_wake_irq failed: -22
[    5.102440@4] meson-saradc ff809000.saradc: set delay per tick to <1ms> by default.
[    5.102442@4] meson-saradc ff809000.saradc: set ticks per period to <1> by default.
[    5.103048@4] dmc_monitor_probe
[    5.103144@4] page_trace_module_init, create sysfs failed
[    5.103697@3] atv_demod: aml_atvdemod_init: OK, atv demod version: V2.15.
[    5.103787@3] defendkey ff630218.defendkey: Reserved memory is not enough!
[    5.103793@3] defendkey: probe of ff630218.defendkey failed with error -22
[    5.104068@4] usbcore: registered new interface driver snd-usb-audio
[    5.104676@4] aml_codec_T9015 ff632000.t9015: aml_T9015_audio_codec_probe
[    5.104689@4] T9015 acodec used by auge, tdmout:1
[    5.105170@4] es8316 spk_ctl_gpio 0
[    5.105173@4] es8316 spk_mute_gpio 1
[    5.105176@4] es8316 4-0010: Can not read property hp_det_gpio
[    5.105178@4] es8316_i2c_probe 1329
[    5.105183@4] es8316_i2c_probe 1333
[    5.106503@4] asoc debug: aml_audio_controller_probe-129
[    5.106834@4] aml_tdm_platform_probe, tdm ID = 0, lane_cnt = 4
[    5.106851@4] snd_tdm ff642000.audiobus:tdma: lane_mask_out = 1, lane_oe_mask_out = 1
[    5.106883@4] snd_tdm ff642000.audiobus:tdma: neither mclk_pad nor mclk2pad set
[    5.106947@4] aml_tdm_platform_probe(), share en = 1
[    5.106948@4] No channel mask node Channel_Mask
[    5.107091@4] aml_tdm_platform_probe, tdm ID = 1, lane_cnt = 4
[    5.107136@4] TDM id 1 samesource_sel:3
[    5.107140@4] snd_tdm ff642000.audiobus:tdmb: lane_mask_out = 1, lane_oe_mask_out = 0
[    5.107291@4] aml_tdm_platform_probe(), share en = 1
[    5.107292@4] No channel mask node Channel_Mask
[    5.107401@4] aml_tdm_platform_probe, tdm ID = 2, lane_cnt = 4
[    5.107415@4] snd_tdm ff642000.audiobus:tdmc: lane_mask_out = 1, lane_oe_mask_out = 0
[    5.107518@4] periphs-banks:471 is using the pin GPIOA_11 as gpio
[    5.107520@4] meson-g12a-pinctrl pinctrl@ff634480: request() failed for pin 61
[    5.107522@4] meson-g12a-pinctrl pinctrl@ff634480: pin-61 (ff642000.audiobus:tdmc) status -22
[    5.107525@4] meson-g12a-pinctrl pinctrl@ff634480: could not request pin 61 (GPIOA_11) from group mclk1_a  on device pinctrl-meson
[    5.107527@4] snd_tdm ff642000.audiobus:tdmc: Error applying setting, reverse things back
[    5.107531@4] snd_tdm ff642000.audiobus:tdmc: aml_tdm_get_pins error!
[    5.107537@4] aml_tdm_platform_probe(), share en = 1
[    5.107537@4] No channel mask node Channel_Mask
[    5.108116@4] aml_spdif_platform_probe, register soc platform
[    5.108472@4] audio-ddr-manager ff642000.audiobus:ddr_manager: 0, irqs toddr 41, frddr 44
[    5.108489@4] audio-ddr-manager ff642000.audiobus:ddr_manager: 1, irqs toddr 42, frddr 45
[    5.108504@4] audio-ddr-manager ff642000.audiobus:ddr_manager: 2, irqs toddr 43, frddr 46
[    5.108690@4] loopback ff642000.audiobus:loopback@0: check whether to update loopback chipinfo
[    5.108713@4]        datain_src:4, datain_chnum:4, datain_chumask:f
[    5.108715@4]        datalb_src:1, datalb_chnum:2, datalb_chmask:3
[    5.108716@4]        datain_lane_mask:0x5, datalb_lane_mask:0x1
[    5.108717@4] datalb_format: 1, chmask for lanes: 0x3
[    5.108889@4] loopback_platform_probe, p_loopback->id:0 register soc platform
[    5.109105@4] audiolocker_platform_probe
[    5.109950@5] Register vad
[    5.111717@5] es8316_probe 1088
[    5.111720@5] es8316_probe 1097
[    5.111724@5] es8316_probe 1099
[    5.117524@5] es8316_probe 1103
[    5.231494@2] es8316_probe 1110
[    5.233286@2] es8316_probe 1130
[    5.236316@2] asoc-aml-card auge_sound: control 2:0:0:I2SIn CLK:0 is already present
[    5.236319@2] snd_tdm ff642000.audiobus:tdmb: ASoC: Failed to add I2SIn CLK: -16
[    5.236327@2] aml_dai_tdm_probe, failed add snd tdm controls
[    5.236331@2] asoc-aml-card auge_sound: control 2:0:0:I2SIn CLK:0 is already present
[    5.236333@2] snd_tdm ff642000.audiobus:tdmc: ASoC: Failed to add I2SIn CLK: -16
[    5.236338@2] aml_dai_tdm_probe, failed add snd tdm controls
[    5.236343@2] aml_dai_spdif_probe
[    5.236364@2] pin(1) should be selected for only one usage
[    5.236377@2] master_mode(1), binv(1), finv(0) out_skew(2), in_skew(3)
[    5.236837@2] asoc-aml-card auge_sound: multicodec <-> TDM-A mapping ok
[    5.237703@2] master_mode(1), binv(1), finv(1) out_skew(2), in_skew(3)
[    5.238044@2] asoc-aml-card auge_sound: multicodec <-> TDM-B mapping ok
[    5.238062@2] master_mode(1), binv(1), finv(1) out_skew(2), in_skew(3)
[    5.238391@2] asoc-aml-card auge_sound: multicodec <-> TDM-C mapping ok
[    5.238755@2] asoc-aml-card auge_sound: dummy <-> SPDIF mapping ok
[    5.238762@2] 
[    5.238762@2] loopback_dai_set_sysclk, 0, 12288000, 0
[    5.238763@2] asoc loopback_dai_set_fmt, 0x4010, ed387090
[    5.239066@2] asoc-aml-card auge_sound: dummy <-> ff642000.audiobus:loopback@0 mapping ok
[    5.240198@2] es8316 4-0010: ASoC: Failed to create Left Hp mixer debugfs file
[    5.240201@2] es8316 4-0010: ASoC: Failed to create Right Hp mixer debugfs file
[    5.240347@2] es8316 4-0010: ASoC: Failed to create HPCP L debugfs file
[    5.240489@2] es8316 4-0010: ASoC: Failed to create HPCP R debugfs file
[    5.240635@2] es8316 4-0010: ASoC: Failed to create HPVOL L debugfs file
[    5.240777@2] es8316 4-0010: ASoC: Failed to create HPVOL R debugfs file
[    5.242287@4] snd_card_add_kcontrols card:ed03fc10
[    5.242294@4] effect_v2 is not init
[    5.242296@4] Failed to add VAD controls
[    5.242308@4] eq/drc v1 function enable
[    5.274104@4] GACT probability NOT on
[    5.274111@4] Mirror/redirect action on
[    5.274115@4] u32 classifier
[    5.274116@4]     Actions configured
[    5.274119@4] Netfilter messages via NETLINK v0.30.
[    5.274239@4] nf_conntrack version 0.5.0 (16384 buckets, 65536 max)
[    5.274366@4] ctnetlink v0.93: registering with nfnetlink.
[    5.274657@5] xt_time: kernel timezone is -0000
[    5.274701@5] ipip: IPv4 and MPLS over IPv4 tunneling driver
[    5.274941@5] IPv4 over IPsec tunneling driver
[    5.284258@5] ip_tables: (C) 2000-2006 Netfilter Core Team
[    5.284430@5] arp_tables: arp_tables: (C) 2002 David S. Miller
[    5.291619@5] Initializing XFRM netlink socket
[    5.291841@5] NET: Registered protocol family 10
[    5.292312@5] mip6: Mobile IPv6
[    5.292322@5] ip6_tables: (C) 2000-2006 Netfilter Core Team
[    5.303372@4] sit: IPv6, IPv4 and MPLS over IPv4 tunneling driver
[    5.303848@4] NET: Registered protocol family 17
[    5.303857@4] NET: Registered protocol family 15
[    5.303870@4] bridge: filtering via arp/ip/ip6tables is no longer available by default. Update your scripts to load br_netfilter if you need this.
[    5.303918@5] Bluetooth: RFCOMM TTY layer initialized
[    5.303923@5] Bluetooth: RFCOMM socket layer initialized
[    5.303934@5] Bluetooth: RFCOMM ver 1.11
[    5.303938@5] Bluetooth: BNEP (Ethernet Emulation) ver 1.3
[    5.303939@5] Bluetooth: BNEP filters: protocol multicast
[    5.303943@5] Bluetooth: BNEP socket layer initialized
[    5.303945@5] Bluetooth: HIDP (Human Interface Emulation) ver 1.2
[    5.303948@5] Bluetooth: HIDP socket layer initialized
[    5.303961@5] l2tp_core: L2TP core driver, V2.0
[    5.303966@5] l2tp_ppp: PPPoL2TP kernel driver, V2.0
[    5.303967@5] l2tp_ip: L2TP IP encapsulation support (L2TPv3)
[    5.303974@5] l2tp_netlink: L2TP netlink interface
[    5.303989@5] l2tp_eth: L2TP ethernet pseudowire support (L2TPv3)
[    5.303997@5] l2tp_debugfs: L2TP debugfs support
[    5.303998@5] l2tp_ip6: L2TP IP encapsulation support for IPv6 (L2TPv3)
[    5.304014@5] NET: Registered protocol family 35
[    5.304042@5] Key type dns_resolver registered
[    5.304228@5] Registering SWP/SWPB emulation handler
[    5.304537@5] registered taskstats version 1
[    5.309835@3] dwc3 ff500000.dwc3: Configuration mismatch. dr_mode forced to host
[    5.312469@3] xhci-hcd xhci-hcd.0.auto: xHCI Host Controller
[    5.312480@3] xhci-hcd xhci-hcd.0.auto: new USB bus registered, assigned bus number 1
[    5.312696@3] xhci-hcd xhci-hcd.0.auto: hcc params 0x0228fe6c hci version 0x110 quirks 0x20010010
[    5.312721@3] xhci-hcd xhci-hcd.0.auto: irq 30, io mem 0xff500000
[    5.313088@4] hub 1-0:1.0: USB hub found
[    5.313104@4] hub 1-0:1.0: 2 ports detected
[    5.313301@4] xhci-hcd xhci-hcd.0.auto: xHCI Host Controller
[    5.313306@4] xhci-hcd xhci-hcd.0.auto: new USB bus registered, assigned bus number 2
[    5.313344@4] usb usb2: We don't know the algorithms for LPM for this host, disabling LPM.
[    5.313647@5] hub 2-0:1.0: USB hub found
[    5.313660@5] hub 2-0:1.0: 1 port detected
[    5.314077@5] i2c i2c-4: sensor_probe: kxtj3,ed324e00
[    5.314557@5] sensors 4-000e: sensor_probe:kxtj3:devid=0x35,ops=0xc166a3e4
[    5.316051@5] input: gsensor as /devices/platform/soc/ff800000.aobus/ff805000.i2c/i2c-4/4-000e/input/input5
[    5.316906@2] sensors 4-000e: sensor_probe:use polling,delay=30 ms
[    5.316975@3] sensors 4-000e: sensor_probe:miscdevice: gsensor
[    5.316979@3] sensors 4-000e: sensor_probe:initialized ok,sensor name:kxtj3,type:2,id=0
[    5.316979@3] 
[    5.318288@5] khadas-rtc 4-0051: setting system clock to 2011-01-01 12:04:35 UTC (1293883475)
[    5.318504@5] dwc_otg: usb0: type: 2 speed: 0, config: 0, dma: 0, id: 0, phy: ffe09000, ctrl: 0
[    5.418637@5] dwc_otg: Core Release: 3.30a
[    5.418640@5] dwc_otg: Setting default values for core params
[    5.418646@5] dwc_otg: curmode: 0, host_only: 0
[    5.430816@5] dwc_otg: Using Buffer DMA mode
[    5.430819@5] dwc_otg: OTG VER PARAM: 1, OTG VER FLAG: 1
[    5.430820@5] dwc_otg: Working on port type = SLAVE
[    5.430823@5] dwc_otg: Dedicated Tx FIFOs mode
[    5.431480@5] input: adc_keypad as /devices/platform/adc_keypad/input/input6
[    5.432059@3] bl: chip type/name: (6-g12b)
[    5.432061@3] bl: key_valid: 0
[    5.432069@3] bl: aml_bl_probe from dts
[    5.432073@3] bl: no backlight exist
[    5.432395@3] meson_cdev probe
[    5.432432@3] meson_cdev index: 0
[    5.432483@3] thermal thermal_zone0: binding zone soc_thermal with cdev thermal-cpufreq-0 failed:-22
[    5.432501@3] meson_cdev index: 1
[    5.432559@3] thermal: no cluster id, cpucore as one cooldev
[    5.432572@3] meson_cdev index: 2
[    5.432582@3] cpucore_cooling_register, max_cpu_core_num:6
[    5.432587@3] cpucore_cooling_register, clutser[1] core num:4
[    5.432592@3] cpucore_cooling_register, clutser[0] core num:2
[    5.432658@3] meson_cdev index: 3
[    5.432671@3] meson_cdev index: 4
[    5.432693@3] find tzd id: 0
[    5.432768@3] find tzd id: 0
[    5.432827@3] find tzd id: 0
[    5.432849@3] meson_cdev probe done
[    5.432925@3] gxbb_pm: enter meson_pm_probe!
[    5.432933@3] no vddio3v3_en pin
[    5.432934@3] pm-meson aml_pm: Can't get switch_clk81
[    5.432951@3] gxbb_pm: meson_pm_probe done
[    5.433180@3] ALSA device list:
[    5.433182@3]   #0: AML-AUGESOUND
[    5.637981@4] usb 1-1: new high-speed USB device number 2 using xhci-hcd
[    5.793452@4] hub 1-1:1.0: USB hub found
[    5.793489@4] hub 1-1:1.0: 4 ports detected
[    6.272153@1] meson-mmc: step:8, delay1:0x8208208, delay2:0x8008208
[    6.276140@1] meson-mmc: emmc: adj_win: < 2 3 4 >
[    6.276144@1] meson-mmc: left:3, right:0, mid:4, size:4
[    6.276147@1] meson-mmc: step:0, delay1:0x0, delay2:0x0
[    6.276150@1] meson-mmc: emmc: sd_emmc_regs->gclock=0x10000245,sd_emmc_regs->gadjust=0x32000
[    6.276153@1] meson-mmc: delay1:0x0, delay2:0x0
[    6.276277@1] emmc: new HS200 MMC card at address 0001
[    6.276759@1] emmc: clock 199999997, 8-bit-bus-width
[    6.276759@1]  
[    6.276759@1] mmcblk0: emmc:0001 BJTD4R 29.1 GiB 
[    6.276959@1] mmcblk0boot0: emmc:0001 BJTD4R partition 1 4.00 MiB
[    6.277165@1] mmcblk0boot1: emmc:0001 BJTD4R partition 2 4.00 MiB
[    6.277362@1] mmcblk0rpmb: emmc:0001 BJTD4R partition 3 4.00 MiB
[    6.278314@1] meson-mmc: Enter aml_emmc_partition_ops
[    6.278677@1] meson-mmc: [aml_emmc_partition_ops] mmc read partition OK!
[    6.278679@1] meson-mmc: add_emmc_partition
[    6.278849@1] meson-mmc: [mmcblk0p01]           bootloader  offset 0x000000000000, size 0x000000400000 
[    6.278974@1] meson-mmc: [mmcblk0p02]             reserved  offset 0x000002400000, size 0x000004000000 
[    6.279095@1] meson-mmc: [mmcblk0p03]                  env  offset 0x000006c00000, size 0x000000800000 
[    6.279227@1] meson-mmc: [mmcblk0p04]           justForFun  offset 0x000007c00000, size 0x000740000000 
[    6.279242@1] card key: card_blk_probe.
[    6.279254@1] emmc_key_init:183 emmc key lba_start:0x12020,lba_end:0x12220
[    6.279262@1] emmc key: emmc_key_init:205 ok.
[    6.281147@1] meson-mmc: amlmmc_dtb_init: register dtb chardev
[    6.281147@1] meson-mmc: calc 5f9ab34, store 5f9ab34
[    6.283018@1] meson-mmc: calc 5f9ab34, store 5f9ab34
[    6.283020@1] meson-mmc: total valid 2
[    6.283203@1] meson-mmc: amlmmc_dtb_init: register dtb chardev OK
[    6.283332@1] meson-mmc: amlmmc_ddr_init: register ddr_parameter chardev
[    6.283387@1] meson-mmc: amlmmc_ddr_init: register ddr parameter chardev O+?r???????] meson_uart ff803000.serial: ttyS0 use xtal(24M) 24000000 change 115200 to 115200
[    6.562000@0] prepare_namespace() wait 79
[    6.562068@0] md: Waiting for all devices to be available before autodetect
[    6.567356@3] md: If you don't use raid, use raid=noautodetect
[    6.573653@1] md: Autodetecting RAID arrays.
[    6.577379@1] md: Scanned 0 and added 0 devices.
[    6.581996@1] md: autorun ...
[    6.584898@1] md: ... autorun DONE.
[    6.588549@1] VFS: Cannot open root device "(null)" or unknown-block(0,0): error -6
[    6.596054@1] Please append a correct "root=" boot option; here are the available partitions:
[    6.604523@1] 0100            4096 ram0  (driver?)
[    6.609252@1] 0101            4096 ram1  (driver?)
[    6.614044@1] 0102            4096 ram2  (driver?)
[    6.618801@1] 0103            4096 ram3  (driver?)
[    6.623551@1] 0104            4096 ram4  (driver?)
[    6.628317@1] 0105            4096 ram5  (driver?)
[    6.633084@1] 0106            4096 ram6  (driver?)
[    6.637857@1] 0107            4096 ram7  (driver?)
[    6.642626@1] 0108            4096 ram8  (driver?)
[    6.647390@1] 0109            4096 ram9  (driver?)
[    6.652150@1] 010a            4096 ram10  (driver?)
[    6.657019@1] 010b            4096 ram11  (driver?)
[    6.661857@1] 010c            4096 ram12  (driver?)
[    6.666717@1] 010d            4096 ram13  (driver?)
[    6.671564@1] 010e            4096 ram14  (driver?)
[    6.676417@1] 010f            4096 ram15  (driver?)
[    6.681273@1] b300        30535680 mmcblk0  driver: mmcblk
[    6.686736@1]   b301            4096 mmcblk0p1 
[    6.691237@1]   b302           65536 mmcblk0p2 
[    6.695744@1]   b303            8192 mmcblk0p3 
[    6.700251@1]   b304        30408704 mmcblk0p4 
[    6.704759@1] b360            4096 mmcblk0rpmb  (driver?)
[    6.710137@1] b340            4096 mmcblk0boot1  (driver?)
[    6.715591@1] b320            4096 mmcblk0boot0  (driver?)
[    6.721051@2] Kernel panic - not syncing: VFS: Unable to mount root fs on unknown-block(0,0)
[    6.729459@2] CPU: 2 PID: 1 Comm: swapper/0 Not tainted 4.9.113 #1
[    6.735610@2] Hardware name: Generic DT based system
[    6.740562@2] [bc001c3c+  16][<c020e39c>] show_stack+0x20/0x24
[    6.746363@2] [bc001c64+  40][<c05df694>] dump_stack+0xb8/0xf4
[    6.752169@2] [bc001c8c+  40][<c0340898>] panic+0xfc/0x288
[    6.757631@2] [bc001cfc+  96][<c1501440>] mount_block_root+0x214/0x2e0
[    6.764127@2] [bc001d14+  24][<c1501674>] mount_root+0x7c/0x80
[    6.769933@2] [bc001d3c+  40][<c150184c>] prepare_namespace+0x1d4/0x218
[    6.776521@2] [bc001d7c+  64][<c1501028>] kernel_init_freeable+0x2a8/0x2c0
[    6.783366@2] [bc001d94+  24][<c0fbe074>] kernel_init+0x18/0x118
[    6.789349@2] [00000000+   0][<c020885c>] ret_from_fork+0x14/0x38
[    6.795564@0] CPU0: stopping
[    6.798274@0] CPU: 0 PID: 0 Comm: swapper/0 Not tainted 4.9.113 #1
[    6.804424@0] Hardware name: Generic DT based system
[    6.809381@0] [c18a1d64+  16][<c020e39c>] show_stack+0x20/0x24
[    6.815179@0] [c18a1d8c+  40][<c05df694>] dump_stack+0xb8/0xf4
[    6.820983@0] [c18a1db4+  40][<c021233c>] handle_IPI+0x390/0x3c8
[    6.826963@0] [c18a1ddc+  40][<c0201634>] gic_handle_irq+0x80/0x84
[    6.833116@0] [c1601d3c+   0][<c020f108>] __irq_svc+0x88/0xcc
[    6.838837@0] [c1601d3c+  16][<c0209620>] arch_cpu_idle+0x3c/0x54
[    6.844907@0] [c1601d4c+  16][<c0fc60c0>] default_idle_call+0x38/0x54
[    6.851317@0] [c1601d7c+  48][<c0282d54>] cpu_startup_entry+0x1d0/0x274
[    6.857903@0] [c1601d94+  24][<c0fbe058>] rest_init+0x98/0x9c
[    6.863623@0] [c1601ddc+  72][<c1500d74>] start_kernel+0x3d0/0x3dc
[    6.869778@0] [00000000+   0][<c1504bc4>] fixup_init_thread_union+0x38/0x3c
[    6.876706@3] CPU3: stopping
[    6.879566@3] CPU: 3 PID: 0 Comm: swapper/3 Not tainted 4.9.113 #1
[    6.885716@3] Hardware name: Generic DT based system
[    6.890665@3] [ed9bbd64+  16][<c020e39c>] show_stack+0x20/0x24
[    6.896468@3] [ed9bbd8c+  40][<c05df694>] dump_stack+0xb8/0xf4
[    6.902273@3] [ed9bbdb4+  40][<c021233c>] handle_IPI+0x390/0x3c8
[    6.908252@3] [ed9bbddc+  40][<c0201634>] gic_handle_irq+0x80/0x84
[    6.914406@3] [bc01dd84+   0][<c020f108>] __irq_svc+0x88/0xcc
[    6.920127@3] [bc01dd84+  16][<c0209620>] arch_cpu_idle+0x3c/0x54
[    6.926195@3] [bc01dd94+  16][<c0fc60c0>] default_idle_call+0x38/0x54
[    6.932607@3] [bc01ddc4+  48][<c0282d54>] cpu_startup_entry+0x1d0/0x274
[    6.939193@3] [bc01dddc+  24][<c0211d38>] secondary_start_kernel+0x174/0x180
[    6.946211@5] CPU5: stopping
[    6.949071@5] CPU: 5 PID: 0 Comm: swapper/5 Not tainted 4.9.113 #1
[    6.955223@5] Hardware name: Generic DT based system
[    6.960168@5] [ed9dbd64+  16][<c020e39c>] show_stack+0x20/0x24
[    6.965974@5] [ed9dbd8c+  40][<c05df694>] dump_stack+0xb8/0xf4
[    6.971779@5] [ed9dbdb4+  40][<c021233c>] handle_IPI+0x390/0x3c8
[    6.977759@5] [ed9dbddc+  40][<c0201634>] gic_handle_irq+0x80/0x84
[    6.983912@5] [bc021d84+   0][<c020f108>] __irq_svc+0x88/0xcc
[    6.989634@5] [bc021d84+  16][<c0209620>] arch_cpu_idle+0x3c/0x54
[    6.995700@5] [bc021d94+  16][<c0fc60c0>] default_idle_call+0x38/0x54
[    7.002112@5] [bc021dc4+  48][<c0282d54>] cpu_startup_entry+0x1d0/0x274
[    7.008700@5] [bc021ddc+  24][<c0211d38>] secondary_start_kernel+0x174/0x180
[    7.015717@4] CPU4: stopping
[    7.018577@4] CPU: 4 PID: 0 Comm: swapper/4 Not tainted 4.9.113 #1
[    7.024729@4] Hardware name: Generic DT based system
[    7.029674@4] [ed9c3d64+  16][<c020e39c>] show_stack+0x20/0x24
[    7.035480@4] [ed9c3d8c+  40][<c05df694>] dump_stack+0xb8/0xf4
[    7.041286@4] [ed9c3db4+  40][<c021233c>] handle_IPI+0x390/0x3c8
[    7.047266@4] [ed9c3ddc+  40][<c0201634>] gic_handle_irq+0x80/0x84
[    7.053419@4] [bc01fd84+   0][<c020f108>] __irq_svc+0x88/0xcc
[    7.059140@4] [bc01fd84+  16][<c0209620>] arch_cpu_idle+0x3c/0x54
[    7.065207@4] [bc01fd94+  16][<c0fc60c0>] default_idle_call+0x38/0x54
[    7.071619@4] [bc01fdc4+  48][<c0282d54>] cpu_startup_entry+0x1d0/0x274
[    7.078206@4] [bc01fddc+  24][<c0211d38>] secondary_start_kernel+0x174/0x180
[    7.085225@1] CPU1: stopping
[    7.088086@1] CPU: 1 PID: 0 Comm: swapper/1 Not tainted 4.9.113 #1
[    7.094237@1] Hardware name: Generic DT based system
[    7.099184@1] [ed8f3d64+  16][<c020e39c>] show_stack+0x20/0x24
[    7.104990@1] [ed8f3d8c+  40][<c05df694>] dump_stack+0xb8/0xf4
[    7.110795@1] [ed8f3db4+  40][<c021233c>] handle_IPI+0x390/0x3c8
[    7.116775@1] [ed8f3ddc+  40][<c0201634>] gic_handle_irq+0x80/0x84
[    7.122929@1] [bc019d84+   0][<c020f108>] __irq_svc+0x88/0xcc
[    7.128650@1] [bc019d84+  16][<c0209620>] arch_cpu_idle+0x3c/0x54
[    7.134717@1] [bc019d94+  16][<c0fc60c0>] default_idle_call+0x38/0x54
[    7.141128@1] [bc019dc4+  48][<c0282d54>] cpu_startup_entry+0x1d0/0x274
[    7.147716@1] [bc019ddc+  24][<c0211d38>] secondary_start_kernel+0x174/0x180
[    7.158416@2] Rebooting in 5 seconds..
[   12.158418@2] reboot reason 12
```

其中earlycon=aml_uart,0xff803000的来源为：

```
fdt print /aliases
aliases {
        serial0 = "/soc/aobus@ff800000/serial@3000";
        serial1 = "/serial@ffd24000";
        serial2 = "/serial@ffd23000";
        serial3 = "/serial@ffd22000";
        serial4 = "/soc/aobus@ff800000/serial@4000";
        i2c0 = "/soc/cbus@ffd00000/i2c@1f000";
        i2c1 = "/soc/cbus@ffd00000/i2c@1e000";
        i2c2 = "/soc/cbus@ffd00000/i2c@1d000";
        i2c3 = "/soc/cbus@ffd00000/i2c@1c000";
        i2c4 = "/soc/aobus@ff800000/i2c@5000";
        tsensor0 = "/p_tsensor@ff634594";
        tsensor1 = "/d_tsensor@ff800228";
};
```

### 内存大小获取

对于 Amlogic G12B（Khadas VIM3 的 A311D/S922X），AO_SEC_GP_CFG0 是 AO（Always-On）安全域中的一个通用配置寄存器，由 BL2/ATF 在启动早期写入，后续 U-Boot 和 Linux 用它获取一些启动信息。它并不是硬件自动生成的寄存器，而是 BootROM/BL2 软件约定使用的“信息传递寄存器”。

从 Amlogic 的 U-Boot 代码可以直接看到：

```c
#define AO_SEC_GP_CFG0 (0xff800000 + (0x090 << 2))
#define CONFIG_SYS_MEM_TOP_HIDE 0x08000000 //hide 128MB for kernel reserve
phys_size_t get_effective_memsize(void)
{
  #if defined(CONFIG_SYS_MEM_TOP_HIDE)
    size[0] = (((readl(AO_SEC_GP_CFG0)) & 0xFFFF0000) << 4) - CONFIG_SYS_MEM_TOP_HIDE;
  #else
    size[0] = (((readl(AO_SEC_GP_CFG0)) & 0xFFFF0000) << 4);
  #endif
}
```

也就是说，DDR 容量信息就是从 AO_SEC_GP_CFG0 里取出来的。

```
=> md.l 0xFF800240 1
ff800240: 0f5808f1                             ..X.
```

((0x0f5808f1 & 0xFFFF0000)<<4) - 0x08000000 = (0xF580000 << 4) - 0x08000000 =  0xF5800000 -  0x08000000 = 0xED800000 = 3,984,588,800 

# system.img

### 编译时map报错问题

```
FAILED: out/target/product/kvim3/dex_bootjars/system/framework/arm/boot.art 
/bin/bash -c "(mkdir -p out/target/product/kvim3/symbols/system/framework/arm/ ) && (rm -f out/target/product/kvim3/dex_bootjars/system/framework/arm//*.art out/target/product/kvim3/dex_bootjars/system/framework/arm//*.oat out/target/product/kvim3/dex_bootjars/system/framework/arm//*.art.rel ) && (rm -f out/target/product/kvim3/symbols/system/framework/arm//*.art ) && (rm -f out/target/product/kvim3/symbols/system/framework/arm//*.oat ) && (rm -f out/target/product/kvim3/symbols/system/framework/arm//*.art.rel ) && (ANDROID_LOG_TAGS=\"*:e\" out/host/linux-x86/bin/dex2oatd --runtime-arg -Xms64m 		--runtime-arg -Xmx64m 		--compiler-filter=speed-profile --profile-file=out/target/product/kvim3/dex_bootjars/system/framework/boot.prof 		--dex-file=out/target/common/obj/JAVA_LIBRARIES/exoplayer_intermediates/javalib.jar --dex-file=out/target/common/obj/JAVA_LIBRARIES/core-oj_intermediates/javalib.jar --dex-file=out/target/common/obj/JAVA_LIBRARIES/core-libart_intermediates/javalib.jar --dex-file=out/target/common/obj/JAVA_LIBRARIES/conscrypt_intermediates/javalib.jar --dex-file=out/target/common/obj/JAVA_LIBRARIES/okhttp_intermediates/javalib.jar --dex-file=out/target/common/obj/JAVA_LIBRARIES/bouncycastle_intermediates/javalib.jar --dex-file=out/target/common/obj/JAVA_LIBRARIES/apache-xml_intermediates/javalib.jar --dex-file=out/target/common/obj/JAVA_LIBRARIES/ext_intermediates/javalib.jar --dex-file=out/target/common/obj/JAVA_LIBRARIES/framework_intermediates/javalib.jar --dex-file=out/target/common/obj/JAVA_LIBRARIES/telephony-common_intermediates/javalib.jar --dex-file=out/target/common/obj/JAVA_LIBRARIES/voip-common_intermediates/javalib.jar --dex-file=out/target/common/obj/JAVA_LIBRARIES/ims-common_intermediates/javalib.jar --dex-file=out/target/common/obj/JAVA_LIBRARIES/android.hidl.base-V1.0-java_intermediates/javalib.jar --dex-file=out/target/common/obj/JAVA_LIBRARIES/android.hidl.manager-V1.0-java_intermediates/javalib.jar --dex-file=out/target/common/obj/JAVA_LIBRARIES/framework-oahl-backward-compatibility_intermediates/javalib.jar --dex-file=out/target/common/obj/JAVA_LIBRARIES/android.test.base_intermediates/javalib.jar 		--dex-location=/system/framework/exoplayer.jar --dex-location=/system/framework/core-oj.jar --dex-location=/system/framework/core-libart.jar --dex-location=/system/framework/conscrypt.jar --dex-location=/system/framework/okhttp.jar --dex-location=/system/framework/bouncycastle.jar --dex-location=/system/framework/apache-xml.jar --dex-location=/system/framework/ext.jar --dex-location=/system/framework/framework.jar --dex-location=/system/framework/telephony-common.jar --dex-location=/system/framework/voip-common.jar --dex-location=/system/framework/ims-common.jar --dex-location=/system/framework/android.hidl.base-V1.0-java.jar --dex-location=/system/framework/android.hidl.manager-V1.0-java.jar --dex-location=/system/framework/framework-oahl-backward-compatibility.jar --dex-location=/system/framework/android.test.base.jar 		--oat-symbols=out/target/product/kvim3/symbols/system/framework/arm/boot.oat 		--oat-file=out/target/product/kvim3/dex_bootjars/system/framework/arm/boot.oat 		--oat-location=/system/framework/arm/boot.oat--image=out/target/product/kvim3/dex_bootjars/system/framework/arm/boot.art --base=0x70000000 		--instruction-set=arm 		--instruction-set-variant=cortex-a9 		--instruction-set-features=default 		--android-root=out/target/product/kvim3/system 		--runtime-arg -Xnorelocate --compile-pic 		--no-generate-debug-info --generate-build-id 		--multi-image --no-inline-from=core-oj.jar 		--abort-on-hard-verifier-error 		--abort-on-soft-verifier-error 		 --generate-mini-debug-info   		|| ( echo \"ERROR: Dex2oat failed to compile a boot image. It is likely that the boot classpath is inconsistent. Rebuild with ART_BOOT_IMAGE_EXTRA_ARGS=\"--runtime-arg -verbose:verifier\" to see verification errors.\" ; false ) && 	ANDROID_LOG_TAGS=\"*:e\" ANDROID_ROOT=out/target/product/kvim3/system ANDROID_DATA=out/target/product/kvim3/dex_bootjars/system/framework/arm/ out/host/linux-x86/bin/patchoatd 		--input-image-location=out/target/product/kvim3/dex_bootjars/system/framework/boot.art 		--output-image-relocation-directory=out/target/product/kvim3/dex_bootjars/system/framework/arm/ 		--instruction-set=arm 		--base-offset-delta=0x10000000 )"
patchoatd E 06-11 15:06:32 19956 19956 image_space.cc:1761] Could not create image space with image file 'out/target/product/kvim3/dex_bootjars/system/framework/boot.art'. Attempting to fall back to imageless running. Error was: Failed to mmap at expected address, mapped at 0x7f3c97c00000 instead of 0x704c2000
```

解决方法：

- https://groups.google.com/g/android-building/c/ZfUQQWt_ABI
- https://android-review.googlesource.com/c/platform/art/+/2226578
- https://android-review.googlesource.com/c/platform/art/+/2226578/2/runtime/mem_map.cc

就是修改art/runtime/mem_map.cc中的文件.

```
project art/
diff --git a/runtime/mem_map.cc b/runtime/mem_map.cc
index b9d51c1125..f034a3db4f 100644
--- a/runtime/mem_map.cc
+++ b/runtime/mem_map.cc
@@ -504,6 +504,11 @@ MemMap* MemMap::MapFileAtAddress(uint8_t* expected_ptr,
     DCHECK(ContainedWithinExistingMap(expected_ptr, byte_count, error_msg))
         << ((error_msg != nullptr) ? *error_msg : std::string());
     flags |= MAP_FIXED;
+#if !defined(ART_TARGET)
+  } else if (expected_ptr) {
+#define MAP_FIXED_NOREPLACE 0x100000
+    flags |= MAP_FIXED_NOREPLACE;
+#endif
   } else {
     CHECK_EQ(0, flags & MAP_FIXED);
     // Don't bother checking for an overlapping region here. We'll
```

# AVB 配置

```log
Hit any key to stop autoboot: 0
Card did not respond to voltage select! : -110
Card did not respond to voltage select! : -110
** Booting bootflow 'mmc@ffe07000.bootdev.whole' with android
get_partition: can't find partition 'vbmeta'
avb_footer.c:22: ERROR: Footer magic is incorrect.
avb_vbmeta_image.c:46: ERROR: Magic is incorrect.
avb_slot_verify.c:745: ERROR: boot: Error verifying vbmeta image: invalid vbmeta header
Unlocked verification failed, reason: Metadata is invalid or inconsistent
Boot failed (err=-5)
meson_pcie_wait_link_up: error: wait linkup timeout
PCIE-0: Link up (Gen1-x1, Bus0)
USB XHCI 1.10
Bus usb@ff500000: 2 USB Device(s) found
=>
```

### 密钥配置

用于avbtool的密钥生成：

```shell
$ openssl genrsa -out avb_private_key_4096.pem 4096
```

从密钥生成用于u-boot进行验证的共钥：

```shell
$ python2.7 out/host/linux-x86/bin/avbtool extract_public_key --key avb_private_key_4096.pem --output a
$ xxd -i a
```

用这个生成的公钥替换u-boot中的avb_root_pub变量

### 生成vbmeta.img

```shell
$ python2.7 out/host/linux-x86/bin/avbtool add_hash_footer \
  --image out/target/product/kvim3/boot.img \
  --partition_name boot \
  --partition_size 16777216 \
  --algorithm SHA256_RSA4096 \
  --key avb_private_key_4096.pem

$ python2.7 out/host/linux-x86/bin/avbtool make_vbmeta_image \
	--key avb_private_key_4096.pem \
	--output vbmeta.img \
	--algorithm SHA256_RSA4096 \
	--rollback_index 0 \
	--include_descriptors_from_image out/target/product/kvim3/boot.img 
```

# 一些有用的知识

- dts文件路径: common/arch/arm/boot/dts/amlogic/kvim3.dts（编译规则定义在：device/khadas/common/factory.mk）, 其中分区的定义以#include "partition..."开头(partition_mbox_normal_P_32.dtsi)。

- First Stage Mount：位于system/core/init/init_first_stage.cpp，根据dt挂载对应的分区，具体为：

```dt
/*
 * Amlogic partition set for normal
 *
 * Copyright (c) 2017-2017 Amlogic Ltd
 *
 * This file is licensed under a dual GPLv2 or BSD license.
 *
 */
/ {
	firmware {
		android {
			compatible = "android,firmware";
			vbmeta {
				compatible = "android,vbmeta";
				parts = "vbmeta,boot,system,vendor";
				by_name_prefix="/dev/block";
			};
		fstab {
			compatible = "android,fstab";

			vendor {
				compatible = "android,vendor";
				dev = "/dev/block/vendor";
				type = "ext4";
				mnt_flags = "ro,barrier=1,inode_readahead_blks=8";
				fsmgr_flags = "wait";
				};
			product {
				compatible = "android,product";
				dev = "/dev/block/product";
				type = "ext4";
				mnt_flags = "ro,barrier=1,inode_readahead_blks=8";
				fsmgr_flags = "wait";
				};
			odm {
				compatible = "android,odm";
				dev = "/dev/block/odm";
				type = "ext4";
				mnt_flags = "ro,barrier=1,inode_readahead_blks=8";
				fsmgr_flags = "wait";
				};
			};
		};
	};
};/* end of / */
```

# bug

### 关于mainline u-boot 在 bootm go 之前添加 bootm prep 无法启动分析

正常的memblock 布局：

```log
=> mmc dev 2
switch to partitions #0, OK
mmc2(part 0) is current device
=> mmc read 0x1080000 0x3E000 0x5000
MMC read: dev # 2, block # 253952, count 20480 ... 20480 blocks read: OK
=> bootm start 0x1080000
## Booting Android Image at 0x01080000 ...
Kernel load addr 0x01080000 size 9264 KiB
Kernel command line: console=ttyS0,115200n8 no_console_suspend earlycon=aml-uart,0xff803000 buildvariant=userdebug
Error: header_version must be >= 2 to get dtb
second address is 0x198c800
Working FDT set to 198c800
=> bootm loados
   Loading Kernel Image to 1080000
=> bootm fdt
   Loading Device Tree to 000000001ffe5000, end 000000001ffff818 ... OK
Working FDT set to 1ffe5000
=> fdt chosen
=> fdt set /chosen bootargs "init=/init console=ttyS0,115200 no_console_suspend earlycon=aml-uart,0xff803000 initcall_debug ignore_loglevel loglevel=8 memblock=debug"
=> fdt print /chosen
chosen {
        smbios3-entrypoint = <0x00000000 0xeaf3a000>;
        u-boot,version = "2026.07-rc3-00035-gf850b4d66d23-dirty";
        bootargs = "init=/init console=ttyS0,115200 no_console_suspend earlycon=aml-uart,0xff803000 initcall_debug ignore_loglevel loglevel=8 memblock=debug";
        kaslr-seed = <0x86900b6e 0xbdccdc5f>;
};
=> fdt mknod / memory   
=> fdt set /memory device_type "memory" 
=> fdt set /memory reg <0x0 0xED800000> 
=> fdt print /memory
memory {
        reg = <0x00000000 0xed800000>;
        device_type = "memory";
};
=> bdinfo
boot_params = 0x0000000000000000
DRAM bank   = 0x0000000000000000
-> start    = 0x0000000000000000
-> size     = 0x00000000f5000000
flashstart  = 0x0000000000000000
flashsize   = 0x0000000000000000
flashoffset = 0x0000000000000000
baudrate    = 115200 bps
relocaddr   = 0x00000000f2f1f000
reloc off   = 0x00000000f1f1f000
Build       = 64-bit
current eth = ethernet@ff3f0000
ethaddr     = c8:63:14:70:5a:50
IP addr     = <NULL>
fdt_blob    = 0x00000000eaefa3a0
Video       = vpu@ff900000 active
FB base     = 0x00000000f4e5b000
FB size     = 720x576x32
lmb_dump_all:
 memory.count = 0x1
 memory[0]      [0x0-0xf4ffffff], 0xf5000000 bytes, flags: none
 reserved.count = 0x6
 reserved[0]    [0x1080000-0x198bde7], 0x90bde8 bytes, flags: none
 reserved[1]    [0x5000000-0x72fffff], 0x2300000 bytes, flags: no-map
 reserved[2]    [0x7400000-0x74fffff], 0x100000 bytes, flags: no-overwrite
 reserved[3]    [0x1ffe5000-0x1ffff818], 0x1a819 bytes, flags: none
 reserved[4]    [0xe9eed000-0xe9ef9fff], 0xd000 bytes, flags: no-notify, no-overwrite
 reserved[5]    [0xe9efa390-0xf4ffffff], 0xb105c70 bytes, flags: no-overwrite
devicetree  = separate
arch_number = 0x0000000000000000
TLB addr    = 0x00000000f4ff0000
irq_sp      = 0x00000000eaefa390
sp start    = 0x00000000eaefa390
Early malloc usage: 1080 / 2000
fdt rsvmem print
index              start                    size
------------------------------------------------
=> bootm go

Starting kernel ...

   FDT blob at 0x1ffe5000, size 108569 bytes
   IH_ARCH_DEFAULT is 22, images->os.arch is 0
[    0.000000@0] Booting Linux on physical CPU 0x0
[    0.000000@0] Linux version 4.9.113 (root@9a46a5882b4c) (gcc version 6.3.1 20170109 (Linaro GCC 6.3-2017.02) ) #2 SMP PREEMPT Fri Jun 12 11:55:34 CST 2026
[    0.000000@0] CPU: cpu_v7_name [410fd034] revision 4 (ARMv7), cr=10c5383d
[    0.000000@0] CPU: div instructions available: patching division code
[    0.000000@0] CPU: PIPT / VIPT nonaliasing data cache, VIPT aliasing instruction cache
[    0.000000@0] Machine model: Khadas
[    0.000000@0] earlycon: aml-uart0 at MMIO 0xff803000 (options '')
[    0.000000@0] bootconsole [aml-uart0] enabled
[    0.000000@0] debug: ignoring loglevel setting.
[    0.000000@0] memblock_reserve: [0x00000000200000-0x000000018b2e43] flags 0x0 arm_memblock_init+0x44/0x190
[    0.000000@0] memblock_reserve: [0x00000000104000-0x00000000107fff] flags 0x0 arm_mm_memblock_reserve+0x20/0x24
[    0.000000@0] memblock_reserve: [0x0000001ffe5000-0x0000001ffff818] flags 0x0 early_init_dt_reserve_memory_arch+0x20/0x24
[    0.000000@0] memblock_reserve: [0x00000007400000-0x000000074fffff] flags 0x0 early_init_dt_reserve_memory_arch+0x20/0x24
[    0.000000@0]        07400000 - 07500000,     1024 KB, ramoops@0x07400000
[    0.000000@0] memblock_reserve: [0x00000005000000-0x000000053fffff] flags 0x0 memblock_alloc_range_nid+0x40/0x58
[    0.000000@0]        05000000 - 05400000,     4096 KB, linux,secmon
[    0.000000@0] memblock_reserve: [0x0000007f800000-0x0000007fffffff] flags 0x0 memblock_alloc_range_nid+0x40/0x58
[    0.000000@0]        7f800000 - 80000000,     8192 KB, linux,meson-fb
[    0.000000@0] memblock_reserve: [0x000000e5800000-0x000000ed7fffff] flags 0x0 memblock_alloc_range_nid+0x40/0x58
[    0.000000@0]        e5800000 - ed800000,   131072 KB, linux,ion-dev
[    0.000000@0] memblock_reserve: [0x000000e3000000-0x000000e57fffff] flags 0x0 memblock_alloc_range_nid+0x40/0x58
[    0.000000@0]        e3000000 - e5800000,    40960 KB, linux,di_cma
[    0.000000@0] memblock_reserve: [0x000000e3000000-0x000000e2ffffff] flags 0x0 memblock_alloc_range_nid+0x40/0x58
[    0.000000@0] Reserved memory: regions without no-map are not yet supported
[    0.000000@0] memblock_reserve: [0x000000cfc00000-0x000000e2ffffff] flags 0x0 memblock_alloc_range_nid+0x40/0x58
[    0.000000@0]        cfc00000 - e3000000,   315392 KB, linux,codec_mm_cma
[    0.000000@0] memblock_reserve: [0x000000cfc00000-0x000000cfbfffff] flags 0x0 memblock_alloc_range_nid+0x40/0x58
[    0.000000@0]        cfc00000 - cfc00000,        0 KB, linux,codec_mm_reserved
[    0.000000@0] memblock_reserve: [0x000000cbc00000-0x000000cfbfffff] flags 0x0 memblock_alloc_range_nid+0x40/0x58
[    0.000000@0]        cbc00000 - cfc00000,    65536 KB, linux,vdin0_cma
[    0.000000@0] memblock_reserve: [0x000000c7c00000-0x000000cbbfffff] flags 0x0 memblock_alloc_range_nid+0x40/0x58
[    0.000000@0]        c7c00000 - cbc00000,    65536 KB, linux,vdin1_cma
[    0.000000@0] memblock_reserve: [0x000000c6c00000-0x000000c7bfffff] flags 0x0 memblock_alloc_range_nid+0x40/0x58
[    0.000000@0]        c6c00000 - c7c00000,    16384 KB, linux,galcore
[    0.000000@0] memblock_reserve: [0x000000bec00000-0x000000c6bfffff] flags 0x0 memblock_alloc_range_nid+0x40/0x58
[    0.000000@0]        bec00000 - c6c00000,   131072 KB, linux,isp_cma
[    0.000000@0] memblock_reserve: [0x000000bd400000-0x000000bebfffff] flags 0x0 memblock_alloc_range_nid+0x40/0x58
[    0.000000@0]        bd400000 - bec00000,    24576 KB, linux,adapt_cma
[    0.000000@0] memblock_reserve: [0x000000bcc00000-0x000000bd3fffff] flags 0x0 memblock_alloc_range_nid+0x40/0x58
[    0.000000@0] cma: Reserved 8 MiB at 0xbcc00000
[    0.000000@0] MEMBLOCK configuration:
[    0.000000@0]  memory size = 0xed800000 reserved size = 0x32fd165d
[    0.000000@0]  memory.cnt  = 0x1
[    0.000000@0]  memory[0x0]   [0x00000000000000-0x000000ed7fffff], 0xed800000 bytes flags: 0x0
[    0.000000@0]  reserved.cnt  = 0x7
[    0.000000@0]  reserved[0x0] [0x00000000104000-0x00000000107fff], 0x4000 bytes flags: 0x0
[    0.000000@0]  reserved[0x1] [0x00000000200000-0x000000018b2e43], 0x16b2e44 bytes flags: 0x0
[    0.000000@0]  reserved[0x2] [0x00000005000000-0x000000053fffff], 0x400000 bytes flags: 0x0
[    0.000000@0]  reserved[0x3] [0x00000007400000-0x000000074fffff], 0x100000 bytes flags: 0x0
[    0.000000@0]  reserved[0x4] [0x0000001ffe5000-0x0000001ffff818], 0x1a819 bytes flags: 0x0
[    0.000000@0]  reserved[0x5] [0x0000007f800000-0x0000007fffffff], 0x800000 bytes flags: 0x0
[    0.000000@0]  reserved[0x6] [0x000000bcc00000-0x000000ed7fffff], 0x30c00000 bytes flags: 0x0
[    0.000000@0] Memory policy: Data cache writealloc
[    0.000000@0] memblock_reserve: [0x0000002fffffd8-0x0000002fffffff] flags 0x0 memblock_alloc_range_nid+0x40/0x58
[    0.000000@0] memblock_reserve: [0x0000002fffe000-0x0000002fffefff] flags 0x0 memblock_alloc_range_nid+0x40/0x58
[    0.000000@0] memblock_reserve: [0x0000002fffd000-0x0000002fffdfff] flags 0x0 memblock_alloc_range_nid+0x40/0x58
```

非正常memblock:

```log
=> mmc dev 2
switch to partitions #0, OK
mmc2(part 0) is current device
=> mmc read 0x1080000 0x3E000 0x5000
MMC read: dev # 2, block # 253952, count 20480 ... 20480 blocks read: OK
=> bootm start 0x1080000
## Booting Android Image at 0x01080000 ...
Kernel load addr 0x01080000 size 9264 KiB
Kernel command line: console=ttyS0,115200n8 no_console_suspend earlycon=aml-uart,0xff803000 buildvariant=userdebug
Error: header_version must be >= 2 to get dtb
second address is 0x198c800
Working FDT set to 198c800
=> bootm loados
   Loading Kernel Image to 1080000
=> bootm fdt
   Loading Device Tree to 000000001ffe5000, end 000000001ffff818 ... OK
Working FDT set to 1ffe5000
=> bootm prep
   Loading Device Tree to 000000001ffc7000, end 000000001ffe4818 ... OK
Working FDT set to 1ffc7000
Cannot setup simplefb: node not found
=> fdt print /chosen
chosen {
        smbios3-entrypoint = <0x00000000 0xeaf3a000>;
        u-boot,version = "2026.07-rc3-00035-gf850b4d66d23-dirty";
        bootargs = "console=ttyS0,115200n8 no_console_suspend earlycon=aml-uart,0xff803000 buildvariant=userdebug";
        kaslr-seed = <0x4a03290b 0x1cdbdde6>;
};
=> fdt set /chosen bootargs "init=/init console=ttyS0,115200 no_console_suspend earlycon=aml-uart,0xff803000 initcall_debug ignore_loglevel loglevel=8 memblock=debug"
=> fdt print /chosen
chosen {
        smbios3-entrypoint = <0x00000000 0xeaf3a000>;
        u-boot,version = "2026.07-rc3-00035-gf850b4d66d23-dirty";
        bootargs = "init=/init console=ttyS0,115200 no_console_suspend earlycon=aml-uart,0xff803000 initcall_debug ignore_loglevel loglevel=8 memblock=debug";
        kaslr-seed = <0x4a03290b 0x1cdbdde6>;
};
=> bdinfo
boot_params = 0x0000000000000000
DRAM bank   = 0x0000000000000000
-> start    = 0x0000000000000000
-> size     = 0x00000000f5000000
flashstart  = 0x0000000000000000
flashsize   = 0x0000000000000000
flashoffset = 0x0000000000000000
baudrate    = 115200 bps
relocaddr   = 0x00000000f2f1f000
reloc off   = 0x00000000f1f1f000
Build       = 64-bit
current eth = ethernet@ff3f0000
ethaddr     = c8:63:14:70:5a:50
IP addr     = <NULL>
fdt_blob    = 0x00000000eaefa3a0
Video       = vpu@ff900000 active
FB base     = 0x00000000f4e5b000
FB size     = 720x576x32
lmb_dump_all:
 memory.count = 0x1
 memory[0]      [0x0-0xf4ffffff], 0xf5000000 bytes, flags: none
 reserved.count = 0x7
 reserved[0]    [0x1080000-0x198bde7], 0x90bde8 bytes, flags: none
 reserved[1]    [0x5000000-0x72fffff], 0x2300000 bytes, flags: no-map
 reserved[2]    [0x7400000-0x74fffff], 0x100000 bytes, flags: no-overwrite
 reserved[3]    [0x1ffc7000-0x1ffdefff], 0x18000 bytes, flags: none
 reserved[4]    [0x1ffe5000-0x1ffff818], 0x1a819 bytes, flags: none
 reserved[5]    [0xe9eed000-0xe9ef9fff], 0xd000 bytes, flags: no-notify, no-overwrite
 reserved[6]    [0xe9efa390-0xf4ffffff], 0xb105c70 bytes, flags: no-overwrite
devicetree  = separate
arch_number = 0x0000000000000000
TLB addr    = 0x00000000f4ff0000
irq_sp      = 0x00000000eaefa390
sp start    = 0x00000000eaefa390
Early malloc usage: 1080 / 2000
=> fdt rsvmem print 
index              start                    size
------------------------------------------------
    0   0000000005000000        0000000000300000
    1   00000000f4e5b000        00000000001a5000
=> bootm go

Starting kernel ...

   FDT blob at 0x1ffc7000, size 108569 bytes
   IH_ARCH_DEFAULT is 22, images->os.arch is 0
[    0.000000@0] Booting Linux on physical CPU 0x0
[    0.000000@0] Linux version 4.9.113 (root@9a46a5882b4c) (gcc version 6.3.1 20170109 (Linaro GCC 6.3-2017.02) ) #2 SMP PREEMPT Fri Jun 12 11:55:34 CST 2026
[    0.000000@0] CPU: cpu_v7_name [410fd034] revision 4 (ARMv7), cr=10c5383d
[    0.000000@0] CPU: div instructions available: patching division code
[    0.000000@0] CPU: PIPT / VIPT nonaliasing data cache, VIPT aliasing instruction cache
[    0.000000@0] Machine model: Khadas
[    0.000000@0] earlycon: aml-uart0 at MMIO 0xff803000 (options '')
[    0.000000@0] bootconsole [aml-uart0] enabled
[    0.000000@0] debug: ignoring loglevel setting.
[    0.000000@0] memblock_reserve: [0x00000000200000-0x000000018b2e43] flags 0x0 arm_memblock_init+0x44/0x190
[    0.000000@0] memblock_reserve: [0x00000000104000-0x00000000107fff] flags 0x0 arm_mm_memblock_reserve+0x20/0x24
[    0.000000@0] memblock_reserve: [0x0000001ffc7000-0x0000001ffdefff] flags 0x0 early_init_dt_reserve_memory_arch+0x20/0x24
[    0.000000@0] memblock_reserve: [0x00000005000000-0x000000052fffff] flags 0x0 early_init_dt_reserve_memory_arch+0x20/0x24
[    0.000000@0] memblock_reserve: [0x000000f4e5b000-0x000000f4ffffff] flags 0x0 early_init_dt_reserve_memory_arch+0x20/0x24
[    0.000000@0] memblock_reserve: [0x00000007400000-0x000000074fffff] flags 0x0 early_init_dt_reserve_memory_arch+0x20/0x24
[    0.000000@0]        07400000 - 07500000,     1024 KB, ramoops@0x07400000
[    0.000000@0] memblock_reserve: [0x00000004c00000-0x00000004ffffff] flags 0x0 memblock_alloc_range_nid+0x40/0x58
[    0.000000@0]    memblock_free: [0x00000004c00000-0x00000004ffffff] early_init_dt_alloc_reserved_memory_arch+0x44/0x74
[    0.000000@0] failed to allocate memory for node linux,secmon, size:4 MB
[    0.000000@0] memblock_reserve: [0x0000007f800000-0x0000007fffffff] flags 0x0 memblock_alloc_range_nid+0x40/0x58
[    0.000000@0]        7f800000 - 80000000,     8192 KB, linux,meson-fb
[    0.000000@0] memblock_reserve: [0x000000e5800000-0x000000ed7fffff] flags 0x0 memblock_alloc_range_nid+0x40/0x58
[    0.000000@0]        e5800000 - ed800000,   131072 KB, linux,ion-dev
[    0.000000@0] memblock_reserve: [0x000000e3000000-0x000000e57fffff] flags 0x0 memblock_alloc_range_nid+0x40/0x58
[    0.000000@0]        e3000000 - e5800000,    40960 KB, linux,di_cma
[    0.000000@0] memblock_reserve: [0x000000e3000000-0x000000e2ffffff] flags 0x0 memblock_alloc_range_nid+0x40/0x58
[    0.000000@0] Reserved memory: regions without no-map are not yet supported
[    0.000000@0] memblock_reserve: [0x000000cfc00000-0x000000e2ffffff] flags 0x0 memblock_alloc_range_nid+0x40/0x58
[    0.000000@0]        cfc00000 - e3000000,   315392 KB, linux,codec_mm_cma
[    0.000000@0] memblock_reserve: [0x000000cfc00000-0x000000cfbfffff] flags 0x0 memblock_alloc_range_nid+0x40/0x58
[    0.000000@0]        cfc00000 - cfc00000,        0 KB, linux,codec_mm_reserved
[    0.000000@0] memblock_reserve: [0x000000cbc00000-0x000000cfbfffff] flags 0x0 memblock_alloc_range_nid+0x40/0x58
[    0.000000@0]        cbc00000 - cfc00000,    65536 KB, linux,vdin0_cma
[    0.000000@0] memblock_reserve: [0x000000c7c00000-0x000000cbbfffff] flags 0x0 memblock_alloc_range_nid+0x40/0x58
[    0.000000@0]        c7c00000 - cbc00000,    65536 KB, linux,vdin1_cma
[    0.000000@0] memblock_reserve: [0x000000c6c00000-0x000000c7bfffff] flags 0x0 memblock_alloc_range_nid+0x40/0x58
[    0.000000@0]        c6c00000 - c7c00000,    16384 KB, linux,galcore
[    0.000000@0] memblock_reserve: [0x000000bec00000-0x000000c6bfffff] flags 0x0 memblock_alloc_range_nid+0x40/0x58
[    0.000000@0]        bec00000 - c6c00000,   131072 KB, linux,isp_cma
[    0.000000@0] memblock_reserve: [0x000000bd400000-0x000000bebfffff] flags 0x0 memblock_alloc_range_nid+0x40/0x58
[    0.000000@0]        bd400000 - bec00000,    24576 KB, linux,adapt_cma
[    0.000000@0] memblock_reserve: [0x000000bcc00000-0x000000bd3fffff] flags 0x0 memblock_alloc_range_nid+0x40/0x58
[    0.000000@0] cma: Reserved 8 MiB at 0xbcc00000
[    0.000000@0] MEMBLOCK configuration:
[    0.000000@0]  memory size = 0xed800000 reserved size = 0x33073e44
[    0.000000@0]  memory.cnt  = 0x1
[    0.000000@0]  memory[0x0]   [0x00000000000000-0x000000ed7fffff], 0xed800000 bytes flags: 0x0
[    0.000000@0]  reserved.cnt  = 0x8
[    0.000000@0]  reserved[0x0] [0x00000000104000-0x00000000107fff], 0x4000 bytes flags: 0x0
[    0.000000@0]  reserved[0x1] [0x00000000200000-0x000000018b2e43], 0x16b2e44 bytes flags: 0x0
[    0.000000@0]  reserved[0x2] [0x00000005000000-0x000000052fffff], 0x300000 bytes flags: 0x0
[    0.000000@0]  reserved[0x3] [0x00000007400000-0x000000074fffff], 0x100000 bytes flags: 0x0
[    0.000000@0]  reserved[0x4] [0x0000001ffc7000-0x0000001ffdefff], 0x18000 bytes flags: 0x0
[    0.000000@0]  reserved[0x5] [0x0000007f800000-0x0000007fffffff], 0x800000 bytes flags: 0x0
[    0.000000@0]  reserved[0x6] [0x000000bcc00000-0x000000ed7fffff], 0x30c00000 bytes flags: 0x0
[    0.000000@0]  reserved[0x7] [0x000000f4e5b000-0x000000f4ffffff], 0x1a5000 bytes flags: 0x0
[    0.000000@0] Memory policy: Data cache writealloc
```

根本原因：

meson_init_reserved_memory

调用链：boot_prep_linux→  image_setup_linux→ image_setup_libfdt→ ft_board_setup → meson_init_reserved_memory → meson_board_add_reserved_memory → fdt_add_mem_rsv(fdt, start, size)

（meson_init_reserved_memory）board-g12a.c:27 从硬件寄存器读取 BL31/BL32（TF-A/OP-TEE）的实际内存位置，然后通过 fdt_add_mem_rsv 添加到 FDT 的二进制 memreserve 表，而不是 /reserved-memory 节点：

```c
bl31_start = readl(G12A_AO_SEC_GP_CFG5);
bl32_start = readl(G12A_AO_SEC_GP_CFG4);

meson_board_add_reserved_memory(fdt, bl31_start, bl31_size);  // fdt_add_mem_rsv!
meson_board_add_reserved_memory(fdt, bl32_start, bl32_size);  // fdt_add_mem_rsv!
```

这就是为什么 fdt print /reserved-memory/linux,secmon 看不到变化——memreserve 表是 FDT 二进制头部的独立结构，不是 DT 节点。只能通过 **fdt rsvmem print** 看出变化。


**与内核日志的对应关系**

kernel log 中这两行正是 memreserve 表的 BL31/BL32 条目：

```
memblock_reserve: [0x0000001ffe5000-0x0000001fffcfff]  ← BL31
memblock_reserve: [0x00000005000000-0x000000052fffff]  ← BL32
```

内核处理 FDT memreserve 表时调用 early_init_dt_reserve_memory_arch(base, size, false)（nomap=false），产生 memblock_reserve 调用。

随后内核处理 /reserved-memory 中 BL32 对应的 static no-map 节点时：

```c
if (memblock_is_region_reserved(0x5000000, 0x300000))  // TRUE! (已被memreserve加入)
    return memblock_mark_nomap(base, size);  // 改为mark_nomap而非remove
return memblock_remove(base, size);          // 本应走这里
```

这改变了 memblock.memory 的布局，影响了 linux,secmon 的动态分配。

**根本原因**

Android DTB 中 linux,secmon 是动态分配节点（无固定 reg），它的 alloc-ranges 大概率覆盖了 0x5000000 附近区域（OP-TEE 运行内存）。

内核处理顺序：

- 1. 先处理 memreserve 表 → memblock_reserve(0x5000000, 0x300000) ← U-Boot 加的
- 2. 再处理 /reserved-memory/linux,secmon（no-map，动态分配）
- 3. memblock_phys_alloc_range 发现 0x5000000 已被占用，退而求其次分配到 0x4c00000
- 4. memblock_mark_nomap(0x4c00000, ...) 失败（0x4c00000 不在 alloc-ranges 允许的范围内）
- 5. memblock_free 回滚 → failed to allocate

**根本矛盾**

meson_init_reserved_memory 是为主线内核设计的——主线 DTB 没有 linux,secmon 节点，需要 U-Boot 把 BL32 加入 memreserve 让内核知道它。

但 Android 内核的 DTB 已经通过 /reserved-memory/linux,secmon 管理这块内存，U-Boot 再加入 memreserve 就造成了双重冲突。



# 参考资料

Khadas VIM1

https://docs.khadas.com/products/sbc/vim1/start?redirect=1#Krescue-Khadas-Rescue-OS

android_device_khadas

https://github.com/khadas/android_device_khadas/tree/Vim

Le Potato

https://libre.computer/products/aml-s905x-cc/#

Libre Computer Project

https://github.com/libre-computer-project

Linux for Amlogic

https://linux-meson.com

Bootflow and configuration on Amlogic device / Amlogic设备上的启动流程和配置

https://7ji.github.io/embedded/2022/11/11/amlogic-booting.html

Installation of ArchLinux ARM on an out-of-tree Amlogic device / 在不被官方支持的Amlogic设备上安装ArchLinux ARM

https://7ji.github.io/embedded/2022/11/08/alarm-install.html

Partitioning on Amlogic's proprietary eMMC partition table with ampart / 使用ampart在Amlogic专有的eMMC分区表上分区

https://7ji.github.io/embedded/2022/11/11/ept-with-ampart.html

VIM3/3L Build Android

https://docs.khadas.com/products/sbc/vim3/development/android/build-android#vim33l-build-android