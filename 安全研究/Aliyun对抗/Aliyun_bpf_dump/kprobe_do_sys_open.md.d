int kprobe_do_sys_open(struct pt_regs * ctx):
; int dfd = PT_REGS_PARM1(ctx);
   0: (79) r3 = *(u64 *)(r1 +112)
; int flags = PT_REGS_PARM3(ctx);  
   1: (79) r6 = *(u64 *)(r1 +96)
; char *filename = (char *)PT_REGS_PARM2(ctx);
   2: (79) r8 = *(u64 *)(r1 +104)
; if(filename == NULL)
   3: (15) if r8 == 0x0 goto pc+185
   4: (bf) r2 = r6
   5: (57) r2 &= 3
   6: (15) if r2 == 0x0 goto pc+182
   7: (7b) *(u64 *)(r10 -32) = r3
   8: (7b) *(u64 *)(r10 -24) = r1
   9: (b7) r9 = 0
; int map_id = 0;
  10: (63) *(u32 *)(r10 -12) = r9
  11: (bf) r2 = r10
; 
  12: (07) r2 += -12
; map_value = bpf_map_lookup_elem(&data_tmp_store_map, &map_id);
  13: (18) r1 = map[id:1]
  15: (85) call percpu_array_map_lookup_elem#149152
  16: (bf) r7 = r0
; if (!map_value) {
  17: (15) if r7 == 0x0 goto pc+171
; pFileData-&gt;filepath[0] = &#39;\0&#39;;
  18: (73) *(u8 *)(r7 +40) = r9
; pFileData-&gt;filepath[0] = &#39;\0&#39;;
  19: (bf) r9 = r7
  20: (07) r9 += 40
; long pathlen = bpf_probe_read_str(pFileData-&gt;filepath, PATH_MAX, (char *)filename);
  21: (bf) r1 = r9
  22: (b7) r2 = 4096
  23: (bf) r3 = r8
  24: (85) call bpf_probe_read_compat_str#-46512
  25: (bf) r8 = r0
; if (pathlen &lt; 0 || is_open_path_filter(pFileData-&gt;filepath, pathlen))
  26: (b7) r1 = 0
  27: (6d) if r1 s&gt; r8 goto pc+161
; if (*(int*)&path[0] == &#39;ved/&#39; && path[4] == &#39;/&#39;)
  28: (61) r1 = *(u32 *)(r9 +0)
; if (*(int*)&path[0] == &#39;ved/&#39; && path[4] == &#39;/&#39;)
  29: (15) if r1 == 0x6e75722f goto pc+4
  30: (55) if r1 != 0x7665642f goto pc+5
; if (*(int*)&path[0] == &#39;ved/&#39; && path[4] == &#39;/&#39;)
  31: (71) r1 = *(u8 *)(r7 +44)
; if (*(int*)&path[0] == &#39;ved/&#39; && path[4] == &#39;/&#39;)
  32: (15) if r1 == 0x2f goto pc+156
  33: (05) goto pc+2
; if (*(int*)&path[0] == &#39;nur/&#39; && path[4] == &#39;/&#39;)
  34: (71) r1 = *(u8 *)(r7 +44)
; if (*(int*)&path[0] == &#39;nur/&#39; && path[4] == &#39;/&#39;)
  35: (15) if r1 == 0x2f goto pc+153
; u32 tgid = bpf_get_current_pid_tgid() &gt;&gt; 32;
  36: (85) call bpf_get_current_pid_tgid#124560
  37: (7b) *(u64 *)(r10 -48) = r0
  38: (7b) *(u64 *)(r10 -40) = r8
; pFileData-&gt;pathlen = pathlen - 1; // has 0 end
  39: (07) r8 += -1
; pFileData-&gt;pathlen = pathlen - 1; // has 0 end
  40: (bf) r9 = r8
  41: (77) r9 &gt;&gt;= 24
; u32 tid = bpf_get_current_pid_tgid();
  42: (85) call bpf_get_current_pid_tgid#124560
  43: (7b) *(u64 *)(r10 -56) = r0
; pFileData-&gt;pathlen = pathlen - 1; // has 0 end
  44: (73) *(u8 *)(r7 +39) = r9
  45: (bf) r1 = r8
  46: (77) r1 &gt;&gt;= 16
  47: (73) *(u8 *)(r7 +38) = r1
  48: (bf) r1 = r8
  49: (77) r1 &gt;&gt;= 8
  50: (73) *(u8 *)(r7 +37) = r1
  51: (73) *(u8 *)(r7 +36) = r8
  52: (79) r8 = *(u64 *)(r10 -48)
  53: (b7) r1 = 77
; pFileData-&gt;header.magic = HEADER_MAGIC;
  54: (73) *(u8 *)(r7 +3) = r1
  55: (b7) r1 = 68
  56: (73) *(u8 *)(r7 +1) = r1
  57: (b7) r1 = 84
  58: (73) *(u8 *)(r7 +2) = r1
  59: (73) *(u8 *)(r7 +0) = r1
  60: (79) r2 = *(u64 *)(r10 -32)
; pFileData-&gt;dfd = dfd;
  61: (bf) r1 = r2
  62: (77) r1 &gt;&gt;= 24
  63: (73) *(u8 *)(r7 +35) = r1
  64: (bf) r1 = r2
  65: (77) r1 &gt;&gt;= 16
  66: (73) *(u8 *)(r7 +34) = r1
  67: (bf) r1 = r2
  68: (77) r1 &gt;&gt;= 8
  69: (73) *(u8 *)(r7 +33) = r1
  70: (73) *(u8 *)(r7 +32) = r2
; pFileData-&gt;flags = flags;
  71: (bf) r1 = r6
  72: (77) r1 &gt;&gt;= 24
  73: (73) *(u8 *)(r7 +31) = r1
  74: (bf) r1 = r6
  75: (77) r1 &gt;&gt;= 16
  76: (73) *(u8 *)(r7 +30) = r1
  77: (bf) r1 = r6
  78: (77) r1 &gt;&gt;= 8
  79: (73) *(u8 *)(r7 +29) = r1
  80: (73) *(u8 *)(r7 +28) = r6
; pFileData-&gt;pid = tgid;
  81: (bf) r1 = r8
  82: (77) r1 &gt;&gt;= 56
  83: (73) *(u8 *)(r7 +27) = r1
  84: (bf) r1 = r8
  85: (77) r1 &gt;&gt;= 48
  86: (73) *(u8 *)(r7 +26) = r1
  87: (bf) r1 = r8
  88: (77) r1 &gt;&gt;= 40
  89: (73) *(u8 *)(r7 +25) = r1
  90: (b7) r1 = 1
; pFileData-&gt;header.protover = PROTOCOL_VERSION;
  91: (73) *(u8 *)(r7 +4) = r1
; pFileData-&gt;header.minor_cmd = MDCMD_FILEEVENT_WRITING;
  92: (73) *(u8 *)(r7 +7) = r1
  93: (b7) r1 = 3
; pFileData-&gt;header.major_cmd = MULTIDATA_FILEEVENT;
  94: (73) *(u8 *)(r7 +6) = r1
  95: (b7) r6 = 0
; pFileData-&gt;header.protover = PROTOCOL_VERSION;
  96: (73) *(u8 *)(r7 +5) = r6
; u32 tgid = bpf_get_current_pid_tgid() &gt;&gt; 32;
  97: (77) r8 &gt;&gt;= 32
; pFileData-&gt;pid = tgid;
  98: (73) *(u8 *)(r7 +24) = r8
; pFileData-&gt;ktime_event = bpf_ktime_get_ns();
  99: (85) call bpf_ktime_get_ns#124928
; pFileData-&gt;ktime_proc = 0;
 100: (73) *(u8 *)(r7 +23) = r6
 101: (73) *(u8 *)(r7 +22) = r6
 102: (73) *(u8 *)(r7 +21) = r6
 103: (73) *(u8 *)(r7 +20) = r6
 104: (73) *(u8 *)(r7 +19) = r6
 105: (73) *(u8 *)(r7 +18) = r6
 106: (73) *(u8 *)(r7 +17) = r6
 107: (73) *(u8 *)(r7 +16) = r6
; pFileData-&gt;ktime_event = bpf_ktime_get_ns();
 108: (bf) r1 = r0
 109: (77) r1 &gt;&gt;= 56
 110: (73) *(u8 *)(r7 +15) = r1
 111: (bf) r1 = r0
 112: (77) r1 &gt;&gt;= 48
 113: (73) *(u8 *)(r7 +14) = r1
 114: (bf) r1 = r0
 115: (77) r1 &gt;&gt;= 40
 116: (73) *(u8 *)(r7 +13) = r1
 117: (bf) r1 = r0
 118: (77) r1 &gt;&gt;= 32
 119: (73) *(u8 *)(r7 +12) = r1
 120: (bf) r1 = r0
 121: (77) r1 &gt;&gt;= 24
 122: (73) *(u8 *)(r7 +11) = r1
 123: (bf) r1 = r0
 124: (77) r1 &gt;&gt;= 16
 125: (73) *(u8 *)(r7 +10) = r1
 126: (73) *(u8 *)(r7 +8) = r0
 127: (77) r0 &gt;&gt;= 8
 128: (73) *(u8 *)(r7 +9) = r0
; struct task_struct *task = bpf_get_current_task();
 129: (85) call bpf_get_current_task#-55200
; if(task)
 130: (15) if r0 == 0x0 goto pc+48
 131: (79) r1 = *(u64 *)(r10 -56)
; u32 tid = bpf_get_current_pid_tgid();
 132: (67) r1 &lt;&lt;= 32
 133: (77) r1 &gt;&gt;= 32
; if(tgid != tid)
 134: (1d) if r8 == r1 goto pc+10
 135: (b7) r1 = 0
; struct task_struct *group_leader = READ_KERN(task-&gt;group_leader);
 136: (7b) *(u64 *)(r10 -8) = r1
 137: (b7) r1 = 2368
 138: (0f) r0 += r1
 139: (bf) r1 = r10
; 
 140: (07) r1 += -8
; struct task_struct *group_leader = READ_KERN(task-&gt;group_leader);
 141: (b7) r2 = 8
 142: (bf) r3 = r0
 143: (85) call bpf_probe_read_kernel#-51920
 144: (79) r0 = *(u64 *)(r10 -8)
 145: (b7) r1 = 0
; if(task == NULL)
 146: (15) if r0 == 0x0 goto pc+11
 147: (b7) r1 = 0
; stime = READ_KERN(new_task-&gt;start_boottime);
 148: (b7) r1 = 0
; stime = READ_KERN(task-&gt;real_start_time);
 149: (7b) *(u64 *)(r10 -8) = r1
 150: (b7) r1 = 2664
 151: (0f) r0 += r1
 152: (bf) r1 = r10
; 
 153: (07) r1 += -8
 154: (b7) r2 = 8
 155: (bf) r3 = r0
 156: (85) call bpf_probe_read_kernel#-51920
 157: (79) r1 = *(u64 *)(r10 -8)
; pFileData-&gt;ktime_proc = get_task_start_time(task);
 158: (bf) r2 = r1
 159: (77) r2 &gt;&gt;= 56
 160: (73) *(u8 *)(r7 +23) = r2
 161: (bf) r2 = r1
 162: (77) r2 &gt;&gt;= 48
 163: (73) *(u8 *)(r7 +22) = r2
 164: (bf) r2 = r1
 165: (77) r2 &gt;&gt;= 40
 166: (73) *(u8 *)(r7 +21) = r2
 167: (bf) r2 = r1
 168: (77) r2 &gt;&gt;= 32
 169: (73) *(u8 *)(r7 +20) = r2
 170: (bf) r2 = r1
 171: (77) r2 &gt;&gt;= 24
 172: (73) *(u8 *)(r7 +19) = r2
 173: (bf) r2 = r1
 174: (77) r2 &gt;&gt;= 16
 175: (73) *(u8 *)(r7 +18) = r2
 176: (73) *(u8 *)(r7 +16) = r1
 177: (77) r1 &gt;&gt;= 8
 178: (73) *(u8 *)(r7 +17) = r1
 179: (79) r5 = *(u64 *)(r10 -40)
; u32 out_len = (sizeof(struct FileEventData) + pathlen) & (MAX_PERCPU_BUFSIZE - 1);
 180: (07) r5 += 41
 181: (57) r5 &= 32767
; bpf_perf_event_output(ctx, &perf_event_array_map, BPF_F_CURRENT_CPU, map_value, out_len);
 182: (79) r1 = *(u64 *)(r10 -24)
 183: (18) r2 = map[id:2]
 185: (18) r3 = 0xffffffff
 187: (bf) r4 = r7
 188: (85) call bpf_perf_event_output#-50016
; return get_open_event(ctx, dfd, filename, flags);
 189: (b7) r0 = 0
 190: (95) exit
