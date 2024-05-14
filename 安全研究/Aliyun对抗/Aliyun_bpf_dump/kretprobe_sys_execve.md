```c
int kretprobe_sys_execve(struct pt_regs * ctx):
; int kretprobe_sys_execve(struct pt_regs *ctx)
   0: (bf) r7 = r1
; if(PT_REGS_RC(ctx) != 0)
   1: (79) r1 = *(u64 *)(r7 +80)
; if(PT_REGS_RC(ctx) != 0)
   2: (55) if r1 != 0x0 goto pc+6431
; u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
   3: (85) call bpf_get_current_pid_tgid#124560
   4: (bf) r6 = r0
; struct task_struct *task = bpf_get_current_task();
   5: (85) call bpf_get_current_task#-55200
   6: (bf) r8 = r0
   7: (b7) r1 = 0
; int map_id = 0;
   8: (63) *(u32 *)(r10 -68) = r1
   9: (bf) r2 = r10
; u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
  10: (07) r2 += -68
; map_value = bpf_map_lookup_elem(&data_tmp_store_map, &map_id);
  11: (18) r1 = map[id:1]
  13: (85) call percpu_array_map_lookup_elem#149152
  14: (bf) r9 = r0
; if (!map_value)
  15: (15) if r9 == 0x0 goto pc+6418
; pinfo->pid = curpid;                   //tgid
  16: (bf) r1 = r6
  17: (77) r1 >>= 24
  18: (73) *(u8 *)(r9 +35) = r1
  19: (bf) r1 = r6
  20: (77) r1 >>= 16
  21: (73) *(u8 *)(r9 +34) = r1
  22: (73) *(u8 *)(r9 +32) = r6
  23: (77) r6 >>= 8
  24: (73) *(u8 *)(r9 +33) = r6
; bpf_get_current_comm(pinfo->comm, sizeof(pinfo->comm)); //comm
  25: (bf) r1 = r9
  26: (07) r1 += 100
; bpf_get_current_comm(pinfo->comm, sizeof(pinfo->comm)); //comm
  27: (b7) r2 = 16
  28: (85) call bpf_get_current_comm#125056
; pinfo->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;       //uid
  29: (85) call bpf_get_current_uid_gid#124960
; pinfo->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;       //uid
  30: (bf) r1 = r0
  31: (77) r1 >>= 24
  32: (73) *(u8 *)(r9 +43) = r1
  33: (bf) r1 = r0
  34: (77) r1 >>= 16
  35: (73) *(u8 *)(r9 +42) = r1
  36: (73) *(u8 *)(r9 +40) = r0
  37: (77) r0 >>= 8
  38: (73) *(u8 *)(r9 +41) = r0
; pinfo->gid = bpf_get_current_uid_gid() >> 32;              //gid
  39: (85) call bpf_get_current_uid_gid#124960
; pinfo->gid = bpf_get_current_uid_gid() >> 32;              //gid
  40: (bf) r1 = r0
  41: (77) r1 >>= 56
  42: (73) *(u8 *)(r9 +47) = r1
  43: (bf) r1 = r0
  44: (77) r1 >>= 48
  45: (73) *(u8 *)(r9 +46) = r1
  46: (bf) r1 = r0
  47: (77) r1 >>= 40
  48: (73) *(u8 *)(r9 +45) = r1
; pinfo->gid = bpf_get_current_uid_gid() >> 32;              //gid
  49: (77) r0 >>= 32
; pinfo->gid = bpf_get_current_uid_gid() >> 32;              //gid
  50: (73) *(u8 *)(r9 +44) = r0
; pinfo->ktime_event = bpf_ktime_get_ns();                   //event_time
  51: (85) call bpf_ktime_get_ns#124928
; pinfo->ktime_event = bpf_ktime_get_ns();                   //event_time
  52: (bf) r1 = r0
  53: (77) r1 >>= 56
  54: (73) *(u8 *)(r9 +15) = r1
  55: (bf) r1 = r0
  56: (77) r1 >>= 48
  57: (73) *(u8 *)(r9 +14) = r1
  58: (bf) r1 = r0
  59: (77) r1 >>= 40
  60: (73) *(u8 *)(r9 +13) = r1
  61: (bf) r1 = r0
  62: (77) r1 >>= 32
  63: (73) *(u8 *)(r9 +12) = r1
  64: (bf) r1 = r0
  65: (77) r1 >>= 24
  66: (73) *(u8 *)(r9 +11) = r1
  67: (bf) r1 = r0
  68: (77) r1 >>= 16
  69: (73) *(u8 *)(r9 +10) = r1
  70: (73) *(u8 *)(r9 +8) = r0
  71: (77) r0 >>= 8
  72: (73) *(u8 *)(r9 +9) = r0
; if(task != NULL)
  73: (15) if r8 == 0x0 goto pc+6334
  74: (7b) *(u64 *)(r10 -112) = r7
  75: (b7) r7 = 0
; struct task_struct *parent = READ_KERN(task->real_parent);
  76: (7b) *(u64 *)(r10 -16) = r7
  77: (b7) r1 = 2320
  78: (bf) r3 = r8
  79: (0f) r3 += r1
  80: (bf) r1 = r10
; 
  81: (07) r1 += -16
; struct task_struct *parent = READ_KERN(task->real_parent);
  82: (b7) r2 = 8
  83: (85) call bpf_probe_read_kernel#-51920
  84: (b7) r1 = 2308
  85: (79) r3 = *(u64 *)(r10 -16)
  86: (0f) r3 += r1
; return READ_KERN(parent->tgid);
  87: (63) *(u32 *)(r10 -16) = r7
  88: (bf) r1 = r10
; 
  89: (07) r1 += -16
; return READ_KERN(parent->tgid);
  90: (b7) r2 = 4
  91: (85) call bpf_probe_read_kernel#-51920
  92: (61) r1 = *(u32 *)(r10 -16)
; pinfo->ppid = get_task_ppid(task); //ppid
  93: (bf) r2 = r1
  94: (77) r2 >>= 24
  95: (73) *(u8 *)(r9 +39) = r2
  96: (bf) r2 = r1
  97: (77) r2 >>= 16
  98: (73) *(u8 *)(r9 +38) = r2
  99: (bf) r2 = r1
 100: (77) r2 >>= 8
 101: (73) *(u8 *)(r9 +37) = r2
 102: (73) *(u8 *)(r9 +36) = r1
; return READ_KERN(task->real_cred);
 103: (7b) *(u64 *)(r10 -16) = r7
 104: (b7) r1 = 2768
 105: (bf) r6 = r8
 106: (0f) r6 += r1
 107: (bf) r1 = r10
; 
 108: (07) r1 += -16
; return READ_KERN(task->real_cred);
 109: (b7) r2 = 8
 110: (bf) r3 = r6
 111: (85) call bpf_probe_read_kernel#-51920
 112: (79) r1 = *(u64 *)(r10 -16)
; if(real_cred != NULL)
 113: (15) if r1 == 0x0 goto pc+22
; return READ_KERN(task->real_cred);
 114: (7b) *(u64 *)(r10 -16) = r7
 115: (bf) r1 = r10
; 
 116: (07) r1 += -16
; return READ_KERN(task->real_cred);
 117: (b7) r2 = 8
 118: (bf) r3 = r6
 119: (85) call bpf_probe_read_kernel#-51920
 120: (79) r6 = *(u64 *)(r10 -16)
; if(real_cred)
 121: (15) if r6 == 0x0 goto pc+14
 122: (b7) r1 = 20
 123: (bf) r3 = r6
 124: (0f) r3 += r1
; get_task_euid_egid(task, &(pinfo->euid), &(pinfo->egid));
 125: (bf) r1 = r9
 126: (07) r1 += 48
; bpf_core_read(euid, sizeof(u32), &real_cred->euid);
 127: (b7) r2 = 4
 128: (85) call bpf_probe_read_kernel#-51920
 129: (b7) r1 = 24
 130: (0f) r6 += r1
; get_task_euid_egid(task, &(pinfo->euid), &(pinfo->egid));
 131: (bf) r1 = r9
 132: (07) r1 += 52
; bpf_core_read(egid, sizeof(u32), &real_cred->egid);
 133: (b7) r2 = 4
 134: (bf) r3 = r6
 135: (85) call bpf_probe_read_kernel#-51920
; psignal = READ_KERN(task->signal);
 136: (7b) *(u64 *)(r10 -16) = r7
 137: (b7) r1 = 2864
 138: (bf) r3 = r8
 139: (0f) r3 += r1
 140: (bf) r1 = r10
; 
 141: (07) r1 += -16
; psignal = READ_KERN(task->signal);
 142: (b7) r2 = 8
 143: (85) call bpf_probe_read_kernel#-51920
 144: (79) r3 = *(u64 *)(r10 -16)
; if(psignal != NULL)
 145: (55) if r3 != 0x0 goto pc+3
 146: (b7) r1 = 0
; pinfo->ttyname[0] = '\0';
 147: (73) *(u8 *)(r9 +84) = r1
 148: (05) goto pc+17
 149: (b7) r1 = 392
 150: (0f) r3 += r1
 151: (b7) r6 = 0
; ptty = READ_KERN(psignal->tty);
 152: (7b) *(u64 *)(r10 -16) = r6
 153: (bf) r1 = r10
; 
 154: (07) r1 += -16
; ptty = READ_KERN(psignal->tty);
 155: (b7) r2 = 8
 156: (85) call bpf_probe_read_kernel#-51920
 157: (79) r3 = *(u64 *)(r10 -16)
; pinfo->ttyname[0] = '\0';
 158: (73) *(u8 *)(r9 +84) = r6
; if(ptty)
 159: (15) if r3 == 0x0 goto pc+6
 160: (bf) r1 = r9
 161: (07) r1 += 84
 162: (b7) r2 = 368
 163: (0f) r3 += r2
; bpf_core_read_str(pinfo->ttyname, sizeof(pinfo->ttyname), &ptty->name);
 164: (b7) r2 = 16
 165: (85) call bpf_probe_read_kernel_str#-51856
 166: (b7) r1 = 2864
 167: (bf) r3 = r8
 168: (0f) r3 += r1
 169: (b7) r6 = 0
; struct signal_struct *psignal = READ_KERN(task->signal);
 170: (7b) *(u64 *)(r10 -16) = r6
 171: (bf) r1 = r10
; 
 172: (07) r1 += -16
; struct signal_struct *psignal = READ_KERN(task->signal);
 173: (b7) r2 = 8
 174: (85) call bpf_probe_read_kernel#-51920
 175: (79) r3 = *(u64 *)(r10 -16)
; 
 176: (b7) r7 = 0
; if(psignal)
 177: (15) if r3 == 0x0 goto pc+25
 178: (18) r1 = 0x2
; 
 180: (67) r1 <<= 32
 181: (77) r1 >>= 32
 182: (b7) r2 = 1048
 183: (0f) r3 += r2
; struct pid* sid_pid = READ_KERN(psignal->pids[pid_type_sid]);
 184: (67) r1 <<= 3
 185: (0f) r3 += r1
 186: (b7) r7 = 0
 187: (7b) *(u64 *)(r10 -16) = r7
 188: (bf) r1 = r10
; 
 189: (07) r1 += -16
; struct pid* sid_pid = READ_KERN(psignal->pids[pid_type_sid]);
 190: (b7) r2 = 8
 191: (85) call bpf_probe_read_kernel#-51920
 192: (79) r3 = *(u64 *)(r10 -16)
; if(sid_pid)
 193: (15) if r3 == 0x0 goto pc+9
 194: (b7) r1 = 0
; sid = READ_KERN(sid_pid->numbers[0].nr);
 195: (63) *(u32 *)(r10 -16) = r1
 196: (b7) r1 = 56
 197: (0f) r3 += r1
 198: (bf) r1 = r10
; 
 199: (07) r1 += -16
; sid = READ_KERN(sid_pid->numbers[0].nr);
 200: (b7) r2 = 4
 201: (85) call bpf_probe_read_kernel#-51920
 202: (61) r7 = *(u32 *)(r10 -16)
; pinfo->sid = get_task_sid(task);
 203: (bf) r1 = r7
 204: (77) r1 >>= 24
 205: (73) *(u8 *)(r9 +59) = r1
 206: (bf) r1 = r7
 207: (77) r1 >>= 16
 208: (73) *(u8 *)(r9 +58) = r1
 209: (73) *(u8 *)(r9 +56) = r7
 210: (77) r7 >>= 8
 211: (73) *(u8 *)(r9 +57) = r7
; pinfo->buff_off = 0;
 212: (73) *(u8 *)(r9 +119) = r6
 213: (73) *(u8 *)(r9 +118) = r6
 214: (73) *(u8 *)(r9 +117) = r6
 215: (73) *(u8 *)(r9 +116) = r6
; css = READ_KERN(task->cgroups);
 216: (7b) *(u64 *)(r10 -16) = r6
 217: (b7) r1 = 3336
 218: (7b) *(u64 *)(r10 -104) = r8
 219: (0f) r8 += r1
 220: (bf) r1 = r10
; 
 221: (07) r1 += -16
; css = READ_KERN(task->cgroups);
 222: (b7) r2 = 8
 223: (bf) r3 = r8
 224: (85) call bpf_probe_read_kernel#-51920
 225: (79) r3 = *(u64 *)(r10 -16)
 226: (7b) *(u64 *)(r10 -96) = r9
; if(css == NULL)
 227: (15) if r3 == 0x0 goto pc+94
 228: (b7) r6 = 0
; sbs = READ_KERN(css->subsys[0]);
 229: (7b) *(u64 *)(r10 -16) = r6
 230: (b7) r1 = 0
 231: (0f) r3 += r1
 232: (bf) r1 = r10
; 
 233: (07) r1 += -16
; sbs = READ_KERN(css->subsys[0]);
 234: (b7) r2 = 8
 235: (85) call bpf_probe_read_kernel#-51920
 236: (79) r3 = *(u64 *)(r10 -16)
; if(sbs == NULL)
 237: (15) if r3 == 0x0 goto pc+84
; cgrp = READ_KERN(sbs->cgroup);
 238: (7b) *(u64 *)(r10 -16) = r6
 239: (b7) r1 = 0
 240: (0f) r3 += r1
 241: (bf) r1 = r10
; 
 242: (07) r1 += -16
; cgrp = READ_KERN(sbs->cgroup);
 243: (b7) r2 = 8
 244: (85) call bpf_probe_read_kernel#-51920
 245: (79) r3 = *(u64 *)(r10 -16)
; if(cgrp == NULL)
 246: (15) if r3 == 0x0 goto pc+75
 247: (b7) r6 = 0
; knode = READ_KERN(cgrp->kn);
 248: (7b) *(u64 *)(r10 -16) = r6
 249: (b7) r1 = 352
 250: (0f) r3 += r1
 251: (bf) r1 = r10
; 
 252: (07) r1 += -16
; knode = READ_KERN(cgrp->kn);
 253: (b7) r2 = 8
 254: (85) call bpf_probe_read_kernel#-51920
 255: (79) r3 = *(u64 *)(r10 -16)
; if(knode == NULL)
 256: (15) if r3 == 0x0 goto pc+65
; knode_name = READ_KERN(knode->name);
 257: (7b) *(u64 *)(r10 -16) = r6
 258: (b7) r1 = 16
 259: (0f) r3 += r1
 260: (bf) r1 = r10
; 
 261: (07) r1 += -16
; knode_name = READ_KERN(knode->name);
 262: (b7) r2 = 8
 263: (85) call bpf_probe_read_kernel#-51920
 264: (79) r6 = *(u64 *)(r10 -16)
; if(knode_name)
 265: (15) if r6 == 0x0 goto pc+56
; u32 ret = save_str_to_buf(pinfo->buff, pinfo->buff_off, knode_name, enProcInfoContainerId);
 266: (71) r1 = *(u8 *)(r9 +118)
 267: (71) r8 = *(u8 *)(r9 +119)
 268: (71) r2 = *(u8 *)(r9 +116)
 269: (71) r3 = *(u8 *)(r9 +117)
 270: (b7) r4 = 0
 271: (63) *(u32 *)(r10 -16) = r4
 272: (67) r3 <<= 8
 273: (4f) r3 |= r2
 274: (67) r8 <<= 8
 275: (4f) r8 |= r1
 276: (67) r8 <<= 16
 277: (4f) r8 |= r3
; if (buf_off > MAX_VALID_BUFSIZE - MAX_STRING_SIZE - sizeof(int) - sizeof(enType))
 278: (25) if r8 > 0x2ff8 goto pc+43
; 
 279: (07) r9 += 120
; bpf_probe_read(&buf[buf_off & (MAX_PERCPU_BUFSIZE - 1)], sizeof(enType), &enType);
 280: (bf) r7 = r9
 281: (0f) r7 += r8
 282: (bf) r3 = r10
; 
 283: (07) r3 += -16
; bpf_probe_read(&buf[buf_off & (MAX_PERCPU_BUFSIZE - 1)], sizeof(enType), &enType);
 284: (bf) r1 = r7
 285: (b7) r2 = 4
 286: (85) call bpf_probe_read_compat#-45600
; int sz = bpf_probe_read_str(&(buf[buf_off + sizeof(enType) + sizeof(int)]), MAX_STRING_SIZE, ptr);
 287: (07) r7 += 8
; int sz = bpf_probe_read_str(&(buf[buf_off + sizeof(enType) + sizeof(int)]), MAX_STRING_SIZE, ptr);
 288: (bf) r1 = r7
 289: (b7) r2 = 4096
 290: (bf) r3 = r6
 291: (85) call bpf_probe_read_compat_str#-46512
; int sz = bpf_probe_read_str(&(buf[buf_off + sizeof(enType) + sizeof(int)]), MAX_STRING_SIZE, ptr);
 292: (63) *(u32 *)(r10 -40) = r0
; int sz = bpf_probe_read_str(&(buf[buf_off + sizeof(enType) + sizeof(int)]), MAX_STRING_SIZE, ptr);
 293: (67) r0 <<= 32
 294: (c7) r0 s>>= 32
; if (sz > 0) {
 295: (65) if r0 s> 0x0 goto pc+2
 296: (79) r9 = *(u64 *)(r10 -96)
 297: (05) goto pc+24
; if ((buf_off + sizeof(enType)) <= MAX_VALID_BUFSIZE - MAX_STRING_SIZE - sizeof(int)) 
 298: (bf) r1 = r8
 299: (0f) r1 += r9
; bpf_probe_read(&(buf[buf_off + sizeof(enType)]), sizeof(int), &sz);		
 300: (07) r1 += 4
 301: (bf) r3 = r10
; if ((buf_off + sizeof(enType)) <= MAX_VALID_BUFSIZE - MAX_STRING_SIZE - sizeof(int)) 
 302: (07) r3 += -40
; bpf_probe_read(&(buf[buf_off + sizeof(enType)]), sizeof(int), &sz);		
 303: (b7) r2 = 4
 304: (85) call bpf_probe_read_compat#-45600
; buf_off += sz + sizeof(enType) + sizeof(int);
 305: (61) r1 = *(u32 *)(r10 -40)
; buf_off += sz + sizeof(enType) + sizeof(int);
 306: (0f) r8 += r1
; buf_off += sz + sizeof(enType) + sizeof(int);
 307: (07) r8 += 8
 308: (bf) r1 = r8
 309: (67) r1 <<= 32
 310: (77) r1 >>= 32
 311: (79) r9 = *(u64 *)(r10 -96)
; if(ret != 0)
 312: (15) if r1 == 0x0 goto pc+9
; pinfo->buff_off = ret;
 313: (bf) r1 = r8
 314: (77) r1 >>= 24
 315: (73) *(u8 *)(r9 +119) = r1
 316: (bf) r1 = r8
 317: (77) r1 >>= 16
 318: (73) *(u8 *)(r9 +118) = r1
 319: (73) *(u8 *)(r9 +116) = r8
 320: (77) r8 >>= 8
 321: (73) *(u8 *)(r9 +117) = r8
 322: (b7) r1 = 1
; pinfo->core_enable = 1;
 323: (73) *(u8 *)(r9 +80) = r1
 324: (b7) r1 = 0
 325: (73) *(u8 *)(r9 +83) = r1
 326: (73) *(u8 *)(r9 +82) = r1
 327: (73) *(u8 *)(r9 +81) = r1
; pinfo->initpid = 0;
 328: (73) *(u8 *)(r9 +63) = r1
 329: (73) *(u8 *)(r9 +62) = r1
 330: (73) *(u8 *)(r9 +61) = r1
 331: (73) *(u8 *)(r9 +60) = r1
 332: (b7) r2 = 0
; stime = READ_KERN(task->real_start_time);
 333: (7b) *(u64 *)(r10 -16) = r1
 334: (b7) r1 = 2664
 335: (79) r8 = *(u64 *)(r10 -104)
 336: (bf) r3 = r8
 337: (0f) r3 += r1
 338: (bf) r1 = r10
; 
 339: (07) r1 += -16
 340: (b7) r2 = 8
 341: (85) call bpf_probe_read_kernel#-51920
 342: (79) r1 = *(u64 *)(r10 -16)
; pinfo->ktime_proc = get_task_start_time(task);
 343: (bf) r2 = r1
 344: (77) r2 >>= 56
 345: (73) *(u8 *)(r9 +23) = r2
 346: (bf) r2 = r1
 347: (77) r2 >>= 48
 348: (73) *(u8 *)(r9 +22) = r2
 349: (bf) r2 = r1
 350: (77) r2 >>= 40
 351: (73) *(u8 *)(r9 +21) = r2
 352: (bf) r2 = r1
 353: (77) r2 >>= 32
 354: (73) *(u8 *)(r9 +20) = r2
 355: (bf) r2 = r1
 356: (77) r2 >>= 24
 357: (73) *(u8 *)(r9 +19) = r2
 358: (bf) r2 = r1
 359: (77) r2 >>= 16
 360: (73) *(u8 *)(r9 +18) = r2
 361: (73) *(u8 *)(r9 +16) = r1
 362: (77) r1 >>= 8
 363: (73) *(u8 *)(r9 +17) = r1
 364: (b7) r7 = 0
; struct task_struct *parent = READ_KERN(task->real_parent);
 365: (7b) *(u64 *)(r10 -16) = r7
 366: (b7) r1 = 2320
 367: (bf) r3 = r8
 368: (0f) r3 += r1
 369: (bf) r1 = r10
; pinfo->ktime_proc = get_task_start_time(task);
 370: (07) r1 += -16
; struct task_struct *parent = READ_KERN(task->real_parent);
 371: (b7) r2 = 8
 372: (85) call bpf_probe_read_kernel#-51920
 373: (79) r6 = *(u64 *)(r10 -16)
; if(parent)
 374: (15) if r6 == 0x0 goto pc+64
; u32 parent_pid = READ_KERN(parent->pid);
 375: (63) *(u32 *)(r10 -16) = r7
 376: (b7) r1 = 2304
 377: (bf) r3 = r6
 378: (0f) r3 += r1
 379: (bf) r1 = r10
; 
 380: (07) r1 += -16
; u32 parent_pid = READ_KERN(parent->pid);
 381: (b7) r2 = 4
 382: (85) call bpf_probe_read_kernel#-51920
 383: (61) r1 = *(u32 *)(r10 -16)
; if(parent_pid != pinfo->ppid)
 384: (71) r2 = *(u8 *)(r9 +37)
 385: (67) r2 <<= 8
 386: (71) r3 = *(u8 *)(r9 +36)
 387: (4f) r2 |= r3
 388: (71) r3 = *(u8 *)(r9 +38)
 389: (71) r4 = *(u8 *)(r9 +39)
 390: (67) r4 <<= 8
 391: (4f) r4 |= r3
 392: (67) r4 <<= 16
 393: (4f) r4 |= r2
; if(parent_pid != pinfo->ppid)
 394: (1d) if r1 == r4 goto pc+11
 395: (b7) r1 = 2368
 396: (0f) r6 += r1
 397: (b7) r8 = 0
; struct task_struct *group_leader = READ_KERN(task->group_leader);
 398: (7b) *(u64 *)(r10 -16) = r8
 399: (bf) r1 = r10
; 
 400: (07) r1 += -16
; struct task_struct *group_leader = READ_KERN(task->group_leader);
 401: (b7) r2 = 8
 402: (bf) r3 = r6
 403: (85) call bpf_probe_read_kernel#-51920
 404: (79) r6 = *(u64 *)(r10 -16)
; if(task == NULL)
 405: (15) if r6 == 0x0 goto pc+11
 406: (b7) r1 = 0
; stime = READ_KERN(new_task->start_boottime);
 407: (b7) r1 = 0
; stime = READ_KERN(task->real_start_time);
 408: (7b) *(u64 *)(r10 -16) = r1
 409: (b7) r1 = 2664
 410: (0f) r6 += r1
 411: (bf) r1 = r10
; 
 412: (07) r1 += -16
 413: (b7) r2 = 8
 414: (bf) r3 = r6
 415: (85) call bpf_probe_read_kernel#-51920
 416: (79) r8 = *(u64 *)(r10 -16)
; pinfo->ktime_parent = get_task_start_time(parent);
 417: (bf) r1 = r8
 418: (77) r1 >>= 56
 419: (73) *(u8 *)(r9 +31) = r1
 420: (bf) r1 = r8
 421: (77) r1 >>= 48
 422: (73) *(u8 *)(r9 +30) = r1
 423: (bf) r1 = r8
 424: (77) r1 >>= 40
 425: (73) *(u8 *)(r9 +29) = r1
 426: (bf) r1 = r8
 427: (77) r1 >>= 32
 428: (73) *(u8 *)(r9 +28) = r1
 429: (bf) r1 = r8
 430: (77) r1 >>= 24
 431: (73) *(u8 *)(r9 +27) = r1
 432: (bf) r1 = r8
 433: (77) r1 >>= 16
 434: (73) *(u8 *)(r9 +26) = r1
 435: (73) *(u8 *)(r9 +24) = r8
 436: (77) r8 >>= 8
 437: (73) *(u8 *)(r9 +25) = r8
 438: (79) r8 = *(u64 *)(r10 -104)
; struct mm_struct * pmm = READ_KERN(task->mm);
 439: (7b) *(u64 *)(r10 -16) = r7
 440: (b7) r1 = 2128
 441: (bf) r9 = r8
 442: (0f) r9 += r1
 443: (bf) r1 = r10
; 
 444: (07) r1 += -16
; struct mm_struct * pmm = READ_KERN(task->mm);
 445: (b7) r2 = 8
 446: (bf) r3 = r9
 447: (85) call bpf_probe_read_kernel#-51920
 448: (79) r7 = *(u64 *)(r10 -16)
; if(pmm != NULL)
 449: (15) if r7 == 0x0 goto pc+75
 450: (b7) r1 = 0
; arg_start = READ_KERN(pmm->arg_start);
 451: (7b) *(u64 *)(r10 -16) = r1
 452: (b7) r1 = 304
 453: (bf) r3 = r7
 454: (0f) r3 += r1
 455: (bf) r1 = r10
; 
 456: (07) r1 += -16
; arg_start = READ_KERN(pmm->arg_start);
 457: (b7) r2 = 8
 458: (85) call bpf_probe_read_kernel#-51920
 459: (bf) r6 = r8
 460: (79) r8 = *(u64 *)(r10 -16)
; arg_end = READ_KERN(pmm->arg_end);
 461: (b7) r1 = 0
 462: (7b) *(u64 *)(r10 -16) = r1
 463: (b7) r1 = 312
 464: (0f) r7 += r1
 465: (bf) r1 = r10
; 
 466: (07) r1 += -16
; arg_end = READ_KERN(pmm->arg_end);
 467: (b7) r2 = 8
 468: (bf) r3 = r7
 469: (85) call bpf_probe_read_kernel#-51920
 470: (bf) r0 = r8
 471: (bf) r8 = r6
; if(arg_start != 0 && arg_end != 0 && arg_end > arg_start)
 472: (15) if r0 == 0x0 goto pc+52
; 
 473: (79) r1 = *(u64 *)(r10 -16)
; if(arg_start != 0 && arg_end != 0 && arg_end > arg_start)
 474: (3d) if r0 >= r1 goto pc+50
; ncmdlen = arg_end - arg_start > CMDLINE_MAX ? CMDLINE_MAX : arg_end - arg_start;
 475: (1f) r1 -= r0
 476: (b7) r2 = 8192
; ncmdlen = arg_end - arg_start > CMDLINE_MAX ? CMDLINE_MAX : arg_end - arg_start;
 477: (2d) if r2 > r1 goto pc+1
 478: (b7) r1 = 8192
 479: (bf) r2 = r1
 480: (67) r2 <<= 32
 481: (77) r2 >>= 32
 482: (b7) r3 = 8191
; if(real_len  >  (MAX_CMDLINE_SIZE - 1))
 483: (2d) if r3 > r2 goto pc+1
 484: (b7) r1 = 8191
 485: (79) r4 = *(u64 *)(r10 -96)
; u32 ret = save_data_to_buf(pinfo->buff, pinfo->buff_off, enProcInfoCmdline, arg_start, ncmdlen);
 486: (71) r2 = *(u8 *)(r4 +118)
 487: (71) r6 = *(u8 *)(r4 +119)
 488: (71) r3 = *(u8 *)(r4 +116)
 489: (71) r4 = *(u8 *)(r4 +117)
 490: (b7) r5 = 1
 491: (63) *(u32 *)(r10 -16) = r5
; 
 492: (63) *(u32 *)(r10 -40) = r1
; u32 ret = save_data_to_buf(pinfo->buff, pinfo->buff_off, enProcInfoCmdline, arg_start, ncmdlen);
 493: (67) r4 <<= 8
 494: (4f) r4 |= r3
 495: (67) r6 <<= 8
 496: (4f) r6 |= r2
 497: (67) r6 <<= 16
 498: (4f) r6 |= r4
; if (buf_off > MAX_VALID_BUFSIZE - MAX_CMDLINE_SIZE - sizeof(int) - sizeof(enType))
 499: (25) if r6 > 0x1ff8 goto pc+25
; 
 500: (79) r8 = *(u64 *)(r10 -96)
 501: (07) r8 += 120
; bpf_probe_read(&buf[buf_off & (MAX_PERCPU_BUFSIZE - 1)], sizeof(enType), &enType);
 502: (bf) r7 = r8
 503: (0f) r7 += r6
 504: (bf) r3 = r10
; 
 505: (07) r3 += -16
; bpf_probe_read(&buf[buf_off & (MAX_PERCPU_BUFSIZE - 1)], sizeof(enType), &enType);
 506: (bf) r1 = r7
 507: (b7) r2 = 4
 508: (7b) *(u64 *)(r10 -120) = r0
 509: (85) call bpf_probe_read_compat#-45600
; bpf_probe_read(&buf[buf_off + sizeof(enType)], sizeof(int), &real_len);
 510: (07) r7 += 4
 511: (bf) r3 = r10
; 
 512: (07) r3 += -40
; bpf_probe_read(&buf[buf_off + sizeof(enType)], sizeof(int), &real_len);
 513: (bf) r1 = r7
 514: (b7) r2 = 4
 515: (85) call bpf_probe_read_compat#-45600
; if((buf_off + sizeof(enType) + sizeof(int)) > (MAX_VALID_BUFSIZE - MAX_CMDLINE_SIZE))
 516: (07) r6 += 8
; if(bpf_probe_read(&buf[buf_off + sizeof(enType) + sizeof(int)], real_len & (MAX_CMDLINE_SIZE - 1), ptr) == 0)
 517: (0f) r8 += r6
; if(bpf_probe_read(&buf[buf_off + sizeof(enType) + sizeof(int)], real_len & (MAX_CMDLINE_SIZE - 1), ptr) == 0)
 518: (61) r2 = *(u32 *)(r10 -40)
; if(bpf_probe_read(&buf[buf_off + sizeof(enType) + sizeof(int)], real_len & (MAX_CMDLINE_SIZE - 1), ptr) == 0)
 519: (57) r2 &= 8191
; if(bpf_probe_read(&buf[buf_off + sizeof(enType) + sizeof(int)], real_len & (MAX_CMDLINE_SIZE - 1), ptr) == 0)
 520: (bf) r1 = r8
 521: (79) r8 = *(u64 *)(r10 -104)
 522: (79) r3 = *(u64 *)(r10 -120)
 523: (85) call bpf_probe_read_compat#-45600
; if(bpf_probe_read(&buf[buf_off + sizeof(enType) + sizeof(int)], real_len & (MAX_CMDLINE_SIZE - 1), ptr) == 0)
 524: (15) if r0 == 0x0 goto pc+140
 525: (b7) r7 = 0
; pmm = READ_KERN(task->mm);
 526: (7b) *(u64 *)(r10 -16) = r7
 527: (bf) r1 = r10
; 
 528: (07) r1 += -16
; pmm = READ_KERN(task->mm);
 529: (b7) r2 = 8
 530: (bf) r3 = r9
 531: (85) call bpf_probe_read_kernel#-51920
 532: (79) r3 = *(u64 *)(r10 -16)
; if(pmm != NULL)
 533: (15) if r3 == 0x0 goto pc+2941
; pexe_file = READ_KERN(pmm->exe_file);
 534: (7b) *(u64 *)(r10 -16) = r7
 535: (b7) r1 = 920
 536: (0f) r3 += r1
 537: (bf) r1 = r10
; 
 538: (07) r1 += -16
; pexe_file = READ_KERN(pmm->exe_file);
 539: (b7) r2 = 8
 540: (85) call bpf_probe_read_kernel#-51920
 541: (79) r3 = *(u64 *)(r10 -16)
; if(pexe_file != NULL)
 542: (15) if r3 == 0x0 goto pc+2932
 543: (b7) r1 = 0
; struct path exe_path = READ_KERN(pexe_file->f_path);
 544: (7b) *(u64 *)(r10 -8) = r1
 545: (7b) *(u64 *)(r10 -16) = r1
 546: (b7) r1 = 16
 547: (0f) r3 += r1
 548: (bf) r1 = r10
 549: (07) r1 += -16
 550: (b7) r2 = 16
 551: (85) call bpf_probe_read_kernel#-51920
 552: (79) r1 = *(u64 *)(r10 -8)
 553: (7b) *(u64 *)(r10 -80) = r1
 554: (79) r1 = *(u64 *)(r10 -16)
 555: (7b) *(u64 *)(r10 -88) = r1
 556: (bf) r1 = r10
 557: (07) r1 += -88
; if (exe_path.dentry != NULL && exe_path.mnt != NULL)
 558: (79) r1 = *(u64 *)(r1 +8)
; if (exe_path.dentry != NULL && exe_path.mnt != NULL)
 559: (15) if r1 == 0x0 goto pc+2915
 560: (bf) r1 = r10
; if (exe_path.dentry != NULL && exe_path.mnt != NULL)
 561: (07) r1 += -88
 562: (79) r1 = *(u64 *)(r1 +0)
; if (exe_path.dentry != NULL && exe_path.mnt != NULL)
 563: (15) if r1 == 0x0 goto pc+2911
 564: (bf) r7 = r10
; 
 565: (07) r7 += -16
 566: (bf) r3 = r10
 567: (07) r3 += -88
; bpf_probe_read(&f_path, sizeof(struct path), ppath);
 568: (bf) r1 = r7
 569: (b7) r2 = 16
 570: (85) call bpf_probe_read_compat#-45600
 571: (b7) r1 = 47
; char slash = '/';
 572: (73) *(u8 *)(r10 -17) = r1
 573: (b7) r6 = 0
; int zero = 0;
 574: (63) *(u32 *)(r10 -24) = r6
; struct dentry *dentry = f_path.dentry;
 575: (79) r1 = *(u64 *)(r7 +8)
; struct vfsmount *vfsmnt = f_path.mnt;
 576: (7b) *(u64 *)(r10 -136) = r1
 577: (79) r9 = *(u64 *)(r7 +0)
 578: (b7) r1 = 32
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 579: (7b) *(u64 *)(r10 -40) = r6
; struct mount *mnt_p = container_of(vfsmnt, struct mount, mnt);
 580: (bf) r3 = r9
 581: (1f) r3 -= r1
 582: (b7) r1 = 16
 583: (7b) *(u64 *)(r10 -120) = r3
 584: (0f) r3 += r1
 585: (bf) r1 = r10
; 
 586: (07) r1 += -40
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 587: (b7) r2 = 8
 588: (85) call bpf_probe_read_kernel#-51920
 589: (79) r7 = *(u64 *)(r10 -40)
 590: (b7) r1 = 1
; int map_id = 1;
 591: (63) *(u32 *)(r10 -44) = r1
 592: (bf) r2 = r10
; 
 593: (07) r2 += -44
; char *map_value = bpf_map_lookup_elem(&data_tmp_store_map, &map_id);
 594: (18) r1 = map[id:1]
 596: (85) call percpu_array_map_lookup_elem#149152
; if (!map_value)
 597: (15) if r0 == 0x0 goto pc+2814
 598: (7b) *(u64 *)(r10 -152) = r7
 599: (7b) *(u64 *)(r10 -128) = r0
 600: (b7) r1 = 0
 601: (7b) *(u64 *)(r10 -160) = r9
 602: (0f) r9 += r1
 603: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 604: (7b) *(u64 *)(r10 -64) = r7
 605: (bf) r1 = r10
; 
 606: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 607: (b7) r2 = 8
 608: (bf) r3 = r9
 609: (85) call bpf_probe_read_kernel#-51920
 610: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 611: (7b) *(u64 *)(r10 -64) = r7
 612: (b7) r1 = 24
 613: (79) r9 = *(u64 *)(r10 -136)
 614: (bf) r3 = r9
 615: (0f) r3 += r1
 616: (bf) r1 = r10
; 
 617: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 618: (b7) r2 = 8
 619: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 620: (1d) if r9 == r6 goto pc+3
; 
 621: (79) r1 = *(u64 *)(r10 -64)
 622: (7b) *(u64 *)(r10 -144) = r1
; if (dentry == mnt_root || dentry == d_parent) {
 623: (5d) if r9 != r1 goto pc+58
 624: (79) r7 = *(u64 *)(r10 -128)
; if (dentry != mnt_root) {
 625: (79) r1 = *(u64 *)(r10 -120)
 626: (79) r2 = *(u64 *)(r10 -152)
 627: (1d) if r2 == r1 goto pc+2741
 628: (5d) if r9 != r6 goto pc+2740
 629: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 630: (7b) *(u64 *)(r10 -64) = r6
 631: (b7) r1 = 24
 632: (79) r8 = *(u64 *)(r10 -120)
 633: (bf) r3 = r8
 634: (0f) r3 += r1
 635: (bf) r1 = r10
; 
 636: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 637: (b7) r2 = 8
 638: (85) call bpf_probe_read_kernel#-51920
 639: (b7) r7 = 16
 640: (0f) r8 += r7
 641: (79) r9 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 642: (7b) *(u64 *)(r10 -64) = r6
 643: (bf) r1 = r10
; 
 644: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 645: (b7) r2 = 8
 646: (bf) r3 = r8
 647: (85) call bpf_probe_read_kernel#-51920
 648: (79) r8 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 649: (7b) *(u64 *)(r10 -64) = r6
 650: (bf) r3 = r8
 651: (0f) r3 += r7
 652: (bf) r1 = r10
; 
 653: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 654: (b7) r2 = 8
 655: (85) call bpf_probe_read_kernel#-51920
 656: (b7) r1 = 4096
 657: (7b) *(u64 *)(r10 -136) = r1
 658: (b7) r1 = 32
 659: (7b) *(u64 *)(r10 -120) = r8
 660: (bf) r3 = r8
 661: (0f) r3 += r1
 662: (79) r1 = *(u64 *)(r10 -64)
; continue;
 663: (7b) *(u64 *)(r10 -152) = r1
 664: (05) goto pc+61
; return buf_off + sizeof(enType) + sizeof(int) + real_len;		
 665: (61) r1 = *(u32 *)(r10 -40)
; return buf_off + sizeof(enType) + sizeof(int) + real_len;		
 666: (0f) r1 += r6
 667: (bf) r2 = r1
 668: (67) r2 <<= 32
 669: (77) r2 >>= 32
; if(ret != 0)
 670: (15) if r2 == 0x0 goto pc-146
; pinfo->buff_off = ret;
 671: (bf) r2 = r1
 672: (77) r2 >>= 24
 673: (79) r3 = *(u64 *)(r10 -96)
 674: (73) *(u8 *)(r3 +119) = r2
 675: (bf) r2 = r1
 676: (77) r2 >>= 16
 677: (73) *(u8 *)(r3 +118) = r2
 678: (73) *(u8 *)(r3 +116) = r1
 679: (77) r1 >>= 8
 680: (73) *(u8 *)(r3 +117) = r1
 681: (05) goto pc-157
 682: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 683: (7b) *(u64 *)(r10 -56) = r1
 684: (7b) *(u64 *)(r10 -64) = r1
 685: (b7) r1 = 32
 686: (bf) r3 = r9
 687: (0f) r3 += r1
 688: (bf) r1 = r10
 689: (07) r1 += -64
 690: (b7) r2 = 16
 691: (85) call bpf_probe_read_kernel#-51920
 692: (79) r1 = *(u64 *)(r10 -56)
 693: (7b) *(u64 *)(r10 -32) = r1
 694: (79) r1 = *(u64 *)(r10 -64)
 695: (7b) *(u64 *)(r10 -40) = r1
 696: (bf) r3 = r10
 697: (07) r3 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 698: (61) r2 = *(u32 *)(r3 +4)
 699: (b7) r4 = 4095
; off = buf_off - len;
 700: (1f) r4 -= r2
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 701: (57) r4 &= 4095
 702: (79) r7 = *(u64 *)(r10 -128)
 703: (bf) r1 = r7
 704: (0f) r1 += r4
 705: (79) r3 = *(u64 *)(r3 +8)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 706: (07) r2 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 707: (57) r2 &= 4095
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 708: (85) call bpf_probe_read_kernel_str#-51856
 709: (bf) r6 = r0
 710: (bf) r1 = r6
 711: (67) r1 <<= 32
 712: (c7) r1 s>>= 32
 713: (b7) r2 = 2
; if (sz > 1) {
 714: (6d) if r2 s> r1 goto pc+2654
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 715: (07) r7 += 4095
 716: (bf) r3 = r10
; 
 717: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 718: (bf) r1 = r7
 719: (b7) r2 = 1
 720: (85) call bpf_probe_read_compat#-45600
 721: (b7) r1 = 4096
; buf_off -= sz - 1;
 722: (1f) r1 -= r6
 723: (7b) *(u64 *)(r10 -136) = r1
 724: (79) r9 = *(u64 *)(r10 -144)
 725: (79) r3 = *(u64 *)(r10 -160)
 726: (b7) r1 = 0
 727: (7b) *(u64 *)(r10 -160) = r3
 728: (0f) r3 += r1
 729: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 730: (7b) *(u64 *)(r10 -64) = r7
 731: (bf) r1 = r10
; 
 732: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 733: (b7) r2 = 8
 734: (85) call bpf_probe_read_kernel#-51920
 735: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 736: (7b) *(u64 *)(r10 -64) = r7
 737: (b7) r1 = 24
 738: (bf) r3 = r9
 739: (0f) r3 += r1
 740: (bf) r1 = r10
; 
 741: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 742: (b7) r2 = 8
 743: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 744: (7b) *(u64 *)(r10 -144) = r9
 745: (1d) if r9 == r6 goto pc+56
; 
 746: (79) r7 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 747: (1d) if r9 == r7 goto pc+54
 748: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 749: (7b) *(u64 *)(r10 -56) = r1
 750: (7b) *(u64 *)(r10 -64) = r1
 751: (b7) r1 = 32
 752: (0f) r9 += r1
 753: (bf) r1 = r10
 754: (07) r1 += -64
 755: (b7) r2 = 16
 756: (bf) r3 = r9
 757: (85) call bpf_probe_read_kernel#-51920
 758: (79) r1 = *(u64 *)(r10 -56)
 759: (7b) *(u64 *)(r10 -32) = r1
 760: (79) r1 = *(u64 *)(r10 -64)
 761: (7b) *(u64 *)(r10 -40) = r1
 762: (bf) r1 = r10
 763: (07) r1 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 764: (61) r1 = *(u32 *)(r1 +4)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 765: (07) r1 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 766: (bf) r2 = r1
 767: (57) r2 &= 4095
; if (off <= buf_off) { // verify no wrap occurred
 768: (79) r3 = *(u64 *)(r10 -136)
 769: (67) r3 <<= 32
 770: (77) r3 >>= 32
; if (off <= buf_off) { // verify no wrap occurred
 771: (2d) if r2 > r3 goto pc+2589
; off = buf_off - len;
 772: (79) r3 = *(u64 *)(r10 -136)
 773: (1f) r3 -= r1
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 774: (57) r3 &= 4095
 775: (79) r1 = *(u64 *)(r10 -128)
 776: (0f) r1 += r3
 777: (bf) r3 = r10
; off = buf_off - len;
 778: (07) r3 += -40
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 779: (79) r3 = *(u64 *)(r3 +8)
 780: (85) call bpf_probe_read_kernel_str#-51856
 781: (bf) r6 = r0
 782: (bf) r1 = r6
 783: (67) r1 <<= 32
 784: (c7) r1 s>>= 32
 785: (b7) r2 = 2
; if (sz > 1) {
 786: (6d) if r2 s> r1 goto pc+2574
 787: (79) r8 = *(u64 *)(r10 -136)
; buf_off -= 1; // remove null byte termination with slash sign
 788: (bf) r2 = r8
 789: (07) r2 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 790: (57) r2 &= 4095
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 791: (79) r1 = *(u64 *)(r10 -128)
 792: (0f) r1 += r2
 793: (bf) r3 = r10
; buf_off -= 1; // remove null byte termination with slash sign
 794: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 795: (b7) r2 = 1
 796: (85) call bpf_probe_read_compat#-45600
; buf_off -= sz - 1;
 797: (1f) r8 -= r6
 798: (7b) *(u64 *)(r10 -136) = r8
; 
 799: (bf) r8 = r7
 800: (79) r3 = *(u64 *)(r10 -160)
 801: (05) goto pc+39
; if (dentry != mnt_root) {
 802: (79) r1 = *(u64 *)(r10 -120)
 803: (79) r2 = *(u64 *)(r10 -152)
 804: (1d) if r1 == r2 goto pc+2556
 805: (79) r1 = *(u64 *)(r10 -144)
 806: (5d) if r1 != r6 goto pc+2554
 807: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 808: (7b) *(u64 *)(r10 -64) = r6
 809: (b7) r1 = 24
 810: (79) r8 = *(u64 *)(r10 -120)
 811: (bf) r3 = r8
 812: (0f) r3 += r1
 813: (bf) r1 = r10
; 
 814: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 815: (b7) r2 = 8
 816: (85) call bpf_probe_read_kernel#-51920
 817: (b7) r7 = 16
 818: (0f) r8 += r7
 819: (79) r9 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 820: (7b) *(u64 *)(r10 -64) = r6
 821: (bf) r1 = r10
; 
 822: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 823: (b7) r2 = 8
 824: (bf) r3 = r8
 825: (85) call bpf_probe_read_kernel#-51920
 826: (79) r8 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 827: (7b) *(u64 *)(r10 -64) = r6
 828: (bf) r3 = r8
 829: (0f) r3 += r7
 830: (bf) r1 = r10
; 
 831: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 832: (b7) r2 = 8
 833: (85) call bpf_probe_read_kernel#-51920
 834: (b7) r1 = 32
 835: (7b) *(u64 *)(r10 -120) = r8
 836: (bf) r3 = r8
 837: (bf) r8 = r9
 838: (0f) r3 += r1
 839: (79) r1 = *(u64 *)(r10 -64)
 840: (7b) *(u64 *)(r10 -152) = r1
 841: (b7) r1 = 0
 842: (bf) r9 = r3
 843: (0f) r3 += r1
 844: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 845: (7b) *(u64 *)(r10 -64) = r7
 846: (bf) r1 = r10
; 
 847: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 848: (b7) r2 = 8
 849: (85) call bpf_probe_read_kernel#-51920
 850: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 851: (7b) *(u64 *)(r10 -64) = r7
 852: (b7) r1 = 24
 853: (bf) r3 = r8
 854: (0f) r3 += r1
 855: (bf) r1 = r10
; 
 856: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 857: (b7) r2 = 8
 858: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 859: (7b) *(u64 *)(r10 -144) = r8
 860: (1d) if r8 == r6 goto pc+56
; 
 861: (79) r7 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 862: (1d) if r8 == r7 goto pc+54
 863: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 864: (7b) *(u64 *)(r10 -56) = r1
 865: (7b) *(u64 *)(r10 -64) = r1
 866: (b7) r1 = 32
 867: (bf) r3 = r8
 868: (0f) r3 += r1
 869: (bf) r1 = r10
 870: (07) r1 += -64
 871: (b7) r2 = 16
 872: (85) call bpf_probe_read_kernel#-51920
 873: (79) r1 = *(u64 *)(r10 -56)
 874: (7b) *(u64 *)(r10 -32) = r1
 875: (79) r1 = *(u64 *)(r10 -64)
 876: (7b) *(u64 *)(r10 -40) = r1
 877: (bf) r1 = r10
 878: (07) r1 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 879: (61) r1 = *(u32 *)(r1 +4)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 880: (07) r1 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 881: (bf) r2 = r1
 882: (57) r2 &= 4095
; if (off <= buf_off) { // verify no wrap occurred
 883: (79) r3 = *(u64 *)(r10 -136)
 884: (67) r3 <<= 32
 885: (77) r3 >>= 32
; if (off <= buf_off) { // verify no wrap occurred
 886: (2d) if r2 > r3 goto pc+2474
; off = buf_off - len;
 887: (79) r3 = *(u64 *)(r10 -136)
 888: (1f) r3 -= r1
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 889: (57) r3 &= 4095
 890: (79) r1 = *(u64 *)(r10 -128)
 891: (0f) r1 += r3
 892: (bf) r3 = r10
; off = buf_off - len;
 893: (07) r3 += -40
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 894: (79) r3 = *(u64 *)(r3 +8)
 895: (85) call bpf_probe_read_kernel_str#-51856
 896: (bf) r6 = r0
 897: (bf) r1 = r6
 898: (67) r1 <<= 32
 899: (c7) r1 s>>= 32
 900: (b7) r2 = 2
; if (sz > 1) {
 901: (6d) if r2 s> r1 goto pc+2459
 902: (79) r8 = *(u64 *)(r10 -136)
; buf_off -= 1; // remove null byte termination with slash sign
 903: (bf) r2 = r8
 904: (07) r2 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 905: (57) r2 &= 4095
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 906: (79) r1 = *(u64 *)(r10 -128)
 907: (0f) r1 += r2
 908: (bf) r3 = r10
; buf_off -= 1; // remove null byte termination with slash sign
 909: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 910: (b7) r2 = 1
 911: (85) call bpf_probe_read_compat#-45600
; buf_off -= sz - 1;
 912: (1f) r8 -= r6
 913: (7b) *(u64 *)(r10 -136) = r8
; 
 914: (bf) r8 = r7
 915: (bf) r3 = r9
 916: (05) goto pc+39
; if (dentry != mnt_root) {
 917: (79) r1 = *(u64 *)(r10 -120)
 918: (79) r2 = *(u64 *)(r10 -152)
 919: (1d) if r1 == r2 goto pc+2441
 920: (79) r1 = *(u64 *)(r10 -144)
 921: (5d) if r1 != r6 goto pc+2439
 922: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 923: (7b) *(u64 *)(r10 -64) = r6
 924: (b7) r1 = 24
 925: (79) r8 = *(u64 *)(r10 -120)
 926: (bf) r3 = r8
 927: (0f) r3 += r1
 928: (bf) r1 = r10
; 
 929: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 930: (b7) r2 = 8
 931: (85) call bpf_probe_read_kernel#-51920
 932: (b7) r7 = 16
 933: (0f) r8 += r7
 934: (79) r9 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 935: (7b) *(u64 *)(r10 -64) = r6
 936: (bf) r1 = r10
; 
 937: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 938: (b7) r2 = 8
 939: (bf) r3 = r8
 940: (85) call bpf_probe_read_kernel#-51920
 941: (79) r8 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 942: (7b) *(u64 *)(r10 -64) = r6
 943: (bf) r3 = r8
 944: (0f) r3 += r7
 945: (bf) r1 = r10
; 
 946: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 947: (b7) r2 = 8
 948: (85) call bpf_probe_read_kernel#-51920
 949: (b7) r1 = 32
 950: (7b) *(u64 *)(r10 -120) = r8
 951: (bf) r3 = r8
 952: (bf) r8 = r9
 953: (0f) r3 += r1
 954: (79) r1 = *(u64 *)(r10 -64)
 955: (7b) *(u64 *)(r10 -152) = r1
 956: (b7) r1 = 0
 957: (bf) r9 = r3
 958: (0f) r3 += r1
 959: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 960: (7b) *(u64 *)(r10 -64) = r7
 961: (bf) r1 = r10
; 
 962: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 963: (b7) r2 = 8
 964: (85) call bpf_probe_read_kernel#-51920
 965: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 966: (7b) *(u64 *)(r10 -64) = r7
 967: (b7) r1 = 24
 968: (bf) r3 = r8
 969: (0f) r3 += r1
 970: (bf) r1 = r10
; 
 971: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 972: (b7) r2 = 8
 973: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 974: (7b) *(u64 *)(r10 -144) = r8
 975: (1d) if r8 == r6 goto pc+56
; 
 976: (79) r7 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 977: (1d) if r8 == r7 goto pc+54
 978: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 979: (7b) *(u64 *)(r10 -56) = r1
 980: (7b) *(u64 *)(r10 -64) = r1
 981: (b7) r1 = 32
 982: (bf) r3 = r8
 983: (0f) r3 += r1
 984: (bf) r1 = r10
 985: (07) r1 += -64
 986: (b7) r2 = 16
 987: (85) call bpf_probe_read_kernel#-51920
 988: (79) r1 = *(u64 *)(r10 -56)
 989: (7b) *(u64 *)(r10 -32) = r1
 990: (79) r1 = *(u64 *)(r10 -64)
 991: (7b) *(u64 *)(r10 -40) = r1
 992: (bf) r1 = r10
 993: (07) r1 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 994: (61) r1 = *(u32 *)(r1 +4)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 995: (07) r1 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 996: (bf) r2 = r1
 997: (57) r2 &= 4095
; if (off <= buf_off) { // verify no wrap occurred
 998: (79) r3 = *(u64 *)(r10 -136)
 999: (67) r3 <<= 32
 1000: (77) r3 >>= 32
; if (off <= buf_off) { // verify no wrap occurred
 1001: (2d) if r2 > r3 goto pc+2359
; off = buf_off - len;
 1002: (79) r3 = *(u64 *)(r10 -136)
 1003: (1f) r3 -= r1
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 1004: (57) r3 &= 4095
 1005: (79) r1 = *(u64 *)(r10 -128)
 1006: (0f) r1 += r3
 1007: (bf) r3 = r10
; off = buf_off - len;
 1008: (07) r3 += -40
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 1009: (79) r3 = *(u64 *)(r3 +8)
 1010: (85) call bpf_probe_read_kernel_str#-51856
 1011: (bf) r6 = r0
 1012: (bf) r1 = r6
 1013: (67) r1 <<= 32
 1014: (c7) r1 s>>= 32
 1015: (b7) r2 = 2
; if (sz > 1) {
 1016: (6d) if r2 s> r1 goto pc+2344
 1017: (79) r8 = *(u64 *)(r10 -136)
; buf_off -= 1; // remove null byte termination with slash sign
 1018: (bf) r2 = r8
 1019: (07) r2 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 1020: (57) r2 &= 4095
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 1021: (79) r1 = *(u64 *)(r10 -128)
 1022: (0f) r1 += r2
 1023: (bf) r3 = r10
; buf_off -= 1; // remove null byte termination with slash sign
 1024: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 1025: (b7) r2 = 1
 1026: (85) call bpf_probe_read_compat#-45600
; buf_off -= sz - 1;
 1027: (1f) r8 -= r6
 1028: (7b) *(u64 *)(r10 -136) = r8
; 
 1029: (bf) r8 = r7
 1030: (bf) r3 = r9
 1031: (05) goto pc+39
; if (dentry != mnt_root) {
 1032: (79) r1 = *(u64 *)(r10 -120)
 1033: (79) r2 = *(u64 *)(r10 -152)
 1034: (1d) if r1 == r2 goto pc+2326
 1035: (79) r1 = *(u64 *)(r10 -144)
 1036: (5d) if r1 != r6 goto pc+2324
 1037: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 1038: (7b) *(u64 *)(r10 -64) = r6
 1039: (b7) r1 = 24
 1040: (79) r8 = *(u64 *)(r10 -120)
 1041: (bf) r3 = r8
 1042: (0f) r3 += r1
 1043: (bf) r1 = r10
; 
 1044: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 1045: (b7) r2 = 8
 1046: (85) call bpf_probe_read_kernel#-51920
 1047: (b7) r7 = 16
 1048: (0f) r8 += r7
 1049: (79) r9 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 1050: (7b) *(u64 *)(r10 -64) = r6
 1051: (bf) r1 = r10
; 
 1052: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 1053: (b7) r2 = 8
 1054: (bf) r3 = r8
 1055: (85) call bpf_probe_read_kernel#-51920
 1056: (79) r8 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 1057: (7b) *(u64 *)(r10 -64) = r6
 1058: (bf) r3 = r8
 1059: (0f) r3 += r7
 1060: (bf) r1 = r10
; 
 1061: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 1062: (b7) r2 = 8
 1063: (85) call bpf_probe_read_kernel#-51920
 1064: (b7) r1 = 32
 1065: (7b) *(u64 *)(r10 -120) = r8
 1066: (bf) r3 = r8
 1067: (bf) r8 = r9
 1068: (0f) r3 += r1
 1069: (79) r1 = *(u64 *)(r10 -64)
 1070: (7b) *(u64 *)(r10 -152) = r1
 1071: (b7) r1 = 0
 1072: (7b) *(u64 *)(r10 -160) = r3
 1073: (0f) r3 += r1
 1074: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 1075: (7b) *(u64 *)(r10 -64) = r7
 1076: (bf) r1 = r10
; 
 1077: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 1078: (b7) r2 = 8
 1079: (85) call bpf_probe_read_kernel#-51920
 1080: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 1081: (7b) *(u64 *)(r10 -64) = r7
 1082: (b7) r1 = 24
 1083: (bf) r3 = r8
 1084: (0f) r3 += r1
 1085: (bf) r1 = r10
; 
 1086: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 1087: (b7) r2 = 8
 1088: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 1089: (7b) *(u64 *)(r10 -144) = r8
 1090: (1d) if r8 == r6 goto pc+56
; 
 1091: (79) r7 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 1092: (1d) if r8 == r7 goto pc+54
 1093: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 1094: (7b) *(u64 *)(r10 -56) = r1
 1095: (7b) *(u64 *)(r10 -64) = r1
 1096: (b7) r1 = 32
 1097: (bf) r3 = r8
 1098: (0f) r3 += r1
 1099: (bf) r1 = r10
 1100: (07) r1 += -64
 1101: (b7) r2 = 16
 1102: (85) call bpf_probe_read_kernel#-51920
 1103: (79) r1 = *(u64 *)(r10 -56)
 1104: (7b) *(u64 *)(r10 -32) = r1
 1105: (79) r1 = *(u64 *)(r10 -64)
 1106: (7b) *(u64 *)(r10 -40) = r1
 1107: (bf) r1 = r10
 1108: (07) r1 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 1109: (61) r1 = *(u32 *)(r1 +4)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 1110: (07) r1 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 1111: (bf) r2 = r1
 1112: (57) r2 &= 4095
; if (off <= buf_off) { // verify no wrap occurred
 1113: (79) r3 = *(u64 *)(r10 -136)
 1114: (67) r3 <<= 32
 1115: (77) r3 >>= 32
; if (off <= buf_off) { // verify no wrap occurred
 1116: (2d) if r2 > r3 goto pc+2244
; off = buf_off - len;
 1117: (79) r3 = *(u64 *)(r10 -136)
 1118: (1f) r3 -= r1
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 1119: (57) r3 &= 4095
 1120: (79) r1 = *(u64 *)(r10 -128)
 1121: (0f) r1 += r3
 1122: (bf) r3 = r10
; off = buf_off - len;
 1123: (07) r3 += -40
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 1124: (79) r3 = *(u64 *)(r3 +8)
 1125: (85) call bpf_probe_read_kernel_str#-51856
 1126: (bf) r6 = r0
 1127: (bf) r1 = r6
 1128: (67) r1 <<= 32
 1129: (c7) r1 s>>= 32
 1130: (b7) r2 = 2
; if (sz > 1) {
 1131: (6d) if r2 s> r1 goto pc+2229
 1132: (79) r8 = *(u64 *)(r10 -136)
; buf_off -= 1; // remove null byte termination with slash sign
 1133: (bf) r2 = r8
 1134: (07) r2 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 1135: (57) r2 &= 4095
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 1136: (79) r1 = *(u64 *)(r10 -128)
 1137: (0f) r1 += r2
 1138: (bf) r3 = r10
; buf_off -= 1; // remove null byte termination with slash sign
 1139: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 1140: (b7) r2 = 1
 1141: (85) call bpf_probe_read_compat#-45600
; buf_off -= sz - 1;
 1142: (1f) r8 -= r6
 1143: (7b) *(u64 *)(r10 -136) = r8
; 
 1144: (bf) r9 = r7
 1145: (79) r3 = *(u64 *)(r10 -160)
 1146: (05) goto pc+38
; if (dentry != mnt_root) {
 1147: (79) r1 = *(u64 *)(r10 -120)
 1148: (79) r2 = *(u64 *)(r10 -152)
 1149: (1d) if r1 == r2 goto pc+2211
 1150: (79) r1 = *(u64 *)(r10 -144)
 1151: (5d) if r1 != r6 goto pc+2209
 1152: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 1153: (7b) *(u64 *)(r10 -64) = r6
 1154: (b7) r1 = 24
 1155: (79) r8 = *(u64 *)(r10 -120)
 1156: (bf) r3 = r8
 1157: (0f) r3 += r1
 1158: (bf) r1 = r10
; 
 1159: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 1160: (b7) r2 = 8
 1161: (85) call bpf_probe_read_kernel#-51920
 1162: (b7) r7 = 16
 1163: (0f) r8 += r7
 1164: (79) r9 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 1165: (7b) *(u64 *)(r10 -64) = r6
 1166: (bf) r1 = r10
; 
 1167: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 1168: (b7) r2 = 8
 1169: (bf) r3 = r8
 1170: (85) call bpf_probe_read_kernel#-51920
 1171: (79) r8 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 1172: (7b) *(u64 *)(r10 -64) = r6
 1173: (bf) r3 = r8
 1174: (0f) r3 += r7
 1175: (bf) r1 = r10
; 
 1176: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 1177: (b7) r2 = 8
 1178: (85) call bpf_probe_read_kernel#-51920
 1179: (b7) r1 = 32
 1180: (7b) *(u64 *)(r10 -120) = r8
 1181: (bf) r3 = r8
 1182: (0f) r3 += r1
 1183: (79) r1 = *(u64 *)(r10 -64)
 1184: (7b) *(u64 *)(r10 -152) = r1
 1185: (b7) r1 = 0
 1186: (7b) *(u64 *)(r10 -160) = r3
 1187: (0f) r3 += r1
 1188: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 1189: (7b) *(u64 *)(r10 -64) = r7
 1190: (bf) r1 = r10
; 
 1191: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 1192: (b7) r2 = 8
 1193: (85) call bpf_probe_read_kernel#-51920
 1194: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 1195: (7b) *(u64 *)(r10 -64) = r7
 1196: (b7) r1 = 24
 1197: (bf) r3 = r9
 1198: (0f) r3 += r1
 1199: (bf) r1 = r10
; 
 1200: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 1201: (b7) r2 = 8
 1202: (85) call bpf_probe_read_kernel#-51920
 1203: (bf) r3 = r9
; if (dentry == mnt_root || dentry == d_parent) {
 1204: (7b) *(u64 *)(r10 -144) = r3
 1205: (1d) if r3 == r6 goto pc+54
; 
 1206: (79) r7 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 1207: (1d) if r3 == r7 goto pc+52
 1208: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 1209: (7b) *(u64 *)(r10 -56) = r1
 1210: (7b) *(u64 *)(r10 -64) = r1
 1211: (b7) r1 = 32
 1212: (0f) r3 += r1
 1213: (bf) r1 = r10
 1214: (07) r1 += -64
 1215: (b7) r2 = 16
 1216: (85) call bpf_probe_read_kernel#-51920
 1217: (79) r1 = *(u64 *)(r10 -56)
 1218: (7b) *(u64 *)(r10 -32) = r1
 1219: (79) r1 = *(u64 *)(r10 -64)
 1220: (7b) *(u64 *)(r10 -40) = r1
 1221: (bf) r1 = r10
 1222: (07) r1 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 1223: (61) r1 = *(u32 *)(r1 +4)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 1224: (07) r1 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 1225: (bf) r2 = r1
 1226: (57) r2 &= 4095
; if (off <= buf_off) { // verify no wrap occurred
 1227: (79) r3 = *(u64 *)(r10 -136)
 1228: (67) r3 <<= 32
 1229: (77) r3 >>= 32
; if (off <= buf_off) { // verify no wrap occurred
 1230: (2d) if r2 > r3 goto pc+2130
; off = buf_off - len;
 1231: (79) r3 = *(u64 *)(r10 -136)
 1232: (1f) r3 -= r1
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 1233: (57) r3 &= 4095
 1234: (79) r1 = *(u64 *)(r10 -128)
 1235: (0f) r1 += r3
 1236: (bf) r3 = r10
; off = buf_off - len;
 1237: (07) r3 += -40
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 1238: (79) r3 = *(u64 *)(r3 +8)
 1239: (85) call bpf_probe_read_kernel_str#-51856
 1240: (bf) r6 = r0
 1241: (bf) r1 = r6
 1242: (67) r1 <<= 32
 1243: (c7) r1 s>>= 32
 1244: (b7) r2 = 2
; if (sz > 1) {
 1245: (6d) if r2 s> r1 goto pc+2115
 1246: (79) r8 = *(u64 *)(r10 -136)
; buf_off -= 1; // remove null byte termination with slash sign
 1247: (bf) r2 = r8
 1248: (07) r2 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 1249: (57) r2 &= 4095
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 1250: (79) r1 = *(u64 *)(r10 -128)
 1251: (0f) r1 += r2
 1252: (bf) r3 = r10
; buf_off -= 1; // remove null byte termination with slash sign
 1253: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 1254: (b7) r2 = 1
 1255: (85) call bpf_probe_read_compat#-45600
; buf_off -= sz - 1;
 1256: (1f) r8 -= r6
 1257: (7b) *(u64 *)(r10 -136) = r8
; 
 1258: (7b) *(u64 *)(r10 -144) = r7
 1259: (05) goto pc+39
; if (dentry != mnt_root) {
 1260: (79) r1 = *(u64 *)(r10 -120)
 1261: (79) r2 = *(u64 *)(r10 -152)
 1262: (1d) if r1 == r2 goto pc+2098
 1263: (79) r1 = *(u64 *)(r10 -144)
 1264: (5d) if r1 != r6 goto pc+2096
 1265: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 1266: (7b) *(u64 *)(r10 -64) = r6
 1267: (b7) r1 = 24
 1268: (79) r8 = *(u64 *)(r10 -120)
 1269: (bf) r3 = r8
 1270: (0f) r3 += r1
 1271: (bf) r1 = r10
; 
 1272: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 1273: (b7) r2 = 8
 1274: (85) call bpf_probe_read_kernel#-51920
 1275: (b7) r7 = 16
 1276: (0f) r8 += r7
 1277: (79) r1 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 1278: (7b) *(u64 *)(r10 -144) = r1
 1279: (7b) *(u64 *)(r10 -64) = r6
 1280: (bf) r1 = r10
; 
 1281: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 1282: (b7) r2 = 8
 1283: (bf) r3 = r8
 1284: (85) call bpf_probe_read_kernel#-51920
 1285: (79) r8 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 1286: (7b) *(u64 *)(r10 -64) = r6
 1287: (bf) r3 = r8
 1288: (0f) r3 += r7
 1289: (bf) r1 = r10
; 
 1290: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 1291: (b7) r2 = 8
 1292: (85) call bpf_probe_read_kernel#-51920
 1293: (b7) r1 = 32
 1294: (7b) *(u64 *)(r10 -120) = r8
 1295: (0f) r8 += r1
 1296: (7b) *(u64 *)(r10 -160) = r8
 1297: (79) r1 = *(u64 *)(r10 -64)
 1298: (7b) *(u64 *)(r10 -152) = r1
 1299: (b7) r1 = 0
 1300: (79) r3 = *(u64 *)(r10 -160)
 1301: (0f) r3 += r1
 1302: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 1303: (7b) *(u64 *)(r10 -64) = r7
 1304: (bf) r1 = r10
; 
 1305: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 1306: (b7) r2 = 8
 1307: (85) call bpf_probe_read_kernel#-51920
 1308: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 1309: (7b) *(u64 *)(r10 -64) = r7
 1310: (b7) r1 = 24
 1311: (79) r8 = *(u64 *)(r10 -144)
 1312: (bf) r3 = r8
 1313: (0f) r3 += r1
 1314: (bf) r1 = r10
; 
 1315: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 1316: (b7) r2 = 8
 1317: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 1318: (1d) if r8 == r6 goto pc+55
; 
 1319: (79) r7 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 1320: (1d) if r8 == r7 goto pc+53
 1321: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 1322: (7b) *(u64 *)(r10 -56) = r1
 1323: (7b) *(u64 *)(r10 -64) = r1
 1324: (b7) r1 = 32
 1325: (bf) r3 = r8
 1326: (0f) r3 += r1
 1327: (bf) r1 = r10
 1328: (07) r1 += -64
 1329: (b7) r2 = 16
 1330: (85) call bpf_probe_read_kernel#-51920
 1331: (79) r1 = *(u64 *)(r10 -56)
 1332: (7b) *(u64 *)(r10 -32) = r1
 1333: (79) r1 = *(u64 *)(r10 -64)
 1334: (7b) *(u64 *)(r10 -40) = r1
 1335: (bf) r1 = r10
 1336: (07) r1 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 1337: (61) r1 = *(u32 *)(r1 +4)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 1338: (07) r1 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 1339: (bf) r2 = r1
 1340: (57) r2 &= 4095
; if (off <= buf_off) { // verify no wrap occurred
 1341: (79) r3 = *(u64 *)(r10 -136)
 1342: (67) r3 <<= 32
 1343: (77) r3 >>= 32
; if (off <= buf_off) { // verify no wrap occurred
 1344: (2d) if r2 > r3 goto pc+2016
; off = buf_off - len;
 1345: (79) r3 = *(u64 *)(r10 -136)
 1346: (1f) r3 -= r1
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 1347: (57) r3 &= 4095
 1348: (79) r1 = *(u64 *)(r10 -128)
 1349: (0f) r1 += r3
 1350: (bf) r3 = r10
; off = buf_off - len;
 1351: (07) r3 += -40
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 1352: (79) r3 = *(u64 *)(r3 +8)
 1353: (85) call bpf_probe_read_kernel_str#-51856
 1354: (bf) r6 = r0
 1355: (bf) r1 = r6
 1356: (67) r1 <<= 32
 1357: (c7) r1 s>>= 32
 1358: (b7) r2 = 2
; if (sz > 1) {
 1359: (6d) if r2 s> r1 goto pc+2001
 1360: (79) r8 = *(u64 *)(r10 -136)
; buf_off -= 1; // remove null byte termination with slash sign
 1361: (bf) r2 = r8
 1362: (07) r2 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 1363: (57) r2 &= 4095
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 1364: (79) r1 = *(u64 *)(r10 -128)
 1365: (0f) r1 += r2
 1366: (bf) r3 = r10
; buf_off -= 1; // remove null byte termination with slash sign
 1367: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 1368: (b7) r2 = 1
 1369: (85) call bpf_probe_read_compat#-45600
; buf_off -= sz - 1;
 1370: (1f) r8 -= r6
 1371: (7b) *(u64 *)(r10 -136) = r8
; 
 1372: (7b) *(u64 *)(r10 -144) = r7
 1373: (05) goto pc+39
; if (dentry != mnt_root) {
 1374: (79) r1 = *(u64 *)(r10 -120)
 1375: (79) r2 = *(u64 *)(r10 -152)
 1376: (1d) if r1 == r2 goto pc+1984
 1377: (79) r1 = *(u64 *)(r10 -144)
 1378: (5d) if r1 != r6 goto pc+1982
 1379: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 1380: (7b) *(u64 *)(r10 -64) = r6
 1381: (b7) r1 = 24
 1382: (79) r8 = *(u64 *)(r10 -120)
 1383: (bf) r3 = r8
 1384: (0f) r3 += r1
 1385: (bf) r1 = r10
; 
 1386: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 1387: (b7) r2 = 8
 1388: (85) call bpf_probe_read_kernel#-51920
 1389: (b7) r7 = 16
 1390: (0f) r8 += r7
 1391: (79) r1 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 1392: (7b) *(u64 *)(r10 -144) = r1
 1393: (7b) *(u64 *)(r10 -64) = r6
 1394: (bf) r1 = r10
; 
 1395: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 1396: (b7) r2 = 8
 1397: (bf) r3 = r8
 1398: (85) call bpf_probe_read_kernel#-51920
 1399: (79) r8 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 1400: (7b) *(u64 *)(r10 -64) = r6
 1401: (bf) r3 = r8
 1402: (0f) r3 += r7
 1403: (bf) r1 = r10
; 
 1404: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 1405: (b7) r2 = 8
 1406: (85) call bpf_probe_read_kernel#-51920
 1407: (b7) r1 = 32
 1408: (7b) *(u64 *)(r10 -120) = r8
 1409: (0f) r8 += r1
 1410: (7b) *(u64 *)(r10 -160) = r8
 1411: (79) r1 = *(u64 *)(r10 -64)
 1412: (7b) *(u64 *)(r10 -152) = r1
 1413: (b7) r1 = 0
 1414: (79) r3 = *(u64 *)(r10 -160)
 1415: (0f) r3 += r1
 1416: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 1417: (7b) *(u64 *)(r10 -64) = r7
 1418: (bf) r1 = r10
; 
 1419: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 1420: (b7) r2 = 8
 1421: (85) call bpf_probe_read_kernel#-51920
 1422: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 1423: (7b) *(u64 *)(r10 -64) = r7
 1424: (b7) r1 = 24
 1425: (79) r7 = *(u64 *)(r10 -144)
 1426: (bf) r3 = r7
 1427: (0f) r3 += r1
 1428: (bf) r1 = r10
; 
 1429: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 1430: (b7) r2 = 8
 1431: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 1432: (1d) if r7 == r6 goto pc+56
; 
 1433: (79) r7 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 1434: (79) r1 = *(u64 *)(r10 -144)
 1435: (1d) if r1 == r7 goto pc+53
 1436: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 1437: (7b) *(u64 *)(r10 -56) = r1
 1438: (7b) *(u64 *)(r10 -64) = r1
 1439: (b7) r1 = 32
 1440: (79) r3 = *(u64 *)(r10 -144)
 1441: (0f) r3 += r1
 1442: (bf) r1 = r10
 1443: (07) r1 += -64
 1444: (b7) r2 = 16
 1445: (85) call bpf_probe_read_kernel#-51920
 1446: (79) r1 = *(u64 *)(r10 -56)
 1447: (7b) *(u64 *)(r10 -32) = r1
 1448: (79) r1 = *(u64 *)(r10 -64)
 1449: (7b) *(u64 *)(r10 -40) = r1
 1450: (bf) r1 = r10
 1451: (07) r1 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 1452: (61) r1 = *(u32 *)(r1 +4)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 1453: (07) r1 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 1454: (bf) r2 = r1
 1455: (57) r2 &= 4095
; if (off <= buf_off) { // verify no wrap occurred
 1456: (79) r3 = *(u64 *)(r10 -136)
 1457: (67) r3 <<= 32
 1458: (77) r3 >>= 32
; if (off <= buf_off) { // verify no wrap occurred
 1459: (2d) if r2 > r3 goto pc+1901
; off = buf_off - len;
 1460: (79) r3 = *(u64 *)(r10 -136)
 1461: (1f) r3 -= r1
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 1462: (57) r3 &= 4095
 1463: (79) r1 = *(u64 *)(r10 -128)
 1464: (0f) r1 += r3
 1465: (bf) r3 = r10
; off = buf_off - len;
 1466: (07) r3 += -40
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 1467: (79) r3 = *(u64 *)(r3 +8)
 1468: (85) call bpf_probe_read_kernel_str#-51856
 1469: (bf) r6 = r0
 1470: (bf) r1 = r6
 1471: (67) r1 <<= 32
 1472: (c7) r1 s>>= 32
 1473: (b7) r2 = 2
; if (sz > 1) {
 1474: (6d) if r2 s> r1 goto pc+1886
 1475: (79) r8 = *(u64 *)(r10 -136)
; buf_off -= 1; // remove null byte termination with slash sign
 1476: (bf) r2 = r8
 1477: (07) r2 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 1478: (57) r2 &= 4095
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 1479: (79) r1 = *(u64 *)(r10 -128)
 1480: (0f) r1 += r2
 1481: (bf) r3 = r10
; buf_off -= 1; // remove null byte termination with slash sign
 1482: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 1483: (b7) r2 = 1
 1484: (85) call bpf_probe_read_compat#-45600
; buf_off -= sz - 1;
 1485: (1f) r8 -= r6
 1486: (7b) *(u64 *)(r10 -136) = r8
; 
 1487: (7b) *(u64 *)(r10 -144) = r7
 1488: (05) goto pc+39
; if (dentry != mnt_root) {
 1489: (79) r1 = *(u64 *)(r10 -120)
 1490: (79) r2 = *(u64 *)(r10 -152)
 1491: (1d) if r1 == r2 goto pc+1869
 1492: (79) r1 = *(u64 *)(r10 -144)
 1493: (5d) if r1 != r6 goto pc+1867
 1494: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 1495: (7b) *(u64 *)(r10 -64) = r6
 1496: (b7) r1 = 24
 1497: (79) r8 = *(u64 *)(r10 -120)
 1498: (bf) r3 = r8
 1499: (0f) r3 += r1
 1500: (bf) r1 = r10
; 
 1501: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 1502: (b7) r2 = 8
 1503: (85) call bpf_probe_read_kernel#-51920
 1504: (b7) r7 = 16
 1505: (0f) r8 += r7
 1506: (79) r1 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 1507: (7b) *(u64 *)(r10 -144) = r1
 1508: (7b) *(u64 *)(r10 -64) = r6
 1509: (bf) r1 = r10
; 
 1510: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 1511: (b7) r2 = 8
 1512: (bf) r3 = r8
 1513: (85) call bpf_probe_read_kernel#-51920
 1514: (79) r8 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 1515: (7b) *(u64 *)(r10 -64) = r6
 1516: (bf) r3 = r8
 1517: (0f) r3 += r7
 1518: (bf) r1 = r10
; 
 1519: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 1520: (b7) r2 = 8
 1521: (85) call bpf_probe_read_kernel#-51920
 1522: (b7) r1 = 32
 1523: (7b) *(u64 *)(r10 -120) = r8
 1524: (0f) r8 += r1
 1525: (7b) *(u64 *)(r10 -160) = r8
 1526: (79) r1 = *(u64 *)(r10 -64)
 1527: (7b) *(u64 *)(r10 -152) = r1
 1528: (b7) r1 = 0
 1529: (79) r3 = *(u64 *)(r10 -160)
 1530: (0f) r3 += r1
 1531: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 1532: (7b) *(u64 *)(r10 -64) = r7
 1533: (bf) r1 = r10
; 
 1534: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 1535: (b7) r2 = 8
 1536: (85) call bpf_probe_read_kernel#-51920
 1537: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 1538: (7b) *(u64 *)(r10 -64) = r7
 1539: (b7) r1 = 24
 1540: (79) r7 = *(u64 *)(r10 -144)
 1541: (bf) r3 = r7
 1542: (0f) r3 += r1
 1543: (bf) r1 = r10
; 
 1544: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 1545: (b7) r2 = 8
 1546: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 1547: (1d) if r7 == r6 goto pc+56
; 
 1548: (79) r7 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 1549: (79) r1 = *(u64 *)(r10 -144)
 1550: (1d) if r1 == r7 goto pc+53
 1551: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 1552: (7b) *(u64 *)(r10 -56) = r1
 1553: (7b) *(u64 *)(r10 -64) = r1
 1554: (b7) r1 = 32
 1555: (79) r3 = *(u64 *)(r10 -144)
 1556: (0f) r3 += r1
 1557: (bf) r1 = r10
 1558: (07) r1 += -64
 1559: (b7) r2 = 16
 1560: (85) call bpf_probe_read_kernel#-51920
 1561: (79) r1 = *(u64 *)(r10 -56)
 1562: (7b) *(u64 *)(r10 -32) = r1
 1563: (79) r1 = *(u64 *)(r10 -64)
 1564: (7b) *(u64 *)(r10 -40) = r1
 1565: (bf) r1 = r10
 1566: (07) r1 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 1567: (61) r1 = *(u32 *)(r1 +4)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 1568: (07) r1 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 1569: (bf) r2 = r1
 1570: (57) r2 &= 4095
; if (off <= buf_off) { // verify no wrap occurred
 1571: (79) r3 = *(u64 *)(r10 -136)
 1572: (67) r3 <<= 32
 1573: (77) r3 >>= 32
; if (off <= buf_off) { // verify no wrap occurred
 1574: (2d) if r2 > r3 goto pc+1786
; off = buf_off - len;
 1575: (79) r3 = *(u64 *)(r10 -136)
 1576: (1f) r3 -= r1
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 1577: (57) r3 &= 4095
 1578: (79) r1 = *(u64 *)(r10 -128)
 1579: (0f) r1 += r3
 1580: (bf) r3 = r10
; off = buf_off - len;
 1581: (07) r3 += -40
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 1582: (79) r3 = *(u64 *)(r3 +8)
 1583: (85) call bpf_probe_read_kernel_str#-51856
 1584: (bf) r6 = r0
 1585: (bf) r1 = r6
 1586: (67) r1 <<= 32
 1587: (c7) r1 s>>= 32
 1588: (b7) r2 = 2
; if (sz > 1) {
 1589: (6d) if r2 s> r1 goto pc+1771
 1590: (79) r8 = *(u64 *)(r10 -136)
; buf_off -= 1; // remove null byte termination with slash sign
 1591: (bf) r2 = r8
 1592: (07) r2 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 1593: (57) r2 &= 4095
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 1594: (79) r1 = *(u64 *)(r10 -128)
 1595: (0f) r1 += r2
 1596: (bf) r3 = r10
; buf_off -= 1; // remove null byte termination with slash sign
 1597: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 1598: (b7) r2 = 1
 1599: (85) call bpf_probe_read_compat#-45600
; buf_off -= sz - 1;
 1600: (1f) r8 -= r6
 1601: (7b) *(u64 *)(r10 -136) = r8
; 
 1602: (7b) *(u64 *)(r10 -144) = r7
 1603: (05) goto pc+39
; if (dentry != mnt_root) {
 1604: (79) r1 = *(u64 *)(r10 -120)
 1605: (79) r2 = *(u64 *)(r10 -152)
 1606: (1d) if r1 == r2 goto pc+1754
 1607: (79) r1 = *(u64 *)(r10 -144)
 1608: (5d) if r1 != r6 goto pc+1752
 1609: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 1610: (7b) *(u64 *)(r10 -64) = r6
 1611: (b7) r1 = 24
 1612: (79) r8 = *(u64 *)(r10 -120)
 1613: (bf) r3 = r8
 1614: (0f) r3 += r1
 1615: (bf) r1 = r10
; 
 1616: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 1617: (b7) r2 = 8
 1618: (85) call bpf_probe_read_kernel#-51920
 1619: (b7) r7 = 16
 1620: (0f) r8 += r7
 1621: (79) r1 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 1622: (7b) *(u64 *)(r10 -144) = r1
 1623: (7b) *(u64 *)(r10 -64) = r6
 1624: (bf) r1 = r10
; 
 1625: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 1626: (b7) r2 = 8
 1627: (bf) r3 = r8
 1628: (85) call bpf_probe_read_kernel#-51920
 1629: (79) r8 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 1630: (7b) *(u64 *)(r10 -64) = r6
 1631: (bf) r3 = r8
 1632: (0f) r3 += r7
 1633: (bf) r1 = r10
; 
 1634: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 1635: (b7) r2 = 8
 1636: (85) call bpf_probe_read_kernel#-51920
 1637: (b7) r1 = 32
 1638: (7b) *(u64 *)(r10 -120) = r8
 1639: (0f) r8 += r1
 1640: (7b) *(u64 *)(r10 -160) = r8
 1641: (79) r1 = *(u64 *)(r10 -64)
 1642: (7b) *(u64 *)(r10 -152) = r1
 1643: (b7) r1 = 0
 1644: (79) r3 = *(u64 *)(r10 -160)
 1645: (0f) r3 += r1
 1646: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 1647: (7b) *(u64 *)(r10 -64) = r7
 1648: (bf) r1 = r10
; 
 1649: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 1650: (b7) r2 = 8
 1651: (85) call bpf_probe_read_kernel#-51920
 1652: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 1653: (7b) *(u64 *)(r10 -64) = r7
 1654: (b7) r1 = 24
 1655: (79) r7 = *(u64 *)(r10 -144)
 1656: (bf) r3 = r7
 1657: (0f) r3 += r1
 1658: (bf) r1 = r10
; 
 1659: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 1660: (b7) r2 = 8
 1661: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 1662: (1d) if r7 == r6 goto pc+56
; 
 1663: (79) r7 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 1664: (79) r1 = *(u64 *)(r10 -144)
 1665: (1d) if r1 == r7 goto pc+53
 1666: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 1667: (7b) *(u64 *)(r10 -56) = r1
 1668: (7b) *(u64 *)(r10 -64) = r1
 1669: (b7) r1 = 32
 1670: (79) r3 = *(u64 *)(r10 -144)
 1671: (0f) r3 += r1
 1672: (bf) r1 = r10
 1673: (07) r1 += -64
 1674: (b7) r2 = 16
 1675: (85) call bpf_probe_read_kernel#-51920
 1676: (79) r1 = *(u64 *)(r10 -56)
 1677: (7b) *(u64 *)(r10 -32) = r1
 1678: (79) r1 = *(u64 *)(r10 -64)
 1679: (7b) *(u64 *)(r10 -40) = r1
 1680: (bf) r1 = r10
 1681: (07) r1 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 1682: (61) r1 = *(u32 *)(r1 +4)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 1683: (07) r1 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 1684: (bf) r2 = r1
 1685: (57) r2 &= 4095
; if (off <= buf_off) { // verify no wrap occurred
 1686: (79) r3 = *(u64 *)(r10 -136)
 1687: (67) r3 <<= 32
 1688: (77) r3 >>= 32
; if (off <= buf_off) { // verify no wrap occurred
 1689: (2d) if r2 > r3 goto pc+1671
; off = buf_off - len;
 1690: (79) r3 = *(u64 *)(r10 -136)
 1691: (1f) r3 -= r1
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 1692: (57) r3 &= 4095
 1693: (79) r1 = *(u64 *)(r10 -128)
 1694: (0f) r1 += r3
 1695: (bf) r3 = r10
; off = buf_off - len;
 1696: (07) r3 += -40
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 1697: (79) r3 = *(u64 *)(r3 +8)
 1698: (85) call bpf_probe_read_kernel_str#-51856
 1699: (bf) r6 = r0
 1700: (bf) r1 = r6
 1701: (67) r1 <<= 32
 1702: (c7) r1 s>>= 32
 1703: (b7) r2 = 2
; if (sz > 1) {
 1704: (6d) if r2 s> r1 goto pc+1656
 1705: (79) r8 = *(u64 *)(r10 -136)
; buf_off -= 1; // remove null byte termination with slash sign
 1706: (bf) r2 = r8
 1707: (07) r2 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 1708: (57) r2 &= 4095
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 1709: (79) r1 = *(u64 *)(r10 -128)
 1710: (0f) r1 += r2
 1711: (bf) r3 = r10
; buf_off -= 1; // remove null byte termination with slash sign
 1712: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 1713: (b7) r2 = 1
 1714: (85) call bpf_probe_read_compat#-45600
; buf_off -= sz - 1;
 1715: (1f) r8 -= r6
 1716: (7b) *(u64 *)(r10 -136) = r8
; 
 1717: (7b) *(u64 *)(r10 -144) = r7
 1718: (05) goto pc+39
; if (dentry != mnt_root) {
 1719: (79) r1 = *(u64 *)(r10 -120)
 1720: (79) r2 = *(u64 *)(r10 -152)
 1721: (1d) if r1 == r2 goto pc+1639
 1722: (79) r1 = *(u64 *)(r10 -144)
 1723: (5d) if r1 != r6 goto pc+1637
 1724: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 1725: (7b) *(u64 *)(r10 -64) = r6
 1726: (b7) r1 = 24
 1727: (79) r8 = *(u64 *)(r10 -120)
 1728: (bf) r3 = r8
 1729: (0f) r3 += r1
 1730: (bf) r1 = r10
; 
 1731: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 1732: (b7) r2 = 8
 1733: (85) call bpf_probe_read_kernel#-51920
 1734: (b7) r7 = 16
 1735: (0f) r8 += r7
 1736: (79) r1 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 1737: (7b) *(u64 *)(r10 -144) = r1
 1738: (7b) *(u64 *)(r10 -64) = r6
 1739: (bf) r1 = r10
; 
 1740: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 1741: (b7) r2 = 8
 1742: (bf) r3 = r8
 1743: (85) call bpf_probe_read_kernel#-51920
 1744: (79) r8 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 1745: (7b) *(u64 *)(r10 -64) = r6
 1746: (bf) r3 = r8
 1747: (0f) r3 += r7
 1748: (bf) r1 = r10
; 
 1749: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 1750: (b7) r2 = 8
 1751: (85) call bpf_probe_read_kernel#-51920
 1752: (b7) r1 = 32
 1753: (7b) *(u64 *)(r10 -120) = r8
 1754: (0f) r8 += r1
 1755: (7b) *(u64 *)(r10 -160) = r8
 1756: (79) r1 = *(u64 *)(r10 -64)
 1757: (7b) *(u64 *)(r10 -152) = r1
 1758: (b7) r1 = 0
 1759: (79) r3 = *(u64 *)(r10 -160)
 1760: (0f) r3 += r1
 1761: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 1762: (7b) *(u64 *)(r10 -64) = r7
 1763: (bf) r1 = r10
; 
 1764: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 1765: (b7) r2 = 8
 1766: (85) call bpf_probe_read_kernel#-51920
 1767: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 1768: (7b) *(u64 *)(r10 -64) = r7
 1769: (b7) r1 = 24
 1770: (79) r7 = *(u64 *)(r10 -144)
 1771: (bf) r3 = r7
 1772: (0f) r3 += r1
 1773: (bf) r1 = r10
; 
 1774: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 1775: (b7) r2 = 8
 1776: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 1777: (1d) if r7 == r6 goto pc+56
; 
 1778: (79) r7 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 1779: (79) r1 = *(u64 *)(r10 -144)
 1780: (1d) if r1 == r7 goto pc+53
 1781: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 1782: (7b) *(u64 *)(r10 -56) = r1
 1783: (7b) *(u64 *)(r10 -64) = r1
 1784: (b7) r1 = 32
 1785: (79) r3 = *(u64 *)(r10 -144)
 1786: (0f) r3 += r1
 1787: (bf) r1 = r10
 1788: (07) r1 += -64
 1789: (b7) r2 = 16
 1790: (85) call bpf_probe_read_kernel#-51920
 1791: (79) r1 = *(u64 *)(r10 -56)
 1792: (7b) *(u64 *)(r10 -32) = r1
 1793: (79) r1 = *(u64 *)(r10 -64)
 1794: (7b) *(u64 *)(r10 -40) = r1
 1795: (bf) r1 = r10
 1796: (07) r1 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 1797: (61) r1 = *(u32 *)(r1 +4)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 1798: (07) r1 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 1799: (bf) r2 = r1
 1800: (57) r2 &= 4095
; if (off <= buf_off) { // verify no wrap occurred
 1801: (79) r3 = *(u64 *)(r10 -136)
 1802: (67) r3 <<= 32
 1803: (77) r3 >>= 32
; if (off <= buf_off) { // verify no wrap occurred
 1804: (2d) if r2 > r3 goto pc+1556
; off = buf_off - len;
 1805: (79) r3 = *(u64 *)(r10 -136)
 1806: (1f) r3 -= r1
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 1807: (57) r3 &= 4095
 1808: (79) r1 = *(u64 *)(r10 -128)
 1809: (0f) r1 += r3
 1810: (bf) r3 = r10
; off = buf_off - len;
 1811: (07) r3 += -40
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 1812: (79) r3 = *(u64 *)(r3 +8)
 1813: (85) call bpf_probe_read_kernel_str#-51856
 1814: (bf) r6 = r0
 1815: (bf) r1 = r6
 1816: (67) r1 <<= 32
 1817: (c7) r1 s>>= 32
 1818: (b7) r2 = 2
; if (sz > 1) {
 1819: (6d) if r2 s> r1 goto pc+1541
 1820: (79) r8 = *(u64 *)(r10 -136)
; buf_off -= 1; // remove null byte termination with slash sign
 1821: (bf) r2 = r8
 1822: (07) r2 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 1823: (57) r2 &= 4095
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 1824: (79) r1 = *(u64 *)(r10 -128)
 1825: (0f) r1 += r2
 1826: (bf) r3 = r10
; buf_off -= 1; // remove null byte termination with slash sign
 1827: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 1828: (b7) r2 = 1
 1829: (85) call bpf_probe_read_compat#-45600
; buf_off -= sz - 1;
 1830: (1f) r8 -= r6
 1831: (7b) *(u64 *)(r10 -136) = r8
; 
 1832: (7b) *(u64 *)(r10 -144) = r7
 1833: (05) goto pc+39
; if (dentry != mnt_root) {
 1834: (79) r1 = *(u64 *)(r10 -120)
 1835: (79) r2 = *(u64 *)(r10 -152)
 1836: (1d) if r1 == r2 goto pc+1524
 1837: (79) r1 = *(u64 *)(r10 -144)
 1838: (5d) if r1 != r6 goto pc+1522
 1839: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 1840: (7b) *(u64 *)(r10 -64) = r6
 1841: (b7) r1 = 24
 1842: (79) r8 = *(u64 *)(r10 -120)
 1843: (bf) r3 = r8
 1844: (0f) r3 += r1
 1845: (bf) r1 = r10
; 
 1846: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 1847: (b7) r2 = 8
 1848: (85) call bpf_probe_read_kernel#-51920
 1849: (b7) r7 = 16
 1850: (0f) r8 += r7
 1851: (79) r1 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 1852: (7b) *(u64 *)(r10 -144) = r1
 1853: (7b) *(u64 *)(r10 -64) = r6
 1854: (bf) r1 = r10
; 
 1855: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 1856: (b7) r2 = 8
 1857: (bf) r3 = r8
 1858: (85) call bpf_probe_read_kernel#-51920
 1859: (79) r8 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 1860: (7b) *(u64 *)(r10 -64) = r6
 1861: (bf) r3 = r8
 1862: (0f) r3 += r7
 1863: (bf) r1 = r10
; 
 1864: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 1865: (b7) r2 = 8
 1866: (85) call bpf_probe_read_kernel#-51920
 1867: (b7) r1 = 32
 1868: (7b) *(u64 *)(r10 -120) = r8
 1869: (0f) r8 += r1
 1870: (7b) *(u64 *)(r10 -160) = r8
 1871: (79) r1 = *(u64 *)(r10 -64)
 1872: (7b) *(u64 *)(r10 -152) = r1
 1873: (b7) r1 = 0
 1874: (79) r3 = *(u64 *)(r10 -160)
 1875: (0f) r3 += r1
 1876: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 1877: (7b) *(u64 *)(r10 -64) = r7
 1878: (bf) r1 = r10
; 
 1879: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 1880: (b7) r2 = 8
 1881: (85) call bpf_probe_read_kernel#-51920
 1882: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 1883: (7b) *(u64 *)(r10 -64) = r7
 1884: (b7) r1 = 24
 1885: (79) r7 = *(u64 *)(r10 -144)
 1886: (bf) r3 = r7
 1887: (0f) r3 += r1
 1888: (bf) r1 = r10
; 
 1889: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 1890: (b7) r2 = 8
 1891: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 1892: (1d) if r7 == r6 goto pc+56
; 
 1893: (79) r7 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 1894: (79) r1 = *(u64 *)(r10 -144)
 1895: (1d) if r1 == r7 goto pc+53
 1896: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 1897: (7b) *(u64 *)(r10 -56) = r1
 1898: (7b) *(u64 *)(r10 -64) = r1
 1899: (b7) r1 = 32
 1900: (79) r3 = *(u64 *)(r10 -144)
 1901: (0f) r3 += r1
 1902: (bf) r1 = r10
 1903: (07) r1 += -64
 1904: (b7) r2 = 16
 1905: (85) call bpf_probe_read_kernel#-51920
 1906: (79) r1 = *(u64 *)(r10 -56)
 1907: (7b) *(u64 *)(r10 -32) = r1
 1908: (79) r1 = *(u64 *)(r10 -64)
 1909: (7b) *(u64 *)(r10 -40) = r1
 1910: (bf) r1 = r10
 1911: (07) r1 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 1912: (61) r1 = *(u32 *)(r1 +4)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 1913: (07) r1 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 1914: (bf) r2 = r1
 1915: (57) r2 &= 4095
; if (off <= buf_off) { // verify no wrap occurred
 1916: (79) r3 = *(u64 *)(r10 -136)
 1917: (67) r3 <<= 32
 1918: (77) r3 >>= 32
; if (off <= buf_off) { // verify no wrap occurred
 1919: (2d) if r2 > r3 goto pc+1441
; off = buf_off - len;
 1920: (79) r3 = *(u64 *)(r10 -136)
 1921: (1f) r3 -= r1
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 1922: (57) r3 &= 4095
 1923: (79) r1 = *(u64 *)(r10 -128)
 1924: (0f) r1 += r3
 1925: (bf) r3 = r10
; off = buf_off - len;
 1926: (07) r3 += -40
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 1927: (79) r3 = *(u64 *)(r3 +8)
 1928: (85) call bpf_probe_read_kernel_str#-51856
 1929: (bf) r6 = r0
 1930: (bf) r1 = r6
 1931: (67) r1 <<= 32
 1932: (c7) r1 s>>= 32
 1933: (b7) r2 = 2
; if (sz > 1) {
 1934: (6d) if r2 s> r1 goto pc+1426
 1935: (79) r8 = *(u64 *)(r10 -136)
; buf_off -= 1; // remove null byte termination with slash sign
 1936: (bf) r2 = r8
 1937: (07) r2 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 1938: (57) r2 &= 4095
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 1939: (79) r1 = *(u64 *)(r10 -128)
 1940: (0f) r1 += r2
 1941: (bf) r3 = r10
; buf_off -= 1; // remove null byte termination with slash sign
 1942: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 1943: (b7) r2 = 1
 1944: (85) call bpf_probe_read_compat#-45600
; buf_off -= sz - 1;
 1945: (1f) r8 -= r6
 1946: (7b) *(u64 *)(r10 -136) = r8
; 
 1947: (7b) *(u64 *)(r10 -144) = r7
 1948: (05) goto pc+39
; if (dentry != mnt_root) {
 1949: (79) r1 = *(u64 *)(r10 -120)
 1950: (79) r2 = *(u64 *)(r10 -152)
 1951: (1d) if r1 == r2 goto pc+1409
 1952: (79) r1 = *(u64 *)(r10 -144)
 1953: (5d) if r1 != r6 goto pc+1407
 1954: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 1955: (7b) *(u64 *)(r10 -64) = r6
 1956: (b7) r1 = 24
 1957: (79) r8 = *(u64 *)(r10 -120)
 1958: (bf) r3 = r8
 1959: (0f) r3 += r1
 1960: (bf) r1 = r10
; 
 1961: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 1962: (b7) r2 = 8
 1963: (85) call bpf_probe_read_kernel#-51920
 1964: (b7) r7 = 16
 1965: (0f) r8 += r7
 1966: (79) r1 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 1967: (7b) *(u64 *)(r10 -144) = r1
 1968: (7b) *(u64 *)(r10 -64) = r6
 1969: (bf) r1 = r10
; 
 1970: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 1971: (b7) r2 = 8
 1972: (bf) r3 = r8
 1973: (85) call bpf_probe_read_kernel#-51920
 1974: (79) r8 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 1975: (7b) *(u64 *)(r10 -64) = r6
 1976: (bf) r3 = r8
 1977: (0f) r3 += r7
 1978: (bf) r1 = r10
; 
 1979: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 1980: (b7) r2 = 8
 1981: (85) call bpf_probe_read_kernel#-51920
 1982: (b7) r1 = 32
 1983: (7b) *(u64 *)(r10 -120) = r8
 1984: (0f) r8 += r1
 1985: (7b) *(u64 *)(r10 -160) = r8
 1986: (79) r1 = *(u64 *)(r10 -64)
 1987: (7b) *(u64 *)(r10 -152) = r1
 1988: (b7) r1 = 0
 1989: (79) r3 = *(u64 *)(r10 -160)
 1990: (0f) r3 += r1
 1991: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 1992: (7b) *(u64 *)(r10 -64) = r7
 1993: (bf) r1 = r10
; 
 1994: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 1995: (b7) r2 = 8
 1996: (85) call bpf_probe_read_kernel#-51920
 1997: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 1998: (7b) *(u64 *)(r10 -64) = r7
 1999: (b7) r1 = 24
 2000: (79) r7 = *(u64 *)(r10 -144)
 2001: (bf) r3 = r7
 2002: (0f) r3 += r1
 2003: (bf) r1 = r10
; 
 2004: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 2005: (b7) r2 = 8
 2006: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 2007: (1d) if r7 == r6 goto pc+56
; 
 2008: (79) r7 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 2009: (79) r1 = *(u64 *)(r10 -144)
 2010: (1d) if r1 == r7 goto pc+53
 2011: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 2012: (7b) *(u64 *)(r10 -56) = r1
 2013: (7b) *(u64 *)(r10 -64) = r1
 2014: (b7) r1 = 32
 2015: (79) r3 = *(u64 *)(r10 -144)
 2016: (0f) r3 += r1
 2017: (bf) r1 = r10
 2018: (07) r1 += -64
 2019: (b7) r2 = 16
 2020: (85) call bpf_probe_read_kernel#-51920
 2021: (79) r1 = *(u64 *)(r10 -56)
 2022: (7b) *(u64 *)(r10 -32) = r1
 2023: (79) r1 = *(u64 *)(r10 -64)
 2024: (7b) *(u64 *)(r10 -40) = r1
 2025: (bf) r1 = r10
 2026: (07) r1 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 2027: (61) r1 = *(u32 *)(r1 +4)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 2028: (07) r1 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 2029: (bf) r2 = r1
 2030: (57) r2 &= 4095
; if (off <= buf_off) { // verify no wrap occurred
 2031: (79) r3 = *(u64 *)(r10 -136)
 2032: (67) r3 <<= 32
 2033: (77) r3 >>= 32
; if (off <= buf_off) { // verify no wrap occurred
 2034: (2d) if r2 > r3 goto pc+1326
; off = buf_off - len;
 2035: (79) r3 = *(u64 *)(r10 -136)
 2036: (1f) r3 -= r1
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 2037: (57) r3 &= 4095
 2038: (79) r1 = *(u64 *)(r10 -128)
 2039: (0f) r1 += r3
 2040: (bf) r3 = r10
; off = buf_off - len;
 2041: (07) r3 += -40
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 2042: (79) r3 = *(u64 *)(r3 +8)
 2043: (85) call bpf_probe_read_kernel_str#-51856
 2044: (bf) r6 = r0
 2045: (bf) r1 = r6
 2046: (67) r1 <<= 32
 2047: (c7) r1 s>>= 32
 2048: (b7) r2 = 2
; if (sz > 1) {
 2049: (6d) if r2 s> r1 goto pc+1311
 2050: (79) r8 = *(u64 *)(r10 -136)
; buf_off -= 1; // remove null byte termination with slash sign
 2051: (bf) r2 = r8
 2052: (07) r2 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 2053: (57) r2 &= 4095
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 2054: (79) r1 = *(u64 *)(r10 -128)
 2055: (0f) r1 += r2
 2056: (bf) r3 = r10
; buf_off -= 1; // remove null byte termination with slash sign
 2057: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 2058: (b7) r2 = 1
 2059: (85) call bpf_probe_read_compat#-45600
; buf_off -= sz - 1;
 2060: (1f) r8 -= r6
 2061: (7b) *(u64 *)(r10 -136) = r8
; 
 2062: (7b) *(u64 *)(r10 -144) = r7
 2063: (05) goto pc+39
; if (dentry != mnt_root) {
 2064: (79) r1 = *(u64 *)(r10 -120)
 2065: (79) r2 = *(u64 *)(r10 -152)
 2066: (1d) if r1 == r2 goto pc+1294
 2067: (79) r1 = *(u64 *)(r10 -144)
 2068: (5d) if r1 != r6 goto pc+1292
 2069: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 2070: (7b) *(u64 *)(r10 -64) = r6
 2071: (b7) r1 = 24
 2072: (79) r8 = *(u64 *)(r10 -120)
 2073: (bf) r3 = r8
 2074: (0f) r3 += r1
 2075: (bf) r1 = r10
; 
 2076: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 2077: (b7) r2 = 8
 2078: (85) call bpf_probe_read_kernel#-51920
 2079: (b7) r7 = 16
 2080: (0f) r8 += r7
 2081: (79) r1 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 2082: (7b) *(u64 *)(r10 -144) = r1
 2083: (7b) *(u64 *)(r10 -64) = r6
 2084: (bf) r1 = r10
; 
 2085: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 2086: (b7) r2 = 8
 2087: (bf) r3 = r8
 2088: (85) call bpf_probe_read_kernel#-51920
 2089: (79) r8 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 2090: (7b) *(u64 *)(r10 -64) = r6
 2091: (bf) r3 = r8
 2092: (0f) r3 += r7
 2093: (bf) r1 = r10
; 
 2094: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 2095: (b7) r2 = 8
 2096: (85) call bpf_probe_read_kernel#-51920
 2097: (b7) r1 = 32
 2098: (7b) *(u64 *)(r10 -120) = r8
 2099: (0f) r8 += r1
 2100: (7b) *(u64 *)(r10 -160) = r8
 2101: (79) r1 = *(u64 *)(r10 -64)
 2102: (7b) *(u64 *)(r10 -152) = r1
 2103: (b7) r1 = 0
 2104: (79) r3 = *(u64 *)(r10 -160)
 2105: (0f) r3 += r1
 2106: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 2107: (7b) *(u64 *)(r10 -64) = r7
 2108: (bf) r1 = r10
; 
 2109: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 2110: (b7) r2 = 8
 2111: (85) call bpf_probe_read_kernel#-51920
 2112: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 2113: (7b) *(u64 *)(r10 -64) = r7
 2114: (b7) r1 = 24
 2115: (79) r7 = *(u64 *)(r10 -144)
 2116: (bf) r3 = r7
 2117: (0f) r3 += r1
 2118: (bf) r1 = r10
; 
 2119: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 2120: (b7) r2 = 8
 2121: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 2122: (1d) if r7 == r6 goto pc+56
; 
 2123: (79) r7 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 2124: (79) r1 = *(u64 *)(r10 -144)
 2125: (1d) if r1 == r7 goto pc+53
 2126: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 2127: (7b) *(u64 *)(r10 -56) = r1
 2128: (7b) *(u64 *)(r10 -64) = r1
 2129: (b7) r1 = 32
 2130: (79) r3 = *(u64 *)(r10 -144)
 2131: (0f) r3 += r1
 2132: (bf) r1 = r10
 2133: (07) r1 += -64
 2134: (b7) r2 = 16
 2135: (85) call bpf_probe_read_kernel#-51920
 2136: (79) r1 = *(u64 *)(r10 -56)
 2137: (7b) *(u64 *)(r10 -32) = r1
 2138: (79) r1 = *(u64 *)(r10 -64)
 2139: (7b) *(u64 *)(r10 -40) = r1
 2140: (bf) r1 = r10
 2141: (07) r1 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 2142: (61) r1 = *(u32 *)(r1 +4)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 2143: (07) r1 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 2144: (bf) r2 = r1
 2145: (57) r2 &= 4095
; if (off <= buf_off) { // verify no wrap occurred
 2146: (79) r3 = *(u64 *)(r10 -136)
 2147: (67) r3 <<= 32
 2148: (77) r3 >>= 32
; if (off <= buf_off) { // verify no wrap occurred
 2149: (2d) if r2 > r3 goto pc+1211
; off = buf_off - len;
 2150: (79) r3 = *(u64 *)(r10 -136)
 2151: (1f) r3 -= r1
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 2152: (57) r3 &= 4095
 2153: (79) r1 = *(u64 *)(r10 -128)
 2154: (0f) r1 += r3
 2155: (bf) r3 = r10
; off = buf_off - len;
 2156: (07) r3 += -40
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 2157: (79) r3 = *(u64 *)(r3 +8)
 2158: (85) call bpf_probe_read_kernel_str#-51856
 2159: (bf) r6 = r0
 2160: (bf) r1 = r6
 2161: (67) r1 <<= 32
 2162: (c7) r1 s>>= 32
 2163: (b7) r2 = 2
; if (sz > 1) {
 2164: (6d) if r2 s> r1 goto pc+1196
 2165: (79) r8 = *(u64 *)(r10 -136)
; buf_off -= 1; // remove null byte termination with slash sign
 2166: (bf) r2 = r8
 2167: (07) r2 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 2168: (57) r2 &= 4095
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 2169: (79) r1 = *(u64 *)(r10 -128)
 2170: (0f) r1 += r2
 2171: (bf) r3 = r10
; buf_off -= 1; // remove null byte termination with slash sign
 2172: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 2173: (b7) r2 = 1
 2174: (85) call bpf_probe_read_compat#-45600
; buf_off -= sz - 1;
 2175: (1f) r8 -= r6
 2176: (7b) *(u64 *)(r10 -136) = r8
; 
 2177: (7b) *(u64 *)(r10 -144) = r7
 2178: (05) goto pc+39
; if (dentry != mnt_root) {
 2179: (79) r1 = *(u64 *)(r10 -120)
 2180: (79) r2 = *(u64 *)(r10 -152)
 2181: (1d) if r1 == r2 goto pc+1179
 2182: (79) r1 = *(u64 *)(r10 -144)
 2183: (5d) if r1 != r6 goto pc+1177
 2184: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 2185: (7b) *(u64 *)(r10 -64) = r6
 2186: (b7) r1 = 24
 2187: (79) r8 = *(u64 *)(r10 -120)
 2188: (bf) r3 = r8
 2189: (0f) r3 += r1
 2190: (bf) r1 = r10
; 
 2191: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 2192: (b7) r2 = 8
 2193: (85) call bpf_probe_read_kernel#-51920
 2194: (b7) r7 = 16
 2195: (0f) r8 += r7
 2196: (79) r1 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 2197: (7b) *(u64 *)(r10 -144) = r1
 2198: (7b) *(u64 *)(r10 -64) = r6
 2199: (bf) r1 = r10
; 
 2200: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 2201: (b7) r2 = 8
 2202: (bf) r3 = r8
 2203: (85) call bpf_probe_read_kernel#-51920
 2204: (79) r8 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 2205: (7b) *(u64 *)(r10 -64) = r6
 2206: (bf) r3 = r8
 2207: (0f) r3 += r7
 2208: (bf) r1 = r10
; 
 2209: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 2210: (b7) r2 = 8
 2211: (85) call bpf_probe_read_kernel#-51920
 2212: (b7) r1 = 32
 2213: (7b) *(u64 *)(r10 -120) = r8
 2214: (0f) r8 += r1
 2215: (7b) *(u64 *)(r10 -160) = r8
 2216: (79) r1 = *(u64 *)(r10 -64)
 2217: (7b) *(u64 *)(r10 -152) = r1
 2218: (b7) r1 = 0
 2219: (79) r3 = *(u64 *)(r10 -160)
 2220: (0f) r3 += r1
 2221: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 2222: (7b) *(u64 *)(r10 -64) = r7
 2223: (bf) r1 = r10
; 
 2224: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 2225: (b7) r2 = 8
 2226: (85) call bpf_probe_read_kernel#-51920
 2227: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 2228: (7b) *(u64 *)(r10 -64) = r7
 2229: (b7) r1 = 24
 2230: (79) r7 = *(u64 *)(r10 -144)
 2231: (bf) r3 = r7
 2232: (0f) r3 += r1
 2233: (bf) r1 = r10
; 
 2234: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 2235: (b7) r2 = 8
 2236: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 2237: (1d) if r7 == r6 goto pc+56
; 
 2238: (79) r7 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 2239: (79) r1 = *(u64 *)(r10 -144)
 2240: (1d) if r1 == r7 goto pc+53
 2241: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 2242: (7b) *(u64 *)(r10 -56) = r1
 2243: (7b) *(u64 *)(r10 -64) = r1
 2244: (b7) r1 = 32
 2245: (79) r3 = *(u64 *)(r10 -144)
 2246: (0f) r3 += r1
 2247: (bf) r1 = r10
 2248: (07) r1 += -64
 2249: (b7) r2 = 16
 2250: (85) call bpf_probe_read_kernel#-51920
 2251: (79) r1 = *(u64 *)(r10 -56)
 2252: (7b) *(u64 *)(r10 -32) = r1
 2253: (79) r1 = *(u64 *)(r10 -64)
 2254: (7b) *(u64 *)(r10 -40) = r1
 2255: (bf) r1 = r10
 2256: (07) r1 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 2257: (61) r1 = *(u32 *)(r1 +4)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 2258: (07) r1 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 2259: (bf) r2 = r1
 2260: (57) r2 &= 4095
; if (off <= buf_off) { // verify no wrap occurred
 2261: (79) r3 = *(u64 *)(r10 -136)
 2262: (67) r3 <<= 32
 2263: (77) r3 >>= 32
; if (off <= buf_off) { // verify no wrap occurred
 2264: (2d) if r2 > r3 goto pc+1096
; off = buf_off - len;
 2265: (79) r3 = *(u64 *)(r10 -136)
 2266: (1f) r3 -= r1
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 2267: (57) r3 &= 4095
 2268: (79) r1 = *(u64 *)(r10 -128)
 2269: (0f) r1 += r3
 2270: (bf) r3 = r10
; off = buf_off - len;
 2271: (07) r3 += -40
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 2272: (79) r3 = *(u64 *)(r3 +8)
 2273: (85) call bpf_probe_read_kernel_str#-51856
 2274: (bf) r6 = r0
 2275: (bf) r1 = r6
 2276: (67) r1 <<= 32
 2277: (c7) r1 s>>= 32
 2278: (b7) r2 = 2
; if (sz > 1) {
 2279: (6d) if r2 s> r1 goto pc+1081
 2280: (79) r8 = *(u64 *)(r10 -136)
; buf_off -= 1; // remove null byte termination with slash sign
 2281: (bf) r2 = r8
 2282: (07) r2 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 2283: (57) r2 &= 4095
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 2284: (79) r1 = *(u64 *)(r10 -128)
 2285: (0f) r1 += r2
 2286: (bf) r3 = r10
; buf_off -= 1; // remove null byte termination with slash sign
 2287: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 2288: (b7) r2 = 1
 2289: (85) call bpf_probe_read_compat#-45600
; buf_off -= sz - 1;
 2290: (1f) r8 -= r6
 2291: (7b) *(u64 *)(r10 -136) = r8
; 
 2292: (7b) *(u64 *)(r10 -144) = r7
 2293: (05) goto pc+39
; if (dentry != mnt_root) {
 2294: (79) r1 = *(u64 *)(r10 -120)
 2295: (79) r2 = *(u64 *)(r10 -152)
 2296: (1d) if r1 == r2 goto pc+1064
 2297: (79) r1 = *(u64 *)(r10 -144)
 2298: (5d) if r1 != r6 goto pc+1062
 2299: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 2300: (7b) *(u64 *)(r10 -64) = r6
 2301: (b7) r1 = 24
 2302: (79) r8 = *(u64 *)(r10 -120)
 2303: (bf) r3 = r8
 2304: (0f) r3 += r1
 2305: (bf) r1 = r10
; 
 2306: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 2307: (b7) r2 = 8
 2308: (85) call bpf_probe_read_kernel#-51920
 2309: (b7) r7 = 16
 2310: (0f) r8 += r7
 2311: (79) r1 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 2312: (7b) *(u64 *)(r10 -144) = r1
 2313: (7b) *(u64 *)(r10 -64) = r6
 2314: (bf) r1 = r10
; 
 2315: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 2316: (b7) r2 = 8
 2317: (bf) r3 = r8
 2318: (85) call bpf_probe_read_kernel#-51920
 2319: (79) r8 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 2320: (7b) *(u64 *)(r10 -64) = r6
 2321: (bf) r3 = r8
 2322: (0f) r3 += r7
 2323: (bf) r1 = r10
; 
 2324: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 2325: (b7) r2 = 8
 2326: (85) call bpf_probe_read_kernel#-51920
 2327: (b7) r1 = 32
 2328: (7b) *(u64 *)(r10 -120) = r8
 2329: (0f) r8 += r1
 2330: (7b) *(u64 *)(r10 -160) = r8
 2331: (79) r1 = *(u64 *)(r10 -64)
 2332: (7b) *(u64 *)(r10 -152) = r1
 2333: (b7) r1 = 0
 2334: (79) r3 = *(u64 *)(r10 -160)
 2335: (0f) r3 += r1
 2336: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 2337: (7b) *(u64 *)(r10 -64) = r7
 2338: (bf) r1 = r10
; 
 2339: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 2340: (b7) r2 = 8
 2341: (85) call bpf_probe_read_kernel#-51920
 2342: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 2343: (7b) *(u64 *)(r10 -64) = r7
 2344: (b7) r1 = 24
 2345: (79) r7 = *(u64 *)(r10 -144)
 2346: (bf) r3 = r7
 2347: (0f) r3 += r1
 2348: (bf) r1 = r10
; 
 2349: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 2350: (b7) r2 = 8
 2351: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 2352: (1d) if r7 == r6 goto pc+56
; 
 2353: (79) r7 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 2354: (79) r1 = *(u64 *)(r10 -144)
 2355: (1d) if r1 == r7 goto pc+53
 2356: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 2357: (7b) *(u64 *)(r10 -56) = r1
 2358: (7b) *(u64 *)(r10 -64) = r1
 2359: (b7) r1 = 32
 2360: (79) r3 = *(u64 *)(r10 -144)
 2361: (0f) r3 += r1
 2362: (bf) r1 = r10
 2363: (07) r1 += -64
 2364: (b7) r2 = 16
 2365: (85) call bpf_probe_read_kernel#-51920
 2366: (79) r1 = *(u64 *)(r10 -56)
 2367: (7b) *(u64 *)(r10 -32) = r1
 2368: (79) r1 = *(u64 *)(r10 -64)
 2369: (7b) *(u64 *)(r10 -40) = r1
 2370: (bf) r1 = r10
 2371: (07) r1 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 2372: (61) r1 = *(u32 *)(r1 +4)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 2373: (07) r1 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 2374: (bf) r2 = r1
 2375: (57) r2 &= 4095
; if (off <= buf_off) { // verify no wrap occurred
 2376: (79) r3 = *(u64 *)(r10 -136)
 2377: (67) r3 <<= 32
 2378: (77) r3 >>= 32
; if (off <= buf_off) { // verify no wrap occurred
 2379: (2d) if r2 > r3 goto pc+981
; off = buf_off - len;
 2380: (79) r3 = *(u64 *)(r10 -136)
 2381: (1f) r3 -= r1
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 2382: (57) r3 &= 4095
 2383: (79) r1 = *(u64 *)(r10 -128)
 2384: (0f) r1 += r3
 2385: (bf) r3 = r10
; off = buf_off - len;
 2386: (07) r3 += -40
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 2387: (79) r3 = *(u64 *)(r3 +8)
 2388: (85) call bpf_probe_read_kernel_str#-51856
 2389: (bf) r6 = r0
 2390: (bf) r1 = r6
 2391: (67) r1 <<= 32
 2392: (c7) r1 s>>= 32
 2393: (b7) r2 = 2
; if (sz > 1) {
 2394: (6d) if r2 s> r1 goto pc+966
 2395: (79) r8 = *(u64 *)(r10 -136)
; buf_off -= 1; // remove null byte termination with slash sign
 2396: (bf) r2 = r8
 2397: (07) r2 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 2398: (57) r2 &= 4095
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 2399: (79) r1 = *(u64 *)(r10 -128)
 2400: (0f) r1 += r2
 2401: (bf) r3 = r10
; buf_off -= 1; // remove null byte termination with slash sign
 2402: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 2403: (b7) r2 = 1
 2404: (85) call bpf_probe_read_compat#-45600
; buf_off -= sz - 1;
 2405: (1f) r8 -= r6
 2406: (7b) *(u64 *)(r10 -136) = r8
; 
 2407: (7b) *(u64 *)(r10 -144) = r7
 2408: (05) goto pc+39
; if (dentry != mnt_root) {
 2409: (79) r1 = *(u64 *)(r10 -120)
 2410: (79) r2 = *(u64 *)(r10 -152)
 2411: (1d) if r1 == r2 goto pc+949
 2412: (79) r1 = *(u64 *)(r10 -144)
 2413: (5d) if r1 != r6 goto pc+947
 2414: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 2415: (7b) *(u64 *)(r10 -64) = r6
 2416: (b7) r1 = 24
 2417: (79) r8 = *(u64 *)(r10 -120)
 2418: (bf) r3 = r8
 2419: (0f) r3 += r1
 2420: (bf) r1 = r10
; 
 2421: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 2422: (b7) r2 = 8
 2423: (85) call bpf_probe_read_kernel#-51920
 2424: (b7) r7 = 16
 2425: (0f) r8 += r7
 2426: (79) r1 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 2427: (7b) *(u64 *)(r10 -144) = r1
 2428: (7b) *(u64 *)(r10 -64) = r6
 2429: (bf) r1 = r10
; 
 2430: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 2431: (b7) r2 = 8
 2432: (bf) r3 = r8
 2433: (85) call bpf_probe_read_kernel#-51920
 2434: (79) r8 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 2435: (7b) *(u64 *)(r10 -64) = r6
 2436: (bf) r3 = r8
 2437: (0f) r3 += r7
 2438: (bf) r1 = r10
; 
 2439: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 2440: (b7) r2 = 8
 2441: (85) call bpf_probe_read_kernel#-51920
 2442: (b7) r1 = 32
 2443: (7b) *(u64 *)(r10 -120) = r8
 2444: (0f) r8 += r1
 2445: (7b) *(u64 *)(r10 -160) = r8
 2446: (79) r1 = *(u64 *)(r10 -64)
 2447: (7b) *(u64 *)(r10 -152) = r1
 2448: (b7) r1 = 0
 2449: (79) r3 = *(u64 *)(r10 -160)
 2450: (0f) r3 += r1
 2451: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 2452: (7b) *(u64 *)(r10 -64) = r7
 2453: (bf) r1 = r10
; 
 2454: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 2455: (b7) r2 = 8
 2456: (85) call bpf_probe_read_kernel#-51920
 2457: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 2458: (7b) *(u64 *)(r10 -64) = r7
 2459: (b7) r1 = 24
 2460: (79) r7 = *(u64 *)(r10 -144)
 2461: (bf) r3 = r7
 2462: (0f) r3 += r1
 2463: (bf) r1 = r10
; 
 2464: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 2465: (b7) r2 = 8
 2466: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 2467: (1d) if r7 == r6 goto pc+56
; 
 2468: (79) r7 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 2469: (79) r1 = *(u64 *)(r10 -144)
 2470: (1d) if r1 == r7 goto pc+53
 2471: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 2472: (7b) *(u64 *)(r10 -56) = r1
 2473: (7b) *(u64 *)(r10 -64) = r1
 2474: (b7) r1 = 32
 2475: (79) r3 = *(u64 *)(r10 -144)
 2476: (0f) r3 += r1
 2477: (bf) r1 = r10
 2478: (07) r1 += -64
 2479: (b7) r2 = 16
 2480: (85) call bpf_probe_read_kernel#-51920
 2481: (79) r1 = *(u64 *)(r10 -56)
 2482: (7b) *(u64 *)(r10 -32) = r1
 2483: (79) r1 = *(u64 *)(r10 -64)
 2484: (7b) *(u64 *)(r10 -40) = r1
 2485: (bf) r1 = r10
 2486: (07) r1 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 2487: (61) r1 = *(u32 *)(r1 +4)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 2488: (07) r1 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 2489: (bf) r2 = r1
 2490: (57) r2 &= 4095
; if (off <= buf_off) { // verify no wrap occurred
 2491: (79) r3 = *(u64 *)(r10 -136)
 2492: (67) r3 <<= 32
 2493: (77) r3 >>= 32
; if (off <= buf_off) { // verify no wrap occurred
 2494: (2d) if r2 > r3 goto pc+866
; off = buf_off - len;
 2495: (79) r3 = *(u64 *)(r10 -136)
 2496: (1f) r3 -= r1
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 2497: (57) r3 &= 4095
 2498: (79) r1 = *(u64 *)(r10 -128)
 2499: (0f) r1 += r3
 2500: (bf) r3 = r10
; off = buf_off - len;
 2501: (07) r3 += -40
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 2502: (79) r3 = *(u64 *)(r3 +8)
 2503: (85) call bpf_probe_read_kernel_str#-51856
 2504: (bf) r6 = r0
 2505: (bf) r1 = r6
 2506: (67) r1 <<= 32
 2507: (c7) r1 s>>= 32
 2508: (b7) r2 = 2
; if (sz > 1) {
 2509: (6d) if r2 s> r1 goto pc+851
 2510: (79) r8 = *(u64 *)(r10 -136)
; buf_off -= 1; // remove null byte termination with slash sign
 2511: (bf) r2 = r8
 2512: (07) r2 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 2513: (57) r2 &= 4095
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 2514: (79) r1 = *(u64 *)(r10 -128)
 2515: (0f) r1 += r2
 2516: (bf) r3 = r10
; buf_off -= 1; // remove null byte termination with slash sign
 2517: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 2518: (b7) r2 = 1
 2519: (85) call bpf_probe_read_compat#-45600
; buf_off -= sz - 1;
 2520: (1f) r8 -= r6
 2521: (7b) *(u64 *)(r10 -136) = r8
; 
 2522: (7b) *(u64 *)(r10 -144) = r7
 2523: (05) goto pc+39
; if (dentry != mnt_root) {
 2524: (79) r1 = *(u64 *)(r10 -120)
 2525: (79) r2 = *(u64 *)(r10 -152)
 2526: (1d) if r1 == r2 goto pc+834
 2527: (79) r1 = *(u64 *)(r10 -144)
 2528: (5d) if r1 != r6 goto pc+832
 2529: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 2530: (7b) *(u64 *)(r10 -64) = r6
 2531: (b7) r1 = 24
 2532: (79) r8 = *(u64 *)(r10 -120)
 2533: (bf) r3 = r8
 2534: (0f) r3 += r1
 2535: (bf) r1 = r10
; 
 2536: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 2537: (b7) r2 = 8
 2538: (85) call bpf_probe_read_kernel#-51920
 2539: (b7) r7 = 16
 2540: (0f) r8 += r7
 2541: (79) r1 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 2542: (7b) *(u64 *)(r10 -144) = r1
 2543: (7b) *(u64 *)(r10 -64) = r6
 2544: (bf) r1 = r10
; 
 2545: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 2546: (b7) r2 = 8
 2547: (bf) r3 = r8
 2548: (85) call bpf_probe_read_kernel#-51920
 2549: (79) r8 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 2550: (7b) *(u64 *)(r10 -64) = r6
 2551: (bf) r3 = r8
 2552: (0f) r3 += r7
 2553: (bf) r1 = r10
; 
 2554: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 2555: (b7) r2 = 8
 2556: (85) call bpf_probe_read_kernel#-51920
 2557: (b7) r1 = 32
 2558: (7b) *(u64 *)(r10 -120) = r8
 2559: (0f) r8 += r1
 2560: (7b) *(u64 *)(r10 -160) = r8
 2561: (79) r1 = *(u64 *)(r10 -64)
 2562: (7b) *(u64 *)(r10 -152) = r1
 2563: (b7) r1 = 0
 2564: (79) r3 = *(u64 *)(r10 -160)
 2565: (0f) r3 += r1
 2566: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 2567: (7b) *(u64 *)(r10 -64) = r7
 2568: (bf) r1 = r10
; 
 2569: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 2570: (b7) r2 = 8
 2571: (85) call bpf_probe_read_kernel#-51920
 2572: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 2573: (7b) *(u64 *)(r10 -64) = r7
 2574: (b7) r1 = 24
 2575: (79) r7 = *(u64 *)(r10 -144)
 2576: (bf) r3 = r7
 2577: (0f) r3 += r1
 2578: (bf) r1 = r10
; 
 2579: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 2580: (b7) r2 = 8
 2581: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 2582: (1d) if r7 == r6 goto pc+56
; 
 2583: (79) r7 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 2584: (79) r1 = *(u64 *)(r10 -144)
 2585: (1d) if r1 == r7 goto pc+53
 2586: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 2587: (7b) *(u64 *)(r10 -56) = r1
 2588: (7b) *(u64 *)(r10 -64) = r1
 2589: (b7) r1 = 32
 2590: (79) r3 = *(u64 *)(r10 -144)
 2591: (0f) r3 += r1
 2592: (bf) r1 = r10
 2593: (07) r1 += -64
 2594: (b7) r2 = 16
 2595: (85) call bpf_probe_read_kernel#-51920
 2596: (79) r1 = *(u64 *)(r10 -56)
 2597: (7b) *(u64 *)(r10 -32) = r1
 2598: (79) r1 = *(u64 *)(r10 -64)
 2599: (7b) *(u64 *)(r10 -40) = r1
 2600: (bf) r1 = r10
 2601: (07) r1 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 2602: (61) r1 = *(u32 *)(r1 +4)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 2603: (07) r1 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 2604: (bf) r2 = r1
 2605: (57) r2 &= 4095
; if (off <= buf_off) { // verify no wrap occurred
 2606: (79) r3 = *(u64 *)(r10 -136)
 2607: (67) r3 <<= 32
 2608: (77) r3 >>= 32
; if (off <= buf_off) { // verify no wrap occurred
 2609: (2d) if r2 > r3 goto pc+751
; off = buf_off - len;
 2610: (79) r3 = *(u64 *)(r10 -136)
 2611: (1f) r3 -= r1
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 2612: (57) r3 &= 4095
 2613: (79) r1 = *(u64 *)(r10 -128)
 2614: (0f) r1 += r3
 2615: (bf) r3 = r10
; off = buf_off - len;
 2616: (07) r3 += -40
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 2617: (79) r3 = *(u64 *)(r3 +8)
 2618: (85) call bpf_probe_read_kernel_str#-51856
 2619: (bf) r6 = r0
 2620: (bf) r1 = r6
 2621: (67) r1 <<= 32
 2622: (c7) r1 s>>= 32
 2623: (b7) r2 = 2
; if (sz > 1) {
 2624: (6d) if r2 s> r1 goto pc+736
 2625: (79) r8 = *(u64 *)(r10 -136)
; buf_off -= 1; // remove null byte termination with slash sign
 2626: (bf) r2 = r8
 2627: (07) r2 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 2628: (57) r2 &= 4095
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 2629: (79) r1 = *(u64 *)(r10 -128)
 2630: (0f) r1 += r2
 2631: (bf) r3 = r10
; buf_off -= 1; // remove null byte termination with slash sign
 2632: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 2633: (b7) r2 = 1
 2634: (85) call bpf_probe_read_compat#-45600
; buf_off -= sz - 1;
 2635: (1f) r8 -= r6
 2636: (7b) *(u64 *)(r10 -136) = r8
; 
 2637: (7b) *(u64 *)(r10 -144) = r7
 2638: (05) goto pc+39
; if (dentry != mnt_root) {
 2639: (79) r1 = *(u64 *)(r10 -120)
 2640: (79) r2 = *(u64 *)(r10 -152)
 2641: (1d) if r1 == r2 goto pc+719
 2642: (79) r1 = *(u64 *)(r10 -144)
 2643: (5d) if r1 != r6 goto pc+717
 2644: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 2645: (7b) *(u64 *)(r10 -64) = r6
 2646: (b7) r1 = 24
 2647: (79) r8 = *(u64 *)(r10 -120)
 2648: (bf) r3 = r8
 2649: (0f) r3 += r1
 2650: (bf) r1 = r10
; 
 2651: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 2652: (b7) r2 = 8
 2653: (85) call bpf_probe_read_kernel#-51920
 2654: (b7) r7 = 16
 2655: (0f) r8 += r7
 2656: (79) r1 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 2657: (7b) *(u64 *)(r10 -144) = r1
 2658: (7b) *(u64 *)(r10 -64) = r6
 2659: (bf) r1 = r10
; 
 2660: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 2661: (b7) r2 = 8
 2662: (bf) r3 = r8
 2663: (85) call bpf_probe_read_kernel#-51920
 2664: (79) r8 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 2665: (7b) *(u64 *)(r10 -64) = r6
 2666: (bf) r3 = r8
 2667: (0f) r3 += r7
 2668: (bf) r1 = r10
; 
 2669: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 2670: (b7) r2 = 8
 2671: (85) call bpf_probe_read_kernel#-51920
 2672: (b7) r1 = 32
 2673: (7b) *(u64 *)(r10 -120) = r8
 2674: (0f) r8 += r1
 2675: (7b) *(u64 *)(r10 -160) = r8
 2676: (79) r1 = *(u64 *)(r10 -64)
 2677: (7b) *(u64 *)(r10 -152) = r1
 2678: (b7) r1 = 0
 2679: (79) r3 = *(u64 *)(r10 -160)
 2680: (0f) r3 += r1
 2681: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 2682: (7b) *(u64 *)(r10 -64) = r7
 2683: (bf) r1 = r10
; 
 2684: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 2685: (b7) r2 = 8
 2686: (85) call bpf_probe_read_kernel#-51920
 2687: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 2688: (7b) *(u64 *)(r10 -64) = r7
 2689: (b7) r1 = 24
 2690: (79) r7 = *(u64 *)(r10 -144)
 2691: (bf) r3 = r7
 2692: (0f) r3 += r1
 2693: (bf) r1 = r10
; 
 2694: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 2695: (b7) r2 = 8
 2696: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 2697: (1d) if r7 == r6 goto pc+56
; 
 2698: (79) r7 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 2699: (79) r1 = *(u64 *)(r10 -144)
 2700: (1d) if r1 == r7 goto pc+53
 2701: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 2702: (7b) *(u64 *)(r10 -56) = r1
 2703: (7b) *(u64 *)(r10 -64) = r1
 2704: (b7) r1 = 32
 2705: (79) r3 = *(u64 *)(r10 -144)
 2706: (0f) r3 += r1
 2707: (bf) r1 = r10
 2708: (07) r1 += -64
 2709: (b7) r2 = 16
 2710: (85) call bpf_probe_read_kernel#-51920
 2711: (79) r1 = *(u64 *)(r10 -56)
 2712: (7b) *(u64 *)(r10 -32) = r1
 2713: (79) r1 = *(u64 *)(r10 -64)
 2714: (7b) *(u64 *)(r10 -40) = r1
 2715: (bf) r1 = r10
 2716: (07) r1 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 2717: (61) r1 = *(u32 *)(r1 +4)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 2718: (07) r1 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 2719: (bf) r2 = r1
 2720: (57) r2 &= 4095
; if (off <= buf_off) { // verify no wrap occurred
 2721: (79) r3 = *(u64 *)(r10 -136)
 2722: (67) r3 <<= 32
 2723: (77) r3 >>= 32
; if (off <= buf_off) { // verify no wrap occurred
 2724: (2d) if r2 > r3 goto pc+636
; off = buf_off - len;
 2725: (79) r3 = *(u64 *)(r10 -136)
 2726: (1f) r3 -= r1
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 2727: (57) r3 &= 4095
 2728: (79) r1 = *(u64 *)(r10 -128)
 2729: (0f) r1 += r3
 2730: (bf) r3 = r10
; off = buf_off - len;
 2731: (07) r3 += -40
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 2732: (79) r3 = *(u64 *)(r3 +8)
 2733: (85) call bpf_probe_read_kernel_str#-51856
 2734: (bf) r6 = r0
 2735: (bf) r1 = r6
 2736: (67) r1 <<= 32
 2737: (c7) r1 s>>= 32
 2738: (b7) r2 = 2
; if (sz > 1) {
 2739: (6d) if r2 s> r1 goto pc+621
 2740: (79) r8 = *(u64 *)(r10 -136)
; buf_off -= 1; // remove null byte termination with slash sign
 2741: (bf) r2 = r8
 2742: (07) r2 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 2743: (57) r2 &= 4095
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 2744: (79) r1 = *(u64 *)(r10 -128)
 2745: (0f) r1 += r2
 2746: (bf) r3 = r10
; buf_off -= 1; // remove null byte termination with slash sign
 2747: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 2748: (b7) r2 = 1
 2749: (85) call bpf_probe_read_compat#-45600
; buf_off -= sz - 1;
 2750: (1f) r8 -= r6
 2751: (7b) *(u64 *)(r10 -136) = r8
; 
 2752: (7b) *(u64 *)(r10 -144) = r7
 2753: (05) goto pc+39
; if (dentry != mnt_root) {
 2754: (79) r1 = *(u64 *)(r10 -120)
 2755: (79) r2 = *(u64 *)(r10 -152)
 2756: (1d) if r1 == r2 goto pc+604
 2757: (79) r1 = *(u64 *)(r10 -144)
 2758: (5d) if r1 != r6 goto pc+602
 2759: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 2760: (7b) *(u64 *)(r10 -64) = r6
 2761: (b7) r1 = 24
 2762: (79) r8 = *(u64 *)(r10 -120)
 2763: (bf) r3 = r8
 2764: (0f) r3 += r1
 2765: (bf) r1 = r10
; 
 2766: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 2767: (b7) r2 = 8
 2768: (85) call bpf_probe_read_kernel#-51920
 2769: (b7) r7 = 16
 2770: (0f) r8 += r7
 2771: (79) r1 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 2772: (7b) *(u64 *)(r10 -144) = r1
 2773: (7b) *(u64 *)(r10 -64) = r6
 2774: (bf) r1 = r10
; 
 2775: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 2776: (b7) r2 = 8
 2777: (bf) r3 = r8
 2778: (85) call bpf_probe_read_kernel#-51920
 2779: (79) r8 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 2780: (7b) *(u64 *)(r10 -64) = r6
 2781: (bf) r3 = r8
 2782: (0f) r3 += r7
 2783: (bf) r1 = r10
; 
 2784: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 2785: (b7) r2 = 8
 2786: (85) call bpf_probe_read_kernel#-51920
 2787: (b7) r1 = 32
 2788: (7b) *(u64 *)(r10 -120) = r8
 2789: (0f) r8 += r1
 2790: (7b) *(u64 *)(r10 -160) = r8
 2791: (79) r1 = *(u64 *)(r10 -64)
 2792: (7b) *(u64 *)(r10 -152) = r1
 2793: (b7) r1 = 0
 2794: (79) r3 = *(u64 *)(r10 -160)
 2795: (0f) r3 += r1
 2796: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 2797: (7b) *(u64 *)(r10 -64) = r7
 2798: (bf) r1 = r10
; 
 2799: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 2800: (b7) r2 = 8
 2801: (85) call bpf_probe_read_kernel#-51920
 2802: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 2803: (7b) *(u64 *)(r10 -64) = r7
 2804: (b7) r1 = 24
 2805: (79) r7 = *(u64 *)(r10 -144)
 2806: (bf) r3 = r7
 2807: (0f) r3 += r1
 2808: (bf) r1 = r10
; 
 2809: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 2810: (b7) r2 = 8
 2811: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 2812: (1d) if r7 == r6 goto pc+56
; 
 2813: (79) r7 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 2814: (79) r1 = *(u64 *)(r10 -144)
 2815: (1d) if r1 == r7 goto pc+53
 2816: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 2817: (7b) *(u64 *)(r10 -56) = r1
 2818: (7b) *(u64 *)(r10 -64) = r1
 2819: (b7) r1 = 32
 2820: (79) r3 = *(u64 *)(r10 -144)
 2821: (0f) r3 += r1
 2822: (bf) r1 = r10
 2823: (07) r1 += -64
 2824: (b7) r2 = 16
 2825: (85) call bpf_probe_read_kernel#-51920
 2826: (79) r1 = *(u64 *)(r10 -56)
 2827: (7b) *(u64 *)(r10 -32) = r1
 2828: (79) r1 = *(u64 *)(r10 -64)
 2829: (7b) *(u64 *)(r10 -40) = r1
 2830: (bf) r1 = r10
 2831: (07) r1 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 2832: (61) r1 = *(u32 *)(r1 +4)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 2833: (07) r1 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 2834: (bf) r2 = r1
 2835: (57) r2 &= 4095
; if (off <= buf_off) { // verify no wrap occurred
 2836: (79) r3 = *(u64 *)(r10 -136)
 2837: (67) r3 <<= 32
 2838: (77) r3 >>= 32
; if (off <= buf_off) { // verify no wrap occurred
 2839: (2d) if r2 > r3 goto pc+521
; off = buf_off - len;
 2840: (79) r3 = *(u64 *)(r10 -136)
 2841: (1f) r3 -= r1
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 2842: (57) r3 &= 4095
 2843: (79) r1 = *(u64 *)(r10 -128)
 2844: (0f) r1 += r3
 2845: (bf) r3 = r10
; off = buf_off - len;
 2846: (07) r3 += -40
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 2847: (79) r3 = *(u64 *)(r3 +8)
 2848: (85) call bpf_probe_read_kernel_str#-51856
 2849: (bf) r6 = r0
 2850: (bf) r1 = r6
 2851: (67) r1 <<= 32
 2852: (c7) r1 s>>= 32
 2853: (b7) r2 = 2
; if (sz > 1) {
 2854: (6d) if r2 s> r1 goto pc+506
 2855: (79) r8 = *(u64 *)(r10 -136)
; buf_off -= 1; // remove null byte termination with slash sign
 2856: (bf) r2 = r8
 2857: (07) r2 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 2858: (57) r2 &= 4095
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 2859: (79) r1 = *(u64 *)(r10 -128)
 2860: (0f) r1 += r2
 2861: (bf) r3 = r10
; buf_off -= 1; // remove null byte termination with slash sign
 2862: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 2863: (b7) r2 = 1
 2864: (85) call bpf_probe_read_compat#-45600
; buf_off -= sz - 1;
 2865: (1f) r8 -= r6
 2866: (7b) *(u64 *)(r10 -136) = r8
; 
 2867: (7b) *(u64 *)(r10 -144) = r7
 2868: (05) goto pc+39
; if (dentry != mnt_root) {
 2869: (79) r1 = *(u64 *)(r10 -120)
 2870: (79) r2 = *(u64 *)(r10 -152)
 2871: (1d) if r1 == r2 goto pc+489
 2872: (79) r1 = *(u64 *)(r10 -144)
 2873: (5d) if r1 != r6 goto pc+487
 2874: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 2875: (7b) *(u64 *)(r10 -64) = r6
 2876: (b7) r1 = 24
 2877: (79) r8 = *(u64 *)(r10 -120)
 2878: (bf) r3 = r8
 2879: (0f) r3 += r1
 2880: (bf) r1 = r10
; 
 2881: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 2882: (b7) r2 = 8
 2883: (85) call bpf_probe_read_kernel#-51920
 2884: (b7) r7 = 16
 2885: (0f) r8 += r7
 2886: (79) r1 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 2887: (7b) *(u64 *)(r10 -144) = r1
 2888: (7b) *(u64 *)(r10 -64) = r6
 2889: (bf) r1 = r10
; 
 2890: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 2891: (b7) r2 = 8
 2892: (bf) r3 = r8
 2893: (85) call bpf_probe_read_kernel#-51920
 2894: (79) r8 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 2895: (7b) *(u64 *)(r10 -64) = r6
 2896: (bf) r3 = r8
 2897: (0f) r3 += r7
 2898: (bf) r1 = r10
; 
 2899: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 2900: (b7) r2 = 8
 2901: (85) call bpf_probe_read_kernel#-51920
 2902: (b7) r1 = 32
 2903: (7b) *(u64 *)(r10 -120) = r8
 2904: (0f) r8 += r1
 2905: (7b) *(u64 *)(r10 -160) = r8
 2906: (79) r1 = *(u64 *)(r10 -64)
 2907: (7b) *(u64 *)(r10 -152) = r1
 2908: (b7) r1 = 0
 2909: (79) r3 = *(u64 *)(r10 -160)
 2910: (0f) r3 += r1
 2911: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 2912: (7b) *(u64 *)(r10 -64) = r7
 2913: (bf) r1 = r10
; 
 2914: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 2915: (b7) r2 = 8
 2916: (85) call bpf_probe_read_kernel#-51920
 2917: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 2918: (7b) *(u64 *)(r10 -64) = r7
 2919: (b7) r1 = 24
 2920: (79) r7 = *(u64 *)(r10 -144)
 2921: (bf) r3 = r7
 2922: (0f) r3 += r1
 2923: (bf) r1 = r10
; 
 2924: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 2925: (b7) r2 = 8
 2926: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 2927: (1d) if r7 == r6 goto pc+56
; 
 2928: (79) r7 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 2929: (79) r1 = *(u64 *)(r10 -144)
 2930: (1d) if r1 == r7 goto pc+53
 2931: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 2932: (7b) *(u64 *)(r10 -56) = r1
 2933: (7b) *(u64 *)(r10 -64) = r1
 2934: (b7) r1 = 32
 2935: (79) r3 = *(u64 *)(r10 -144)
 2936: (0f) r3 += r1
 2937: (bf) r1 = r10
 2938: (07) r1 += -64
 2939: (b7) r2 = 16
 2940: (85) call bpf_probe_read_kernel#-51920
 2941: (79) r1 = *(u64 *)(r10 -56)
 2942: (7b) *(u64 *)(r10 -32) = r1
 2943: (79) r1 = *(u64 *)(r10 -64)
 2944: (7b) *(u64 *)(r10 -40) = r1
 2945: (bf) r1 = r10
 2946: (07) r1 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 2947: (61) r1 = *(u32 *)(r1 +4)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 2948: (07) r1 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 2949: (bf) r2 = r1
 2950: (57) r2 &= 4095
; if (off <= buf_off) { // verify no wrap occurred
 2951: (79) r3 = *(u64 *)(r10 -136)
 2952: (67) r3 <<= 32
 2953: (77) r3 >>= 32
; if (off <= buf_off) { // verify no wrap occurred
 2954: (2d) if r2 > r3 goto pc+406
; off = buf_off - len;
 2955: (79) r3 = *(u64 *)(r10 -136)
 2956: (1f) r3 -= r1
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 2957: (57) r3 &= 4095
 2958: (79) r1 = *(u64 *)(r10 -128)
 2959: (0f) r1 += r3
 2960: (bf) r3 = r10
; off = buf_off - len;
 2961: (07) r3 += -40
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 2962: (79) r3 = *(u64 *)(r3 +8)
 2963: (85) call bpf_probe_read_kernel_str#-51856
 2964: (bf) r6 = r0
 2965: (bf) r1 = r6
 2966: (67) r1 <<= 32
 2967: (c7) r1 s>>= 32
 2968: (b7) r2 = 2
; if (sz > 1) {
 2969: (6d) if r2 s> r1 goto pc+391
 2970: (79) r8 = *(u64 *)(r10 -136)
; buf_off -= 1; // remove null byte termination with slash sign
 2971: (bf) r2 = r8
 2972: (07) r2 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 2973: (57) r2 &= 4095
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 2974: (79) r1 = *(u64 *)(r10 -128)
 2975: (0f) r1 += r2
 2976: (bf) r3 = r10
; buf_off -= 1; // remove null byte termination with slash sign
 2977: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 2978: (b7) r2 = 1
 2979: (85) call bpf_probe_read_compat#-45600
; buf_off -= sz - 1;
 2980: (1f) r8 -= r6
 2981: (7b) *(u64 *)(r10 -136) = r8
; 
 2982: (7b) *(u64 *)(r10 -144) = r7
 2983: (05) goto pc+39
; if (dentry != mnt_root) {
 2984: (79) r1 = *(u64 *)(r10 -120)
 2985: (79) r2 = *(u64 *)(r10 -152)
 2986: (1d) if r1 == r2 goto pc+374
 2987: (79) r1 = *(u64 *)(r10 -144)
 2988: (5d) if r1 != r6 goto pc+372
 2989: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 2990: (7b) *(u64 *)(r10 -64) = r6
 2991: (b7) r1 = 24
 2992: (79) r8 = *(u64 *)(r10 -120)
 2993: (bf) r3 = r8
 2994: (0f) r3 += r1
 2995: (bf) r1 = r10
; 
 2996: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 2997: (b7) r2 = 8
 2998: (85) call bpf_probe_read_kernel#-51920
 2999: (b7) r7 = 16
 3000: (0f) r8 += r7
 3001: (79) r1 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 3002: (7b) *(u64 *)(r10 -144) = r1
 3003: (7b) *(u64 *)(r10 -64) = r6
 3004: (bf) r1 = r10
; 
 3005: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 3006: (b7) r2 = 8
 3007: (bf) r3 = r8
 3008: (85) call bpf_probe_read_kernel#-51920
 3009: (79) r8 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 3010: (7b) *(u64 *)(r10 -64) = r6
 3011: (bf) r3 = r8
 3012: (0f) r3 += r7
 3013: (bf) r1 = r10
; 
 3014: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 3015: (b7) r2 = 8
 3016: (85) call bpf_probe_read_kernel#-51920
 3017: (b7) r1 = 32
 3018: (7b) *(u64 *)(r10 -120) = r8
 3019: (0f) r8 += r1
 3020: (7b) *(u64 *)(r10 -160) = r8
 3021: (79) r1 = *(u64 *)(r10 -64)
 3022: (7b) *(u64 *)(r10 -152) = r1
 3023: (b7) r1 = 0
 3024: (79) r3 = *(u64 *)(r10 -160)
 3025: (0f) r3 += r1
 3026: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 3027: (7b) *(u64 *)(r10 -64) = r7
 3028: (bf) r1 = r10
; 
 3029: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 3030: (b7) r2 = 8
 3031: (85) call bpf_probe_read_kernel#-51920
 3032: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 3033: (7b) *(u64 *)(r10 -64) = r7
 3034: (b7) r1 = 24
 3035: (79) r7 = *(u64 *)(r10 -144)
 3036: (bf) r3 = r7
 3037: (0f) r3 += r1
 3038: (bf) r1 = r10
; 
 3039: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 3040: (b7) r2 = 8
 3041: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 3042: (1d) if r7 == r6 goto pc+56
; 
 3043: (79) r7 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 3044: (79) r1 = *(u64 *)(r10 -144)
 3045: (1d) if r1 == r7 goto pc+53
 3046: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 3047: (7b) *(u64 *)(r10 -56) = r1
 3048: (7b) *(u64 *)(r10 -64) = r1
 3049: (b7) r1 = 32
 3050: (79) r3 = *(u64 *)(r10 -144)
 3051: (0f) r3 += r1
 3052: (bf) r1 = r10
 3053: (07) r1 += -64
 3054: (b7) r2 = 16
 3055: (85) call bpf_probe_read_kernel#-51920
 3056: (79) r1 = *(u64 *)(r10 -56)
 3057: (7b) *(u64 *)(r10 -32) = r1
 3058: (79) r1 = *(u64 *)(r10 -64)
 3059: (7b) *(u64 *)(r10 -40) = r1
 3060: (bf) r1 = r10
 3061: (07) r1 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 3062: (61) r1 = *(u32 *)(r1 +4)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 3063: (07) r1 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 3064: (bf) r2 = r1
 3065: (57) r2 &= 4095
; if (off <= buf_off) { // verify no wrap occurred
 3066: (79) r3 = *(u64 *)(r10 -136)
 3067: (67) r3 <<= 32
 3068: (77) r3 >>= 32
; if (off <= buf_off) { // verify no wrap occurred
 3069: (2d) if r2 > r3 goto pc+291
; off = buf_off - len;
 3070: (79) r3 = *(u64 *)(r10 -136)
 3071: (1f) r3 -= r1
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 3072: (57) r3 &= 4095
 3073: (79) r1 = *(u64 *)(r10 -128)
 3074: (0f) r1 += r3
 3075: (bf) r3 = r10
; off = buf_off - len;
 3076: (07) r3 += -40
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 3077: (79) r3 = *(u64 *)(r3 +8)
 3078: (85) call bpf_probe_read_kernel_str#-51856
 3079: (bf) r6 = r0
 3080: (bf) r1 = r6
 3081: (67) r1 <<= 32
 3082: (c7) r1 s>>= 32
 3083: (b7) r2 = 2
; if (sz > 1) {
 3084: (6d) if r2 s> r1 goto pc+276
 3085: (79) r8 = *(u64 *)(r10 -136)
; buf_off -= 1; // remove null byte termination with slash sign
 3086: (bf) r2 = r8
 3087: (07) r2 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 3088: (57) r2 &= 4095
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 3089: (79) r1 = *(u64 *)(r10 -128)
 3090: (0f) r1 += r2
 3091: (bf) r3 = r10
; buf_off -= 1; // remove null byte termination with slash sign
 3092: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 3093: (b7) r2 = 1
 3094: (85) call bpf_probe_read_compat#-45600
; buf_off -= sz - 1;
 3095: (1f) r8 -= r6
 3096: (7b) *(u64 *)(r10 -136) = r8
; 
 3097: (7b) *(u64 *)(r10 -144) = r7
 3098: (05) goto pc+39
; if (dentry != mnt_root) {
 3099: (79) r1 = *(u64 *)(r10 -120)
 3100: (79) r2 = *(u64 *)(r10 -152)
 3101: (1d) if r1 == r2 goto pc+259
 3102: (79) r1 = *(u64 *)(r10 -144)
 3103: (5d) if r1 != r6 goto pc+257
 3104: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 3105: (7b) *(u64 *)(r10 -64) = r6
 3106: (b7) r1 = 24
 3107: (79) r8 = *(u64 *)(r10 -120)
 3108: (bf) r3 = r8
 3109: (0f) r3 += r1
 3110: (bf) r1 = r10
; 
 3111: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 3112: (b7) r2 = 8
 3113: (85) call bpf_probe_read_kernel#-51920
 3114: (b7) r7 = 16
 3115: (0f) r8 += r7
 3116: (79) r1 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 3117: (7b) *(u64 *)(r10 -144) = r1
 3118: (7b) *(u64 *)(r10 -64) = r6
 3119: (bf) r1 = r10
; 
 3120: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 3121: (b7) r2 = 8
 3122: (bf) r3 = r8
 3123: (85) call bpf_probe_read_kernel#-51920
 3124: (79) r8 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 3125: (7b) *(u64 *)(r10 -64) = r6
 3126: (bf) r3 = r8
 3127: (0f) r3 += r7
 3128: (bf) r1 = r10
; 
 3129: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 3130: (b7) r2 = 8
 3131: (85) call bpf_probe_read_kernel#-51920
 3132: (b7) r1 = 32
 3133: (7b) *(u64 *)(r10 -120) = r8
 3134: (0f) r8 += r1
 3135: (7b) *(u64 *)(r10 -160) = r8
 3136: (79) r1 = *(u64 *)(r10 -64)
 3137: (7b) *(u64 *)(r10 -152) = r1
 3138: (b7) r1 = 0
 3139: (79) r3 = *(u64 *)(r10 -160)
 3140: (0f) r3 += r1
 3141: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 3142: (7b) *(u64 *)(r10 -64) = r7
 3143: (bf) r1 = r10
; 
 3144: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 3145: (b7) r2 = 8
 3146: (85) call bpf_probe_read_kernel#-51920
 3147: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 3148: (7b) *(u64 *)(r10 -64) = r7
 3149: (b7) r1 = 24
 3150: (79) r7 = *(u64 *)(r10 -144)
 3151: (bf) r3 = r7
 3152: (0f) r3 += r1
 3153: (bf) r1 = r10
; 
 3154: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 3155: (b7) r2 = 8
 3156: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 3157: (1d) if r7 == r6 goto pc+56
; 
 3158: (79) r7 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 3159: (79) r1 = *(u64 *)(r10 -144)
 3160: (1d) if r1 == r7 goto pc+53
 3161: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 3162: (7b) *(u64 *)(r10 -56) = r1
 3163: (7b) *(u64 *)(r10 -64) = r1
 3164: (b7) r1 = 32
 3165: (79) r3 = *(u64 *)(r10 -144)
 3166: (0f) r3 += r1
 3167: (bf) r1 = r10
 3168: (07) r1 += -64
 3169: (b7) r2 = 16
 3170: (85) call bpf_probe_read_kernel#-51920
 3171: (79) r1 = *(u64 *)(r10 -56)
 3172: (7b) *(u64 *)(r10 -32) = r1
 3173: (79) r1 = *(u64 *)(r10 -64)
 3174: (7b) *(u64 *)(r10 -40) = r1
 3175: (bf) r1 = r10
 3176: (07) r1 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 3177: (61) r1 = *(u32 *)(r1 +4)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 3178: (07) r1 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 3179: (bf) r2 = r1
 3180: (57) r2 &= 4095
; if (off <= buf_off) { // verify no wrap occurred
 3181: (79) r3 = *(u64 *)(r10 -136)
 3182: (67) r3 <<= 32
 3183: (77) r3 >>= 32
; if (off <= buf_off) { // verify no wrap occurred
 3184: (2d) if r2 > r3 goto pc+176
; off = buf_off - len;
 3185: (79) r3 = *(u64 *)(r10 -136)
 3186: (1f) r3 -= r1
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 3187: (57) r3 &= 4095
 3188: (79) r1 = *(u64 *)(r10 -128)
 3189: (0f) r1 += r3
 3190: (bf) r3 = r10
; off = buf_off - len;
 3191: (07) r3 += -40
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 3192: (79) r3 = *(u64 *)(r3 +8)
 3193: (85) call bpf_probe_read_kernel_str#-51856
 3194: (bf) r6 = r0
 3195: (bf) r1 = r6
 3196: (67) r1 <<= 32
 3197: (c7) r1 s>>= 32
 3198: (b7) r2 = 2
; if (sz > 1) {
 3199: (6d) if r2 s> r1 goto pc+161
 3200: (79) r8 = *(u64 *)(r10 -136)
; buf_off -= 1; // remove null byte termination with slash sign
 3201: (bf) r2 = r8
 3202: (07) r2 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 3203: (57) r2 &= 4095
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 3204: (79) r1 = *(u64 *)(r10 -128)
 3205: (0f) r1 += r2
 3206: (bf) r3 = r10
; buf_off -= 1; // remove null byte termination with slash sign
 3207: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 3208: (b7) r2 = 1
 3209: (85) call bpf_probe_read_compat#-45600
; buf_off -= sz - 1;
 3210: (1f) r8 -= r6
 3211: (7b) *(u64 *)(r10 -136) = r8
; 
 3212: (7b) *(u64 *)(r10 -144) = r7
 3213: (05) goto pc+39
; if (dentry != mnt_root) {
 3214: (79) r1 = *(u64 *)(r10 -120)
 3215: (79) r2 = *(u64 *)(r10 -152)
 3216: (1d) if r1 == r2 goto pc+144
 3217: (79) r1 = *(u64 *)(r10 -144)
 3218: (5d) if r1 != r6 goto pc+142
 3219: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 3220: (7b) *(u64 *)(r10 -64) = r6
 3221: (b7) r1 = 24
 3222: (79) r8 = *(u64 *)(r10 -120)
 3223: (bf) r3 = r8
 3224: (0f) r3 += r1
 3225: (bf) r1 = r10
; 
 3226: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 3227: (b7) r2 = 8
 3228: (85) call bpf_probe_read_kernel#-51920
 3229: (b7) r7 = 16
 3230: (0f) r8 += r7
 3231: (79) r1 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 3232: (7b) *(u64 *)(r10 -144) = r1
 3233: (7b) *(u64 *)(r10 -64) = r6
 3234: (bf) r1 = r10
; 
 3235: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 3236: (b7) r2 = 8
 3237: (bf) r3 = r8
 3238: (85) call bpf_probe_read_kernel#-51920
 3239: (79) r8 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 3240: (7b) *(u64 *)(r10 -64) = r6
 3241: (bf) r3 = r8
 3242: (0f) r3 += r7
 3243: (bf) r1 = r10
; 
 3244: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 3245: (b7) r2 = 8
 3246: (85) call bpf_probe_read_kernel#-51920
 3247: (b7) r1 = 32
 3248: (7b) *(u64 *)(r10 -120) = r8
 3249: (0f) r8 += r1
 3250: (7b) *(u64 *)(r10 -160) = r8
 3251: (79) r1 = *(u64 *)(r10 -64)
 3252: (7b) *(u64 *)(r10 -152) = r1
 3253: (b7) r1 = 0
 3254: (79) r3 = *(u64 *)(r10 -160)
 3255: (0f) r3 += r1
 3256: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 3257: (7b) *(u64 *)(r10 -64) = r7
 3258: (bf) r1 = r10
; 
 3259: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 3260: (b7) r2 = 8
 3261: (85) call bpf_probe_read_kernel#-51920
 3262: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 3263: (7b) *(u64 *)(r10 -64) = r7
 3264: (b7) r1 = 24
 3265: (79) r7 = *(u64 *)(r10 -144)
 3266: (bf) r3 = r7
 3267: (0f) r3 += r1
 3268: (bf) r1 = r10
; 
 3269: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 3270: (b7) r2 = 8
 3271: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 3272: (1d) if r7 == r6 goto pc+56
; 
 3273: (79) r7 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 3274: (79) r1 = *(u64 *)(r10 -144)
 3275: (1d) if r1 == r7 goto pc+53
 3276: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 3277: (7b) *(u64 *)(r10 -56) = r1
 3278: (7b) *(u64 *)(r10 -64) = r1
 3279: (b7) r1 = 32
 3280: (79) r3 = *(u64 *)(r10 -144)
 3281: (0f) r3 += r1
 3282: (bf) r1 = r10
 3283: (07) r1 += -64
 3284: (b7) r2 = 16
 3285: (85) call bpf_probe_read_kernel#-51920
 3286: (79) r1 = *(u64 *)(r10 -56)
 3287: (7b) *(u64 *)(r10 -32) = r1
 3288: (79) r1 = *(u64 *)(r10 -64)
 3289: (7b) *(u64 *)(r10 -40) = r1
 3290: (bf) r1 = r10
 3291: (07) r1 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 3292: (61) r1 = *(u32 *)(r1 +4)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 3293: (07) r1 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 3294: (bf) r2 = r1
 3295: (57) r2 &= 4095
; if (off <= buf_off) { // verify no wrap occurred
 3296: (79) r3 = *(u64 *)(r10 -136)
 3297: (67) r3 <<= 32
 3298: (77) r3 >>= 32
; if (off <= buf_off) { // verify no wrap occurred
 3299: (2d) if r2 > r3 goto pc+61
; off = buf_off - len;
 3300: (79) r3 = *(u64 *)(r10 -136)
 3301: (1f) r3 -= r1
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 3302: (57) r3 &= 4095
 3303: (79) r1 = *(u64 *)(r10 -128)
 3304: (0f) r1 += r3
 3305: (bf) r3 = r10
; off = buf_off - len;
 3306: (07) r3 += -40
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 3307: (79) r3 = *(u64 *)(r3 +8)
 3308: (85) call bpf_probe_read_kernel_str#-51856
 3309: (bf) r6 = r0
 3310: (bf) r1 = r6
 3311: (67) r1 <<= 32
 3312: (c7) r1 s>>= 32
 3313: (b7) r2 = 2
; if (sz > 1) {
 3314: (6d) if r2 s> r1 goto pc+46
 3315: (79) r8 = *(u64 *)(r10 -136)
; buf_off -= 1; // remove null byte termination with slash sign
 3316: (bf) r2 = r8
 3317: (07) r2 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 3318: (57) r2 &= 4095
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 3319: (79) r1 = *(u64 *)(r10 -128)
 3320: (0f) r1 += r2
 3321: (bf) r3 = r10
; buf_off -= 1; // remove null byte termination with slash sign
 3322: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 3323: (b7) r2 = 1
 3324: (85) call bpf_probe_read_compat#-45600
; buf_off -= sz - 1;
 3325: (1f) r8 -= r6
 3326: (7b) *(u64 *)(r10 -136) = r8
; 
 3327: (7b) *(u64 *)(r10 -144) = r7
 3328: (05) goto pc+32
; if (dentry != mnt_root) {
 3329: (79) r1 = *(u64 *)(r10 -120)
 3330: (79) r2 = *(u64 *)(r10 -152)
 3331: (1d) if r1 == r2 goto pc+29
 3332: (79) r1 = *(u64 *)(r10 -144)
 3333: (5d) if r1 != r6 goto pc+27
 3334: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 3335: (7b) *(u64 *)(r10 -64) = r6
 3336: (b7) r1 = 24
 3337: (79) r8 = *(u64 *)(r10 -120)
 3338: (bf) r3 = r8
 3339: (0f) r3 += r1
 3340: (bf) r1 = r10
; 
 3341: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 3342: (b7) r2 = 8
 3343: (85) call bpf_probe_read_kernel#-51920
 3344: (b7) r7 = 16
 3345: (0f) r8 += r7
 3346: (79) r1 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 3347: (7b) *(u64 *)(r10 -144) = r1
 3348: (7b) *(u64 *)(r10 -64) = r6
 3349: (bf) r1 = r10
; 
 3350: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 3351: (b7) r2 = 8
 3352: (bf) r3 = r8
 3353: (85) call bpf_probe_read_kernel#-51920
 3354: (79) r3 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 3355: (7b) *(u64 *)(r10 -64) = r6
 3356: (0f) r3 += r7
 3357: (bf) r1 = r10
; 
 3358: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 3359: (b7) r2 = 8
 3360: (85) call bpf_probe_read_kernel#-51920
 3361: (79) r7 = *(u64 *)(r10 -136)
; if (buf_off == MAX_STRING_SIZE) {
 3362: (bf) r1 = r7
 3363: (67) r1 <<= 32
 3364: (77) r1 >>= 32
 3365: (79) r8 = *(u64 *)(r10 -104)
; if (buf_off == MAX_STRING_SIZE) {
 3366: (55) if r1 != 0x1000 goto pc+26
 3367: (79) r9 = *(u64 *)(r10 -144)
 3368: (79) r7 = *(u64 *)(r10 -128)
 3369: (b7) r1 = 32
 3370: (0f) r9 += r1
 3371: (b7) r6 = 0
; d_name = READ_KERN(dentry->d_name);
 3372: (7b) *(u64 *)(r10 -56) = r6
 3373: (7b) *(u64 *)(r10 -64) = r6
 3374: (bf) r1 = r10
; 
 3375: (07) r1 += -64
; d_name = READ_KERN(dentry->d_name);
 3376: (b7) r2 = 16
 3377: (bf) r3 = r9
 3378: (85) call bpf_probe_read_kernel#-51920
 3379: (79) r1 = *(u64 *)(r10 -56)
 3380: (7b) *(u64 *)(r10 -32) = r1
 3381: (79) r1 = *(u64 *)(r10 -64)
 3382: (7b) *(u64 *)(r10 -40) = r1
 3383: (bf) r1 = r10
; 
 3384: (07) r1 += -40
; bpf_core_read(&(map_value[0]), len, (void *)d_name.name);
 3385: (79) r3 = *(u64 *)(r1 +8)
; len = d_name.len & (MAX_STRING_SIZE - 1);
 3386: (61) r2 = *(u32 *)(r1 +4)
; len = d_name.len & (MAX_STRING_SIZE - 1);
 3387: (57) r2 &= 4095
; bpf_core_read(&(map_value[0]), len, (void *)d_name.name);
 3388: (bf) r1 = r7
 3389: (85) call bpf_probe_read_kernel#-51920
; return &map_value[buf_off];
 3390: (0f) r7 += r6
; 
 3391: (bf) r6 = r7
 3392: (05) goto pc+19
; buf_off -= 1;
 3393: (07) r7 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 3394: (bf) r2 = r7
 3395: (57) r2 &= 4095
 3396: (79) r6 = *(u64 *)(r10 -128)
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 3397: (bf) r1 = r6
 3398: (0f) r1 += r2
 3399: (bf) r3 = r10
; buf_off -= 1;
 3400: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 3401: (b7) r2 = 1
 3402: (85) call bpf_probe_read_compat#-45600
; bpf_probe_read(&(map_value[MAX_STRING_SIZE -1]), 1, &zero);
 3403: (bf) r1 = r6
 3404: (07) r1 += 4095
 3405: (bf) r3 = r10
; buf_off -= 1;
 3406: (07) r3 += -24
; bpf_probe_read(&(map_value[MAX_STRING_SIZE -1]), 1, &zero);
 3407: (b7) r2 = 1
 3408: (85) call bpf_probe_read_compat#-45600
 3409: (67) r7 <<= 32
 3410: (77) r7 >>= 32
; return &map_value[buf_off];
 3411: (0f) r6 += r7
 3412: (b7) r7 = 0
; if(path)
 3413: (15) if r6 == 0x0 goto pc+61
 3414: (79) r3 = *(u64 *)(r10 -96)
; int ret = save_str_to_buf(pinfo->buff, pinfo->buff_off, path, enProcInfoPath);
 3415: (71) r1 = *(u8 *)(r3 +118)
 3416: (71) r9 = *(u8 *)(r3 +119)
 3417: (71) r2 = *(u8 *)(r3 +116)
 3418: (71) r3 = *(u8 *)(r3 +117)
 3419: (b7) r4 = 2
 3420: (63) *(u32 *)(r10 -16) = r4
 3421: (67) r3 <<= 8
 3422: (4f) r3 |= r2
 3423: (67) r9 <<= 8
 3424: (4f) r9 |= r1
 3425: (67) r9 <<= 16
 3426: (4f) r9 |= r3
; if (buf_off > MAX_VALID_BUFSIZE - MAX_STRING_SIZE - sizeof(int) - sizeof(enType))
 3427: (25) if r9 > 0x2ff8 goto pc+47
; 
 3428: (79) r8 = *(u64 *)(r10 -96)
 3429: (07) r8 += 120
; bpf_probe_read(&buf[buf_off & (MAX_PERCPU_BUFSIZE - 1)], sizeof(enType), &enType);
 3430: (bf) r7 = r8
 3431: (0f) r7 += r9
 3432: (bf) r3 = r10
; 
 3433: (07) r3 += -16
; bpf_probe_read(&buf[buf_off & (MAX_PERCPU_BUFSIZE - 1)], sizeof(enType), &enType);
 3434: (bf) r1 = r7
 3435: (b7) r2 = 4
 3436: (85) call bpf_probe_read_compat#-45600
; int sz = bpf_probe_read_str(&(buf[buf_off + sizeof(enType) + sizeof(int)]), MAX_STRING_SIZE, ptr);
 3437: (07) r7 += 8
; int sz = bpf_probe_read_str(&(buf[buf_off + sizeof(enType) + sizeof(int)]), MAX_STRING_SIZE, ptr);
 3438: (bf) r1 = r7
 3439: (b7) r2 = 4096
 3440: (bf) r3 = r6
 3441: (85) call bpf_probe_read_compat_str#-46512
; int sz = bpf_probe_read_str(&(buf[buf_off + sizeof(enType) + sizeof(int)]), MAX_STRING_SIZE, ptr);
 3442: (63) *(u32 *)(r10 -40) = r0
; int sz = bpf_probe_read_str(&(buf[buf_off + sizeof(enType) + sizeof(int)]), MAX_STRING_SIZE, ptr);
 3443: (67) r0 <<= 32
 3444: (c7) r0 s>>= 32
; if (sz > 0) {
 3445: (65) if r0 s> 0x0 goto pc+3
 3446: (79) r8 = *(u64 *)(r10 -104)
 3447: (b7) r7 = 0
 3448: (05) goto pc+26
; if ((buf_off + sizeof(enType)) <= MAX_VALID_BUFSIZE - MAX_STRING_SIZE - sizeof(int)) 
 3449: (bf) r1 = r9
 3450: (0f) r1 += r8
; bpf_probe_read(&(buf[buf_off + sizeof(enType)]), sizeof(int), &sz);		
 3451: (07) r1 += 4
 3452: (bf) r3 = r10
; if ((buf_off + sizeof(enType)) <= MAX_VALID_BUFSIZE - MAX_STRING_SIZE - sizeof(int)) 
 3453: (07) r3 += -40
; bpf_probe_read(&(buf[buf_off + sizeof(enType)]), sizeof(int), &sz);		
 3454: (b7) r2 = 4
 3455: (85) call bpf_probe_read_compat#-45600
; buf_off += sz + sizeof(enType) + sizeof(int);
 3456: (61) r1 = *(u32 *)(r10 -40)
; buf_off += sz + sizeof(enType) + sizeof(int);
 3457: (0f) r9 += r1
; buf_off += sz + sizeof(enType) + sizeof(int);
 3458: (07) r9 += 8
 3459: (bf) r1 = r9
 3460: (67) r1 <<= 32
 3461: (77) r1 >>= 32
 3462: (79) r8 = *(u64 *)(r10 -104)
 3463: (b7) r7 = 0
; if(ret)
 3464: (15) if r1 == 0x0 goto pc+10
; pinfo->buff_off = ret;
 3465: (bf) r1 = r9
 3466: (77) r1 >>= 24
 3467: (79) r2 = *(u64 *)(r10 -96)
 3468: (73) *(u8 *)(r2 +119) = r1
 3469: (bf) r1 = r9
 3470: (77) r1 >>= 16
 3471: (73) *(u8 *)(r2 +118) = r1
 3472: (73) *(u8 *)(r2 +116) = r9
 3473: (77) r9 >>= 8
 3474: (73) *(u8 *)(r2 +117) = r9
; struct path pwd_path = {};
 3475: (7b) *(u64 *)(r10 -80) = r7
 3476: (7b) *(u64 *)(r10 -88) = r7
; pfs = READ_KERN(task->fs);
 3477: (7b) *(u64 *)(r10 -16) = r7
 3478: (b7) r1 = 2840
 3479: (0f) r8 += r1
 3480: (bf) r1 = r10
; 
 3481: (07) r1 += -16
; pfs = READ_KERN(task->fs);
 3482: (b7) r2 = 8
 3483: (bf) r3 = r8
 3484: (85) call bpf_probe_read_kernel#-51920
 3485: (79) r6 = *(u64 *)(r10 -16)
; if(pfs != NULL)
 3486: (15) if r6 == 0x0 goto pc+2919
 3487: (b7) r1 = 0
; pwd_path = READ_KERN(pfs->pwd);
 3488: (7b) *(u64 *)(r10 -8) = r1
 3489: (7b) *(u64 *)(r10 -16) = r1
 3490: (b7) r1 = 40
 3491: (bf) r3 = r6
 3492: (0f) r3 += r1
 3493: (bf) r1 = r10
 3494: (07) r1 += -16
 3495: (b7) r2 = 16
 3496: (85) call bpf_probe_read_kernel#-51920
 3497: (79) r1 = *(u64 *)(r10 -8)
 3498: (7b) *(u64 *)(r10 -80) = r1
 3499: (79) r1 = *(u64 *)(r10 -16)
 3500: (7b) *(u64 *)(r10 -88) = r1
 3501: (bf) r1 = r10
 3502: (07) r1 += -88
; if (pwd_path.dentry != NULL && pwd_path.mnt != NULL)	
 3503: (79) r1 = *(u64 *)(r1 +8)
; if (pwd_path.dentry != NULL && pwd_path.mnt != NULL)	
 3504: (15) if r1 == 0x0 goto pc+2901
 3505: (bf) r1 = r10
; if (pwd_path.dentry != NULL && pwd_path.mnt != NULL)	
 3506: (07) r1 += -88
 3507: (79) r1 = *(u64 *)(r1 +0)
; if (pwd_path.dentry != NULL && pwd_path.mnt != NULL)	
 3508: (15) if r1 == 0x0 goto pc+2897
 3509: (b7) r1 = 40
 3510: (0f) r6 += r1
 3511: (b7) r9 = 0
; pwd_path = READ_KERN(pfs->pwd);
 3512: (7b) *(u64 *)(r10 -8) = r9
 3513: (7b) *(u64 *)(r10 -16) = r9
 3514: (bf) r1 = r10
 3515: (07) r1 += -16
 3516: (b7) r2 = 16
 3517: (bf) r3 = r6
 3518: (85) call bpf_probe_read_kernel#-51920
 3519: (79) r1 = *(u64 *)(r10 -16)
 3520: (7b) *(u64 *)(r10 -88) = r1
 3521: (79) r1 = *(u64 *)(r10 -8)
 3522: (7b) *(u64 *)(r10 -80) = r1
 3523: (bf) r7 = r10
 3524: (07) r7 += -16
 3525: (bf) r3 = r10
 3526: (07) r3 += -88
; bpf_probe_read(&f_path, sizeof(struct path), ppath);
 3527: (bf) r1 = r7
 3528: (b7) r2 = 16
 3529: (85) call bpf_probe_read_compat#-45600
 3530: (b7) r1 = 47
; char slash = '/';
 3531: (73) *(u8 *)(r10 -17) = r1
; int zero = 0;
 3532: (63) *(u32 *)(r10 -24) = r9
; struct dentry *dentry = f_path.dentry;
 3533: (79) r6 = *(u64 *)(r7 +8)
; struct vfsmount *vfsmnt = f_path.mnt;
 3534: (79) r8 = *(u64 *)(r7 +0)
 3535: (b7) r1 = 32
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 3536: (7b) *(u64 *)(r10 -40) = r9
; struct mount *mnt_p = container_of(vfsmnt, struct mount, mnt);
 3537: (bf) r3 = r8
 3538: (1f) r3 -= r1
 3539: (b7) r1 = 16
 3540: (7b) *(u64 *)(r10 -104) = r3
 3541: (0f) r3 += r1
 3542: (bf) r1 = r10
; pwd_path = READ_KERN(pfs->pwd);
 3543: (07) r1 += -40
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 3544: (b7) r2 = 8
 3545: (85) call bpf_probe_read_kernel#-51920
 3546: (79) r7 = *(u64 *)(r10 -40)
 3547: (b7) r1 = 1
; int map_id = 1;
 3548: (63) *(u32 *)(r10 -44) = r1
 3549: (bf) r2 = r10
; pwd_path = READ_KERN(pfs->pwd);
 3550: (07) r2 += -44
; char *map_value = bpf_map_lookup_elem(&data_tmp_store_map, &map_id);
 3551: (18) r1 = map[id:1]
 3553: (85) call percpu_array_map_lookup_elem#149152
; if (!map_value)
 3554: (15) if r0 == 0x0 goto pc+2793
 3555: (bf) r9 = r7
 3556: (7b) *(u64 *)(r10 -120) = r0
 3557: (b7) r1 = 0
 3558: (7b) *(u64 *)(r10 -128) = r8
 3559: (bf) r3 = r8
 3560: (0f) r3 += r1
 3561: (b7) r8 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 3562: (7b) *(u64 *)(r10 -64) = r8
 3563: (bf) r1 = r10
; 
 3564: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 3565: (b7) r2 = 8
 3566: (85) call bpf_probe_read_kernel#-51920
 3567: (79) r7 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 3568: (7b) *(u64 *)(r10 -64) = r8
 3569: (b7) r1 = 24
 3570: (bf) r3 = r6
 3571: (0f) r3 += r1
 3572: (bf) r1 = r10
; 
 3573: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 3574: (b7) r2 = 8
 3575: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 3576: (1d) if r6 == r7 goto pc+2
; 
 3577: (79) r1 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 3578: (5d) if r6 != r1 goto pc+39
 3579: (79) r8 = *(u64 *)(r10 -120)
; if (dentry != mnt_root) {
 3580: (79) r1 = *(u64 *)(r10 -104)
 3581: (1d) if r9 == r1 goto pc+2723
 3582: (5d) if r6 != r7 goto pc+2722
 3583: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 3584: (7b) *(u64 *)(r10 -64) = r6
 3585: (b7) r1 = 24
 3586: (79) r8 = *(u64 *)(r10 -104)
 3587: (bf) r3 = r8
 3588: (0f) r3 += r1
 3589: (bf) r1 = r10
; 
 3590: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 3591: (b7) r2 = 8
 3592: (85) call bpf_probe_read_kernel#-51920
 3593: (b7) r7 = 16
 3594: (0f) r8 += r7
 3595: (79) r9 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 3596: (7b) *(u64 *)(r10 -64) = r6
 3597: (bf) r1 = r10
; 
 3598: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 3599: (b7) r2 = 8
 3600: (bf) r3 = r8
 3601: (85) call bpf_probe_read_kernel#-51920
 3602: (79) r8 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 3603: (7b) *(u64 *)(r10 -64) = r6
 3604: (bf) r3 = r8
 3605: (0f) r3 += r7
 3606: (bf) r1 = r10
; 
 3607: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 3608: (b7) r2 = 8
 3609: (85) call bpf_probe_read_kernel#-51920
 3610: (b7) r1 = 4096
 3611: (7b) *(u64 *)(r10 -144) = r1
 3612: (b7) r1 = 32
 3613: (7b) *(u64 *)(r10 -104) = r8
 3614: (bf) r3 = r8
 3615: (0f) r3 += r1
 3616: (79) r8 = *(u64 *)(r10 -64)
 3617: (05) goto pc+46
 3618: (7b) *(u64 *)(r10 -136) = r1
 3619: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 3620: (7b) *(u64 *)(r10 -56) = r1
 3621: (7b) *(u64 *)(r10 -64) = r1
 3622: (b7) r1 = 32
 3623: (bf) r3 = r6
 3624: (0f) r3 += r1
 3625: (bf) r1 = r10
 3626: (07) r1 += -64
 3627: (b7) r2 = 16
 3628: (85) call bpf_probe_read_kernel#-51920
 3629: (79) r1 = *(u64 *)(r10 -56)
 3630: (7b) *(u64 *)(r10 -32) = r1
 3631: (79) r1 = *(u64 *)(r10 -64)
 3632: (7b) *(u64 *)(r10 -40) = r1
 3633: (bf) r3 = r10
 3634: (07) r3 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 3635: (61) r2 = *(u32 *)(r3 +4)
 3636: (b7) r4 = 4095
; off = buf_off - len;
 3637: (1f) r4 -= r2
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 3638: (57) r4 &= 4095
 3639: (79) r8 = *(u64 *)(r10 -120)
 3640: (bf) r1 = r8
 3641: (0f) r1 += r4
 3642: (79) r3 = *(u64 *)(r3 +8)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 3643: (07) r2 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 3644: (57) r2 &= 4095
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 3645: (85) call bpf_probe_read_kernel_str#-51856
 3646: (bf) r7 = r0
 3647: (bf) r1 = r7
 3648: (67) r1 <<= 32
 3649: (c7) r1 s>>= 32
 3650: (b7) r2 = 2
; if (sz > 1) {
 3651: (6d) if r2 s> r1 goto pc+2653
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 3652: (07) r8 += 4095
 3653: (bf) r3 = r10
; 
 3654: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 3655: (bf) r1 = r8
 3656: (b7) r2 = 1
 3657: (85) call bpf_probe_read_compat#-45600
 3658: (b7) r1 = 4096
; buf_off -= sz - 1;
 3659: (1f) r1 -= r7
 3660: (7b) *(u64 *)(r10 -144) = r1
 3661: (bf) r8 = r9
 3662: (79) r9 = *(u64 *)(r10 -136)
 3663: (79) r3 = *(u64 *)(r10 -128)
 3664: (b7) r1 = 0
 3665: (7b) *(u64 *)(r10 -128) = r3
 3666: (0f) r3 += r1
 3667: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 3668: (7b) *(u64 *)(r10 -64) = r7
 3669: (bf) r1 = r10
; 
 3670: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 3671: (b7) r2 = 8
 3672: (85) call bpf_probe_read_kernel#-51920
 3673: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 3674: (7b) *(u64 *)(r10 -64) = r7
 3675: (b7) r1 = 24
 3676: (bf) r3 = r9
 3677: (0f) r3 += r1
 3678: (bf) r1 = r10
; 
 3679: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 3680: (b7) r2 = 8
 3681: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 3682: (7b) *(u64 *)(r10 -136) = r9
 3683: (1d) if r9 == r6 goto pc+56
; 
 3684: (79) r7 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 3685: (1d) if r9 == r7 goto pc+54
 3686: (7b) *(u64 *)(r10 -152) = r8
 3687: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 3688: (7b) *(u64 *)(r10 -56) = r1
 3689: (7b) *(u64 *)(r10 -64) = r1
 3690: (b7) r1 = 32
 3691: (0f) r9 += r1
 3692: (bf) r1 = r10
 3693: (07) r1 += -64
 3694: (b7) r2 = 16
 3695: (bf) r3 = r9
 3696: (85) call bpf_probe_read_kernel#-51920
 3697: (79) r1 = *(u64 *)(r10 -56)
 3698: (7b) *(u64 *)(r10 -32) = r1
 3699: (79) r1 = *(u64 *)(r10 -64)
 3700: (7b) *(u64 *)(r10 -40) = r1
 3701: (bf) r1 = r10
 3702: (07) r1 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 3703: (61) r1 = *(u32 *)(r1 +4)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 3704: (07) r1 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 3705: (bf) r2 = r1
 3706: (57) r2 &= 4095
; if (off <= buf_off) { // verify no wrap occurred
 3707: (79) r3 = *(u64 *)(r10 -144)
 3708: (67) r3 <<= 32
 3709: (77) r3 >>= 32
; if (off <= buf_off) { // verify no wrap occurred
 3710: (2d) if r2 > r3 goto pc+2587
; off = buf_off - len;
 3711: (79) r3 = *(u64 *)(r10 -144)
 3712: (1f) r3 -= r1
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 3713: (57) r3 &= 4095
 3714: (79) r1 = *(u64 *)(r10 -120)
 3715: (0f) r1 += r3
 3716: (bf) r3 = r10
; off = buf_off - len;
 3717: (07) r3 += -40
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 3718: (79) r3 = *(u64 *)(r3 +8)
 3719: (85) call bpf_probe_read_kernel_str#-51856
 3720: (bf) r6 = r0
 3721: (bf) r1 = r6
 3722: (67) r1 <<= 32
 3723: (c7) r1 s>>= 32
 3724: (b7) r2 = 2
; if (sz > 1) {
 3725: (6d) if r2 s> r1 goto pc+2572
 3726: (79) r8 = *(u64 *)(r10 -144)
; buf_off -= 1; // remove null byte termination with slash sign
 3727: (bf) r2 = r8
 3728: (07) r2 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 3729: (57) r2 &= 4095
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 3730: (79) r1 = *(u64 *)(r10 -120)
 3731: (0f) r1 += r2
 3732: (bf) r3 = r10
; buf_off -= 1; // remove null byte termination with slash sign
 3733: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 3734: (b7) r2 = 1
 3735: (85) call bpf_probe_read_compat#-45600
; buf_off -= sz - 1;
 3736: (1f) r8 -= r6
; 
 3737: (bf) r9 = r7
 3738: (79) r3 = *(u64 *)(r10 -128)
 3739: (05) goto pc+38
; if (dentry != mnt_root) {
 3740: (79) r1 = *(u64 *)(r10 -104)
 3741: (1d) if r1 == r8 goto pc+2556
 3742: (79) r1 = *(u64 *)(r10 -136)
 3743: (5d) if r1 != r6 goto pc+2554
 3744: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 3745: (7b) *(u64 *)(r10 -64) = r6
 3746: (b7) r1 = 24
 3747: (79) r8 = *(u64 *)(r10 -104)
 3748: (bf) r3 = r8
 3749: (0f) r3 += r1
 3750: (bf) r1 = r10
; 
 3751: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 3752: (b7) r2 = 8
 3753: (85) call bpf_probe_read_kernel#-51920
 3754: (b7) r7 = 16
 3755: (0f) r8 += r7
 3756: (79) r9 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 3757: (7b) *(u64 *)(r10 -64) = r6
 3758: (bf) r1 = r10
; 
 3759: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 3760: (b7) r2 = 8
 3761: (bf) r3 = r8
 3762: (85) call bpf_probe_read_kernel#-51920
 3763: (79) r8 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 3764: (7b) *(u64 *)(r10 -64) = r6
 3765: (bf) r3 = r8
 3766: (0f) r3 += r7
 3767: (bf) r1 = r10
; 
 3768: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 3769: (b7) r2 = 8
 3770: (85) call bpf_probe_read_kernel#-51920
 3771: (b7) r1 = 32
 3772: (7b) *(u64 *)(r10 -104) = r8
 3773: (bf) r3 = r8
 3774: (0f) r3 += r1
 3775: (79) r1 = *(u64 *)(r10 -64)
 3776: (7b) *(u64 *)(r10 -152) = r1
 3777: (79) r8 = *(u64 *)(r10 -144)
 3778: (b7) r1 = 0
 3779: (7b) *(u64 *)(r10 -128) = r3
 3780: (0f) r3 += r1
 3781: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 3782: (7b) *(u64 *)(r10 -64) = r7
 3783: (bf) r1 = r10
; 
 3784: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 3785: (b7) r2 = 8
 3786: (85) call bpf_probe_read_kernel#-51920
 3787: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 3788: (7b) *(u64 *)(r10 -64) = r7
 3789: (b7) r1 = 24
 3790: (bf) r3 = r9
 3791: (0f) r3 += r1
 3792: (bf) r1 = r10
; 
 3793: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 3794: (b7) r2 = 8
 3795: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 3796: (7b) *(u64 *)(r10 -144) = r8
 3797: (7b) *(u64 *)(r10 -136) = r9
 3798: (1d) if r9 == r6 goto pc+55
; 
 3799: (79) r7 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 3800: (1d) if r9 == r7 goto pc+53
 3801: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 3802: (7b) *(u64 *)(r10 -56) = r1
 3803: (7b) *(u64 *)(r10 -64) = r1
 3804: (b7) r1 = 32
 3805: (bf) r3 = r9
 3806: (0f) r3 += r1
 3807: (bf) r1 = r10
 3808: (07) r1 += -64
 3809: (b7) r2 = 16
 3810: (85) call bpf_probe_read_kernel#-51920
 3811: (79) r1 = *(u64 *)(r10 -56)
 3812: (7b) *(u64 *)(r10 -32) = r1
 3813: (79) r1 = *(u64 *)(r10 -64)
 3814: (7b) *(u64 *)(r10 -40) = r1
 3815: (bf) r1 = r10
 3816: (07) r1 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 3817: (61) r1 = *(u32 *)(r1 +4)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 3818: (07) r1 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 3819: (bf) r2 = r1
 3820: (57) r2 &= 4095
; if (off <= buf_off) { // verify no wrap occurred
 3821: (bf) r3 = r8
 3822: (67) r3 <<= 32
 3823: (77) r3 >>= 32
; if (off <= buf_off) { // verify no wrap occurred
 3824: (2d) if r2 > r3 goto pc+2473
; off = buf_off - len;
 3825: (79) r3 = *(u64 *)(r10 -144)
 3826: (1f) r3 -= r1
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 3827: (57) r3 &= 4095
 3828: (79) r1 = *(u64 *)(r10 -120)
 3829: (0f) r1 += r3
 3830: (bf) r3 = r10
; off = buf_off - len;
 3831: (07) r3 += -40
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 3832: (79) r3 = *(u64 *)(r3 +8)
 3833: (85) call bpf_probe_read_kernel_str#-51856
 3834: (bf) r6 = r0
 3835: (bf) r1 = r6
 3836: (67) r1 <<= 32
 3837: (c7) r1 s>>= 32
 3838: (b7) r2 = 2
; if (sz > 1) {
 3839: (6d) if r2 s> r1 goto pc+2458
 3840: (79) r8 = *(u64 *)(r10 -144)
; buf_off -= 1; // remove null byte termination with slash sign
 3841: (bf) r2 = r8
 3842: (07) r2 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 3843: (57) r2 &= 4095
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 3844: (79) r1 = *(u64 *)(r10 -120)
 3845: (0f) r1 += r2
 3846: (bf) r3 = r10
; buf_off -= 1; // remove null byte termination with slash sign
 3847: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 3848: (b7) r2 = 1
 3849: (85) call bpf_probe_read_compat#-45600
; buf_off -= sz - 1;
 3850: (1f) r8 -= r6
; 
 3851: (bf) r9 = r7
 3852: (79) r3 = *(u64 *)(r10 -128)
 3853: (05) goto pc+39
; if (dentry != mnt_root) {
 3854: (79) r1 = *(u64 *)(r10 -104)
 3855: (79) r2 = *(u64 *)(r10 -152)
 3856: (1d) if r1 == r2 goto pc+2441
 3857: (79) r1 = *(u64 *)(r10 -136)
 3858: (5d) if r1 != r6 goto pc+2439
 3859: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 3860: (7b) *(u64 *)(r10 -64) = r6
 3861: (b7) r1 = 24
 3862: (79) r8 = *(u64 *)(r10 -104)
 3863: (bf) r3 = r8
 3864: (0f) r3 += r1
 3865: (bf) r1 = r10
; 
 3866: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 3867: (b7) r2 = 8
 3868: (85) call bpf_probe_read_kernel#-51920
 3869: (b7) r7 = 16
 3870: (0f) r8 += r7
 3871: (79) r9 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 3872: (7b) *(u64 *)(r10 -64) = r6
 3873: (bf) r1 = r10
; 
 3874: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 3875: (b7) r2 = 8
 3876: (bf) r3 = r8
 3877: (85) call bpf_probe_read_kernel#-51920
 3878: (79) r8 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 3879: (7b) *(u64 *)(r10 -64) = r6
 3880: (bf) r3 = r8
 3881: (0f) r3 += r7
 3882: (bf) r1 = r10
; 
 3883: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 3884: (b7) r2 = 8
 3885: (85) call bpf_probe_read_kernel#-51920
 3886: (b7) r1 = 32
 3887: (7b) *(u64 *)(r10 -104) = r8
 3888: (bf) r3 = r8
 3889: (0f) r3 += r1
 3890: (79) r1 = *(u64 *)(r10 -64)
 3891: (7b) *(u64 *)(r10 -152) = r1
 3892: (79) r8 = *(u64 *)(r10 -144)
 3893: (b7) r1 = 0
 3894: (7b) *(u64 *)(r10 -128) = r3
 3895: (0f) r3 += r1
 3896: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 3897: (7b) *(u64 *)(r10 -64) = r7
 3898: (bf) r1 = r10
; 
 3899: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 3900: (b7) r2 = 8
 3901: (85) call bpf_probe_read_kernel#-51920
 3902: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 3903: (7b) *(u64 *)(r10 -64) = r7
 3904: (b7) r1 = 24
 3905: (bf) r3 = r9
 3906: (0f) r3 += r1
 3907: (bf) r1 = r10
; 
 3908: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 3909: (b7) r2 = 8
 3910: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 3911: (7b) *(u64 *)(r10 -144) = r8
 3912: (7b) *(u64 *)(r10 -136) = r9
 3913: (1d) if r9 == r6 goto pc+55
; 
 3914: (79) r7 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 3915: (1d) if r9 == r7 goto pc+53
 3916: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 3917: (7b) *(u64 *)(r10 -56) = r1
 3918: (7b) *(u64 *)(r10 -64) = r1
 3919: (b7) r1 = 32
 3920: (bf) r3 = r9
 3921: (0f) r3 += r1
 3922: (bf) r1 = r10
 3923: (07) r1 += -64
 3924: (b7) r2 = 16
 3925: (85) call bpf_probe_read_kernel#-51920
 3926: (79) r1 = *(u64 *)(r10 -56)
 3927: (7b) *(u64 *)(r10 -32) = r1
 3928: (79) r1 = *(u64 *)(r10 -64)
 3929: (7b) *(u64 *)(r10 -40) = r1
 3930: (bf) r1 = r10
 3931: (07) r1 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 3932: (61) r1 = *(u32 *)(r1 +4)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 3933: (07) r1 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 3934: (bf) r2 = r1
 3935: (57) r2 &= 4095
; if (off <= buf_off) { // verify no wrap occurred
 3936: (bf) r3 = r8
 3937: (67) r3 <<= 32
 3938: (77) r3 >>= 32
; if (off <= buf_off) { // verify no wrap occurred
 3939: (2d) if r2 > r3 goto pc+2358
; off = buf_off - len;
 3940: (79) r3 = *(u64 *)(r10 -144)
 3941: (1f) r3 -= r1
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 3942: (57) r3 &= 4095
 3943: (79) r1 = *(u64 *)(r10 -120)
 3944: (0f) r1 += r3
 3945: (bf) r3 = r10
; off = buf_off - len;
 3946: (07) r3 += -40
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 3947: (79) r3 = *(u64 *)(r3 +8)
 3948: (85) call bpf_probe_read_kernel_str#-51856
 3949: (bf) r6 = r0
 3950: (bf) r1 = r6
 3951: (67) r1 <<= 32
 3952: (c7) r1 s>>= 32
 3953: (b7) r2 = 2
; if (sz > 1) {
 3954: (6d) if r2 s> r1 goto pc+2343
 3955: (79) r8 = *(u64 *)(r10 -144)
; buf_off -= 1; // remove null byte termination with slash sign
 3956: (bf) r2 = r8
 3957: (07) r2 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 3958: (57) r2 &= 4095
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 3959: (79) r1 = *(u64 *)(r10 -120)
 3960: (0f) r1 += r2
 3961: (bf) r3 = r10
; buf_off -= 1; // remove null byte termination with slash sign
 3962: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 3963: (b7) r2 = 1
 3964: (85) call bpf_probe_read_compat#-45600
; buf_off -= sz - 1;
 3965: (1f) r8 -= r6
; 
 3966: (bf) r9 = r7
 3967: (79) r3 = *(u64 *)(r10 -128)
 3968: (05) goto pc+39
; if (dentry != mnt_root) {
 3969: (79) r1 = *(u64 *)(r10 -104)
 3970: (79) r2 = *(u64 *)(r10 -152)
 3971: (1d) if r1 == r2 goto pc+2326
 3972: (79) r1 = *(u64 *)(r10 -136)
 3973: (5d) if r1 != r6 goto pc+2324
 3974: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 3975: (7b) *(u64 *)(r10 -64) = r6
 3976: (b7) r1 = 24
 3977: (79) r8 = *(u64 *)(r10 -104)
 3978: (bf) r3 = r8
 3979: (0f) r3 += r1
 3980: (bf) r1 = r10
; 
 3981: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 3982: (b7) r2 = 8
 3983: (85) call bpf_probe_read_kernel#-51920
 3984: (b7) r7 = 16
 3985: (0f) r8 += r7
 3986: (79) r9 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 3987: (7b) *(u64 *)(r10 -64) = r6
 3988: (bf) r1 = r10
; 
 3989: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 3990: (b7) r2 = 8
 3991: (bf) r3 = r8
 3992: (85) call bpf_probe_read_kernel#-51920
 3993: (79) r8 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 3994: (7b) *(u64 *)(r10 -64) = r6
 3995: (bf) r3 = r8
 3996: (0f) r3 += r7
 3997: (bf) r1 = r10
; 
 3998: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 3999: (b7) r2 = 8
 4000: (85) call bpf_probe_read_kernel#-51920
 4001: (b7) r1 = 32
 4002: (7b) *(u64 *)(r10 -104) = r8
 4003: (bf) r3 = r8
 4004: (0f) r3 += r1
 4005: (79) r1 = *(u64 *)(r10 -64)
 4006: (7b) *(u64 *)(r10 -152) = r1
 4007: (79) r8 = *(u64 *)(r10 -144)
 4008: (b7) r1 = 0
 4009: (7b) *(u64 *)(r10 -128) = r3
 4010: (0f) r3 += r1
 4011: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 4012: (7b) *(u64 *)(r10 -64) = r7
 4013: (bf) r1 = r10
; 
 4014: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 4015: (b7) r2 = 8
 4016: (85) call bpf_probe_read_kernel#-51920
 4017: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 4018: (7b) *(u64 *)(r10 -64) = r7
 4019: (b7) r1 = 24
 4020: (bf) r3 = r9
 4021: (0f) r3 += r1
 4022: (bf) r1 = r10
; 
 4023: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 4024: (b7) r2 = 8
 4025: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 4026: (7b) *(u64 *)(r10 -144) = r8
 4027: (7b) *(u64 *)(r10 -136) = r9
 4028: (1d) if r9 == r6 goto pc+57
; 
 4029: (79) r7 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 4030: (1d) if r9 == r7 goto pc+55
 4031: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 4032: (7b) *(u64 *)(r10 -56) = r1
 4033: (7b) *(u64 *)(r10 -64) = r1
 4034: (b7) r1 = 32
 4035: (bf) r3 = r9
 4036: (0f) r3 += r1
 4037: (bf) r1 = r10
 4038: (07) r1 += -64
 4039: (b7) r2 = 16
 4040: (85) call bpf_probe_read_kernel#-51920
 4041: (79) r1 = *(u64 *)(r10 -56)
 4042: (7b) *(u64 *)(r10 -32) = r1
 4043: (79) r1 = *(u64 *)(r10 -64)
 4044: (7b) *(u64 *)(r10 -40) = r1
 4045: (bf) r1 = r10
 4046: (07) r1 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 4047: (61) r1 = *(u32 *)(r1 +4)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 4048: (07) r1 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 4049: (bf) r2 = r1
 4050: (57) r2 &= 4095
; if (off <= buf_off) { // verify no wrap occurred
 4051: (bf) r3 = r8
 4052: (67) r3 <<= 32
 4053: (77) r3 >>= 32
; if (off <= buf_off) { // verify no wrap occurred
 4054: (2d) if r2 > r3 goto pc+2243
; off = buf_off - len;
 4055: (79) r3 = *(u64 *)(r10 -144)
 4056: (1f) r3 -= r1
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 4057: (57) r3 &= 4095
 4058: (79) r1 = *(u64 *)(r10 -120)
 4059: (0f) r1 += r3
 4060: (bf) r3 = r10
; off = buf_off - len;
 4061: (07) r3 += -40
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 4062: (79) r3 = *(u64 *)(r3 +8)
 4063: (85) call bpf_probe_read_kernel_str#-51856
 4064: (bf) r6 = r0
 4065: (bf) r1 = r6
 4066: (67) r1 <<= 32
 4067: (c7) r1 s>>= 32
 4068: (b7) r2 = 2
; if (sz > 1) {
 4069: (6d) if r2 s> r1 goto pc+2228
 4070: (79) r8 = *(u64 *)(r10 -144)
; buf_off -= 1; // remove null byte termination with slash sign
 4071: (bf) r2 = r8
 4072: (07) r2 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 4073: (57) r2 &= 4095
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 4074: (79) r1 = *(u64 *)(r10 -120)
 4075: (0f) r1 += r2
 4076: (bf) r3 = r10
; buf_off -= 1; // remove null byte termination with slash sign
 4077: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 4078: (b7) r2 = 1
 4079: (85) call bpf_probe_read_compat#-45600
; buf_off -= sz - 1;
 4080: (1f) r8 -= r6
 4081: (7b) *(u64 *)(r10 -144) = r8
; 
 4082: (bf) r9 = r7
 4083: (79) r8 = *(u64 *)(r10 -152)
 4084: (79) r3 = *(u64 *)(r10 -128)
 4085: (05) goto pc+37
; if (dentry != mnt_root) {
 4086: (79) r1 = *(u64 *)(r10 -104)
 4087: (79) r2 = *(u64 *)(r10 -152)
 4088: (1d) if r1 == r2 goto pc+2209
 4089: (79) r1 = *(u64 *)(r10 -136)
 4090: (5d) if r1 != r6 goto pc+2207
 4091: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 4092: (7b) *(u64 *)(r10 -64) = r6
 4093: (b7) r1 = 24
 4094: (79) r8 = *(u64 *)(r10 -104)
 4095: (bf) r3 = r8
 4096: (0f) r3 += r1
 4097: (bf) r1 = r10
; 
 4098: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 4099: (b7) r2 = 8
 4100: (85) call bpf_probe_read_kernel#-51920
 4101: (b7) r7 = 16
 4102: (0f) r8 += r7
 4103: (79) r9 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 4104: (7b) *(u64 *)(r10 -64) = r6
 4105: (bf) r1 = r10
; 
 4106: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 4107: (b7) r2 = 8
 4108: (bf) r3 = r8
 4109: (85) call bpf_probe_read_kernel#-51920
 4110: (79) r8 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 4111: (7b) *(u64 *)(r10 -64) = r6
 4112: (bf) r3 = r8
 4113: (0f) r3 += r7
 4114: (bf) r1 = r10
; 
 4115: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 4116: (b7) r2 = 8
 4117: (85) call bpf_probe_read_kernel#-51920
 4118: (b7) r1 = 32
 4119: (7b) *(u64 *)(r10 -104) = r8
 4120: (bf) r3 = r8
 4121: (0f) r3 += r1
 4122: (79) r8 = *(u64 *)(r10 -64)
 4123: (b7) r1 = 0
 4124: (7b) *(u64 *)(r10 -128) = r3
 4125: (0f) r3 += r1
 4126: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 4127: (7b) *(u64 *)(r10 -64) = r7
 4128: (bf) r1 = r10
; 
 4129: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 4130: (b7) r2 = 8
 4131: (85) call bpf_probe_read_kernel#-51920
 4132: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 4133: (7b) *(u64 *)(r10 -64) = r7
 4134: (b7) r1 = 24
 4135: (bf) r3 = r9
 4136: (0f) r3 += r1
 4137: (bf) r1 = r10
; 
 4138: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 4139: (b7) r2 = 8
 4140: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 4141: (7b) *(u64 *)(r10 -136) = r9
 4142: (1d) if r9 == r6 goto pc+56
; 
 4143: (79) r7 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 4144: (1d) if r9 == r7 goto pc+54
 4145: (7b) *(u64 *)(r10 -152) = r8
 4146: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 4147: (7b) *(u64 *)(r10 -56) = r1
 4148: (7b) *(u64 *)(r10 -64) = r1
 4149: (b7) r1 = 32
 4150: (bf) r3 = r9
 4151: (0f) r3 += r1
 4152: (bf) r1 = r10
 4153: (07) r1 += -64
 4154: (b7) r2 = 16
 4155: (85) call bpf_probe_read_kernel#-51920
 4156: (79) r1 = *(u64 *)(r10 -56)
 4157: (7b) *(u64 *)(r10 -32) = r1
 4158: (79) r1 = *(u64 *)(r10 -64)
 4159: (7b) *(u64 *)(r10 -40) = r1
 4160: (bf) r1 = r10
 4161: (07) r1 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 4162: (61) r1 = *(u32 *)(r1 +4)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 4163: (07) r1 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 4164: (bf) r2 = r1
 4165: (57) r2 &= 4095
; if (off <= buf_off) { // verify no wrap occurred
 4166: (79) r3 = *(u64 *)(r10 -144)
 4167: (67) r3 <<= 32
 4168: (77) r3 >>= 32
; if (off <= buf_off) { // verify no wrap occurred
 4169: (2d) if r2 > r3 goto pc+2128
; off = buf_off - len;
 4170: (79) r3 = *(u64 *)(r10 -144)
 4171: (1f) r3 -= r1
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 4172: (57) r3 &= 4095
 4173: (79) r1 = *(u64 *)(r10 -120)
 4174: (0f) r1 += r3
 4175: (bf) r3 = r10
; off = buf_off - len;
 4176: (07) r3 += -40
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 4177: (79) r3 = *(u64 *)(r3 +8)
 4178: (85) call bpf_probe_read_kernel_str#-51856
 4179: (bf) r6 = r0
 4180: (bf) r1 = r6
 4181: (67) r1 <<= 32
 4182: (c7) r1 s>>= 32
 4183: (b7) r2 = 2
; if (sz > 1) {
 4184: (6d) if r2 s> r1 goto pc+2113
 4185: (79) r8 = *(u64 *)(r10 -144)
; buf_off -= 1; // remove null byte termination with slash sign
 4186: (bf) r2 = r8
 4187: (07) r2 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 4188: (57) r2 &= 4095
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 4189: (79) r1 = *(u64 *)(r10 -120)
 4190: (0f) r1 += r2
 4191: (bf) r3 = r10
; buf_off -= 1; // remove null byte termination with slash sign
 4192: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 4193: (b7) r2 = 1
 4194: (85) call bpf_probe_read_compat#-45600
; buf_off -= sz - 1;
 4195: (1f) r8 -= r6
 4196: (7b) *(u64 *)(r10 -144) = r8
; 
 4197: (bf) r9 = r7
 4198: (05) goto pc+37
; if (dentry != mnt_root) {
 4199: (79) r1 = *(u64 *)(r10 -104)
 4200: (1d) if r1 == r8 goto pc+2097
 4201: (79) r1 = *(u64 *)(r10 -136)
 4202: (5d) if r1 != r6 goto pc+2095
 4203: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 4204: (7b) *(u64 *)(r10 -64) = r6
 4205: (b7) r1 = 24
 4206: (79) r8 = *(u64 *)(r10 -104)
 4207: (bf) r3 = r8
 4208: (0f) r3 += r1
 4209: (bf) r1 = r10
; 
 4210: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 4211: (b7) r2 = 8
 4212: (85) call bpf_probe_read_kernel#-51920
 4213: (b7) r7 = 16
 4214: (0f) r8 += r7
 4215: (79) r9 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 4216: (7b) *(u64 *)(r10 -64) = r6
 4217: (bf) r1 = r10
; 
 4218: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 4219: (b7) r2 = 8
 4220: (bf) r3 = r8
 4221: (85) call bpf_probe_read_kernel#-51920
 4222: (79) r8 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 4223: (7b) *(u64 *)(r10 -64) = r6
 4224: (bf) r3 = r8
 4225: (0f) r3 += r7
 4226: (bf) r1 = r10
; 
 4227: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 4228: (b7) r2 = 8
 4229: (85) call bpf_probe_read_kernel#-51920
 4230: (b7) r1 = 32
 4231: (7b) *(u64 *)(r10 -104) = r8
 4232: (0f) r8 += r1
 4233: (7b) *(u64 *)(r10 -128) = r8
 4234: (79) r1 = *(u64 *)(r10 -64)
 4235: (7b) *(u64 *)(r10 -152) = r1
 4236: (b7) r1 = 0
 4237: (79) r3 = *(u64 *)(r10 -128)
 4238: (0f) r3 += r1
 4239: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 4240: (7b) *(u64 *)(r10 -64) = r7
 4241: (bf) r1 = r10
; 
 4242: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 4243: (b7) r2 = 8
 4244: (85) call bpf_probe_read_kernel#-51920
 4245: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 4246: (7b) *(u64 *)(r10 -64) = r7
 4247: (b7) r1 = 24
 4248: (bf) r3 = r9
 4249: (0f) r3 += r1
 4250: (bf) r1 = r10
; 
 4251: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 4252: (b7) r2 = 8
 4253: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 4254: (7b) *(u64 *)(r10 -136) = r9
 4255: (1d) if r9 == r6 goto pc+55
; 
 4256: (79) r7 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 4257: (1d) if r9 == r7 goto pc+53
 4258: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 4259: (7b) *(u64 *)(r10 -56) = r1
 4260: (7b) *(u64 *)(r10 -64) = r1
 4261: (b7) r1 = 32
 4262: (bf) r3 = r9
 4263: (0f) r3 += r1
 4264: (bf) r1 = r10
 4265: (07) r1 += -64
 4266: (b7) r2 = 16
 4267: (85) call bpf_probe_read_kernel#-51920
 4268: (79) r1 = *(u64 *)(r10 -56)
 4269: (7b) *(u64 *)(r10 -32) = r1
 4270: (79) r1 = *(u64 *)(r10 -64)
 4271: (7b) *(u64 *)(r10 -40) = r1
 4272: (bf) r1 = r10
 4273: (07) r1 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 4274: (61) r1 = *(u32 *)(r1 +4)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 4275: (07) r1 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 4276: (bf) r2 = r1
 4277: (57) r2 &= 4095
; if (off <= buf_off) { // verify no wrap occurred
 4278: (79) r3 = *(u64 *)(r10 -144)
 4279: (67) r3 <<= 32
 4280: (77) r3 >>= 32
; if (off <= buf_off) { // verify no wrap occurred
 4281: (2d) if r2 > r3 goto pc+2016
; off = buf_off - len;
 4282: (79) r3 = *(u64 *)(r10 -144)
 4283: (1f) r3 -= r1
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 4284: (57) r3 &= 4095
 4285: (79) r1 = *(u64 *)(r10 -120)
 4286: (0f) r1 += r3
 4287: (bf) r3 = r10
; off = buf_off - len;
 4288: (07) r3 += -40
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 4289: (79) r3 = *(u64 *)(r3 +8)
 4290: (85) call bpf_probe_read_kernel_str#-51856
 4291: (bf) r6 = r0
 4292: (bf) r1 = r6
 4293: (67) r1 <<= 32
 4294: (c7) r1 s>>= 32
 4295: (b7) r2 = 2
; if (sz > 1) {
 4296: (6d) if r2 s> r1 goto pc+2001
 4297: (79) r8 = *(u64 *)(r10 -144)
; buf_off -= 1; // remove null byte termination with slash sign
 4298: (bf) r2 = r8
 4299: (07) r2 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 4300: (57) r2 &= 4095
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 4301: (79) r1 = *(u64 *)(r10 -120)
 4302: (0f) r1 += r2
 4303: (bf) r3 = r10
; buf_off -= 1; // remove null byte termination with slash sign
 4304: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 4305: (b7) r2 = 1
 4306: (85) call bpf_probe_read_compat#-45600
; buf_off -= sz - 1;
 4307: (1f) r8 -= r6
 4308: (7b) *(u64 *)(r10 -144) = r8
; 
 4309: (7b) *(u64 *)(r10 -136) = r7
 4310: (05) goto pc+39
; if (dentry != mnt_root) {
 4311: (79) r1 = *(u64 *)(r10 -104)
 4312: (79) r2 = *(u64 *)(r10 -152)
 4313: (1d) if r1 == r2 goto pc+1984
 4314: (79) r1 = *(u64 *)(r10 -136)
 4315: (5d) if r1 != r6 goto pc+1982
 4316: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 4317: (7b) *(u64 *)(r10 -64) = r6
 4318: (b7) r1 = 24
 4319: (79) r8 = *(u64 *)(r10 -104)
 4320: (bf) r3 = r8
 4321: (0f) r3 += r1
 4322: (bf) r1 = r10
; 
 4323: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 4324: (b7) r2 = 8
 4325: (85) call bpf_probe_read_kernel#-51920
 4326: (b7) r7 = 16
 4327: (0f) r8 += r7
 4328: (79) r1 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 4329: (7b) *(u64 *)(r10 -136) = r1
 4330: (7b) *(u64 *)(r10 -64) = r6
 4331: (bf) r1 = r10
; 
 4332: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 4333: (b7) r2 = 8
 4334: (bf) r3 = r8
 4335: (85) call bpf_probe_read_kernel#-51920
 4336: (79) r8 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 4337: (7b) *(u64 *)(r10 -64) = r6
 4338: (bf) r3 = r8
 4339: (0f) r3 += r7
 4340: (bf) r1 = r10
; 
 4341: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 4342: (b7) r2 = 8
 4343: (85) call bpf_probe_read_kernel#-51920
 4344: (b7) r1 = 32
 4345: (7b) *(u64 *)(r10 -104) = r8
 4346: (0f) r8 += r1
 4347: (7b) *(u64 *)(r10 -128) = r8
 4348: (79) r1 = *(u64 *)(r10 -64)
 4349: (7b) *(u64 *)(r10 -152) = r1
 4350: (b7) r1 = 0
 4351: (79) r3 = *(u64 *)(r10 -128)
 4352: (0f) r3 += r1
 4353: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 4354: (7b) *(u64 *)(r10 -64) = r7
 4355: (bf) r1 = r10
; 
 4356: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 4357: (b7) r2 = 8
 4358: (85) call bpf_probe_read_kernel#-51920
 4359: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 4360: (7b) *(u64 *)(r10 -64) = r7
 4361: (b7) r1 = 24
 4362: (79) r7 = *(u64 *)(r10 -136)
 4363: (bf) r3 = r7
 4364: (0f) r3 += r1
 4365: (bf) r1 = r10
; 
 4366: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 4367: (b7) r2 = 8
 4368: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 4369: (1d) if r7 == r6 goto pc+56
; 
 4370: (79) r7 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 4371: (79) r1 = *(u64 *)(r10 -136)
 4372: (1d) if r1 == r7 goto pc+53
 4373: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 4374: (7b) *(u64 *)(r10 -56) = r1
 4375: (7b) *(u64 *)(r10 -64) = r1
 4376: (b7) r1 = 32
 4377: (79) r3 = *(u64 *)(r10 -136)
 4378: (0f) r3 += r1
 4379: (bf) r1 = r10
 4380: (07) r1 += -64
 4381: (b7) r2 = 16
 4382: (85) call bpf_probe_read_kernel#-51920
 4383: (79) r1 = *(u64 *)(r10 -56)
 4384: (7b) *(u64 *)(r10 -32) = r1
 4385: (79) r1 = *(u64 *)(r10 -64)
 4386: (7b) *(u64 *)(r10 -40) = r1
 4387: (bf) r1 = r10
 4388: (07) r1 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 4389: (61) r1 = *(u32 *)(r1 +4)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 4390: (07) r1 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 4391: (bf) r2 = r1
 4392: (57) r2 &= 4095
; if (off <= buf_off) { // verify no wrap occurred
 4393: (79) r3 = *(u64 *)(r10 -144)
 4394: (67) r3 <<= 32
 4395: (77) r3 >>= 32
; if (off <= buf_off) { // verify no wrap occurred
 4396: (2d) if r2 > r3 goto pc+1901
; off = buf_off - len;
 4397: (79) r3 = *(u64 *)(r10 -144)
 4398: (1f) r3 -= r1
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 4399: (57) r3 &= 4095
 4400: (79) r1 = *(u64 *)(r10 -120)
 4401: (0f) r1 += r3
 4402: (bf) r3 = r10
; off = buf_off - len;
 4403: (07) r3 += -40
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 4404: (79) r3 = *(u64 *)(r3 +8)
 4405: (85) call bpf_probe_read_kernel_str#-51856
 4406: (bf) r6 = r0
 4407: (bf) r1 = r6
 4408: (67) r1 <<= 32
 4409: (c7) r1 s>>= 32
 4410: (b7) r2 = 2
; if (sz > 1) {
 4411: (6d) if r2 s> r1 goto pc+1886
 4412: (79) r8 = *(u64 *)(r10 -144)
; buf_off -= 1; // remove null byte termination with slash sign
 4413: (bf) r2 = r8
 4414: (07) r2 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 4415: (57) r2 &= 4095
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 4416: (79) r1 = *(u64 *)(r10 -120)
 4417: (0f) r1 += r2
 4418: (bf) r3 = r10
; buf_off -= 1; // remove null byte termination with slash sign
 4419: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 4420: (b7) r2 = 1
 4421: (85) call bpf_probe_read_compat#-45600
; buf_off -= sz - 1;
 4422: (1f) r8 -= r6
 4423: (7b) *(u64 *)(r10 -144) = r8
; 
 4424: (7b) *(u64 *)(r10 -136) = r7
 4425: (05) goto pc+39
; if (dentry != mnt_root) {
 4426: (79) r1 = *(u64 *)(r10 -104)
 4427: (79) r2 = *(u64 *)(r10 -152)
 4428: (1d) if r1 == r2 goto pc+1869
 4429: (79) r1 = *(u64 *)(r10 -136)
 4430: (5d) if r1 != r6 goto pc+1867
 4431: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 4432: (7b) *(u64 *)(r10 -64) = r6
 4433: (b7) r1 = 24
 4434: (79) r8 = *(u64 *)(r10 -104)
 4435: (bf) r3 = r8
 4436: (0f) r3 += r1
 4437: (bf) r1 = r10
; 
 4438: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 4439: (b7) r2 = 8
 4440: (85) call bpf_probe_read_kernel#-51920
 4441: (b7) r7 = 16
 4442: (0f) r8 += r7
 4443: (79) r1 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 4444: (7b) *(u64 *)(r10 -136) = r1
 4445: (7b) *(u64 *)(r10 -64) = r6
 4446: (bf) r1 = r10
; 
 4447: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 4448: (b7) r2 = 8
 4449: (bf) r3 = r8
 4450: (85) call bpf_probe_read_kernel#-51920
 4451: (79) r8 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 4452: (7b) *(u64 *)(r10 -64) = r6
 4453: (bf) r3 = r8
 4454: (0f) r3 += r7
 4455: (bf) r1 = r10
; 
 4456: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 4457: (b7) r2 = 8
 4458: (85) call bpf_probe_read_kernel#-51920
 4459: (b7) r1 = 32
 4460: (7b) *(u64 *)(r10 -104) = r8
 4461: (0f) r8 += r1
 4462: (7b) *(u64 *)(r10 -128) = r8
 4463: (79) r1 = *(u64 *)(r10 -64)
 4464: (7b) *(u64 *)(r10 -152) = r1
 4465: (b7) r1 = 0
 4466: (79) r3 = *(u64 *)(r10 -128)
 4467: (0f) r3 += r1
 4468: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 4469: (7b) *(u64 *)(r10 -64) = r7
 4470: (bf) r1 = r10
; 
 4471: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 4472: (b7) r2 = 8
 4473: (85) call bpf_probe_read_kernel#-51920
 4474: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 4475: (7b) *(u64 *)(r10 -64) = r7
 4476: (b7) r1 = 24
 4477: (79) r7 = *(u64 *)(r10 -136)
 4478: (bf) r3 = r7
 4479: (0f) r3 += r1
 4480: (bf) r1 = r10
; 
 4481: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 4482: (b7) r2 = 8
 4483: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 4484: (1d) if r7 == r6 goto pc+56
; 
 4485: (79) r7 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 4486: (79) r1 = *(u64 *)(r10 -136)
 4487: (1d) if r1 == r7 goto pc+53
 4488: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 4489: (7b) *(u64 *)(r10 -56) = r1
 4490: (7b) *(u64 *)(r10 -64) = r1
 4491: (b7) r1 = 32
 4492: (79) r3 = *(u64 *)(r10 -136)
 4493: (0f) r3 += r1
 4494: (bf) r1 = r10
 4495: (07) r1 += -64
 4496: (b7) r2 = 16
 4497: (85) call bpf_probe_read_kernel#-51920
 4498: (79) r1 = *(u64 *)(r10 -56)
 4499: (7b) *(u64 *)(r10 -32) = r1
 4500: (79) r1 = *(u64 *)(r10 -64)
 4501: (7b) *(u64 *)(r10 -40) = r1
 4502: (bf) r1 = r10
 4503: (07) r1 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 4504: (61) r1 = *(u32 *)(r1 +4)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 4505: (07) r1 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 4506: (bf) r2 = r1
 4507: (57) r2 &= 4095
; if (off <= buf_off) { // verify no wrap occurred
 4508: (79) r3 = *(u64 *)(r10 -144)
 4509: (67) r3 <<= 32
 4510: (77) r3 >>= 32
; if (off <= buf_off) { // verify no wrap occurred
 4511: (2d) if r2 > r3 goto pc+1786
; off = buf_off - len;
 4512: (79) r3 = *(u64 *)(r10 -144)
 4513: (1f) r3 -= r1
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 4514: (57) r3 &= 4095
 4515: (79) r1 = *(u64 *)(r10 -120)
 4516: (0f) r1 += r3
 4517: (bf) r3 = r10
; off = buf_off - len;
 4518: (07) r3 += -40
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 4519: (79) r3 = *(u64 *)(r3 +8)
 4520: (85) call bpf_probe_read_kernel_str#-51856
 4521: (bf) r6 = r0
 4522: (bf) r1 = r6
 4523: (67) r1 <<= 32
 4524: (c7) r1 s>>= 32
 4525: (b7) r2 = 2
; if (sz > 1) {
 4526: (6d) if r2 s> r1 goto pc+1771
 4527: (79) r8 = *(u64 *)(r10 -144)
; buf_off -= 1; // remove null byte termination with slash sign
 4528: (bf) r2 = r8
 4529: (07) r2 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 4530: (57) r2 &= 4095
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 4531: (79) r1 = *(u64 *)(r10 -120)
 4532: (0f) r1 += r2
 4533: (bf) r3 = r10
; buf_off -= 1; // remove null byte termination with slash sign
 4534: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 4535: (b7) r2 = 1
 4536: (85) call bpf_probe_read_compat#-45600
; buf_off -= sz - 1;
 4537: (1f) r8 -= r6
 4538: (7b) *(u64 *)(r10 -144) = r8
; 
 4539: (7b) *(u64 *)(r10 -136) = r7
 4540: (05) goto pc+39
; if (dentry != mnt_root) {
 4541: (79) r1 = *(u64 *)(r10 -104)
 4542: (79) r2 = *(u64 *)(r10 -152)
 4543: (1d) if r1 == r2 goto pc+1754
 4544: (79) r1 = *(u64 *)(r10 -136)
 4545: (5d) if r1 != r6 goto pc+1752
 4546: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 4547: (7b) *(u64 *)(r10 -64) = r6
 4548: (b7) r1 = 24
 4549: (79) r8 = *(u64 *)(r10 -104)
 4550: (bf) r3 = r8
 4551: (0f) r3 += r1
 4552: (bf) r1 = r10
; 
 4553: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 4554: (b7) r2 = 8
 4555: (85) call bpf_probe_read_kernel#-51920
 4556: (b7) r7 = 16
 4557: (0f) r8 += r7
 4558: (79) r1 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 4559: (7b) *(u64 *)(r10 -136) = r1
 4560: (7b) *(u64 *)(r10 -64) = r6
 4561: (bf) r1 = r10
; 
 4562: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 4563: (b7) r2 = 8
 4564: (bf) r3 = r8
 4565: (85) call bpf_probe_read_kernel#-51920
 4566: (79) r8 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 4567: (7b) *(u64 *)(r10 -64) = r6
 4568: (bf) r3 = r8
 4569: (0f) r3 += r7
 4570: (bf) r1 = r10
; 
 4571: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 4572: (b7) r2 = 8
 4573: (85) call bpf_probe_read_kernel#-51920
 4574: (b7) r1 = 32
 4575: (7b) *(u64 *)(r10 -104) = r8
 4576: (0f) r8 += r1
 4577: (7b) *(u64 *)(r10 -128) = r8
 4578: (79) r1 = *(u64 *)(r10 -64)
 4579: (7b) *(u64 *)(r10 -152) = r1
 4580: (b7) r1 = 0
 4581: (79) r3 = *(u64 *)(r10 -128)
 4582: (0f) r3 += r1
 4583: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 4584: (7b) *(u64 *)(r10 -64) = r7
 4585: (bf) r1 = r10
; 
 4586: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 4587: (b7) r2 = 8
 4588: (85) call bpf_probe_read_kernel#-51920
 4589: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 4590: (7b) *(u64 *)(r10 -64) = r7
 4591: (b7) r1 = 24
 4592: (79) r7 = *(u64 *)(r10 -136)
 4593: (bf) r3 = r7
 4594: (0f) r3 += r1
 4595: (bf) r1 = r10
; 
 4596: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 4597: (b7) r2 = 8
 4598: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 4599: (1d) if r7 == r6 goto pc+56
; 
 4600: (79) r7 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 4601: (79) r1 = *(u64 *)(r10 -136)
 4602: (1d) if r1 == r7 goto pc+53
 4603: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 4604: (7b) *(u64 *)(r10 -56) = r1
 4605: (7b) *(u64 *)(r10 -64) = r1
 4606: (b7) r1 = 32
 4607: (79) r3 = *(u64 *)(r10 -136)
 4608: (0f) r3 += r1
 4609: (bf) r1 = r10
 4610: (07) r1 += -64
 4611: (b7) r2 = 16
 4612: (85) call bpf_probe_read_kernel#-51920
 4613: (79) r1 = *(u64 *)(r10 -56)
 4614: (7b) *(u64 *)(r10 -32) = r1
 4615: (79) r1 = *(u64 *)(r10 -64)
 4616: (7b) *(u64 *)(r10 -40) = r1
 4617: (bf) r1 = r10
 4618: (07) r1 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 4619: (61) r1 = *(u32 *)(r1 +4)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 4620: (07) r1 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 4621: (bf) r2 = r1
 4622: (57) r2 &= 4095
; if (off <= buf_off) { // verify no wrap occurred
 4623: (79) r3 = *(u64 *)(r10 -144)
 4624: (67) r3 <<= 32
 4625: (77) r3 >>= 32
; if (off <= buf_off) { // verify no wrap occurred
 4626: (2d) if r2 > r3 goto pc+1671
; off = buf_off - len;
 4627: (79) r3 = *(u64 *)(r10 -144)
 4628: (1f) r3 -= r1
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 4629: (57) r3 &= 4095
 4630: (79) r1 = *(u64 *)(r10 -120)
 4631: (0f) r1 += r3
 4632: (bf) r3 = r10
; off = buf_off - len;
 4633: (07) r3 += -40
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 4634: (79) r3 = *(u64 *)(r3 +8)
 4635: (85) call bpf_probe_read_kernel_str#-51856
 4636: (bf) r6 = r0
 4637: (bf) r1 = r6
 4638: (67) r1 <<= 32
 4639: (c7) r1 s>>= 32
 4640: (b7) r2 = 2
; if (sz > 1) {
 4641: (6d) if r2 s> r1 goto pc+1656
 4642: (79) r8 = *(u64 *)(r10 -144)
; buf_off -= 1; // remove null byte termination with slash sign
 4643: (bf) r2 = r8
 4644: (07) r2 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 4645: (57) r2 &= 4095
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 4646: (79) r1 = *(u64 *)(r10 -120)
 4647: (0f) r1 += r2
 4648: (bf) r3 = r10
; buf_off -= 1; // remove null byte termination with slash sign
 4649: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 4650: (b7) r2 = 1
 4651: (85) call bpf_probe_read_compat#-45600
; buf_off -= sz - 1;
 4652: (1f) r8 -= r6
 4653: (7b) *(u64 *)(r10 -144) = r8
; 
 4654: (7b) *(u64 *)(r10 -136) = r7
 4655: (05) goto pc+39
; if (dentry != mnt_root) {
 4656: (79) r1 = *(u64 *)(r10 -104)
 4657: (79) r2 = *(u64 *)(r10 -152)
 4658: (1d) if r1 == r2 goto pc+1639
 4659: (79) r1 = *(u64 *)(r10 -136)
 4660: (5d) if r1 != r6 goto pc+1637
 4661: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 4662: (7b) *(u64 *)(r10 -64) = r6
 4663: (b7) r1 = 24
 4664: (79) r8 = *(u64 *)(r10 -104)
 4665: (bf) r3 = r8
 4666: (0f) r3 += r1
 4667: (bf) r1 = r10
; 
 4668: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 4669: (b7) r2 = 8
 4670: (85) call bpf_probe_read_kernel#-51920
 4671: (b7) r7 = 16
 4672: (0f) r8 += r7
 4673: (79) r1 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 4674: (7b) *(u64 *)(r10 -136) = r1
 4675: (7b) *(u64 *)(r10 -64) = r6
 4676: (bf) r1 = r10
; 
 4677: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 4678: (b7) r2 = 8
 4679: (bf) r3 = r8
 4680: (85) call bpf_probe_read_kernel#-51920
 4681: (79) r8 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 4682: (7b) *(u64 *)(r10 -64) = r6
 4683: (bf) r3 = r8
 4684: (0f) r3 += r7
 4685: (bf) r1 = r10
; 
 4686: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 4687: (b7) r2 = 8
 4688: (85) call bpf_probe_read_kernel#-51920
 4689: (b7) r1 = 32
 4690: (7b) *(u64 *)(r10 -104) = r8
 4691: (0f) r8 += r1
 4692: (7b) *(u64 *)(r10 -128) = r8
 4693: (79) r1 = *(u64 *)(r10 -64)
 4694: (7b) *(u64 *)(r10 -152) = r1
 4695: (b7) r1 = 0
 4696: (79) r3 = *(u64 *)(r10 -128)
 4697: (0f) r3 += r1
 4698: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 4699: (7b) *(u64 *)(r10 -64) = r7
 4700: (bf) r1 = r10
; 
 4701: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 4702: (b7) r2 = 8
 4703: (85) call bpf_probe_read_kernel#-51920
 4704: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 4705: (7b) *(u64 *)(r10 -64) = r7
 4706: (b7) r1 = 24
 4707: (79) r7 = *(u64 *)(r10 -136)
 4708: (bf) r3 = r7
 4709: (0f) r3 += r1
 4710: (bf) r1 = r10
; 
 4711: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 4712: (b7) r2 = 8
 4713: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 4714: (1d) if r7 == r6 goto pc+56
; 
 4715: (79) r7 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 4716: (79) r1 = *(u64 *)(r10 -136)
 4717: (1d) if r1 == r7 goto pc+53
 4718: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 4719: (7b) *(u64 *)(r10 -56) = r1
 4720: (7b) *(u64 *)(r10 -64) = r1
 4721: (b7) r1 = 32
 4722: (79) r3 = *(u64 *)(r10 -136)
 4723: (0f) r3 += r1
 4724: (bf) r1 = r10
 4725: (07) r1 += -64
 4726: (b7) r2 = 16
 4727: (85) call bpf_probe_read_kernel#-51920
 4728: (79) r1 = *(u64 *)(r10 -56)
 4729: (7b) *(u64 *)(r10 -32) = r1
 4730: (79) r1 = *(u64 *)(r10 -64)
 4731: (7b) *(u64 *)(r10 -40) = r1
 4732: (bf) r1 = r10
 4733: (07) r1 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 4734: (61) r1 = *(u32 *)(r1 +4)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 4735: (07) r1 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 4736: (bf) r2 = r1
 4737: (57) r2 &= 4095
; if (off <= buf_off) { // verify no wrap occurred
 4738: (79) r3 = *(u64 *)(r10 -144)
 4739: (67) r3 <<= 32
 4740: (77) r3 >>= 32
; if (off <= buf_off) { // verify no wrap occurred
 4741: (2d) if r2 > r3 goto pc+1556
; off = buf_off - len;
 4742: (79) r3 = *(u64 *)(r10 -144)
 4743: (1f) r3 -= r1
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 4744: (57) r3 &= 4095
 4745: (79) r1 = *(u64 *)(r10 -120)
 4746: (0f) r1 += r3
 4747: (bf) r3 = r10
; off = buf_off - len;
 4748: (07) r3 += -40
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 4749: (79) r3 = *(u64 *)(r3 +8)
 4750: (85) call bpf_probe_read_kernel_str#-51856
 4751: (bf) r6 = r0
 4752: (bf) r1 = r6
 4753: (67) r1 <<= 32
 4754: (c7) r1 s>>= 32
 4755: (b7) r2 = 2
; if (sz > 1) {
 4756: (6d) if r2 s> r1 goto pc+1541
 4757: (79) r8 = *(u64 *)(r10 -144)
; buf_off -= 1; // remove null byte termination with slash sign
 4758: (bf) r2 = r8
 4759: (07) r2 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 4760: (57) r2 &= 4095
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 4761: (79) r1 = *(u64 *)(r10 -120)
 4762: (0f) r1 += r2
 4763: (bf) r3 = r10
; buf_off -= 1; // remove null byte termination with slash sign
 4764: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 4765: (b7) r2 = 1
 4766: (85) call bpf_probe_read_compat#-45600
; buf_off -= sz - 1;
 4767: (1f) r8 -= r6
 4768: (7b) *(u64 *)(r10 -144) = r8
; 
 4769: (7b) *(u64 *)(r10 -136) = r7
 4770: (05) goto pc+39
; if (dentry != mnt_root) {
 4771: (79) r1 = *(u64 *)(r10 -104)
 4772: (79) r2 = *(u64 *)(r10 -152)
 4773: (1d) if r1 == r2 goto pc+1524
 4774: (79) r1 = *(u64 *)(r10 -136)
 4775: (5d) if r1 != r6 goto pc+1522
 4776: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 4777: (7b) *(u64 *)(r10 -64) = r6
 4778: (b7) r1 = 24
 4779: (79) r8 = *(u64 *)(r10 -104)
 4780: (bf) r3 = r8
 4781: (0f) r3 += r1
 4782: (bf) r1 = r10
; 
 4783: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 4784: (b7) r2 = 8
 4785: (85) call bpf_probe_read_kernel#-51920
 4786: (b7) r7 = 16
 4787: (0f) r8 += r7
 4788: (79) r1 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 4789: (7b) *(u64 *)(r10 -136) = r1
 4790: (7b) *(u64 *)(r10 -64) = r6
 4791: (bf) r1 = r10
; 
 4792: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 4793: (b7) r2 = 8
 4794: (bf) r3 = r8
 4795: (85) call bpf_probe_read_kernel#-51920
 4796: (79) r8 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 4797: (7b) *(u64 *)(r10 -64) = r6
 4798: (bf) r3 = r8
 4799: (0f) r3 += r7
 4800: (bf) r1 = r10
; 
 4801: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 4802: (b7) r2 = 8
 4803: (85) call bpf_probe_read_kernel#-51920
 4804: (b7) r1 = 32
 4805: (7b) *(u64 *)(r10 -104) = r8
 4806: (0f) r8 += r1
 4807: (7b) *(u64 *)(r10 -128) = r8
 4808: (79) r1 = *(u64 *)(r10 -64)
 4809: (7b) *(u64 *)(r10 -152) = r1
 4810: (b7) r1 = 0
 4811: (79) r3 = *(u64 *)(r10 -128)
 4812: (0f) r3 += r1
 4813: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 4814: (7b) *(u64 *)(r10 -64) = r7
 4815: (bf) r1 = r10
; 
 4816: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 4817: (b7) r2 = 8
 4818: (85) call bpf_probe_read_kernel#-51920
 4819: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 4820: (7b) *(u64 *)(r10 -64) = r7
 4821: (b7) r1 = 24
 4822: (79) r7 = *(u64 *)(r10 -136)
 4823: (bf) r3 = r7
 4824: (0f) r3 += r1
 4825: (bf) r1 = r10
; 
 4826: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 4827: (b7) r2 = 8
 4828: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 4829: (1d) if r7 == r6 goto pc+56
; 
 4830: (79) r7 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 4831: (79) r1 = *(u64 *)(r10 -136)
 4832: (1d) if r1 == r7 goto pc+53
 4833: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 4834: (7b) *(u64 *)(r10 -56) = r1
 4835: (7b) *(u64 *)(r10 -64) = r1
 4836: (b7) r1 = 32
 4837: (79) r3 = *(u64 *)(r10 -136)
 4838: (0f) r3 += r1
 4839: (bf) r1 = r10
 4840: (07) r1 += -64
 4841: (b7) r2 = 16
 4842: (85) call bpf_probe_read_kernel#-51920
 4843: (79) r1 = *(u64 *)(r10 -56)
 4844: (7b) *(u64 *)(r10 -32) = r1
 4845: (79) r1 = *(u64 *)(r10 -64)
 4846: (7b) *(u64 *)(r10 -40) = r1
 4847: (bf) r1 = r10
 4848: (07) r1 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 4849: (61) r1 = *(u32 *)(r1 +4)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 4850: (07) r1 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 4851: (bf) r2 = r1
 4852: (57) r2 &= 4095
; if (off <= buf_off) { // verify no wrap occurred
 4853: (79) r3 = *(u64 *)(r10 -144)
 4854: (67) r3 <<= 32
 4855: (77) r3 >>= 32
; if (off <= buf_off) { // verify no wrap occurred
 4856: (2d) if r2 > r3 goto pc+1441
; off = buf_off - len;
 4857: (79) r3 = *(u64 *)(r10 -144)
 4858: (1f) r3 -= r1
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 4859: (57) r3 &= 4095
 4860: (79) r1 = *(u64 *)(r10 -120)
 4861: (0f) r1 += r3
 4862: (bf) r3 = r10
; off = buf_off - len;
 4863: (07) r3 += -40
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 4864: (79) r3 = *(u64 *)(r3 +8)
 4865: (85) call bpf_probe_read_kernel_str#-51856
 4866: (bf) r6 = r0
 4867: (bf) r1 = r6
 4868: (67) r1 <<= 32
 4869: (c7) r1 s>>= 32
 4870: (b7) r2 = 2
; if (sz > 1) {
 4871: (6d) if r2 s> r1 goto pc+1426
 4872: (79) r8 = *(u64 *)(r10 -144)
; buf_off -= 1; // remove null byte termination with slash sign
 4873: (bf) r2 = r8
 4874: (07) r2 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 4875: (57) r2 &= 4095
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 4876: (79) r1 = *(u64 *)(r10 -120)
 4877: (0f) r1 += r2
 4878: (bf) r3 = r10
; buf_off -= 1; // remove null byte termination with slash sign
 4879: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 4880: (b7) r2 = 1
 4881: (85) call bpf_probe_read_compat#-45600
; buf_off -= sz - 1;
 4882: (1f) r8 -= r6
 4883: (7b) *(u64 *)(r10 -144) = r8
; 
 4884: (7b) *(u64 *)(r10 -136) = r7
 4885: (05) goto pc+39
; if (dentry != mnt_root) {
 4886: (79) r1 = *(u64 *)(r10 -104)
 4887: (79) r2 = *(u64 *)(r10 -152)
 4888: (1d) if r1 == r2 goto pc+1409
 4889: (79) r1 = *(u64 *)(r10 -136)
 4890: (5d) if r1 != r6 goto pc+1407
 4891: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 4892: (7b) *(u64 *)(r10 -64) = r6
 4893: (b7) r1 = 24
 4894: (79) r8 = *(u64 *)(r10 -104)
 4895: (bf) r3 = r8
 4896: (0f) r3 += r1
 4897: (bf) r1 = r10
; 
 4898: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 4899: (b7) r2 = 8
 4900: (85) call bpf_probe_read_kernel#-51920
 4901: (b7) r7 = 16
 4902: (0f) r8 += r7
 4903: (79) r1 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 4904: (7b) *(u64 *)(r10 -136) = r1
 4905: (7b) *(u64 *)(r10 -64) = r6
 4906: (bf) r1 = r10
; 
 4907: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 4908: (b7) r2 = 8
 4909: (bf) r3 = r8
 4910: (85) call bpf_probe_read_kernel#-51920
 4911: (79) r8 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 4912: (7b) *(u64 *)(r10 -64) = r6
 4913: (bf) r3 = r8
 4914: (0f) r3 += r7
 4915: (bf) r1 = r10
; 
 4916: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 4917: (b7) r2 = 8
 4918: (85) call bpf_probe_read_kernel#-51920
 4919: (b7) r1 = 32
 4920: (7b) *(u64 *)(r10 -104) = r8
 4921: (0f) r8 += r1
 4922: (7b) *(u64 *)(r10 -128) = r8
 4923: (79) r1 = *(u64 *)(r10 -64)
 4924: (7b) *(u64 *)(r10 -152) = r1
 4925: (b7) r1 = 0
 4926: (79) r3 = *(u64 *)(r10 -128)
 4927: (0f) r3 += r1
 4928: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 4929: (7b) *(u64 *)(r10 -64) = r7
 4930: (bf) r1 = r10
; 
 4931: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 4932: (b7) r2 = 8
 4933: (85) call bpf_probe_read_kernel#-51920
 4934: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 4935: (7b) *(u64 *)(r10 -64) = r7
 4936: (b7) r1 = 24
 4937: (79) r7 = *(u64 *)(r10 -136)
 4938: (bf) r3 = r7
 4939: (0f) r3 += r1
 4940: (bf) r1 = r10
; 
 4941: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 4942: (b7) r2 = 8
 4943: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 4944: (1d) if r7 == r6 goto pc+56
; 
 4945: (79) r7 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 4946: (79) r1 = *(u64 *)(r10 -136)
 4947: (1d) if r1 == r7 goto pc+53
 4948: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 4949: (7b) *(u64 *)(r10 -56) = r1
 4950: (7b) *(u64 *)(r10 -64) = r1
 4951: (b7) r1 = 32
 4952: (79) r3 = *(u64 *)(r10 -136)
 4953: (0f) r3 += r1
 4954: (bf) r1 = r10
 4955: (07) r1 += -64
 4956: (b7) r2 = 16
 4957: (85) call bpf_probe_read_kernel#-51920
 4958: (79) r1 = *(u64 *)(r10 -56)
 4959: (7b) *(u64 *)(r10 -32) = r1
 4960: (79) r1 = *(u64 *)(r10 -64)
 4961: (7b) *(u64 *)(r10 -40) = r1
 4962: (bf) r1 = r10
 4963: (07) r1 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 4964: (61) r1 = *(u32 *)(r1 +4)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 4965: (07) r1 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 4966: (bf) r2 = r1
 4967: (57) r2 &= 4095
; if (off <= buf_off) { // verify no wrap occurred
 4968: (79) r3 = *(u64 *)(r10 -144)
 4969: (67) r3 <<= 32
 4970: (77) r3 >>= 32
; if (off <= buf_off) { // verify no wrap occurred
 4971: (2d) if r2 > r3 goto pc+1326
; off = buf_off - len;
 4972: (79) r3 = *(u64 *)(r10 -144)
 4973: (1f) r3 -= r1
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 4974: (57) r3 &= 4095
 4975: (79) r1 = *(u64 *)(r10 -120)
 4976: (0f) r1 += r3
 4977: (bf) r3 = r10
; off = buf_off - len;
 4978: (07) r3 += -40
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 4979: (79) r3 = *(u64 *)(r3 +8)
 4980: (85) call bpf_probe_read_kernel_str#-51856
 4981: (bf) r6 = r0
 4982: (bf) r1 = r6
 4983: (67) r1 <<= 32
 4984: (c7) r1 s>>= 32
 4985: (b7) r2 = 2
; if (sz > 1) {
 4986: (6d) if r2 s> r1 goto pc+1311
 4987: (79) r8 = *(u64 *)(r10 -144)
; buf_off -= 1; // remove null byte termination with slash sign
 4988: (bf) r2 = r8
 4989: (07) r2 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 4990: (57) r2 &= 4095
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 4991: (79) r1 = *(u64 *)(r10 -120)
 4992: (0f) r1 += r2
 4993: (bf) r3 = r10
; buf_off -= 1; // remove null byte termination with slash sign
 4994: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 4995: (b7) r2 = 1
 4996: (85) call bpf_probe_read_compat#-45600
; buf_off -= sz - 1;
 4997: (1f) r8 -= r6
 4998: (7b) *(u64 *)(r10 -144) = r8
; 
 4999: (7b) *(u64 *)(r10 -136) = r7
 5000: (05) goto pc+39
; if (dentry != mnt_root) {
 5001: (79) r1 = *(u64 *)(r10 -104)
 5002: (79) r2 = *(u64 *)(r10 -152)
 5003: (1d) if r1 == r2 goto pc+1294
 5004: (79) r1 = *(u64 *)(r10 -136)
 5005: (5d) if r1 != r6 goto pc+1292
 5006: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 5007: (7b) *(u64 *)(r10 -64) = r6
 5008: (b7) r1 = 24
 5009: (79) r8 = *(u64 *)(r10 -104)
 5010: (bf) r3 = r8
 5011: (0f) r3 += r1
 5012: (bf) r1 = r10
; 
 5013: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 5014: (b7) r2 = 8
 5015: (85) call bpf_probe_read_kernel#-51920
 5016: (b7) r7 = 16
 5017: (0f) r8 += r7
 5018: (79) r1 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 5019: (7b) *(u64 *)(r10 -136) = r1
 5020: (7b) *(u64 *)(r10 -64) = r6
 5021: (bf) r1 = r10
; 
 5022: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 5023: (b7) r2 = 8
 5024: (bf) r3 = r8
 5025: (85) call bpf_probe_read_kernel#-51920
 5026: (79) r8 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 5027: (7b) *(u64 *)(r10 -64) = r6
 5028: (bf) r3 = r8
 5029: (0f) r3 += r7
 5030: (bf) r1 = r10
; 
 5031: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 5032: (b7) r2 = 8
 5033: (85) call bpf_probe_read_kernel#-51920
 5034: (b7) r1 = 32
 5035: (7b) *(u64 *)(r10 -104) = r8
 5036: (0f) r8 += r1
 5037: (7b) *(u64 *)(r10 -128) = r8
 5038: (79) r1 = *(u64 *)(r10 -64)
 5039: (7b) *(u64 *)(r10 -152) = r1
 5040: (b7) r1 = 0
 5041: (79) r3 = *(u64 *)(r10 -128)
 5042: (0f) r3 += r1
 5043: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 5044: (7b) *(u64 *)(r10 -64) = r7
 5045: (bf) r1 = r10
; 
 5046: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 5047: (b7) r2 = 8
 5048: (85) call bpf_probe_read_kernel#-51920
 5049: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 5050: (7b) *(u64 *)(r10 -64) = r7
 5051: (b7) r1 = 24
 5052: (79) r7 = *(u64 *)(r10 -136)
 5053: (bf) r3 = r7
 5054: (0f) r3 += r1
 5055: (bf) r1 = r10
; 
 5056: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 5057: (b7) r2 = 8
 5058: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 5059: (1d) if r7 == r6 goto pc+56
; 
 5060: (79) r7 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 5061: (79) r1 = *(u64 *)(r10 -136)
 5062: (1d) if r1 == r7 goto pc+53
 5063: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 5064: (7b) *(u64 *)(r10 -56) = r1
 5065: (7b) *(u64 *)(r10 -64) = r1
 5066: (b7) r1 = 32
 5067: (79) r3 = *(u64 *)(r10 -136)
 5068: (0f) r3 += r1
 5069: (bf) r1 = r10
 5070: (07) r1 += -64
 5071: (b7) r2 = 16
 5072: (85) call bpf_probe_read_kernel#-51920
 5073: (79) r1 = *(u64 *)(r10 -56)
 5074: (7b) *(u64 *)(r10 -32) = r1
 5075: (79) r1 = *(u64 *)(r10 -64)
 5076: (7b) *(u64 *)(r10 -40) = r1
 5077: (bf) r1 = r10
 5078: (07) r1 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 5079: (61) r1 = *(u32 *)(r1 +4)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 5080: (07) r1 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 5081: (bf) r2 = r1
 5082: (57) r2 &= 4095
; if (off <= buf_off) { // verify no wrap occurred
 5083: (79) r3 = *(u64 *)(r10 -144)
 5084: (67) r3 <<= 32
 5085: (77) r3 >>= 32
; if (off <= buf_off) { // verify no wrap occurred
 5086: (2d) if r2 > r3 goto pc+1211
; off = buf_off - len;
 5087: (79) r3 = *(u64 *)(r10 -144)
 5088: (1f) r3 -= r1
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 5089: (57) r3 &= 4095
 5090: (79) r1 = *(u64 *)(r10 -120)
 5091: (0f) r1 += r3
 5092: (bf) r3 = r10
; off = buf_off - len;
 5093: (07) r3 += -40
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 5094: (79) r3 = *(u64 *)(r3 +8)
 5095: (85) call bpf_probe_read_kernel_str#-51856
 5096: (bf) r6 = r0
 5097: (bf) r1 = r6
 5098: (67) r1 <<= 32
 5099: (c7) r1 s>>= 32
 5100: (b7) r2 = 2
; if (sz > 1) {
 5101: (6d) if r2 s> r1 goto pc+1196
 5102: (79) r8 = *(u64 *)(r10 -144)
; buf_off -= 1; // remove null byte termination with slash sign
 5103: (bf) r2 = r8
 5104: (07) r2 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 5105: (57) r2 &= 4095
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 5106: (79) r1 = *(u64 *)(r10 -120)
 5107: (0f) r1 += r2
 5108: (bf) r3 = r10
; buf_off -= 1; // remove null byte termination with slash sign
 5109: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 5110: (b7) r2 = 1
 5111: (85) call bpf_probe_read_compat#-45600
; buf_off -= sz - 1;
 5112: (1f) r8 -= r6
 5113: (7b) *(u64 *)(r10 -144) = r8
; 
 5114: (7b) *(u64 *)(r10 -136) = r7
 5115: (05) goto pc+39
; if (dentry != mnt_root) {
 5116: (79) r1 = *(u64 *)(r10 -104)
 5117: (79) r2 = *(u64 *)(r10 -152)
 5118: (1d) if r1 == r2 goto pc+1179
 5119: (79) r1 = *(u64 *)(r10 -136)
 5120: (5d) if r1 != r6 goto pc+1177
 5121: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 5122: (7b) *(u64 *)(r10 -64) = r6
 5123: (b7) r1 = 24
 5124: (79) r8 = *(u64 *)(r10 -104)
 5125: (bf) r3 = r8
 5126: (0f) r3 += r1
 5127: (bf) r1 = r10
; 
 5128: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 5129: (b7) r2 = 8
 5130: (85) call bpf_probe_read_kernel#-51920
 5131: (b7) r7 = 16
 5132: (0f) r8 += r7
 5133: (79) r1 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 5134: (7b) *(u64 *)(r10 -136) = r1
 5135: (7b) *(u64 *)(r10 -64) = r6
 5136: (bf) r1 = r10
; 
 5137: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 5138: (b7) r2 = 8
 5139: (bf) r3 = r8
 5140: (85) call bpf_probe_read_kernel#-51920
 5141: (79) r8 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 5142: (7b) *(u64 *)(r10 -64) = r6
 5143: (bf) r3 = r8
 5144: (0f) r3 += r7
 5145: (bf) r1 = r10
; 
 5146: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 5147: (b7) r2 = 8
 5148: (85) call bpf_probe_read_kernel#-51920
 5149: (b7) r1 = 32
 5150: (7b) *(u64 *)(r10 -104) = r8
 5151: (0f) r8 += r1
 5152: (7b) *(u64 *)(r10 -128) = r8
 5153: (79) r1 = *(u64 *)(r10 -64)
 5154: (7b) *(u64 *)(r10 -152) = r1
 5155: (b7) r1 = 0
 5156: (79) r3 = *(u64 *)(r10 -128)
 5157: (0f) r3 += r1
 5158: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 5159: (7b) *(u64 *)(r10 -64) = r7
 5160: (bf) r1 = r10
; 
 5161: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 5162: (b7) r2 = 8
 5163: (85) call bpf_probe_read_kernel#-51920
 5164: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 5165: (7b) *(u64 *)(r10 -64) = r7
 5166: (b7) r1 = 24
 5167: (79) r7 = *(u64 *)(r10 -136)
 5168: (bf) r3 = r7
 5169: (0f) r3 += r1
 5170: (bf) r1 = r10
; 
 5171: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 5172: (b7) r2 = 8
 5173: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 5174: (1d) if r7 == r6 goto pc+56
; 
 5175: (79) r7 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 5176: (79) r1 = *(u64 *)(r10 -136)
 5177: (1d) if r1 == r7 goto pc+53
 5178: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 5179: (7b) *(u64 *)(r10 -56) = r1
 5180: (7b) *(u64 *)(r10 -64) = r1
 5181: (b7) r1 = 32
 5182: (79) r3 = *(u64 *)(r10 -136)
 5183: (0f) r3 += r1
 5184: (bf) r1 = r10
 5185: (07) r1 += -64
 5186: (b7) r2 = 16
 5187: (85) call bpf_probe_read_kernel#-51920
 5188: (79) r1 = *(u64 *)(r10 -56)
 5189: (7b) *(u64 *)(r10 -32) = r1
 5190: (79) r1 = *(u64 *)(r10 -64)
 5191: (7b) *(u64 *)(r10 -40) = r1
 5192: (bf) r1 = r10
 5193: (07) r1 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 5194: (61) r1 = *(u32 *)(r1 +4)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 5195: (07) r1 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 5196: (bf) r2 = r1
 5197: (57) r2 &= 4095
; if (off <= buf_off) { // verify no wrap occurred
 5198: (79) r3 = *(u64 *)(r10 -144)
 5199: (67) r3 <<= 32
 5200: (77) r3 >>= 32
; if (off <= buf_off) { // verify no wrap occurred
 5201: (2d) if r2 > r3 goto pc+1096
; off = buf_off - len;
 5202: (79) r3 = *(u64 *)(r10 -144)
 5203: (1f) r3 -= r1
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 5204: (57) r3 &= 4095
 5205: (79) r1 = *(u64 *)(r10 -120)
 5206: (0f) r1 += r3
 5207: (bf) r3 = r10
; off = buf_off - len;
 5208: (07) r3 += -40
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 5209: (79) r3 = *(u64 *)(r3 +8)
 5210: (85) call bpf_probe_read_kernel_str#-51856
 5211: (bf) r6 = r0
 5212: (bf) r1 = r6
 5213: (67) r1 <<= 32
 5214: (c7) r1 s>>= 32
 5215: (b7) r2 = 2
; if (sz > 1) {
 5216: (6d) if r2 s> r1 goto pc+1081
 5217: (79) r8 = *(u64 *)(r10 -144)
; buf_off -= 1; // remove null byte termination with slash sign
 5218: (bf) r2 = r8
 5219: (07) r2 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 5220: (57) r2 &= 4095
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 5221: (79) r1 = *(u64 *)(r10 -120)
 5222: (0f) r1 += r2
 5223: (bf) r3 = r10
; buf_off -= 1; // remove null byte termination with slash sign
 5224: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 5225: (b7) r2 = 1
 5226: (85) call bpf_probe_read_compat#-45600
; buf_off -= sz - 1;
 5227: (1f) r8 -= r6
 5228: (7b) *(u64 *)(r10 -144) = r8
; 
 5229: (7b) *(u64 *)(r10 -136) = r7
 5230: (05) goto pc+39
; if (dentry != mnt_root) {
 5231: (79) r1 = *(u64 *)(r10 -104)
 5232: (79) r2 = *(u64 *)(r10 -152)
 5233: (1d) if r1 == r2 goto pc+1064
 5234: (79) r1 = *(u64 *)(r10 -136)
 5235: (5d) if r1 != r6 goto pc+1062
 5236: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 5237: (7b) *(u64 *)(r10 -64) = r6
 5238: (b7) r1 = 24
 5239: (79) r8 = *(u64 *)(r10 -104)
 5240: (bf) r3 = r8
 5241: (0f) r3 += r1
 5242: (bf) r1 = r10
; 
 5243: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 5244: (b7) r2 = 8
 5245: (85) call bpf_probe_read_kernel#-51920
 5246: (b7) r7 = 16
 5247: (0f) r8 += r7
 5248: (79) r1 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 5249: (7b) *(u64 *)(r10 -136) = r1
 5250: (7b) *(u64 *)(r10 -64) = r6
 5251: (bf) r1 = r10
; 
 5252: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 5253: (b7) r2 = 8
 5254: (bf) r3 = r8
 5255: (85) call bpf_probe_read_kernel#-51920
 5256: (79) r8 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 5257: (7b) *(u64 *)(r10 -64) = r6
 5258: (bf) r3 = r8
 5259: (0f) r3 += r7
 5260: (bf) r1 = r10
; 
 5261: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 5262: (b7) r2 = 8
 5263: (85) call bpf_probe_read_kernel#-51920
 5264: (b7) r1 = 32
 5265: (7b) *(u64 *)(r10 -104) = r8
 5266: (0f) r8 += r1
 5267: (7b) *(u64 *)(r10 -128) = r8
 5268: (79) r1 = *(u64 *)(r10 -64)
 5269: (7b) *(u64 *)(r10 -152) = r1
 5270: (b7) r1 = 0
 5271: (79) r3 = *(u64 *)(r10 -128)
 5272: (0f) r3 += r1
 5273: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 5274: (7b) *(u64 *)(r10 -64) = r7
 5275: (bf) r1 = r10
; 
 5276: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 5277: (b7) r2 = 8
 5278: (85) call bpf_probe_read_kernel#-51920
 5279: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 5280: (7b) *(u64 *)(r10 -64) = r7
 5281: (b7) r1 = 24
 5282: (79) r7 = *(u64 *)(r10 -136)
 5283: (bf) r3 = r7
 5284: (0f) r3 += r1
 5285: (bf) r1 = r10
; 
 5286: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 5287: (b7) r2 = 8
 5288: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 5289: (1d) if r7 == r6 goto pc+56
; 
 5290: (79) r7 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 5291: (79) r1 = *(u64 *)(r10 -136)
 5292: (1d) if r1 == r7 goto pc+53
 5293: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 5294: (7b) *(u64 *)(r10 -56) = r1
 5295: (7b) *(u64 *)(r10 -64) = r1
 5296: (b7) r1 = 32
 5297: (79) r3 = *(u64 *)(r10 -136)
 5298: (0f) r3 += r1
 5299: (bf) r1 = r10
 5300: (07) r1 += -64
 5301: (b7) r2 = 16
 5302: (85) call bpf_probe_read_kernel#-51920
 5303: (79) r1 = *(u64 *)(r10 -56)
 5304: (7b) *(u64 *)(r10 -32) = r1
 5305: (79) r1 = *(u64 *)(r10 -64)
 5306: (7b) *(u64 *)(r10 -40) = r1
 5307: (bf) r1 = r10
 5308: (07) r1 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 5309: (61) r1 = *(u32 *)(r1 +4)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 5310: (07) r1 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 5311: (bf) r2 = r1
 5312: (57) r2 &= 4095
; if (off <= buf_off) { // verify no wrap occurred
 5313: (79) r3 = *(u64 *)(r10 -144)
 5314: (67) r3 <<= 32
 5315: (77) r3 >>= 32
; if (off <= buf_off) { // verify no wrap occurred
 5316: (2d) if r2 > r3 goto pc+981
; off = buf_off - len;
 5317: (79) r3 = *(u64 *)(r10 -144)
 5318: (1f) r3 -= r1
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 5319: (57) r3 &= 4095
 5320: (79) r1 = *(u64 *)(r10 -120)
 5321: (0f) r1 += r3
 5322: (bf) r3 = r10
; off = buf_off - len;
 5323: (07) r3 += -40
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 5324: (79) r3 = *(u64 *)(r3 +8)
 5325: (85) call bpf_probe_read_kernel_str#-51856
 5326: (bf) r6 = r0
 5327: (bf) r1 = r6
 5328: (67) r1 <<= 32
 5329: (c7) r1 s>>= 32
 5330: (b7) r2 = 2
; if (sz > 1) {
 5331: (6d) if r2 s> r1 goto pc+966
 5332: (79) r8 = *(u64 *)(r10 -144)
; buf_off -= 1; // remove null byte termination with slash sign
 5333: (bf) r2 = r8
 5334: (07) r2 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 5335: (57) r2 &= 4095
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 5336: (79) r1 = *(u64 *)(r10 -120)
 5337: (0f) r1 += r2
 5338: (bf) r3 = r10
; buf_off -= 1; // remove null byte termination with slash sign
 5339: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 5340: (b7) r2 = 1
 5341: (85) call bpf_probe_read_compat#-45600
; buf_off -= sz - 1;
 5342: (1f) r8 -= r6
 5343: (7b) *(u64 *)(r10 -144) = r8
; 
 5344: (7b) *(u64 *)(r10 -136) = r7
 5345: (05) goto pc+39
; if (dentry != mnt_root) {
 5346: (79) r1 = *(u64 *)(r10 -104)
 5347: (79) r2 = *(u64 *)(r10 -152)
 5348: (1d) if r1 == r2 goto pc+949
 5349: (79) r1 = *(u64 *)(r10 -136)
 5350: (5d) if r1 != r6 goto pc+947
 5351: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 5352: (7b) *(u64 *)(r10 -64) = r6
 5353: (b7) r1 = 24
 5354: (79) r8 = *(u64 *)(r10 -104)
 5355: (bf) r3 = r8
 5356: (0f) r3 += r1
 5357: (bf) r1 = r10
; 
 5358: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 5359: (b7) r2 = 8
 5360: (85) call bpf_probe_read_kernel#-51920
 5361: (b7) r7 = 16
 5362: (0f) r8 += r7
 5363: (79) r1 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 5364: (7b) *(u64 *)(r10 -136) = r1
 5365: (7b) *(u64 *)(r10 -64) = r6
 5366: (bf) r1 = r10
; 
 5367: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 5368: (b7) r2 = 8
 5369: (bf) r3 = r8
 5370: (85) call bpf_probe_read_kernel#-51920
 5371: (79) r8 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 5372: (7b) *(u64 *)(r10 -64) = r6
 5373: (bf) r3 = r8
 5374: (0f) r3 += r7
 5375: (bf) r1 = r10
; 
 5376: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 5377: (b7) r2 = 8
 5378: (85) call bpf_probe_read_kernel#-51920
 5379: (b7) r1 = 32
 5380: (7b) *(u64 *)(r10 -104) = r8
 5381: (0f) r8 += r1
 5382: (7b) *(u64 *)(r10 -128) = r8
 5383: (79) r1 = *(u64 *)(r10 -64)
 5384: (7b) *(u64 *)(r10 -152) = r1
 5385: (b7) r1 = 0
 5386: (79) r3 = *(u64 *)(r10 -128)
 5387: (0f) r3 += r1
 5388: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 5389: (7b) *(u64 *)(r10 -64) = r7
 5390: (bf) r1 = r10
; 
 5391: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 5392: (b7) r2 = 8
 5393: (85) call bpf_probe_read_kernel#-51920
 5394: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 5395: (7b) *(u64 *)(r10 -64) = r7
 5396: (b7) r1 = 24
 5397: (79) r7 = *(u64 *)(r10 -136)
 5398: (bf) r3 = r7
 5399: (0f) r3 += r1
 5400: (bf) r1 = r10
; 
 5401: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 5402: (b7) r2 = 8
 5403: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 5404: (1d) if r7 == r6 goto pc+56
; 
 5405: (79) r7 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 5406: (79) r1 = *(u64 *)(r10 -136)
 5407: (1d) if r1 == r7 goto pc+53
 5408: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 5409: (7b) *(u64 *)(r10 -56) = r1
 5410: (7b) *(u64 *)(r10 -64) = r1
 5411: (b7) r1 = 32
 5412: (79) r3 = *(u64 *)(r10 -136)
 5413: (0f) r3 += r1
 5414: (bf) r1 = r10
 5415: (07) r1 += -64
 5416: (b7) r2 = 16
 5417: (85) call bpf_probe_read_kernel#-51920
 5418: (79) r1 = *(u64 *)(r10 -56)
 5419: (7b) *(u64 *)(r10 -32) = r1
 5420: (79) r1 = *(u64 *)(r10 -64)
 5421: (7b) *(u64 *)(r10 -40) = r1
 5422: (bf) r1 = r10
 5423: (07) r1 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 5424: (61) r1 = *(u32 *)(r1 +4)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 5425: (07) r1 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 5426: (bf) r2 = r1
 5427: (57) r2 &= 4095
; if (off <= buf_off) { // verify no wrap occurred
 5428: (79) r3 = *(u64 *)(r10 -144)
 5429: (67) r3 <<= 32
 5430: (77) r3 >>= 32
; if (off <= buf_off) { // verify no wrap occurred
 5431: (2d) if r2 > r3 goto pc+866
; off = buf_off - len;
 5432: (79) r3 = *(u64 *)(r10 -144)
 5433: (1f) r3 -= r1
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 5434: (57) r3 &= 4095
 5435: (79) r1 = *(u64 *)(r10 -120)
 5436: (0f) r1 += r3
 5437: (bf) r3 = r10
; off = buf_off - len;
 5438: (07) r3 += -40
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 5439: (79) r3 = *(u64 *)(r3 +8)
 5440: (85) call bpf_probe_read_kernel_str#-51856
 5441: (bf) r6 = r0
 5442: (bf) r1 = r6
 5443: (67) r1 <<= 32
 5444: (c7) r1 s>>= 32
 5445: (b7) r2 = 2
; if (sz > 1) {
 5446: (6d) if r2 s> r1 goto pc+851
 5447: (79) r8 = *(u64 *)(r10 -144)
; buf_off -= 1; // remove null byte termination with slash sign
 5448: (bf) r2 = r8
 5449: (07) r2 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 5450: (57) r2 &= 4095
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 5451: (79) r1 = *(u64 *)(r10 -120)
 5452: (0f) r1 += r2
 5453: (bf) r3 = r10
; buf_off -= 1; // remove null byte termination with slash sign
 5454: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 5455: (b7) r2 = 1
 5456: (85) call bpf_probe_read_compat#-45600
; buf_off -= sz - 1;
 5457: (1f) r8 -= r6
 5458: (7b) *(u64 *)(r10 -144) = r8
; 
 5459: (7b) *(u64 *)(r10 -136) = r7
 5460: (05) goto pc+39
; if (dentry != mnt_root) {
 5461: (79) r1 = *(u64 *)(r10 -104)
 5462: (79) r2 = *(u64 *)(r10 -152)
 5463: (1d) if r1 == r2 goto pc+834
 5464: (79) r1 = *(u64 *)(r10 -136)
 5465: (5d) if r1 != r6 goto pc+832
 5466: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 5467: (7b) *(u64 *)(r10 -64) = r6
 5468: (b7) r1 = 24
 5469: (79) r8 = *(u64 *)(r10 -104)
 5470: (bf) r3 = r8
 5471: (0f) r3 += r1
 5472: (bf) r1 = r10
; 
 5473: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 5474: (b7) r2 = 8
 5475: (85) call bpf_probe_read_kernel#-51920
 5476: (b7) r7 = 16
 5477: (0f) r8 += r7
 5478: (79) r1 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 5479: (7b) *(u64 *)(r10 -136) = r1
 5480: (7b) *(u64 *)(r10 -64) = r6
 5481: (bf) r1 = r10
; 
 5482: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 5483: (b7) r2 = 8
 5484: (bf) r3 = r8
 5485: (85) call bpf_probe_read_kernel#-51920
 5486: (79) r8 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 5487: (7b) *(u64 *)(r10 -64) = r6
 5488: (bf) r3 = r8
 5489: (0f) r3 += r7
 5490: (bf) r1 = r10
; 
 5491: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 5492: (b7) r2 = 8
 5493: (85) call bpf_probe_read_kernel#-51920
 5494: (b7) r1 = 32
 5495: (7b) *(u64 *)(r10 -104) = r8
 5496: (0f) r8 += r1
 5497: (7b) *(u64 *)(r10 -128) = r8
 5498: (79) r1 = *(u64 *)(r10 -64)
 5499: (7b) *(u64 *)(r10 -152) = r1
 5500: (b7) r1 = 0
 5501: (79) r3 = *(u64 *)(r10 -128)
 5502: (0f) r3 += r1
 5503: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 5504: (7b) *(u64 *)(r10 -64) = r7
 5505: (bf) r1 = r10
; 
 5506: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 5507: (b7) r2 = 8
 5508: (85) call bpf_probe_read_kernel#-51920
 5509: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 5510: (7b) *(u64 *)(r10 -64) = r7
 5511: (b7) r1 = 24
 5512: (79) r7 = *(u64 *)(r10 -136)
 5513: (bf) r3 = r7
 5514: (0f) r3 += r1
 5515: (bf) r1 = r10
; 
 5516: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 5517: (b7) r2 = 8
 5518: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 5519: (1d) if r7 == r6 goto pc+56
; 
 5520: (79) r7 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 5521: (79) r1 = *(u64 *)(r10 -136)
 5522: (1d) if r1 == r7 goto pc+53
 5523: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 5524: (7b) *(u64 *)(r10 -56) = r1
 5525: (7b) *(u64 *)(r10 -64) = r1
 5526: (b7) r1 = 32
 5527: (79) r3 = *(u64 *)(r10 -136)
 5528: (0f) r3 += r1
 5529: (bf) r1 = r10
 5530: (07) r1 += -64
 5531: (b7) r2 = 16
 5532: (85) call bpf_probe_read_kernel#-51920
 5533: (79) r1 = *(u64 *)(r10 -56)
 5534: (7b) *(u64 *)(r10 -32) = r1
 5535: (79) r1 = *(u64 *)(r10 -64)
 5536: (7b) *(u64 *)(r10 -40) = r1
 5537: (bf) r1 = r10
 5538: (07) r1 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 5539: (61) r1 = *(u32 *)(r1 +4)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 5540: (07) r1 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 5541: (bf) r2 = r1
 5542: (57) r2 &= 4095
; if (off <= buf_off) { // verify no wrap occurred
 5543: (79) r3 = *(u64 *)(r10 -144)
 5544: (67) r3 <<= 32
 5545: (77) r3 >>= 32
; if (off <= buf_off) { // verify no wrap occurred
 5546: (2d) if r2 > r3 goto pc+751
; off = buf_off - len;
 5547: (79) r3 = *(u64 *)(r10 -144)
 5548: (1f) r3 -= r1
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 5549: (57) r3 &= 4095
 5550: (79) r1 = *(u64 *)(r10 -120)
 5551: (0f) r1 += r3
 5552: (bf) r3 = r10
; off = buf_off - len;
 5553: (07) r3 += -40
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 5554: (79) r3 = *(u64 *)(r3 +8)
 5555: (85) call bpf_probe_read_kernel_str#-51856
 5556: (bf) r6 = r0
 5557: (bf) r1 = r6
 5558: (67) r1 <<= 32
 5559: (c7) r1 s>>= 32
 5560: (b7) r2 = 2
; if (sz > 1) {
 5561: (6d) if r2 s> r1 goto pc+736
 5562: (79) r8 = *(u64 *)(r10 -144)
; buf_off -= 1; // remove null byte termination with slash sign
 5563: (bf) r2 = r8
 5564: (07) r2 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 5565: (57) r2 &= 4095
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 5566: (79) r1 = *(u64 *)(r10 -120)
 5567: (0f) r1 += r2
 5568: (bf) r3 = r10
; buf_off -= 1; // remove null byte termination with slash sign
 5569: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 5570: (b7) r2 = 1
 5571: (85) call bpf_probe_read_compat#-45600
; buf_off -= sz - 1;
 5572: (1f) r8 -= r6
 5573: (7b) *(u64 *)(r10 -144) = r8
; 
 5574: (7b) *(u64 *)(r10 -136) = r7
 5575: (05) goto pc+39
; if (dentry != mnt_root) {
 5576: (79) r1 = *(u64 *)(r10 -104)
 5577: (79) r2 = *(u64 *)(r10 -152)
 5578: (1d) if r1 == r2 goto pc+719
 5579: (79) r1 = *(u64 *)(r10 -136)
 5580: (5d) if r1 != r6 goto pc+717
 5581: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 5582: (7b) *(u64 *)(r10 -64) = r6
 5583: (b7) r1 = 24
 5584: (79) r8 = *(u64 *)(r10 -104)
 5585: (bf) r3 = r8
 5586: (0f) r3 += r1
 5587: (bf) r1 = r10
; 
 5588: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 5589: (b7) r2 = 8
 5590: (85) call bpf_probe_read_kernel#-51920
 5591: (b7) r7 = 16
 5592: (0f) r8 += r7
 5593: (79) r1 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 5594: (7b) *(u64 *)(r10 -136) = r1
 5595: (7b) *(u64 *)(r10 -64) = r6
 5596: (bf) r1 = r10
; 
 5597: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 5598: (b7) r2 = 8
 5599: (bf) r3 = r8
 5600: (85) call bpf_probe_read_kernel#-51920
 5601: (79) r8 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 5602: (7b) *(u64 *)(r10 -64) = r6
 5603: (bf) r3 = r8
 5604: (0f) r3 += r7
 5605: (bf) r1 = r10
; 
 5606: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 5607: (b7) r2 = 8
 5608: (85) call bpf_probe_read_kernel#-51920
 5609: (b7) r1 = 32
 5610: (7b) *(u64 *)(r10 -104) = r8
 5611: (0f) r8 += r1
 5612: (7b) *(u64 *)(r10 -128) = r8
 5613: (79) r1 = *(u64 *)(r10 -64)
 5614: (7b) *(u64 *)(r10 -152) = r1
 5615: (b7) r1 = 0
 5616: (79) r3 = *(u64 *)(r10 -128)
 5617: (0f) r3 += r1
 5618: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 5619: (7b) *(u64 *)(r10 -64) = r7
 5620: (bf) r1 = r10
; 
 5621: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 5622: (b7) r2 = 8
 5623: (85) call bpf_probe_read_kernel#-51920
 5624: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 5625: (7b) *(u64 *)(r10 -64) = r7
 5626: (b7) r1 = 24
 5627: (79) r7 = *(u64 *)(r10 -136)
 5628: (bf) r3 = r7
 5629: (0f) r3 += r1
 5630: (bf) r1 = r10
; 
 5631: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 5632: (b7) r2 = 8
 5633: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 5634: (1d) if r7 == r6 goto pc+56
; 
 5635: (79) r7 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 5636: (79) r1 = *(u64 *)(r10 -136)
 5637: (1d) if r1 == r7 goto pc+53
 5638: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 5639: (7b) *(u64 *)(r10 -56) = r1
 5640: (7b) *(u64 *)(r10 -64) = r1
 5641: (b7) r1 = 32
 5642: (79) r3 = *(u64 *)(r10 -136)
 5643: (0f) r3 += r1
 5644: (bf) r1 = r10
 5645: (07) r1 += -64
 5646: (b7) r2 = 16
 5647: (85) call bpf_probe_read_kernel#-51920
 5648: (79) r1 = *(u64 *)(r10 -56)
 5649: (7b) *(u64 *)(r10 -32) = r1
 5650: (79) r1 = *(u64 *)(r10 -64)
 5651: (7b) *(u64 *)(r10 -40) = r1
 5652: (bf) r1 = r10
 5653: (07) r1 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 5654: (61) r1 = *(u32 *)(r1 +4)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 5655: (07) r1 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 5656: (bf) r2 = r1
 5657: (57) r2 &= 4095
; if (off <= buf_off) { // verify no wrap occurred
 5658: (79) r3 = *(u64 *)(r10 -144)
 5659: (67) r3 <<= 32
 5660: (77) r3 >>= 32
; if (off <= buf_off) { // verify no wrap occurred
 5661: (2d) if r2 > r3 goto pc+636
; off = buf_off - len;
 5662: (79) r3 = *(u64 *)(r10 -144)
 5663: (1f) r3 -= r1
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 5664: (57) r3 &= 4095
 5665: (79) r1 = *(u64 *)(r10 -120)
 5666: (0f) r1 += r3
 5667: (bf) r3 = r10
; off = buf_off - len;
 5668: (07) r3 += -40
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 5669: (79) r3 = *(u64 *)(r3 +8)
 5670: (85) call bpf_probe_read_kernel_str#-51856
 5671: (bf) r6 = r0
 5672: (bf) r1 = r6
 5673: (67) r1 <<= 32
 5674: (c7) r1 s>>= 32
 5675: (b7) r2 = 2
; if (sz > 1) {
 5676: (6d) if r2 s> r1 goto pc+621
 5677: (79) r8 = *(u64 *)(r10 -144)
; buf_off -= 1; // remove null byte termination with slash sign
 5678: (bf) r2 = r8
 5679: (07) r2 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 5680: (57) r2 &= 4095
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 5681: (79) r1 = *(u64 *)(r10 -120)
 5682: (0f) r1 += r2
 5683: (bf) r3 = r10
; buf_off -= 1; // remove null byte termination with slash sign
 5684: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 5685: (b7) r2 = 1
 5686: (85) call bpf_probe_read_compat#-45600
; buf_off -= sz - 1;
 5687: (1f) r8 -= r6
 5688: (7b) *(u64 *)(r10 -144) = r8
; 
 5689: (7b) *(u64 *)(r10 -136) = r7
 5690: (05) goto pc+39
; if (dentry != mnt_root) {
 5691: (79) r1 = *(u64 *)(r10 -104)
 5692: (79) r2 = *(u64 *)(r10 -152)
 5693: (1d) if r1 == r2 goto pc+604
 5694: (79) r1 = *(u64 *)(r10 -136)
 5695: (5d) if r1 != r6 goto pc+602
 5696: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 5697: (7b) *(u64 *)(r10 -64) = r6
 5698: (b7) r1 = 24
 5699: (79) r8 = *(u64 *)(r10 -104)
 5700: (bf) r3 = r8
 5701: (0f) r3 += r1
 5702: (bf) r1 = r10
; 
 5703: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 5704: (b7) r2 = 8
 5705: (85) call bpf_probe_read_kernel#-51920
 5706: (b7) r7 = 16
 5707: (0f) r8 += r7
 5708: (79) r1 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 5709: (7b) *(u64 *)(r10 -136) = r1
 5710: (7b) *(u64 *)(r10 -64) = r6
 5711: (bf) r1 = r10
; 
 5712: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 5713: (b7) r2 = 8
 5714: (bf) r3 = r8
 5715: (85) call bpf_probe_read_kernel#-51920
 5716: (79) r8 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 5717: (7b) *(u64 *)(r10 -64) = r6
 5718: (bf) r3 = r8
 5719: (0f) r3 += r7
 5720: (bf) r1 = r10
; 
 5721: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 5722: (b7) r2 = 8
 5723: (85) call bpf_probe_read_kernel#-51920
 5724: (b7) r1 = 32
 5725: (7b) *(u64 *)(r10 -104) = r8
 5726: (0f) r8 += r1
 5727: (7b) *(u64 *)(r10 -128) = r8
 5728: (79) r1 = *(u64 *)(r10 -64)
 5729: (7b) *(u64 *)(r10 -152) = r1
 5730: (b7) r1 = 0
 5731: (79) r3 = *(u64 *)(r10 -128)
 5732: (0f) r3 += r1
 5733: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 5734: (7b) *(u64 *)(r10 -64) = r7
 5735: (bf) r1 = r10
; 
 5736: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 5737: (b7) r2 = 8
 5738: (85) call bpf_probe_read_kernel#-51920
 5739: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 5740: (7b) *(u64 *)(r10 -64) = r7
 5741: (b7) r1 = 24
 5742: (79) r7 = *(u64 *)(r10 -136)
 5743: (bf) r3 = r7
 5744: (0f) r3 += r1
 5745: (bf) r1 = r10
; 
 5746: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 5747: (b7) r2 = 8
 5748: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 5749: (1d) if r7 == r6 goto pc+56
; 
 5750: (79) r7 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 5751: (79) r1 = *(u64 *)(r10 -136)
 5752: (1d) if r1 == r7 goto pc+53
 5753: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 5754: (7b) *(u64 *)(r10 -56) = r1
 5755: (7b) *(u64 *)(r10 -64) = r1
 5756: (b7) r1 = 32
 5757: (79) r3 = *(u64 *)(r10 -136)
 5758: (0f) r3 += r1
 5759: (bf) r1 = r10
 5760: (07) r1 += -64
 5761: (b7) r2 = 16
 5762: (85) call bpf_probe_read_kernel#-51920
 5763: (79) r1 = *(u64 *)(r10 -56)
 5764: (7b) *(u64 *)(r10 -32) = r1
 5765: (79) r1 = *(u64 *)(r10 -64)
 5766: (7b) *(u64 *)(r10 -40) = r1
 5767: (bf) r1 = r10
 5768: (07) r1 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 5769: (61) r1 = *(u32 *)(r1 +4)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 5770: (07) r1 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 5771: (bf) r2 = r1
 5772: (57) r2 &= 4095
; if (off <= buf_off) { // verify no wrap occurred
 5773: (79) r3 = *(u64 *)(r10 -144)
 5774: (67) r3 <<= 32
 5775: (77) r3 >>= 32
; if (off <= buf_off) { // verify no wrap occurred
 5776: (2d) if r2 > r3 goto pc+521
; off = buf_off - len;
 5777: (79) r3 = *(u64 *)(r10 -144)
 5778: (1f) r3 -= r1
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 5779: (57) r3 &= 4095
 5780: (79) r1 = *(u64 *)(r10 -120)
 5781: (0f) r1 += r3
 5782: (bf) r3 = r10
; off = buf_off - len;
 5783: (07) r3 += -40
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 5784: (79) r3 = *(u64 *)(r3 +8)
 5785: (85) call bpf_probe_read_kernel_str#-51856
 5786: (bf) r6 = r0
 5787: (bf) r1 = r6
 5788: (67) r1 <<= 32
 5789: (c7) r1 s>>= 32
 5790: (b7) r2 = 2
; if (sz > 1) {
 5791: (6d) if r2 s> r1 goto pc+506
 5792: (79) r8 = *(u64 *)(r10 -144)
; buf_off -= 1; // remove null byte termination with slash sign
 5793: (bf) r2 = r8
 5794: (07) r2 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 5795: (57) r2 &= 4095
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 5796: (79) r1 = *(u64 *)(r10 -120)
 5797: (0f) r1 += r2
 5798: (bf) r3 = r10
; buf_off -= 1; // remove null byte termination with slash sign
 5799: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 5800: (b7) r2 = 1
 5801: (85) call bpf_probe_read_compat#-45600
; buf_off -= sz - 1;
 5802: (1f) r8 -= r6
 5803: (7b) *(u64 *)(r10 -144) = r8
; 
 5804: (7b) *(u64 *)(r10 -136) = r7
 5805: (05) goto pc+39
; if (dentry != mnt_root) {
 5806: (79) r1 = *(u64 *)(r10 -104)
 5807: (79) r2 = *(u64 *)(r10 -152)
 5808: (1d) if r1 == r2 goto pc+489
 5809: (79) r1 = *(u64 *)(r10 -136)
 5810: (5d) if r1 != r6 goto pc+487
 5811: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 5812: (7b) *(u64 *)(r10 -64) = r6
 5813: (b7) r1 = 24
 5814: (79) r8 = *(u64 *)(r10 -104)
 5815: (bf) r3 = r8
 5816: (0f) r3 += r1
 5817: (bf) r1 = r10
; 
 5818: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 5819: (b7) r2 = 8
 5820: (85) call bpf_probe_read_kernel#-51920
 5821: (b7) r7 = 16
 5822: (0f) r8 += r7
 5823: (79) r1 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 5824: (7b) *(u64 *)(r10 -136) = r1
 5825: (7b) *(u64 *)(r10 -64) = r6
 5826: (bf) r1 = r10
; 
 5827: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 5828: (b7) r2 = 8
 5829: (bf) r3 = r8
 5830: (85) call bpf_probe_read_kernel#-51920
 5831: (79) r8 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 5832: (7b) *(u64 *)(r10 -64) = r6
 5833: (bf) r3 = r8
 5834: (0f) r3 += r7
 5835: (bf) r1 = r10
; 
 5836: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 5837: (b7) r2 = 8
 5838: (85) call bpf_probe_read_kernel#-51920
 5839: (b7) r1 = 32
 5840: (7b) *(u64 *)(r10 -104) = r8
 5841: (0f) r8 += r1
 5842: (7b) *(u64 *)(r10 -128) = r8
 5843: (79) r1 = *(u64 *)(r10 -64)
 5844: (7b) *(u64 *)(r10 -152) = r1
 5845: (b7) r1 = 0
 5846: (79) r3 = *(u64 *)(r10 -128)
 5847: (0f) r3 += r1
 5848: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 5849: (7b) *(u64 *)(r10 -64) = r7
 5850: (bf) r1 = r10
; 
 5851: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 5852: (b7) r2 = 8
 5853: (85) call bpf_probe_read_kernel#-51920
 5854: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 5855: (7b) *(u64 *)(r10 -64) = r7
 5856: (b7) r1 = 24
 5857: (79) r7 = *(u64 *)(r10 -136)
 5858: (bf) r3 = r7
 5859: (0f) r3 += r1
 5860: (bf) r1 = r10
; 
 5861: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 5862: (b7) r2 = 8
 5863: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 5864: (1d) if r7 == r6 goto pc+56
; 
 5865: (79) r7 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 5866: (79) r1 = *(u64 *)(r10 -136)
 5867: (1d) if r1 == r7 goto pc+53
 5868: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 5869: (7b) *(u64 *)(r10 -56) = r1
 5870: (7b) *(u64 *)(r10 -64) = r1
 5871: (b7) r1 = 32
 5872: (79) r3 = *(u64 *)(r10 -136)
 5873: (0f) r3 += r1
 5874: (bf) r1 = r10
 5875: (07) r1 += -64
 5876: (b7) r2 = 16
 5877: (85) call bpf_probe_read_kernel#-51920
 5878: (79) r1 = *(u64 *)(r10 -56)
 5879: (7b) *(u64 *)(r10 -32) = r1
 5880: (79) r1 = *(u64 *)(r10 -64)
 5881: (7b) *(u64 *)(r10 -40) = r1
 5882: (bf) r1 = r10
 5883: (07) r1 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 5884: (61) r1 = *(u32 *)(r1 +4)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 5885: (07) r1 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 5886: (bf) r2 = r1
 5887: (57) r2 &= 4095
; if (off <= buf_off) { // verify no wrap occurred
 5888: (79) r3 = *(u64 *)(r10 -144)
 5889: (67) r3 <<= 32
 5890: (77) r3 >>= 32
; if (off <= buf_off) { // verify no wrap occurred
 5891: (2d) if r2 > r3 goto pc+406
; off = buf_off - len;
 5892: (79) r3 = *(u64 *)(r10 -144)
 5893: (1f) r3 -= r1
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 5894: (57) r3 &= 4095
 5895: (79) r1 = *(u64 *)(r10 -120)
 5896: (0f) r1 += r3
 5897: (bf) r3 = r10
; off = buf_off - len;
 5898: (07) r3 += -40
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 5899: (79) r3 = *(u64 *)(r3 +8)
 5900: (85) call bpf_probe_read_kernel_str#-51856
 5901: (bf) r6 = r0
 5902: (bf) r1 = r6
 5903: (67) r1 <<= 32
 5904: (c7) r1 s>>= 32
 5905: (b7) r2 = 2
; if (sz > 1) {
 5906: (6d) if r2 s> r1 goto pc+391
 5907: (79) r8 = *(u64 *)(r10 -144)
; buf_off -= 1; // remove null byte termination with slash sign
 5908: (bf) r2 = r8
 5909: (07) r2 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 5910: (57) r2 &= 4095
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 5911: (79) r1 = *(u64 *)(r10 -120)
 5912: (0f) r1 += r2
 5913: (bf) r3 = r10
; buf_off -= 1; // remove null byte termination with slash sign
 5914: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 5915: (b7) r2 = 1
 5916: (85) call bpf_probe_read_compat#-45600
; buf_off -= sz - 1;
 5917: (1f) r8 -= r6
 5918: (7b) *(u64 *)(r10 -144) = r8
; 
 5919: (7b) *(u64 *)(r10 -136) = r7
 5920: (05) goto pc+39
; if (dentry != mnt_root) {
 5921: (79) r1 = *(u64 *)(r10 -104)
 5922: (79) r2 = *(u64 *)(r10 -152)
 5923: (1d) if r1 == r2 goto pc+374
 5924: (79) r1 = *(u64 *)(r10 -136)
 5925: (5d) if r1 != r6 goto pc+372
 5926: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 5927: (7b) *(u64 *)(r10 -64) = r6
 5928: (b7) r1 = 24
 5929: (79) r8 = *(u64 *)(r10 -104)
 5930: (bf) r3 = r8
 5931: (0f) r3 += r1
 5932: (bf) r1 = r10
; 
 5933: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 5934: (b7) r2 = 8
 5935: (85) call bpf_probe_read_kernel#-51920
 5936: (b7) r7 = 16
 5937: (0f) r8 += r7
 5938: (79) r1 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 5939: (7b) *(u64 *)(r10 -136) = r1
 5940: (7b) *(u64 *)(r10 -64) = r6
 5941: (bf) r1 = r10
; 
 5942: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 5943: (b7) r2 = 8
 5944: (bf) r3 = r8
 5945: (85) call bpf_probe_read_kernel#-51920
 5946: (79) r8 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 5947: (7b) *(u64 *)(r10 -64) = r6
 5948: (bf) r3 = r8
 5949: (0f) r3 += r7
 5950: (bf) r1 = r10
; 
 5951: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 5952: (b7) r2 = 8
 5953: (85) call bpf_probe_read_kernel#-51920
 5954: (b7) r1 = 32
 5955: (7b) *(u64 *)(r10 -104) = r8
 5956: (0f) r8 += r1
 5957: (7b) *(u64 *)(r10 -128) = r8
 5958: (79) r1 = *(u64 *)(r10 -64)
 5959: (7b) *(u64 *)(r10 -152) = r1
 5960: (b7) r1 = 0
 5961: (79) r3 = *(u64 *)(r10 -128)
 5962: (0f) r3 += r1
 5963: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 5964: (7b) *(u64 *)(r10 -64) = r7
 5965: (bf) r1 = r10
; 
 5966: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 5967: (b7) r2 = 8
 5968: (85) call bpf_probe_read_kernel#-51920
 5969: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 5970: (7b) *(u64 *)(r10 -64) = r7
 5971: (b7) r1 = 24
 5972: (79) r7 = *(u64 *)(r10 -136)
 5973: (bf) r3 = r7
 5974: (0f) r3 += r1
 5975: (bf) r1 = r10
; 
 5976: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 5977: (b7) r2 = 8
 5978: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 5979: (1d) if r7 == r6 goto pc+56
; 
 5980: (79) r7 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 5981: (79) r1 = *(u64 *)(r10 -136)
 5982: (1d) if r1 == r7 goto pc+53
 5983: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 5984: (7b) *(u64 *)(r10 -56) = r1
 5985: (7b) *(u64 *)(r10 -64) = r1
 5986: (b7) r1 = 32
 5987: (79) r3 = *(u64 *)(r10 -136)
 5988: (0f) r3 += r1
 5989: (bf) r1 = r10
 5990: (07) r1 += -64
 5991: (b7) r2 = 16
 5992: (85) call bpf_probe_read_kernel#-51920
 5993: (79) r1 = *(u64 *)(r10 -56)
 5994: (7b) *(u64 *)(r10 -32) = r1
 5995: (79) r1 = *(u64 *)(r10 -64)
 5996: (7b) *(u64 *)(r10 -40) = r1
 5997: (bf) r1 = r10
 5998: (07) r1 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 5999: (61) r1 = *(u32 *)(r1 +4)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 6000: (07) r1 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 6001: (bf) r2 = r1
 6002: (57) r2 &= 4095
; if (off <= buf_off) { // verify no wrap occurred
 6003: (79) r3 = *(u64 *)(r10 -144)
 6004: (67) r3 <<= 32
 6005: (77) r3 >>= 32
; if (off <= buf_off) { // verify no wrap occurred
 6006: (2d) if r2 > r3 goto pc+291
; off = buf_off - len;
 6007: (79) r3 = *(u64 *)(r10 -144)
 6008: (1f) r3 -= r1
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 6009: (57) r3 &= 4095
 6010: (79) r1 = *(u64 *)(r10 -120)
 6011: (0f) r1 += r3
 6012: (bf) r3 = r10
; off = buf_off - len;
 6013: (07) r3 += -40
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 6014: (79) r3 = *(u64 *)(r3 +8)
 6015: (85) call bpf_probe_read_kernel_str#-51856
 6016: (bf) r6 = r0
 6017: (bf) r1 = r6
 6018: (67) r1 <<= 32
 6019: (c7) r1 s>>= 32
 6020: (b7) r2 = 2
; if (sz > 1) {
 6021: (6d) if r2 s> r1 goto pc+276
 6022: (79) r8 = *(u64 *)(r10 -144)
; buf_off -= 1; // remove null byte termination with slash sign
 6023: (bf) r2 = r8
 6024: (07) r2 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 6025: (57) r2 &= 4095
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 6026: (79) r1 = *(u64 *)(r10 -120)
 6027: (0f) r1 += r2
 6028: (bf) r3 = r10
; buf_off -= 1; // remove null byte termination with slash sign
 6029: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 6030: (b7) r2 = 1
 6031: (85) call bpf_probe_read_compat#-45600
; buf_off -= sz - 1;
 6032: (1f) r8 -= r6
 6033: (7b) *(u64 *)(r10 -144) = r8
; 
 6034: (7b) *(u64 *)(r10 -136) = r7
 6035: (05) goto pc+39
; if (dentry != mnt_root) {
 6036: (79) r1 = *(u64 *)(r10 -104)
 6037: (79) r2 = *(u64 *)(r10 -152)
 6038: (1d) if r1 == r2 goto pc+259
 6039: (79) r1 = *(u64 *)(r10 -136)
 6040: (5d) if r1 != r6 goto pc+257
 6041: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 6042: (7b) *(u64 *)(r10 -64) = r6
 6043: (b7) r1 = 24
 6044: (79) r8 = *(u64 *)(r10 -104)
 6045: (bf) r3 = r8
 6046: (0f) r3 += r1
 6047: (bf) r1 = r10
; 
 6048: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 6049: (b7) r2 = 8
 6050: (85) call bpf_probe_read_kernel#-51920
 6051: (b7) r7 = 16
 6052: (0f) r8 += r7
 6053: (79) r1 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 6054: (7b) *(u64 *)(r10 -136) = r1
 6055: (7b) *(u64 *)(r10 -64) = r6
 6056: (bf) r1 = r10
; 
 6057: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 6058: (b7) r2 = 8
 6059: (bf) r3 = r8
 6060: (85) call bpf_probe_read_kernel#-51920
 6061: (79) r8 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 6062: (7b) *(u64 *)(r10 -64) = r6
 6063: (bf) r3 = r8
 6064: (0f) r3 += r7
 6065: (bf) r1 = r10
; 
 6066: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 6067: (b7) r2 = 8
 6068: (85) call bpf_probe_read_kernel#-51920
 6069: (b7) r1 = 32
 6070: (7b) *(u64 *)(r10 -104) = r8
 6071: (0f) r8 += r1
 6072: (7b) *(u64 *)(r10 -128) = r8
 6073: (79) r1 = *(u64 *)(r10 -64)
 6074: (7b) *(u64 *)(r10 -152) = r1
 6075: (b7) r1 = 0
 6076: (79) r3 = *(u64 *)(r10 -128)
 6077: (0f) r3 += r1
 6078: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 6079: (7b) *(u64 *)(r10 -64) = r7
 6080: (bf) r1 = r10
; 
 6081: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 6082: (b7) r2 = 8
 6083: (85) call bpf_probe_read_kernel#-51920
 6084: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 6085: (7b) *(u64 *)(r10 -64) = r7
 6086: (b7) r1 = 24
 6087: (79) r7 = *(u64 *)(r10 -136)
 6088: (bf) r3 = r7
 6089: (0f) r3 += r1
 6090: (bf) r1 = r10
; 
 6091: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 6092: (b7) r2 = 8
 6093: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 6094: (1d) if r7 == r6 goto pc+56
; 
 6095: (79) r7 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 6096: (79) r1 = *(u64 *)(r10 -136)
 6097: (1d) if r1 == r7 goto pc+53
 6098: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 6099: (7b) *(u64 *)(r10 -56) = r1
 6100: (7b) *(u64 *)(r10 -64) = r1
 6101: (b7) r1 = 32
 6102: (79) r3 = *(u64 *)(r10 -136)
 6103: (0f) r3 += r1
 6104: (bf) r1 = r10
 6105: (07) r1 += -64
 6106: (b7) r2 = 16
 6107: (85) call bpf_probe_read_kernel#-51920
 6108: (79) r1 = *(u64 *)(r10 -56)
 6109: (7b) *(u64 *)(r10 -32) = r1
 6110: (79) r1 = *(u64 *)(r10 -64)
 6111: (7b) *(u64 *)(r10 -40) = r1
 6112: (bf) r1 = r10
 6113: (07) r1 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 6114: (61) r1 = *(u32 *)(r1 +4)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 6115: (07) r1 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 6116: (bf) r2 = r1
 6117: (57) r2 &= 4095
; if (off <= buf_off) { // verify no wrap occurred
 6118: (79) r3 = *(u64 *)(r10 -144)
 6119: (67) r3 <<= 32
 6120: (77) r3 >>= 32
; if (off <= buf_off) { // verify no wrap occurred
 6121: (2d) if r2 > r3 goto pc+176
; off = buf_off - len;
 6122: (79) r3 = *(u64 *)(r10 -144)
 6123: (1f) r3 -= r1
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 6124: (57) r3 &= 4095
 6125: (79) r1 = *(u64 *)(r10 -120)
 6126: (0f) r1 += r3
 6127: (bf) r3 = r10
; off = buf_off - len;
 6128: (07) r3 += -40
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 6129: (79) r3 = *(u64 *)(r3 +8)
 6130: (85) call bpf_probe_read_kernel_str#-51856
 6131: (bf) r6 = r0
 6132: (bf) r1 = r6
 6133: (67) r1 <<= 32
 6134: (c7) r1 s>>= 32
 6135: (b7) r2 = 2
; if (sz > 1) {
 6136: (6d) if r2 s> r1 goto pc+161
 6137: (79) r8 = *(u64 *)(r10 -144)
; buf_off -= 1; // remove null byte termination with slash sign
 6138: (bf) r2 = r8
 6139: (07) r2 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 6140: (57) r2 &= 4095
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 6141: (79) r1 = *(u64 *)(r10 -120)
 6142: (0f) r1 += r2
 6143: (bf) r3 = r10
; buf_off -= 1; // remove null byte termination with slash sign
 6144: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 6145: (b7) r2 = 1
 6146: (85) call bpf_probe_read_compat#-45600
; buf_off -= sz - 1;
 6147: (1f) r8 -= r6
 6148: (7b) *(u64 *)(r10 -144) = r8
; 
 6149: (7b) *(u64 *)(r10 -136) = r7
 6150: (05) goto pc+39
; if (dentry != mnt_root) {
 6151: (79) r1 = *(u64 *)(r10 -104)
 6152: (79) r2 = *(u64 *)(r10 -152)
 6153: (1d) if r1 == r2 goto pc+144
 6154: (79) r1 = *(u64 *)(r10 -136)
 6155: (5d) if r1 != r6 goto pc+142
 6156: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 6157: (7b) *(u64 *)(r10 -64) = r6
 6158: (b7) r1 = 24
 6159: (79) r8 = *(u64 *)(r10 -104)
 6160: (bf) r3 = r8
 6161: (0f) r3 += r1
 6162: (bf) r1 = r10
; 
 6163: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 6164: (b7) r2 = 8
 6165: (85) call bpf_probe_read_kernel#-51920
 6166: (b7) r7 = 16
 6167: (0f) r8 += r7
 6168: (79) r1 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 6169: (7b) *(u64 *)(r10 -136) = r1
 6170: (7b) *(u64 *)(r10 -64) = r6
 6171: (bf) r1 = r10
; 
 6172: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 6173: (b7) r2 = 8
 6174: (bf) r3 = r8
 6175: (85) call bpf_probe_read_kernel#-51920
 6176: (79) r8 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 6177: (7b) *(u64 *)(r10 -64) = r6
 6178: (bf) r3 = r8
 6179: (0f) r3 += r7
 6180: (bf) r1 = r10
; 
 6181: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 6182: (b7) r2 = 8
 6183: (85) call bpf_probe_read_kernel#-51920
 6184: (b7) r1 = 32
 6185: (7b) *(u64 *)(r10 -104) = r8
 6186: (0f) r8 += r1
 6187: (7b) *(u64 *)(r10 -128) = r8
 6188: (79) r1 = *(u64 *)(r10 -64)
 6189: (7b) *(u64 *)(r10 -152) = r1
 6190: (b7) r1 = 0
 6191: (79) r3 = *(u64 *)(r10 -128)
 6192: (0f) r3 += r1
 6193: (b7) r7 = 0
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 6194: (7b) *(u64 *)(r10 -64) = r7
 6195: (bf) r1 = r10
; 
 6196: (07) r1 += -64
; mnt_root = READ_KERN(vfsmnt->mnt_root);
 6197: (b7) r2 = 8
 6198: (85) call bpf_probe_read_kernel#-51920
 6199: (79) r6 = *(u64 *)(r10 -64)
; d_parent = READ_KERN(dentry->d_parent);
 6200: (7b) *(u64 *)(r10 -64) = r7
 6201: (b7) r1 = 24
 6202: (79) r7 = *(u64 *)(r10 -136)
 6203: (bf) r3 = r7
 6204: (0f) r3 += r1
 6205: (bf) r1 = r10
; 
 6206: (07) r1 += -64
; d_parent = READ_KERN(dentry->d_parent);
 6207: (b7) r2 = 8
 6208: (85) call bpf_probe_read_kernel#-51920
; if (dentry == mnt_root || dentry == d_parent) {
 6209: (1d) if r7 == r6 goto pc+56
; 
 6210: (79) r7 = *(u64 *)(r10 -64)
; if (dentry == mnt_root || dentry == d_parent) {
 6211: (79) r1 = *(u64 *)(r10 -136)
 6212: (1d) if r1 == r7 goto pc+53
 6213: (b7) r1 = 0
; d_name = READ_KERN(dentry->d_name);
 6214: (7b) *(u64 *)(r10 -56) = r1
 6215: (7b) *(u64 *)(r10 -64) = r1
 6216: (b7) r1 = 32
 6217: (79) r3 = *(u64 *)(r10 -136)
 6218: (0f) r3 += r1
 6219: (bf) r1 = r10
 6220: (07) r1 += -64
 6221: (b7) r2 = 16
 6222: (85) call bpf_probe_read_kernel#-51920
 6223: (79) r1 = *(u64 *)(r10 -56)
 6224: (7b) *(u64 *)(r10 -32) = r1
 6225: (79) r1 = *(u64 *)(r10 -64)
 6226: (7b) *(u64 *)(r10 -40) = r1
 6227: (bf) r1 = r10
 6228: (07) r1 += -40
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 6229: (61) r1 = *(u32 *)(r1 +4)
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 6230: (07) r1 += 1
; len = (d_name.len+1) & (MAX_STRING_SIZE-1);
 6231: (bf) r2 = r1
 6232: (57) r2 &= 4095
; if (off <= buf_off) { // verify no wrap occurred
 6233: (79) r3 = *(u64 *)(r10 -144)
 6234: (67) r3 <<= 32
 6235: (77) r3 >>= 32
; if (off <= buf_off) { // verify no wrap occurred
 6236: (2d) if r2 > r3 goto pc+61
; off = buf_off - len;
 6237: (79) r3 = *(u64 *)(r10 -144)
 6238: (1f) r3 -= r1
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 6239: (57) r3 &= 4095
 6240: (79) r1 = *(u64 *)(r10 -120)
 6241: (0f) r1 += r3
 6242: (bf) r3 = r10
; off = buf_off - len;
 6243: (07) r3 += -40
; sz = bpf_core_read_str(&(map_value[off & (MAX_STRING_SIZE - 1)]), len, (void *)d_name.name);
 6244: (79) r3 = *(u64 *)(r3 +8)
 6245: (85) call bpf_probe_read_kernel_str#-51856
 6246: (bf) r6 = r0
 6247: (bf) r1 = r6
 6248: (67) r1 <<= 32
 6249: (c7) r1 s>>= 32
 6250: (b7) r2 = 2
; if (sz > 1) {
 6251: (6d) if r2 s> r1 goto pc+46
 6252: (79) r8 = *(u64 *)(r10 -144)
; buf_off -= 1; // remove null byte termination with slash sign
 6253: (bf) r2 = r8
 6254: (07) r2 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 6255: (57) r2 &= 4095
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 6256: (79) r1 = *(u64 *)(r10 -120)
 6257: (0f) r1 += r2
 6258: (bf) r3 = r10
; buf_off -= 1; // remove null byte termination with slash sign
 6259: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 6260: (b7) r2 = 1
 6261: (85) call bpf_probe_read_compat#-45600
; buf_off -= sz - 1;
 6262: (1f) r8 -= r6
 6263: (7b) *(u64 *)(r10 -144) = r8
; 
 6264: (7b) *(u64 *)(r10 -136) = r7
 6265: (05) goto pc+32
; if (dentry != mnt_root) {
 6266: (79) r1 = *(u64 *)(r10 -104)
 6267: (79) r2 = *(u64 *)(r10 -152)
 6268: (1d) if r1 == r2 goto pc+29
 6269: (79) r1 = *(u64 *)(r10 -136)
 6270: (5d) if r1 != r6 goto pc+27
 6271: (b7) r6 = 0
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 6272: (7b) *(u64 *)(r10 -64) = r6
 6273: (b7) r1 = 24
 6274: (79) r8 = *(u64 *)(r10 -104)
 6275: (bf) r3 = r8
 6276: (0f) r3 += r1
 6277: (bf) r1 = r10
; 
 6278: (07) r1 += -64
; dentry = READ_KERN(mnt_p->mnt_mountpoint);
 6279: (b7) r2 = 8
 6280: (85) call bpf_probe_read_kernel#-51920
 6281: (b7) r7 = 16
 6282: (0f) r8 += r7
 6283: (79) r1 = *(u64 *)(r10 -64)
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 6284: (7b) *(u64 *)(r10 -136) = r1
 6285: (7b) *(u64 *)(r10 -64) = r6
 6286: (bf) r1 = r10
; 
 6287: (07) r1 += -64
; mnt_p = READ_KERN(mnt_p->mnt_parent);
 6288: (b7) r2 = 8
 6289: (bf) r3 = r8
 6290: (85) call bpf_probe_read_kernel#-51920
 6291: (79) r3 = *(u64 *)(r10 -64)
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 6292: (7b) *(u64 *)(r10 -64) = r6
 6293: (0f) r3 += r7
 6294: (bf) r1 = r10
; 
 6295: (07) r1 += -64
; mnt_parent_p = READ_KERN(mnt_p->mnt_parent);
 6296: (b7) r2 = 8
 6297: (85) call bpf_probe_read_kernel#-51920
 6298: (79) r6 = *(u64 *)(r10 -144)
; if (buf_off == MAX_STRING_SIZE) {
 6299: (bf) r1 = r6
 6300: (67) r1 <<= 32
 6301: (77) r1 >>= 32
; if (buf_off == MAX_STRING_SIZE) {
 6302: (55) if r1 != 0x1000 goto pc+26
 6303: (79) r6 = *(u64 *)(r10 -136)
 6304: (79) r8 = *(u64 *)(r10 -120)
 6305: (b7) r1 = 32
 6306: (0f) r6 += r1
 6307: (b7) r7 = 0
; d_name = READ_KERN(dentry->d_name);
 6308: (7b) *(u64 *)(r10 -56) = r7
 6309: (7b) *(u64 *)(r10 -64) = r7
 6310: (bf) r1 = r10
; 
 6311: (07) r1 += -64
; d_name = READ_KERN(dentry->d_name);
 6312: (b7) r2 = 16
 6313: (bf) r3 = r6
 6314: (85) call bpf_probe_read_kernel#-51920
 6315: (79) r1 = *(u64 *)(r10 -56)
 6316: (7b) *(u64 *)(r10 -32) = r1
 6317: (79) r1 = *(u64 *)(r10 -64)
 6318: (7b) *(u64 *)(r10 -40) = r1
 6319: (bf) r1 = r10
; 
 6320: (07) r1 += -40
; bpf_core_read(&(map_value[0]), len, (void *)d_name.name);
 6321: (79) r3 = *(u64 *)(r1 +8)
; len = d_name.len & (MAX_STRING_SIZE - 1);
 6322: (61) r2 = *(u32 *)(r1 +4)
; len = d_name.len & (MAX_STRING_SIZE - 1);
 6323: (57) r2 &= 4095
; bpf_core_read(&(map_value[0]), len, (void *)d_name.name);
 6324: (bf) r1 = r8
 6325: (85) call bpf_probe_read_kernel#-51920
; return &map_value[buf_off];
 6326: (0f) r8 += r7
; 
 6327: (bf) r9 = r8
 6328: (05) goto pc+19
; buf_off -= 1;
 6329: (07) r6 += -1
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 6330: (bf) r2 = r6
 6331: (57) r2 &= 4095
 6332: (79) r9 = *(u64 *)(r10 -120)
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 6333: (bf) r1 = r9
 6334: (0f) r1 += r2
 6335: (bf) r3 = r10
; buf_off -= 1;
 6336: (07) r3 += -17
; bpf_probe_read(&(map_value[buf_off & (MAX_STRING_SIZE-1)]), 1, &slash);
 6337: (b7) r2 = 1
 6338: (85) call bpf_probe_read_compat#-45600
; bpf_probe_read(&(map_value[MAX_STRING_SIZE -1]), 1, &zero);
 6339: (bf) r1 = r9
 6340: (07) r1 += 4095
 6341: (bf) r3 = r10
; buf_off -= 1;
 6342: (07) r3 += -24
; bpf_probe_read(&(map_value[MAX_STRING_SIZE -1]), 1, &zero);
 6343: (b7) r2 = 1
 6344: (85) call bpf_probe_read_compat#-45600
 6345: (67) r6 <<= 32
 6346: (77) r6 >>= 32
; return &map_value[buf_off];
 6347: (0f) r9 += r6
; if(path)
 6348: (15) if r9 == 0x0 goto pc+57
 6349: (79) r3 = *(u64 *)(r10 -96)
; int ret = save_str_to_buf(pinfo->buff, pinfo->buff_off, path, enProcInfoCwd);
 6350: (71) r1 = *(u8 *)(r3 +118)
 6351: (71) r7 = *(u8 *)(r3 +119)
 6352: (71) r2 = *(u8 *)(r3 +116)
 6353: (71) r3 = *(u8 *)(r3 +117)
 6354: (b7) r4 = 3
 6355: (63) *(u32 *)(r10 -16) = r4
 6356: (67) r3 <<= 8
 6357: (4f) r3 |= r2
 6358: (67) r7 <<= 8
 6359: (4f) r7 |= r1
 6360: (67) r7 <<= 16
 6361: (4f) r7 |= r3
; if (buf_off > MAX_VALID_BUFSIZE - MAX_STRING_SIZE - sizeof(int) - sizeof(enType))
 6362: (25) if r7 > 0x2ff8 goto pc+18
; 
 6363: (79) r8 = *(u64 *)(r10 -96)
 6364: (07) r8 += 120
; bpf_probe_read(&buf[buf_off & (MAX_PERCPU_BUFSIZE - 1)], sizeof(enType), &enType);
 6365: (bf) r6 = r8
 6366: (0f) r6 += r7
 6367: (bf) r3 = r10
; 
 6368: (07) r3 += -16
; bpf_probe_read(&buf[buf_off & (MAX_PERCPU_BUFSIZE - 1)], sizeof(enType), &enType);
 6369: (bf) r1 = r6
 6370: (b7) r2 = 4
 6371: (85) call bpf_probe_read_compat#-45600
; int sz = bpf_probe_read_str(&(buf[buf_off + sizeof(enType) + sizeof(int)]), MAX_STRING_SIZE, ptr);
 6372: (07) r6 += 8
; int sz = bpf_probe_read_str(&(buf[buf_off + sizeof(enType) + sizeof(int)]), MAX_STRING_SIZE, ptr);
 6373: (bf) r1 = r6
 6374: (b7) r2 = 4096
 6375: (bf) r3 = r9
 6376: (85) call bpf_probe_read_compat_str#-46512
; int sz = bpf_probe_read_str(&(buf[buf_off + sizeof(enType) + sizeof(int)]), MAX_STRING_SIZE, ptr);
 6377: (63) *(u32 *)(r10 -40) = r0
; int sz = bpf_probe_read_str(&(buf[buf_off + sizeof(enType) + sizeof(int)]), MAX_STRING_SIZE, ptr);
 6378: (67) r0 <<= 32
 6379: (c7) r0 s>>= 32
; if (sz > 0) {
 6380: (65) if r0 s> 0x0 goto pc+1
 6381: (05) goto pc+24
; if ((buf_off + sizeof(enType)) <= MAX_VALID_BUFSIZE - MAX_STRING_SIZE - sizeof(int)) 
 6382: (bf) r1 = r7
 6383: (0f) r1 += r8
; bpf_probe_read(&(buf[buf_off + sizeof(enType)]), sizeof(int), &sz);		
 6384: (07) r1 += 4
 6385: (bf) r3 = r10
; if ((buf_off + sizeof(enType)) <= MAX_VALID_BUFSIZE - MAX_STRING_SIZE - sizeof(int)) 
 6386: (07) r3 += -40
; bpf_probe_read(&(buf[buf_off + sizeof(enType)]), sizeof(int), &sz);		
 6387: (b7) r2 = 4
 6388: (85) call bpf_probe_read_compat#-45600
; buf_off += sz + sizeof(enType) + sizeof(int);
 6389: (61) r1 = *(u32 *)(r10 -40)
; buf_off += sz + sizeof(enType) + sizeof(int);
 6390: (0f) r7 += r1
; buf_off += sz + sizeof(enType) + sizeof(int);
 6391: (07) r7 += 8
 6392: (bf) r1 = r7
 6393: (67) r1 <<= 32
 6394: (77) r1 >>= 32
; if(ret)
 6395: (15) if r1 == 0x0 goto pc+10
; pinfo->buff_off = ret;
 6396: (bf) r1 = r7
 6397: (77) r1 >>= 24
 6398: (79) r2 = *(u64 *)(r10 -96)
 6399: (73) *(u8 *)(r2 +119) = r1
 6400: (bf) r1 = r7
 6401: (77) r1 >>= 16
 6402: (73) *(u8 *)(r2 +118) = r1
 6403: (73) *(u8 *)(r2 +116) = r7
 6404: (77) r7 >>= 8
 6405: (73) *(u8 *)(r2 +117) = r7
 6406: (79) r7 = *(u64 *)(r10 -112)
 6407: (79) r9 = *(u64 *)(r10 -96)
 6408: (b7) r1 = 0
; pinfo->header.protover = PROTOCOL_VERSION;
 6409: (73) *(u8 *)(r9 +5) = r1
 6410: (b7) r1 = 77
; pinfo->header.magic = HEADER_MAGIC;
 6411: (73) *(u8 *)(r9 +3) = r1
 6412: (b7) r1 = 68
 6413: (73) *(u8 *)(r9 +1) = r1
 6414: (b7) r1 = 84
 6415: (73) *(u8 *)(r9 +2) = r1
 6416: (73) *(u8 *)(r9 +0) = r1
 6417: (b7) r1 = 1
; pinfo->header.protover = PROTOCOL_VERSION;
 6418: (73) *(u8 *)(r9 +4) = r1
; pinfo->header.minor_cmd = MDCMD_PROCESS_FULLINFO;
 6419: (73) *(u8 *)(r9 +7) = r1
; pinfo->header.major_cmd = MULTIDATA_PROCESS;
 6420: (73) *(u8 *)(r9 +6) = r1
; bufflength = bufflength - MAX_VALID_BUFSIZE + pinfo->buff_off;
 6421: (71) r5 = *(u8 *)(r9 +117)
 6422: (67) r5 <<= 8
 6423: (71) r1 = *(u8 *)(r9 +116)
 6424: (4f) r5 |= r1
; bufflength = bufflength - MAX_VALID_BUFSIZE + pinfo->buff_off;
 6425: (07) r5 += 120
; bufflength = bufflength & (MAX_VALID_BUFSIZE - 1);
 6426: (57) r5 &= 16383
; bpf_perf_event_output(ctx, &perf_event_array_map, BPF_F_CURRENT_CPU, map_value, bufflength);
 6427: (bf) r1 = r7
 6428: (18) r2 = map[id:2]
 6430: (18) r3 = 0xffffffff
 6432: (bf) r4 = r9
 6433: (85) call bpf_perf_event_output#-50016
; }
 6434: (b7) r0 = 0
 6435: (95) exit
```