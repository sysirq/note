# 类关系

X86CPUClass -- CPUClass -- DeviceClass -- ObjectClass

# 对象关系

X86CPU -- CPUState -- DeviceState -- Object

# CPU 数据类型

x86_cpu_type_info

# CPU 创建

main -- pc_init1 -- pc_cpus_init -- pc_new_cpu -- device_set_realized -- x86_cpu_realizefn -- qemu_init_vcpu -- qemu_kvm_start_vcpu -- qemu_kvm_cpu_thread_fn

x86_cpu_register_types

# 设置CPU单步执行

找到kvm_cpu_exec，在KVM_RUN 的 ioctl之前添加:

```c
        struct kvm_guest_debug dbg;
        memset(&dbg,0,sizeof(dbg));
        dbg.control |= KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP;
        kvm_vcpu_ioctl(cpu, KVM_SET_GUEST_DEBUG,&dbg);

        ................
        run_ret = kvm_vcpu_ioctl(cpu, KVM_RUN, 0);
        ................
        
        kvm_arch_get_registers(cpu);
        printf("rip:0x%lX\n",X86_CPU(cpu)->env.eip);
```

接着在while循环中处理

exit_reason 为 KVM_EXIT_DEBUG 的情况

# 资料

QEMU的核心初始化流程

https://hhb584520.github.io/kvm_blog/2017/05/16/create-guest.html