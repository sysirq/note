```
> > > Hi,
> > > 
> > > EXIT_REASON_EPT_VIOLATION's corresponding handle is handle_ept_violation(),
> > > and EXIT_REASON_EPT_MISCONFIG's corresponding handle is handle_ept_misconfig(),
> > > what's the difference between them?
> > > 
> > > I read the SDM-3C 28.2.3 EPT-Induced VM Exits, and found below description,
> > > "An EPT misconfiguration occurs when, in the course of translating 
> > > a guest-physical address, the logical processor encounters an EPT 
> > > paging-structure entry that contains an unsupported value. An EPT 
> > > violation occurs when there is no EPT misconfiguration but the EPT 
> > > paging-structure entries disallow an access using the guest physical
> > > address."
> > > 
> > > According to above description, EPT-MISCONFIG is from error settings ,
> > > but from the its exit-handle handle_ept_misconfig(),
> > > it seems that handle_ept_misconfig() handles mmio pagefault,
> > > I'm really confused, I think I'm missing something,
> > > any advices?
> > > 
> > EXIT_REASON_EPT_VIOLATION is similar to a "page not present" pagefault
> > EXIT_REASON_EPT_MISCONFIG is similar to a "reserved bit set" pagefault.
> > handle_ept_misconfig() handles mmio pagefault because KVM has an
> > optimization that uses reserved bits to mark mmio regions.
> >
> Thanks, Gleb, 
> where does kvm use the reserved bits to mark mmio regions?
> 
arch/x86/kvm/mmu.c:mark_mmio_spte

```

MMIO地址引起的EPT退出

https://frankjkl.github.io/2019/01/07/MMIO-Emulation/