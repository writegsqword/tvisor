#include <asm/msr.h>
#include <asm/processor.h>
#include <linux/mm.h> /* Needed for struct page, alloc_pages_node, page_address, etc... */
#include <linux/percpu-defs.h> /* Needed for DEFINE_PER_CPU macro */
#include <linux/printk.h> /* Needed for pr_alert */
#include <linux/slab.h> /* Needed for kmalloc */

#include "cpu.h"
#include "handler.h"
#include "vm.h"
#include "vmx.h"


extern vm_state_t *VM;
extern void *VA_GUEST_MEMORY;

static int vmxon(u64 phys_vmxon_region)
{
	u8 err;
	asm volatile("vmxon %1; setna %0"
		     : "=q"(err)
		     : "m"(phys_vmxon_region)
		     : "memory", "cc");

	return err;
}

int vmxoff(void)
{
	u8 err;
	asm volatile("vmxoff; setna %0" : "=q"(err));

	return err;
}

static u64 vmptrst(void)
{
	u64 vmcspa = 0;
	asm volatile("vmptrst %0" : : "m"(&vmcspa) : "memory", "cc");

	pr_info("tvisor: VMPTRST %llx\n", vmcspa);

	return vmcspa;
}



static int vmclear(u64 vmcs_region_phys)
{

	uint8_t ret;

	__asm__ __volatile__ ("vmclear %[pa]; setna %[ret]"
		: [ret]"=rm"(ret)
		: [pa]"m"(vmcs_region_phys)
		: "cc", "memory");

	return ret;

	return 0;
}

static int vmptrld(u64 vmcs_region_phys)
{
	u64 rflags;
	asm volatile("vmptrld %[vmcs]; pushfq; popq %0"
		     : "=q"(rflags)
		     : [vmcs] "m"(vmcs_region_phys)
		     : "cc");

	u64 cf, pf, af, zf, sf, of;
	cf = (rflags >> 0) & 1;
	pf = (rflags >> 2) & 1;
	af = (rflags >> 4) & 1;
	zf = (rflags >> 6) & 1;
	sf = (rflags >> 7) & 1;
	of = (rflags >> 11) & 1;

	if (cf | pf | af | zf | sf | of) {
		if (cf) {
			pr_debug("tvisor: VMfail Invaild\n");
		} else if (zf) {
			pr_debug("tvisor: VMfail Invalid(ErrorCode)\n");
		} else {
			pr_debug("tvisor: undefined state\n");
		}
		return 1;
	}

	return 0;
}

int vmlaunch(void)
{
	pr_info("vm launch!!!!!\n");
	u64 rflags;
	asm volatile("vmlaunch; pushfq; popq %0" : "=q"(rflags));

	pr_info("fail\n");

	u64 cf, pf, af, zf, sf, of;
	cf = (rflags >> 0) & 1;
	pf = (rflags >> 2) & 1;
	af = (rflags >> 4) & 1;
	zf = (rflags >> 6) & 1;
	sf = (rflags >> 7) & 1;
	of = (rflags >> 11) & 1;

	if (cf | pf | af | zf | sf | of) {
		if (cf) {
			pr_debug("tvisor: VMfail Invaild\n");
		} else if (zf) {
			pr_debug("tvisor: VMfail Invalid(ErrorCode)\n");
		} else {
			pr_debug("tvisor: undefined state\n");
		}
		return 1;
	}

	return 0;
}

int vmresume(void)
{
	u64 rflags;
	asm volatile("vmresume; pushfq; popq %0" : "=q"(rflags));

	u64 cf, pf, af, zf, sf, of;
	cf = (rflags >> 0) & 1;
	pf = (rflags >> 2) & 1;
	af = (rflags >> 4) & 1;
	zf = (rflags >> 6) & 1;
	sf = (rflags >> 7) & 1;
	of = (rflags >> 11) & 1;

	if (cf | pf | af | zf | sf | of) {
		if (cf) {
			pr_debug("tvisor: VMfail Invaild\n");
		} else if (zf) {
			pr_debug("tvisor: VMfail Invalid(ErrorCode)\n");
		} else {
			pr_debug("tvisor: undefined state\n");
		}
		return 1;
	}

	return 0;
}

u64 vmread(enum VMCS_FIELDS field)
{
	u64 val = 9800, rflags = 0;
	asm volatile("vmread %2, %0; pushfq; popq %1"
		     : "=r"(val), "=r"(rflags)
		     : "r"((u64)field));

	u64 cf, pf, af, zf, sf, of;
	cf = (rflags >> 0) & 1;
	pf = (rflags >> 2) & 1;
	af = (rflags >> 4) & 1;
	zf = (rflags >> 6) & 1;
	sf = (rflags >> 7) & 1;
	of = (rflags >> 11) & 1;

	if (cf | pf | af | zf | sf | of) {
		if (cf) {
			pr_debug("tvisor: VMfail Invaild\n");
		} else if (zf) {
			pr_debug("tvisor: VMfail Invalid(ErrorCode)\n");
		} else {
			pr_debug("tvisor: undefined state\n");
		}
		return 0;
	}
	return val;
}

void vmwrite(enum VMCS_FIELDS field, u64 val)
{
	asm volatile("vmwrite %0, %1" : : "r"(val), "r"((u64)field));
}

static void get_segment_descriptor(segment_selector_t *segment_selector,
				   u16 selector, u64 *gdt_base)
{
	if (segment_selector == NULL) {
		return;
	}
	if (selector & 0x4) {
		return;
	}

	segment_descriptor_t *segdesc =
		(segment_descriptor_t *)((u8 *)gdt_base + (selector & ~0x7));

	segment_selector->sel = selector;
	segment_selector->base =
		segdesc->base0 | segdesc->base1 << 16 | segdesc->base2 << 24;
	segment_selector->limit = segdesc->limit0 | (segdesc->limit1attr1 & 0xf)
							    << 16;
	segment_selector->attrs.all =
		segdesc->attr0 | (segdesc->limit1attr1 & 0xf0) << 4;

	if (!(segdesc->attr0 & 0x10)) { // LA_ACCESSED
		u64 tmp = (*(u64 *)((u8 *)segdesc + 8));
		segment_selector->base =
			(segment_selector->base & 0xffffffff) | (tmp << 32);
	}

	if (segment_selector->attrs.fields.g) {
		segment_selector->limit =
			(segment_selector->limit << 12) + 0xfff;
	}
}

static void fill_guest_selector_data(u64 *gdt_base, u64 segment, u16 selector)
{
	segment_selector_t segment_selector = { 0 };
	get_segment_descriptor(&segment_selector, selector, gdt_base);

	u64 access_rights = ((u8 *)&segment_selector.attrs)[0] +
			    (((u8 *)&segment_selector.attrs)[1] << 12);

	if (selector == 0) {
		access_rights |= 0x10000;
	}

	vmwrite(GUEST_ES_SELECTOR + segment * 2, selector);
	vmwrite(GUEST_ES_LIMIT + segment * 2, segment_selector.limit);
	vmwrite(GUEST_ES_AR_BYTES + segment * 2, access_rights);
	vmwrite(GUEST_ES_BASE + segment * 2, segment_selector.base);
}

static u64 adjust_controls(u64 ctl, u64 msr)
{
	u64 content_low, content_high;
	rdmsr(msr, content_low, content_high);

	ctl &= content_high;
	ctl |= content_low;
	return ctl;
}

static u32 is_vmx_supported(void)
{
	cpuid_t cpuid = get_cpuid(1);
	return (u32)(cpuid.ecx & 0b100000);
}

static u32 is_vmxon_supported(void)
{
	u64 ia32_feature_control = 0;
	rdmsrl(MSR_IA32_FEAT_CTL, ia32_feature_control);
	u64 lock = ia32_feature_control & 0b1;
	u64 vmxon_in_smx = ia32_feature_control & 0b10;
	u64 vmxon_outside_smx = ia32_feature_control & 0b100;

	return (u32)(lock | vmxon_in_smx | vmxon_outside_smx);
}

vmcs_t *alloc_vmcs_region(void)
{
	u32 vmx_msr_low, vmx_msr_high;
	rdmsr(MSR_IA32_VMX_BASIC, vmx_msr_low, vmx_msr_high);

	struct page *page = alloc_page(GFP_KERNEL);
	if (page == NULL) {
		return NULL;
	}

	vmcs_t *vmcs = page_address(page);

	size_t vmcs_size = vmx_msr_high & 0x1ffff;
	memset(vmcs, 0, vmcs_size);

	vmcs->rev_id = vmx_msr_low & 0x7fffffff;

	return vmcs;
}

vmxon_region_t *alloc_vmxon_region(void)
{
	return (vmxon_region_t *)alloc_vmcs_region();
}

void free_vmcs_region(vmcs_t *vmcs)
{
	if (vmcs == NULL) {
		return;
	}
	__free_page(virt_to_page(vmcs));
}

void free_vmxon_region(vmxon_region_t *vmxon_region)
{
	free_vmcs_region((vmcs_t *)vmxon_region);
}

static int enable_vmx(vmcs_t *vmxon_region)
{
	vmcs_t *vmxon_vmcs = vmxon_region;
	if (vmxon_vmcs == NULL) {
		return -ENOMEM;
	}

	u64 cr0 = read_cr0();
	u64 msr_val = 0;
	rdmsrl(MSR_IA32_VMX_CR0_FIXED1, msr_val);
	cr0 &= msr_val;
	rdmsrl(MSR_IA32_VMX_CR0_FIXED0, msr_val);
	cr0 |= msr_val;
	write_cr0(cr0);

	u64 cr4 = read_cr4();
	rdmsrl(MSR_IA32_VMX_CR4_FIXED1, msr_val);
	cr4 &= msr_val;
	rdmsrl(MSR_IA32_VMX_CR4_FIXED0, msr_val);
	cr4 |= msr_val;
	write_cr4(cr4);

	u64 phys_vmxon_vmcs = __pa(vmxon_vmcs);

	return vmxon(phys_vmxon_vmcs);
}

static int disable_vmx(void)
{
	return vmxoff();
}

static void enable_vmx_per_cpu(void *data)
{
	vmcs_t *vmxon_region = (vmcs_t *)data;
	int err = enable_vmx(vmxon_region);
	if (err) {
		pr_alert("tvisor: failed to enable VMX[%d]\n", err);
	}
}

static void disable_vmx_per_cpu(void *_dummy)
{
	int err = disable_vmx();
	if (err) {
		pr_alert("tvisor: failed to disable VMX[%d]\n", err);
	}
}

int enable_vmx_on_each_cpu(vmcs_t *vmxon_region)
{
	u32 b = is_vmx_supported() | is_vmxon_supported();
	if (!b) {
		return b;
	}

	on_each_cpu(enable_vmx_per_cpu, vmxon_region, 1);

	return 0;
}

int disable_vmx_on_each_cpu(void)
{
	on_each_cpu(disable_vmx_per_cpu, NULL, 1);

	return 0;
}

int enable_vmx_on_each_cpu_mask(int cpu, vmcs_t *vmxon_region)
{
	u32 b = is_vmx_supported() | is_vmxon_supported();
	if (!b) {
		return b;
	}

	struct cpumask mask;
	cpumask_clear(&mask);
	cpumask_set_cpu(cpu, &mask);
	on_each_cpu_mask(&mask, enable_vmx_per_cpu, vmxon_region, 1);

	return 0;
}

int disable_vmx_on_each_cpu_mask(int cpu)
{
	struct cpumask mask;
	cpumask_clear(&mask);
	cpumask_set_cpu(cpu, &mask);
	on_each_cpu_mask(&mask, disable_vmx_per_cpu, NULL, 1);

	return 0;
}

int clear_vmcs_state(vmcs_t *vmcs)
{
	u64 vmcs_phys = __pa(vmcs);
	pr_debug("tvisor: VMCS physaddr = %llx\n", vmcs_phys);
	return vmclear(vmcs_phys);
}

int load_vmcs(vmcs_t *vmcs)
{
	u64 vmcs_phys = __pa(vmcs);
	pr_debug("tvisor: VMCS physaddr = %llx\n", vmcs_phys);
	return vmptrld(vmcs_phys);
}

static void* target_page;
static void* fake_page;


//IMAGINE
__attribute__((optimize("O0")))
static void loop_test(void) {

	get_cpuid(1);
	char* target_page_v = target_page;
	while(true) {
		
		//printk("test?");
		//write
		*target_page_v = 0x42;
		//read, swap fake
		char read_res = *target_page_v;
		
		if(read_res == 0x69)
			break;
		

	}
	//for trapping again
	get_cpuid(1);

	while (true) {

	}
}

static inline void invept(u64 eptp) {
    struct invept_desc {
        u64 eptp;
        u64 reserved;
    } desc = {
        .eptp = eptp,
        .reserved = 0,
    };
	pr_info("invept %llx",eptp);

    // INVEPT type 1 = Single-Context Invalidation
    uint64_t type = 1;

    asm volatile("invept %[desc], %[type]"
                 :
                 : [desc] "m"(desc), [type] "r"(type)
                 : "memory");
}


static void swap_fake(ept_pointer_t *eptp, ept_pde_2mb_t* pde_2mb) {


}

static void swap_real(ept_pointer_t *eptp, ept_pde_2mb_t* pde_2mb) {



}
static void page_trap_set(ept_pointer_t *eptp, ept_pde_2mb_t* pde_2mb) {
	//set to write only
	pde_2mb->fields.read = 0;
	pde_2mb->fields.write = 0;
	pde_2mb->fields.execute = 0;

}

static void page_trap_set_swapback(ept_pointer_t *eptp, ept_pde_2mb_t* pde_2mb) {
	//set to no access
	pde_2mb->fields.read = 0;
	pde_2mb->fields.write = 0;
	pde_2mb->fields.execute = 0;

}


static void setup_page_trap(ept_pointer_t *eptp) {
	target_page = kmalloc(0x200000, GFP_KERNEL);
	fake_page = kmalloc(0x200000, GFP_KERNEL);
	u64 target_pa = __pa(target_page);
	
	ept_pde_t* pde = gphys_to_pde(target_pa, eptp);
	pr_info("target pa %llx, pde %llx", target_pa, *(u64*)pde);
	page_trap_set(eptp, (ept_pde_2mb_t*)pde);
	pr_info("target pa %llx, pde %llx", target_pa, *(u64*)pde);
	ept_pde_t* pde2 = gphys_to_pde(__pa(loop_test), eptp);
	page_trap_set(eptp, (ept_pde_2mb_t*)pde2);
	pr_info("target pa2 %llx, pde2 %llx", __pa(loop_test), *pde2);
	invept(eptp->all);

	
	
}



static void _print_guest_regs(guest_regs_t* regs) {
	pr_info(
"	u64 rax; %llx\n"
"	u64 rcx; %llx\n"
"	u64 rdx; %llx\n"
"	u64 rbx; %llx\n"
"	u64 rsp; %llx\n"
"	u64 rbp; %llx\n"
"	u64 rsi; %llx\n"
"	u64 rdi; %llx\n"
"	u64 r8; %llx\n"
"	u64 r9; %llx\n"
"	u64 r10; %llx\n"
"	u64 r11; %llx\n"
"	u64 r12; %llx\n"
"	u64 r13; %llx\n"
"	u64 r14; %llx\n"
"	u64 r15; %llx\n", *regs);
}

int setup_vmcs(vmcs_t *vmcs, ept_pointer_t *eptp, u64 *vmm_stack)
{
	vmwrite(EPT_POINTER, eptp->all); // set EPT Pointer

	u16 es, cs, ss, ds, fs, gs, tr;
	es = read_es();
	cs = read_cs();
	ss = read_ss();
	ds = read_ds();
	fs = read_fs();
	gs = read_gs();
	tr = read_tr();
	pr_debug("tvisor: es=%x, cs=%x, ss=%x, ds=%x, fs=%x, gs=%x, tr=%x\n",
		 es, cs, ss, ds, fs, gs, tr);
	vmwrite(HOST_ES_SELECTOR, es & 0xf8);
	vmwrite(HOST_CS_SELECTOR, cs & 0xf8);
	vmwrite(HOST_SS_SELECTOR, ss & 0xf8);
	vmwrite(HOST_DS_SELECTOR, ds & 0xf8);
	vmwrite(HOST_FS_SELECTOR, fs & 0xf8);
	vmwrite(HOST_GS_SELECTOR, gs & 0xf8);
	vmwrite(HOST_TR_SELECTOR, tr & 0xf8);

	vmwrite(VMCS_LINK_POINTER, ~0ull);

	u32 debug_msr_low, debug_msr_high;
	rdmsr(MSR_IA32_DEBUGCTLMSR, debug_msr_low, debug_msr_high);
	pr_debug("tvisor: GUEST_IA32_DEBUGCTL=%x_%x\n", debug_msr_high,
		 debug_msr_low);
	vmwrite(GUEST_IA32_DEBUGCTL, debug_msr_low);
	vmwrite(GUEST_IA32_DEBUGCTL_HIGH, debug_msr_high);

	vmwrite(TSC_OFFSET, 0);
	vmwrite(TSC_OFFSET_HIGH, 0);

	vmwrite(PAGE_FAULT_ERROR_CODE_MASK, 0);
	vmwrite(PAGE_FAULT_ERROR_CODE_MATCH, 0);

	vmwrite(VM_EXIT_MSR_STORE_COUNT, 0);
	vmwrite(VM_EXIT_MSR_LOAD_COUNT, 0);

	vmwrite(VM_ENTRY_MSR_LOAD_COUNT, 0);
	vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0);

	u64 gdt_base = read_gdt_base();
	pr_debug("tvisor: guest GDT Base = %llx\n", gdt_base);

	fill_guest_selector_data((void *)gdt_base, ES, read_es());
	fill_guest_selector_data((void *)gdt_base, CS, read_cs());
	fill_guest_selector_data((void *)gdt_base, SS, read_ss());
	fill_guest_selector_data((void *)gdt_base, DS, read_ds());
	fill_guest_selector_data((void *)gdt_base, FS, read_fs());
	fill_guest_selector_data((void *)gdt_base, GS, read_gs());
	fill_guest_selector_data((void *)gdt_base, LDTR, read_ldt());
	fill_guest_selector_data((void *)gdt_base, TR, read_tr());

	u64 guest_fs_base, guest_gs_base;
	rdmsrl(MSR_FS_BASE, guest_fs_base);
	rdmsrl(MSR_GS_BASE, guest_gs_base);
	pr_debug("tvisor: GUEST_FS_BASE=%llx, GUEST_GS_BASE=%llx\n",
		 guest_fs_base, guest_gs_base);
	vmwrite(GUEST_FS_BASE, guest_fs_base);
	vmwrite(GUEST_GS_BASE, guest_gs_base);

	vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0);
	vmwrite(GUEST_ACTIVITY_STATE, 0); // active state

	vmwrite(CPU_BASED_VM_EXEC_CONTROL,
		adjust_controls(CPU_BASED_HLT_EXITING |
					CPU_BASED_ACTIVATE_SECONDARY_CONTROLS,
				MSR_IA32_VMX_PROCBASED_CTLS));
	vmwrite(SECONDARY_VM_EXEC_CONTROL,
		adjust_controls(CPU_BASED_CTL2_RDTSCP |
					CPU_BASED_CTL2_ENABLE_EPT,
				MSR_IA32_VMX_PROCBASED_CTLS2));

	vmwrite(PIN_BASED_VM_EXEC_CONTROL,
		adjust_controls(0, MSR_IA32_VMX_PINBASED_CTLS));
	vmwrite(VM_EXIT_CONTROLS,
		adjust_controls(VM_EXIT_IA32E_MODE | VM_EXIT_ACK_INTR_ON_EXIT,
				MSR_IA32_VMX_EXIT_CTLS));
	vmwrite(VM_ENTRY_CONTROLS,
		adjust_controls(VM_ENTRY_IA32E_MODE, MSR_IA32_VMX_ENTRY_CTLS));

	vmwrite(CR3_TARGET_COUNT, 0);
	vmwrite(CR3_TARGET_VALUE0, 0);
	vmwrite(CR3_TARGET_VALUE1, 0);
	vmwrite(CR3_TARGET_VALUE2, 0);
	vmwrite(CR3_TARGET_VALUE3, 0);

	u64 cr0, cr3, cr4;
	cr0 = read_cr0();
	//cr3 = setup_sample_guest_page_table(eptp).all; // cr3 = read_cr3();
	cr3 = read_cr3();
	cr4 = read_cr4();
	pr_debug("tvisor: GUEST_CR0=%llx, GUEST_CR3=%llx, GUEST_CR4=%llx\n",
		 cr0, cr3, cr4);
	vmwrite(GUEST_CR0, cr0);
	vmwrite(GUEST_CR3, cr3);
	vmwrite(GUEST_CR4, cr4);

	vmwrite(GUEST_DR7, 0x400);

	cr0 = read_cr0();
	cr3 = read_cr3();
	cr4 = read_cr4();
	pr_debug("tvisor: HOST_CR0=%llx, HOST_CR3=%llx, HOST_CR4=%llx\n", cr0,
		 cr3, cr4);
	vmwrite(HOST_CR0, cr0);
	vmwrite(HOST_CR3, cr3);
	vmwrite(HOST_CR4, cr4);

	u64 guest_gdt_base, guest_idt_base;
	guest_gdt_base = read_gdt_base();
	guest_idt_base = read_idt_base();
	u16 guest_gdt_limit, guest_idt_limit;
	guest_gdt_limit = read_gdt_limit();
	guest_idt_limit = read_idt_limit();
	pr_debug("tvisor: GUEST_GDTR BASE=%llx, LIMIT=%x\n", guest_gdt_base,
		 guest_gdt_limit);
	pr_debug("tvisor: GUEST IDTR BASE=%llx, LIMIT=%x\n", guest_idt_base,
		 guest_idt_limit);
	vmwrite(GUEST_GDTR_BASE, guest_gdt_base);
	vmwrite(GUEST_IDTR_BASE, guest_idt_base);
	vmwrite(GUEST_GDTR_LIMIT, guest_gdt_limit);
	vmwrite(GUEST_IDTR_LIMIT, guest_idt_limit);

	u64 rflags = read_rflags();
	pr_debug("tvisor: GUEST_RFLAGS=%llx\n", rflags);
	vmwrite(GUEST_RFLAGS, rflags);

	u64 sysenter_cs, sysenter_eip, sysenter_esp;
	rdmsrl(MSR_IA32_SYSENTER_CS, sysenter_cs);
	rdmsrl(MSR_IA32_SYSENTER_EIP, sysenter_eip);
	rdmsrl(MSR_IA32_SYSENTER_ESP, sysenter_esp);
	pr_debug("tvisor: GUEST SYSENTER cs=%llx, eip=%llx, esp=%llx\n",
		 sysenter_cs, sysenter_eip, sysenter_esp);
	vmwrite(GUEST_SYSENTER_CS, sysenter_cs);
	vmwrite(GUEST_SYSENTER_EIP, sysenter_eip);
	vmwrite(GUEST_SYSENTER_ESP, sysenter_esp);

	segment_selector_t segment_selector;
	get_segment_descriptor(&segment_selector, read_tr(),
			       (u64 *)read_gdt_base());
	pr_debug(
		"tvisor: HOST_TR_BASE segment_selector sel=%x, base=%llx, limit=%x\n",
		segment_selector.sel, segment_selector.base,
		segment_selector.limit);
	vmwrite(HOST_TR_BASE, segment_selector.base);

	u64 host_fs_base, host_gs_base;
	rdmsrl(MSR_FS_BASE, host_fs_base);
	rdmsrl(MSR_GS_BASE, host_gs_base);
	pr_debug("tvisor: MSR host fs_base=%llx, gs_base=%llx\n", host_fs_base,
		 host_gs_base);
	vmwrite(HOST_FS_BASE, host_fs_base);
	vmwrite(HOST_GS_BASE, host_gs_base);

	vmwrite(HOST_GDTR_BASE, read_gdt_base());
	vmwrite(HOST_IDTR_BASE, read_idt_base());

	rdmsrl(MSR_IA32_SYSENTER_CS, sysenter_cs);
	rdmsrl(MSR_IA32_SYSENTER_EIP, sysenter_eip);
	rdmsrl(MSR_IA32_SYSENTER_ESP, sysenter_esp);
	vmwrite(HOST_IA32_SYSENTER_CS, sysenter_cs);
	vmwrite(HOST_IA32_SYSENTER_EIP, sysenter_eip);
	vmwrite(HOST_IA32_SYSENTER_ESP, sysenter_esp);
	char* guest_stack = ((char*)kmalloc(0x1000, GFP_KERNEL)) + 0xff0;
	u64 guest_rsp, guest_rip;

	guest_rsp = (u64)guest_stack;
	//guest_rip = __pa(loop_test);
	guest_rip = (u64)loop_test;

	
	setup_page_trap(eptp);
	pr_debug("tvisor: GUEST_RSP=%llx, GUEST_RIP=%llx\n",
		guest_rsp, guest_rip);

	// pr_debug("tvisor: mapped to host - GUEST_RSP=%llx, GUEST_RIP=%llx\n",
	// 		gphys_to_hphys(guest_rsp, eptp), gphys_to_hphys(guest_rip, eptp));

	vmwrite(GUEST_RSP, guest_rsp);
	vmwrite(GUEST_RIP, guest_rip);

	pr_debug("tvisor: HOST_RSP=%llx, HOST_RIP=%llx\n",
		 ((u64)vmm_stack + VMM_STACK_SIZE - 0x50), (u64)vmexit_handler);
	vmwrite(HOST_RSP, ((u64)vmm_stack + VMM_STACK_SIZE - 0x50));
	vmwrite(HOST_RIP, (u64)vmexit_handler);

	return 0;
}
void resume_to_next_instruction(void)
{
	char *current_rip = (char *)vmread(GUEST_RIP);
	u64 exit_instruction_length = (u64)vmread(VM_EXIT_INSTRUCTION_LEN);
	
	char *resume_rip = current_rip + exit_instruction_length;
	pr_info("exit instr len %d, cur rip %llx, new rip %llx", exit_instruction_length, current_rip, resume_rip);
	vmwrite(GUEST_RIP, (u64)resume_rip);
}

static void vmexit_on_ept_violation(guest_regs_t *guest_regs) {
	ept_pointer_t ept_ptr = (ept_pointer_t)vmread(EPT_POINTER); 
	char *current_rip = (char *)vmread(GUEST_RIP);
	u64 gpa, gla, qual;
		gpa = vmread(GUEST_PHYSICAL_ADDRESS);
		gla = vmread(GUEST_LINEAR_ADDRESS);
		qual = vmread(EXIT_QUALIFICATION);

		pr_info("EPT Violation: GPA = 0x%llx, GLA = 0x%llx, qual = 0x%llx\n", gpa, gla, qual);
		ept_pde_t* rip_pde = gphys_to_pde(__pa(current_rip), &ept_ptr);
		ept_pde_t* gpa_pde = gphys_to_pde(gpa, &ept_ptr);
		
		
		// ept_pte_t* pte_fault = gphys_to_pte(gpa, &ept_ptr);
		// pr_info("gpa %llx", *pte_fault);
		pr_info("guest rip %llx, target %llx, pde %llx", current_rip, loop_test, *rip_pde);

		pr_info("EPT TRAP YIPEEEEEEEE 🥳🥳🥳 gpa pde %llx", gpa_pde->all);
		pr_info("please trap %llx 🥺", __pa(target_page));
		if(__pa(target_page) == gpa) {
			ept_pde_2mb_t* pde_target = (ept_pde_2mb_t*)gpa_pde;
			*(char*)fake_page = 0x69;
			pr_info("holy shit its happening 🤩🤩");
			pde_target->fields.read = 1;
			pde_target->fields.write = 1;
			pde_target->fields.execute = 0;
			//time to swap
			pde_target->fields.page_address = __pa(fake_page) / 0x200000;
			pr_info("new gpa pde %llx", gpa_pde->all);
			
			invept(ept_ptr.all);
			resume_to_next_instruction();
			return;
			//swap out page
			  

		}
		*(char*)0 = 0;
		//gphys_to_pte((u64)current_rip, &ept_ptr)->fields.execute = 1;
}



void vmexit_handler_main(guest_regs_t *guest_regs)
{

	// /_print_guest_regs(guest_regs);
	u64 exit_reason = vmread(VM_EXIT_REASON);

	u64 exit_qualification = vmread(EXIT_QUALIFICATION);
	char *current_rip = (char *)vmread(GUEST_RIP);
	

	pr_info("tvisor: exit reason[%lld]\n", exit_reason & 0xffff);
	pr_info("tvisor: exit qualification[%lld]\n", exit_qualification);
	ept_pointer_t ept_ptr = (ept_pointer_t)vmread(EPT_POINTER); 
	u64 host_target = __pa(loop_test);
		
	
	
	switch (exit_reason) {
	case EXIT_REASON_VMCLEAR:
	case EXIT_REASON_VMPTRLD:
	case EXIT_REASON_VMPTRST:
	case EXIT_REASON_VMREAD:
	case EXIT_REASON_VMRESUME:
	case EXIT_REASON_VMWRITE:
	case EXIT_REASON_VMXOFF:
	case EXIT_REASON_VMXON:
	case EXIT_REASON_VMLAUNCH:
		pr_info("tvisor: execution of vmx instruction detected...\n");
		break;
	case EXIT_REASON_HLT:
		pr_info("tvisor: execution of hlt detected...\n");
		
		//i will stop putting all my shit here soon i promise
		/*
						pt[i].fields.page_address =
					(u64)(__pa(page) / 0x1000);
				pt[i].fields.accessed = 0;
				pt[i].fields.dirty = 0;
				pt[i].fields.memory_type = 6;
				pt[i].fields.read = 1;
				pt[i].fields.write = 1;
				pt[i].fields.execute = 1;
				pt[i].fields.execute_for_user_mode = 0;
				pt[i].fields.ignore_pat = 0;
				pt[i].fields.ignored1 = 1; // use as used flag
				pt[i].fields.ignored2 = 0;
				pt[i].fields.ignored3 = 0;
				pt[i].fields.ignored4 = 0;
				pt[i].fields.suppress_ve = 0;
		*/

		
		ept_pde_t* pde = gphys_to_pde((u64)current_rip, &ept_ptr);
		
		// ept_pte_t* new_pte = alloc_ept_pt();
		// new_pte->all = 0;
		// new_pte->fields.page_address = host_target >> 12;
		// new_pte->fields.memory_type = 6;
		
		// new_pte->fields.execute_for_user_mode = 0;
		// new_pte->fields.ignore_pat = 0;



		// pde->fields.ept_pt_address = __pa(new_pte) / 0x1000;
		 
		// new_pte->fields.read = 1;
		// new_pte->fields.write = 1;
		// new_pte->fields.execute = 1;
		// new_pte->fields.execute_for_user_mode = 1;
		

		//*(char*)0 = 1;
		// restore_vmxoff_state(VM->rsp, VM->rbp);
		break;
	case EXIT_REASON_TRIPLE_FAULT:
		pr_info("tvisor: triple fault detected...\n");
		*(char*)0 = 1;
		break;
	case EXIT_REASON_EPT_VIOLATION:
		vmexit_on_ept_violation(guest_regs);
		return;

	case EXIT_REASON_EPT_MISCONFIG:
		u64 gpa = vmread(GUEST_PHYSICAL_ADDRESS);
		u64 gla = vmread(GUEST_LINEAR_ADDRESS);
		u64 qual = vmread(EXIT_QUALIFICATION);

		pr_info("EPT Misconfig: GPA = 0x%llx, GLA = 0x%llx, qual = 0x%llx\n", gpa, gla, qual);
		pr_info("misconfig :(");
		*(char*)0 = 0;
		break;

	case EXIT_REASON_CPUID:
		
		pr_info("tvisor: TRAPPING CPUID!!!\n");
		ept_pde_2mb_t* pde2 = (ept_pde_2mb_t*)gphys_to_pde(__pa(current_rip), &ept_ptr);
		//pde2++;
		pde2->fields.execute = 0;
		pr_info("pde %llx large page %llx\n", pde2->all, pde2->fields.large_page);
		pr_info("guest rip va %llx, pa %llx", current_rip, __pa(current_rip));
		invept(ept_ptr.all);
		resume_to_next_instruction();
		break;
	default:
		pr_info("tvisor: execution of other reason detected...\n");
		break;
	}
	
}



void vm_resumer(void)
{
	vmresume();

	u64 err = vmread(VM_INSTRUCTION_ERROR);
	pr_info("tvisor: vmlaunch is failed\n");
	pr_debug("tvisor: vm instruction error[%lld]\n", err);
	for (;;) { // (; o ;)
	}
}