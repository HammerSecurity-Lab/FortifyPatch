// SPDX-License-Identifier: GPL-2.0-only
/*
 * Based on arch/arm/kernel/setup.c
 *
 * Copyright (C) 1995-2001 Russell King
 * Copyright (C) 2012 ARM Ltd.
 */

#include <linux/acpi.h>
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/stddef.h>
#include <linux/ioport.h>
#include <linux/delay.h>
#include <linux/initrd.h>
#include <linux/console.h>
#include <linux/cache.h>
#include <linux/screen_info.h>
#include <linux/init.h>
#include <linux/kexec.h>
#include <linux/root_dev.h>
#include <linux/cpu.h>
#include <linux/interrupt.h>
#include <linux/smp.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/memblock.h>
#include <linux/of_fdt.h>
#include <linux/efi.h>
#include <linux/psci.h>
#include <linux/sched/task.h>
#include <linux/mm.h>

#include <asm/acpi.h>
#include <asm/fixmap.h>
#include <asm/cpu.h>
#include <asm/cputype.h>
#include <asm/daifflags.h>
#include <asm/elf.h>
#include <asm/cpufeature.h>
#include <asm/cpu_ops.h>
#include <asm/kasan.h>
#include <asm/numa.h>
#include <asm/sections.h>
#include <asm/setup.h>
#include <asm/smp_plat.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>
#include <asm/traps.h>
#include <asm/efi.h>
#include <asm/xen/hypervisor.h>
#include <asm/mmu_context.h>

static int num_standard_resources;
static struct resource *standard_resources;

phys_addr_t __fdt_pointer __initdata;

/*
 * Standard memory resources
 */
static struct resource mem_res[] = {
	{
		.name = "Kernel code",
		.start = 0,
		.end = 0,
		.flags = IORESOURCE_SYSTEM_RAM
	},
	{
		.name = "Kernel data",
		.start = 0,
		.end = 0,
		.flags = IORESOURCE_SYSTEM_RAM
	}
};

#define kernel_code mem_res[0]
#define kernel_data mem_res[1]

/*
 * The recorded values of x0 .. x3 upon kernel entry.
 */
u64 __cacheline_aligned boot_args[4];

void __init smp_setup_processor_id(void)
{
	u64 mpidr = read_cpuid_mpidr() & MPIDR_HWID_BITMASK;
	cpu_logical_map(0) = mpidr;

	/*
	 * clear __my_cpu_offset on boot CPU to avoid hang caused by
	 * using percpu variable early, for example, lockdep will
	 * access percpu variable inside lock_release
	 */
	set_my_cpu_offset(0);
	pr_info("Booting Linux on physical CPU 0x%010lx [0x%08x]\n",
		(unsigned long)mpidr, read_cpuid_id());
}

bool arch_match_cpu_phys_id(int cpu, u64 phys_id)
{
	return phys_id == cpu_logical_map(cpu);
}

struct mpidr_hash mpidr_hash;
/**
 * smp_build_mpidr_hash - Pre-compute shifts required at each affinity
 *			  level in order to build a linear index from an
 *			  MPIDR value. Resulting algorithm is a collision
 *			  free hash carried out through shifting and ORing
 */
static void __init smp_build_mpidr_hash(void)
{
	u32 i, affinity, fs[4], bits[4], ls;
	u64 mask = 0;
	/*
	 * Pre-scan the list of MPIDRS and filter out bits that do
	 * not contribute to affinity levels, ie they never toggle.
	 */
	for_each_possible_cpu(i)
		mask |= (cpu_logical_map(i) ^ cpu_logical_map(0));
	pr_debug("mask of set bits %#llx\n", mask);
	/*
	 * Find and stash the last and first bit set at all affinity levels to
	 * check how many bits are required to represent them.
	 */
	for (i = 0; i < 4; i++) {
		affinity = MPIDR_AFFINITY_LEVEL(mask, i);
		/*
		 * Find the MSB bit and LSB bits position
		 * to determine how many bits are required
		 * to express the affinity level.
		 */
		ls = fls(affinity);
		fs[i] = affinity ? ffs(affinity) - 1 : 0;
		bits[i] = ls - fs[i];
	}
	/*
	 * An index can be created from the MPIDR_EL1 by isolating the
	 * significant bits at each affinity level and by shifting
	 * them in order to compress the 32 bits values space to a
	 * compressed set of values. This is equivalent to hashing
	 * the MPIDR_EL1 through shifting and ORing. It is a collision free
	 * hash though not minimal since some levels might contain a number
	 * of CPUs that is not an exact power of 2 and their bit
	 * representation might contain holes, eg MPIDR_EL1[7:0] = {0x2, 0x80}.
	 */
	mpidr_hash.shift_aff[0] = MPIDR_LEVEL_SHIFT(0) + fs[0];
	mpidr_hash.shift_aff[1] = MPIDR_LEVEL_SHIFT(1) + fs[1] - bits[0];
	mpidr_hash.shift_aff[2] = MPIDR_LEVEL_SHIFT(2) + fs[2] -
						(bits[1] + bits[0]);
	mpidr_hash.shift_aff[3] = MPIDR_LEVEL_SHIFT(3) +
				  fs[3] - (bits[2] + bits[1] + bits[0]);
	mpidr_hash.mask = mask;
	mpidr_hash.bits = bits[3] + bits[2] + bits[1] + bits[0];
	pr_debug("MPIDR hash: aff0[%u] aff1[%u] aff2[%u] aff3[%u] mask[%#llx] bits[%u]\n",
		mpidr_hash.shift_aff[0],
		mpidr_hash.shift_aff[1],
		mpidr_hash.shift_aff[2],
		mpidr_hash.shift_aff[3],
		mpidr_hash.mask,
		mpidr_hash.bits);
	/*
	 * 4x is an arbitrary value used to warn on a hash table much bigger
	 * than expected on most systems.
	 */
	if (mpidr_hash_size() > 4 * num_possible_cpus())
		pr_warn("Large number of MPIDR hash buckets detected\n");
}

static void __init setup_machine_fdt(phys_addr_t dt_phys)
{
	void *dt_virt = fixmap_remap_fdt(dt_phys);
	const char *name;

	if (!dt_virt || !early_init_dt_scan(dt_virt)) {
		pr_crit("\n"
			"Error: invalid device tree blob at physical address %pa (virtual address 0x%p)\n"
			"The dtb must be 8-byte aligned and must not exceed 2 MB in size\n"
			"\nPlease check your bootloader.",
			&dt_phys, dt_virt);

		while (true)
			cpu_relax();
	}

	name = of_flat_dt_get_machine_name();
	if (!name)
		return;

	pr_info("Machine model: %s\n", name);
	dump_stack_set_arch_desc("%s (DT)", name);
}

static void __init request_standard_resources(void)
{
	struct memblock_region *region;
	struct resource *res;
	unsigned long i = 0;
	size_t res_size;

	kernel_code.start   = __pa_symbol(_text);
	kernel_code.end     = __pa_symbol(__init_begin - 1);
	kernel_data.start   = __pa_symbol(_sdata);
	kernel_data.end     = __pa_symbol(_end - 1);

	num_standard_resources = memblock.memory.cnt;
	res_size = num_standard_resources * sizeof(*standard_resources);
	standard_resources = memblock_alloc(res_size, SMP_CACHE_BYTES);
	if (!standard_resources)
		panic("%s: Failed to allocate %zu bytes\n", __func__, res_size);

	for_each_memblock(memory, region) {
		res = &standard_resources[i++];
		if (memblock_is_nomap(region)) {
			res->name  = "reserved";
			res->flags = IORESOURCE_MEM;
		} else {
			res->name  = "System RAM";
			res->flags = IORESOURCE_SYSTEM_RAM | IORESOURCE_BUSY;
		}
		res->start = __pfn_to_phys(memblock_region_memory_base_pfn(region));
		res->end = __pfn_to_phys(memblock_region_memory_end_pfn(region)) - 1;

		request_resource(&iomem_resource, res);

		if (kernel_code.start >= res->start &&
		    kernel_code.end <= res->end)
			request_resource(res, &kernel_code);
		if (kernel_data.start >= res->start &&
		    kernel_data.end <= res->end)
			request_resource(res, &kernel_data);
#ifdef CONFIG_KEXEC_CORE
		/* Userspace will find "Crash kernel" region in /proc/iomem. */
		if (crashk_res.end && crashk_res.start >= res->start &&
		    crashk_res.end <= res->end)
			request_resource(res, &crashk_res);
#endif
	}
}

static int __init reserve_memblock_reserved_regions(void)
{
	u64 i, j;

	for (i = 0; i < num_standard_resources; ++i) {
		struct resource *mem = &standard_resources[i];
		phys_addr_t r_start, r_end, mem_size = resource_size(mem);

		if (!memblock_is_region_reserved(mem->start, mem_size))
			continue;

		for_each_reserved_mem_region(j, &r_start, &r_end) {
			resource_size_t start, end;

			start = max(PFN_PHYS(PFN_DOWN(r_start)), mem->start);
			end = min(PFN_PHYS(PFN_UP(r_end)) - 1, mem->end);

			if (start > mem->end || end < mem->start)
				continue;

			reserve_region_with_split(mem, start, end, "reserved");
		}
	}

	return 0;
}
arch_initcall(reserve_memblock_reserved_regions);

u64 __cpu_logical_map[NR_CPUS] = { [0 ... NR_CPUS-1] = INVALID_HWID };

void __init setup_arch(char **cmdline_p)
{
	init_mm.start_code = (unsigned long) _text;
	init_mm.end_code   = (unsigned long) _etext;
	init_mm.end_data   = (unsigned long) _edata;
	init_mm.brk	   = (unsigned long) _end;

	*cmdline_p = boot_command_line;

	early_fixmap_init();
	early_ioremap_init();

	setup_machine_fdt(__fdt_pointer);

	/*
	 * Initialise the static keys early as they may be enabled by the
	 * cpufeature code and early parameters.
	 */
	jump_label_init();
	parse_early_param();

	/*
	 * Unmask asynchronous aborts and fiq after bringing up possible
	 * earlycon. (Report possible System Errors once we can report this
	 * occurred).
	 */
	local_daif_restore(DAIF_PROCCTX_NOIRQ);

	/*
	 * TTBR0 is only used for the identity mapping at this stage. Make it
	 * point to zero page to avoid speculatively fetching new entries.
	 */
	cpu_uninstall_idmap();

	xen_early_init();
	efi_init();
	arm64_memblock_init();

	paging_init();

	acpi_table_upgrade();

	/* Parse the ACPI tables for possible boot-time configuration */
	acpi_boot_table_init();

	if (acpi_disabled)
		unflatten_device_tree();

	bootmem_init();

	kasan_init();

	request_standard_resources();

	early_ioremap_reset();

	if (acpi_disabled)
		psci_dt_init();
	else
		psci_acpi_init();

	cpu_read_bootcpu_ops();
	smp_init_cpus();
	smp_build_mpidr_hash();

	/* Init percpu seeds for random tags after cpus are set up. */
	kasan_init_tags();

#ifdef CONFIG_ARM64_SW_TTBR0_PAN
	/*
	 * Make sure init_thread_info.ttbr0 always generates translation
	 * faults in case uaccess_enable() is inadvertently called by the init
	 * thread.
	 */
	init_task.thread_info.ttbr0 = __pa_symbol(empty_zero_page);
#endif

#ifdef CONFIG_VT
	conswitchp = &dummy_con;
#endif
	if (boot_args[1] || boot_args[2] || boot_args[3]) {
		pr_err("WARNING: x1-x3 nonzero in violation of boot protocol:\n"
			"\tx1: %016llx\n\tx2: %016llx\n\tx3: %016llx\n"
			"This indicates a broken bootloader or old kernel\n",
			boot_args[1], boot_args[2], boot_args[3]);
	}
}

static int __init topology_init(void)
{
	int i;

	for_each_online_node(i)
		register_one_node(i);

	for_each_possible_cpu(i) {
		struct cpu *cpu = &per_cpu(cpu_data.cpu, i);
		cpu->hotpluggable = 1;
		register_cpu(cpu, i);
	}

	return 0;
}
subsys_initcall(topology_init);

/*
 * Dump out kernel offset information on panic.
 */
static int dump_kernel_offset(struct notifier_block *self, unsigned long v,
			      void *p)
{
	const unsigned long offset = kaslr_offset();

	if (IS_ENABLED(CONFIG_RANDOMIZE_BASE) && offset > 0) {
		pr_emerg("Kernel Offset: 0x%lx from 0x%lx\n",
			 offset, KIMAGE_VADDR);
		pr_emerg("PHYS_OFFSET: 0x%llx\n", PHYS_OFFSET);
	} else {
		pr_emerg("Kernel Offset: disabled\n");
	}
	return 0;
}

static struct notifier_block kernel_offset_notifier = {
	.notifier_call = dump_kernel_offset
};

static int __init register_kernel_offset_dumper(void)
{
	atomic_notifier_chain_register(&panic_notifier_list,
				       &kernel_offset_notifier);
	return 0;
}
__initcall(register_kernel_offset_dumper);

u64 kernel_map_base_page = 0x81000;
u64 kernel_map_base_section = 0x200000;
bool is_vttbr_1[4] = {true, true, true, true};
u64 vttbr_el2_1 = 0x321c0000;
u64 vttbr_el2_2 = 0x321d0000;
u64 phys_va_base;
#define INS_TYPE_LDRB				0x1
#define INS_TYPE_LDP				0X2
#define INS_TYPE_LDR				0X3
#define INS_TYPE_LDRH				0X4
#define INS_TYPE_LDXR				0X5
#define INS_TYPE_LDRSW				0X6

#define INS_TYPE_STR				0X13
#define INS_TYPE_STXR				0X19

void *my_memcpy(void *dst, const void *src, u32 len)
{
	const char *s = src;
	char *d = dst;

	while (len--)
		*d++ = *s++;

	return dst;
}

u64 get_pa_page_by_va(u64 va) {
	u64 v;
	__asm__ volatile ("AT S1E1R, %0" : : "r" (va));
	__asm__ volatile ("mrs %0, par_el1" : "=r" (v));

	return v & 0xfffffffff000;
}

u64 get_pa_by_va(u64 va) {
	u64 v;
	__asm__ volatile ("AT S1E1R, %0" : : "r" (va));
	__asm__ volatile ("mrs %0, par_el1" : "=r" (v));

	return (v & 0xfffffffff000) | (va & 0xfff);
}

void data_patch(u64 sp) {
	uint64_t *data_num_64, num_data, world_set[5];
	u64 *work_ptr_64;
	u64 trampoline_address, base_addr;
	char *char_ptr;
	u64 *page_table;
	int j;

	trampoline_address = *(u64 *) (sp + 0x10);
	base_addr = 0x32000000;
	data_num_64 = (uint64_t *) get_pa_by_va(trampoline_address);
	num_data = *data_num_64;
	
	for(j = 0; j < num_data; j++) {
		uint64_t *current_data_num, *curren_data_ptr, data_addr;
		data_num_64++;
		data_addr = get_pa_by_va(*data_num_64);
		current_data_num = (uint64_t *) (base_addr + 0x1d6000);
		curren_data_ptr = (current_data_num + 1);
		
		data_num_64++;
		work_ptr_64 = (uint64_t *) *curren_data_ptr;
		*work_ptr_64 = data_addr;
		char_ptr = (char *) (work_ptr_64 + 1);
		my_memcpy(char_ptr, (char *)(data_num_64 + 1), *data_num_64);			//copy data

		work_ptr_64 = (uint64_t *) (base_addr + 0x1d6000 + 0x10 + (*current_data_num * 0x8));
		*work_ptr_64 = *curren_data_ptr;
		*current_data_num += 1;														//todo :  alignment fault
		*curren_data_ptr += (*data_num_64 + 0x8);
		
		data_num_64++;
		world_set[j] = data_addr;
	}

	page_table = (u64 *) 0x321c36d0;
	*page_table = 0x0;

	page_table = (u64 *) 0x321d46d0;
	*page_table = 0x0;
	// for(i = 0; i < num_data; i++) {
	// 	page_table = (u64 *) (((world_set[i] & 0x1FF000) >> 9) | 0x321c3000);
	// 	*page_table = 0x0;

	// 	page_table = (u64 *) (((world_set[i] & 0x1FF000) >> 9) | 0x321d4000);
	// 	*page_table = 0x0;
	// 	return;
	// }

	return;
}

u64 pagetable_walk(u64 va, u64 kernel_phy) {
	u16 va_region_1, va_region_2;
    u32 va_tail, va_tail_block;
    u64 path_va, ttbr, desc;
      
    va_region_1 = (va >> 30) & 0x1ff;
    va_region_2 = (va >> 21) & 0x1ff;
    va_tail = va & 0xfff;
    va_tail_block = va & 0x1fffff;

    __asm__ volatile ("mrs %0, ttbr1_el1" : "=r" (ttbr));

    desc = (ttbr & 0xfffffffff000) | (va_region_1 << 3);
	desc = (uint64_t) get_pa_by_va(desc);
	path_va = *(uint64_t *)desc;
    if (!(path_va & 0x1)) {
        return -1;
    } else {
        if(!(path_va & 0x2)) {
			return -1;
		} else {
			desc = (path_va & 0xfffffffff000) | (va_region_2 << 3);
			desc = (uint64_t) get_pa_by_va(desc);
			path_va = *(uint64_t *)desc;
			if (!(path_va & 0x1)) {
				return -1;
			} else {
				if(!(path_va & 0x2)) {
					if ((path_va & 0xfffffffff000) != kernel_phy) {
						return -1;
					}
					return 0;
				} else {
					return -1;
				}
			}
		}
    }
}

void detect_kernel_map(void) {
	u64 kernel_start = 0xffffff8010081000, kernel_section_begin = 0xffffff8010200000, kernel_end = 0xffffff80109b0000, address_ptr, kernel_phys;
	int error_count = 0;

	kernel_phys = kernel_map_base_page;

	for(address_ptr = kernel_start; address_ptr < kernel_section_begin; address_ptr += 0x1000) {
		if(!(get_pa_page_by_va(address_ptr) == kernel_phys)) {
			//print error;
			error_count++;
		}
		kernel_phys += 0x1000;
	}

	kernel_phys = kernel_map_base_section;
	for(address_ptr = kernel_section_begin; address_ptr < kernel_end; address_ptr += 0x200000) {
		if(pagetable_walk(address_ptr, kernel_phys) != 0) {
			error_count++;
		}
		kernel_phys += 0x200000;
	}

	return;
}

bool is_adrp(u32 ins) {
	if (((ins >> 24) & 0x9f) == 0x90)
		return true;
	
	return false;
}

u64 handler_hvc_1(u64 addr) {
	phys_va_base = addr;

	return 0;
}

u64 handler_hvc_2(u64 meta_address) {
	u32 *work_ptr_32;
	u64 *work_ptr_64, *current_patch_num, trampoline_list[5], patch_list[5], type_list[5], size_list[5];
	u64 base_addr, patch_func_num, patch_base, phys_addr;
	int idx, jdx;

	base_addr = 0x32000000;

	current_patch_num = (u64 *) base_addr;

	work_ptr_64 = (u64 *) get_pa_by_va(meta_address);
	patch_func_num = (u64)*work_ptr_64;
	work_ptr_64 ++;
	
	for(idx = 0; idx < patch_func_num; idx++)
	{
		trampoline_list[idx] = *(work_ptr_64++);
		patch_list[idx] = phys_va_base;
		size_list[idx] = *(work_ptr_64++);
		type_list[idx] = *(work_ptr_64++);
		patch_base = *(work_ptr_64++);

		my_memcpy((char *) get_pa_by_va(phys_va_base), (char *) ((u64 *) get_pa_by_va(patch_base)), size_list[idx]);
		if(size_list[idx] < 0x1000) {
			phys_va_base += 0x1000;
		} else {
			phys_va_base += 0x2000;		//todo : size > 0x2000
		}
	}

	for(idx = 0; idx < patch_func_num; idx++){
		work_ptr_64 = (u64 *) (base_addr + 0x10 + (*current_patch_num * 0x20));

		*(work_ptr_64++) = trampoline_list[idx];
		*(work_ptr_64++) = patch_list[idx];
		*(work_ptr_64++) = size_list[idx];
		*(work_ptr_64++) = type_list[idx];

		work_ptr_32 = (u32 *)get_pa_by_va(patch_list[idx]);
		if (type_list[idx] == 0x2)
		{
			for (jdx = 0; jdx < size_list[idx]; jdx += 4) {
				*work_ptr_32 = 0x0;
				work_ptr_32++;
			}
			return 0xbadcafe;
		} else if (type_list[idx] == 0x1){
			for (jdx = 0; jdx < size_list[idx]; jdx += 4)
			{
				if (is_adrp(*work_ptr_32))
				{
					u64 offset, des_addr;
					u32 immlo_30_29, immhi_23_5;
					
					immlo_30_29 = (*work_ptr_32 >> 29) & 0x3;
					immhi_23_5 = (*work_ptr_32 >> 5) & 0x7ffff;
					offset = ((immhi_23_5 << 2) | immlo_30_29) << 12;
					if (offset & (0x80000000))
					{
						offset |= 0xffffffff00000000;
					}
					
					des_addr = offset + (trampoline_list[idx] & 0xfffffffffffff000);
					offset = (des_addr - (u64)patch_list[idx]) >> 12;

					immlo_30_29 = (offset << 29) & 0x60000000;
					immhi_23_5 = (offset << 3) & 0xffffe0;

					*work_ptr_32 = (*work_ptr_32 & 0x9f00001f) | immlo_30_29 | immhi_23_5;
				}
				work_ptr_32++;
			}
			
			*current_patch_num += 1;

			work_ptr_32 = (u32 *)get_pa_by_va(trampoline_list[idx]);
			work_ptr_32[0] = 0xd4000002;
		} else {
			return 0xdeadbeef;
		}
	}

	for(idx = 0; idx < patch_func_num; idx++) {
		u64 *page_table;

		phys_addr = get_pa_by_va(patch_list[idx]);
		page_table = (u64 *) (((phys_addr & 0x1FF000) >> 9) | 0x321c2000);
		*page_table = 0x0;
	}

	return 0;
}

int match_reserved_address(u64 addr) {
	if (addr >= 0x32000000 && addr < 0x32010000)
	{
		return 1;
	}

	return 0;
}

int match_kernel_text(u64 addr) {
	if (addr >= 0x81000 && addr < 0x9b0000)
	{
		return 1;
	}

	return 0;
}

void change_vttbr(int cpu_id)
{
	if (is_vttbr_1[cpu_id]) {
    	__asm__ volatile ("msr vttbr_el2, %0" : : "r" (vttbr_el2_2));
		is_vttbr_1[cpu_id] = false;
	} else {
    	__asm__ volatile ("msr vttbr_el2, %0" : : "r" (vttbr_el2_1));
		is_vttbr_1[cpu_id] = true;
	}
}

bool current_is_vttbr_1(int cpu_id) {
	return is_vttbr_1[cpu_id];
}

int is_directly_change(void) {
	u64 far_el2, esr_el2, mpidr_el1;
	int cpu_id;
	u64 phy_addr;

	__asm__ volatile ("mrs %0, far_el2" : "=r" (far_el2));
	__asm__ volatile ("mrs %0, esr_el2" : "=r" (esr_el2));
	__asm__ volatile ("mrs %0, mpidr_el1" : "=r" (mpidr_el1));

	cpu_id = mpidr_el1 & 0xf;

	phy_addr = get_pa_page_by_va(far_el2);	
	if (current_is_vttbr_1(cpu_id)) {
		if (!(match_reserved_address(phy_addr))) {
			// change_vttbr(cpu_id);		//error
			
			return 4;
		}
	} else {
		if (!(match_kernel_text(phy_addr))) {
			// change_vttbr(cpu_id);		//error
			
			return 4;
		}
	}

	change_vttbr(cpu_id);
	return cpu_id;
}

int hvc_change_ttbr(int patch_number)
{
	int cpu_id;
	u64 mpidr_el1, elr_new;
	__asm__ volatile ("mrs %0, mpidr_el1" : "=r" (mpidr_el1));
	cpu_id = mpidr_el1 & 0xf;


	if (current_is_vttbr_1(cpu_id)) {
		elr_new = *(u64 *)(0x32000000 + 0x18 + ((patch_number-1) * 0x20));
	} else {
		change_vttbr(cpu_id);
		elr_new = *(u64 *)(0x32000000 + 0x18 + ((patch_number-1) * 0x20));
	}

    __asm__ volatile ("msr elr_el2, %0" : : "r" (elr_new));
	change_vttbr(cpu_id);
	return cpu_id;
}

void hvc_set_krpobe(u64 addr, u32 insn)
{
	u32 *ptr;

	ptr = (u32 *)addr;
	*ptr = insn;

	return;
}

static inline uint64_t read_spsr_el2(void)	
{
	uint64_t v;
	__asm__ volatile ("mrs %0, spsr_el2": "=r" (v));
	return v;
}

int data_ldr(u32 ins, u64 sp, int64_t data_addr, int64_t data_patch_addr, int cpu_id) {
	u32 n, t;
	int64_t xn = 0, *xt, offset;
	bool write_back = false;

	t = ins & 0x1f;

	xt = (int64_t *) (sp + (t * 0x8));
	
	if ((ins >> 30) & 0x1) {
		int64_t data;
		if(data_patch_addr == 0x1) {
			data = *(int64_t *) data_addr;
		} else {
			data = *(int64_t *) data_patch_addr;
		}
		
		if (!(ins & ((1 << 24) | (1 << 21)))) {
			write_back = true;
			offset = (ins >> 12) & 0x1ff;
			if (offset >> 8) {
				offset |= 0xfffffffffffffe00;
			}
		}
		*xt = data;
	} else {
		int32_t data;
		if(data_patch_addr == 0x1) {
			data = *(int32_t *) data_addr;
		} else {
			data = *(int32_t *) data_patch_addr;
		}

		if (!(ins & ((1 << 24) | (1 << 21)))) {
			write_back = true;
			offset = (ins >> 12) & 0x1ff;
			if (offset >> 8) {
				offset |= 0xfffffffffffffe00;
			}
		}
		*xt = (data & 0xffffffff);
	}

	if(write_back) {
		n = (ins >> 5) & 0x1f;
		if (n == 31) {
			switch (((read_spsr_el2() >> 2) & 0b11)) {
				case 0:
					__asm__ volatile ("mrs %0, sp_el0": "=r" (xn));
					__asm__ volatile ("msr sp_el0, %0" : : "r" (xn + offset));
					break;

				case 1:
					__asm__ volatile ("mrs %0, sp_el1": "=r" (xn));
					__asm__ volatile ("msr sp_el1, %0" : : "r" (xn + offset));
					break;
			}
		} else {
			int64_t *xn_ptr;
			xn_ptr = (int64_t *) (sp + (n * 0x8));
			*xn_ptr += offset;
		}
	}

	return 0;
}

int data_ldrb(uint32_t ins, uint64_t sp, int64_t data_addr, int64_t data_patch_addr, int cpu_id) {
	uint32_t n, t;
	int64_t xn = 0, *xt, offset;
	bool write_back = false;
	int8_t data;

	n = (ins >> 5) & 0x1f;
	t = ins & 0x1f;

	xt = (int64_t *) (sp + (t * 0x8));

	if(data_patch_addr == 0x1) {
		data = *(int8_t *) data_addr;
	} else {
		data = *(int8_t *) data_patch_addr;
	}

	if (!(ins & ((1 << 24) | (1 << 21)))) {
		write_back = true;
		offset = (ins >> 12) & 0x1ff;
		if (offset >> 8) {
			offset |= 0xfffffffffffffe00;
		}
	}
	*xt = (data & 0xffffffff);

	if(write_back) {
		if (n == 31) {
			switch (((read_spsr_el2() >> 2) & 0b11)) {
				case 0:
					__asm__ volatile ("mrs %0, sp_el0": "=r" (xn));
					__asm__ volatile ("msr sp_el0, %0" : : "r" (xn + offset));
					break;

				case 1:
					__asm__ volatile ("mrs %0, sp_el1": "=r" (xn));
					__asm__ volatile ("msr sp_el1, %0" : : "r" (xn + offset));
					break;
			}
		} else {
			int64_t *xn_ptr;
			xn_ptr = (int64_t *) (sp + (n * 0x8));
			*xn_ptr += offset;
		}
	}

	return 0;
}

int data_ldp(uint32_t ins, uint64_t sp, int64_t data_addr, int64_t data_patch_addr, int cpu_id) {		//todo handle 2 data
	uint32_t n, t, t2;
	int64_t xn = 0, *xt, *xt2, offset;
	bool write_back = false;

	t2 = (ins >> 10) & 0x1f;
	t = ins & 0x1f;

	xt = (int64_t *) (sp + (t * 0x8));
	xt2 = (int64_t *) (sp + (t2 * 0x8));
	
	if ((ins >> 31) & 0x1) {
		int64_t data, data2;
		if(data_patch_addr == 0x1) {
			data = *(int64_t *) data_addr;
			data2 = *(int64_t *) (data_addr + 0x8);
		} else {
			// ERROR("handle ldp\n");
			data = *(int64_t *) data_patch_addr;
			data2 = *(int64_t *) (data_patch_addr + 0x8);
		}
		*xt = data;
		*xt2 = data2;

		if (!(((ins >> 23) & 0b11) == 0b10))
		{
			offset = (ins >> 15) & 0x7f;
			if (offset >> 6) {
				offset |= 0xffffffffffffff80;
			}
			offset *= 8;
			write_back = true;
		}
	} else {
		int32_t data, data2;
		if(data_patch_addr == 0x1) {
			data = *(int32_t *) data_addr;
			data2 = *(int32_t *) (data_addr + 0x8);
		} else {
			// ERROR("handle ldp\n");
			data = *(int32_t *) data_patch_addr;
			data2 = *(int32_t *) (data_patch_addr + 0x8);
		}
		*xt = (data & 0xffffffff);
		*xt2 = (data2 & 0xffffffff);

		if (!(((ins >> 23) & 0b11) == 0b10))
		{
			offset = (ins >> 15) & 0x7f;
			if (offset >> 6) {
				offset |= 0xffffffffffffff80;
			}
			offset *= 4;
			write_back = true;
		}
	}
	
	if(write_back) {
		n = (ins >> 5) & 0x1f;
		if (n == 31) {
			switch (((read_spsr_el2() >> 2) & 0b11)) {
				case 0:
					__asm__ volatile ("mrs %0, sp_el0": "=r" (xn));
					__asm__ volatile ("msr sp_el0, %0" : : "r" (xn + offset));
					break;

				case 1:
					__asm__ volatile ("mrs %0, sp_el1": "=r" (xn));
					__asm__ volatile ("msr sp_el1, %0" : : "r" (xn + offset));
					break;
			}
		} else {
			int64_t *xn_ptr;
			xn_ptr = (int64_t *) (sp + (n * 0x8));
			*xn_ptr += offset;
		}
	}

	return 0;
}

int data_ldrh(uint32_t ins, uint64_t sp, int64_t data_addr, int64_t data_patch_addr, int cpu_id) {
	uint32_t n, t;
	int64_t xn = 0, *xt, offset;
	bool write_back = false;
	int16_t data;

	n = (ins >> 5) & 0x1f;
	t = ins & 0x1f;

	xt = (int64_t *) (sp + (t * 0x8));

	if(data_patch_addr == 0x1) {
		data = *(int16_t *) data_addr;
	} else {
		data = *(int16_t *) data_patch_addr;
	}

	if (!(ins & ((1 << 24) | (1 << 21)))) {
		write_back = true;
		offset = (ins >> 12) & 0x1ff;
		if (offset >> 8) {
			offset |= 0xfffffffffffffe00;
		}
	}
	*xt = (data & 0xffffffff);

	if(write_back) {
		if (n == 31) {
			switch (((read_spsr_el2() >> 2) & 0b11)) {
				case 0:
					__asm__ volatile ("mrs %0, sp_el0": "=r" (xn));
					__asm__ volatile ("msr sp_el0, %0" : : "r" (xn + offset));
					break;

				case 1:
					__asm__ volatile ("mrs %0, sp_el1": "=r" (xn));
					__asm__ volatile ("msr sp_el1, %0" : : "r" (xn + offset));
					break;
			}
		} else {
			int64_t *xn_ptr;
			xn_ptr = (int64_t *) (sp + (n * 0x8));
			*xn_ptr += offset;
		}
	}

	return 0;
}

int data_ldxr(uint32_t ins, uint64_t sp, int64_t data_addr, int64_t data_patch_addr, int cpu_id) {
	uint32_t t;
	int64_t *xt;

	t = ins & 0x1f;
	xt = (int64_t *) (sp + (t * 0x8));
	
	if ((ins >> 30) & 0x1) {
		int64_t data;
		if(data_patch_addr == 0x1) {
			data = *(int64_t *) data_addr;
		} else {
			data = *(int64_t *) data_patch_addr;
		}

		*xt = data;
	} else {
		int32_t data;
		if(data_patch_addr == 0x1) {
			data = *(int32_t *) data_addr;
		} else {
			data = *(int32_t *) data_patch_addr;
		}
		*xt = (data & 0xffffffff);
	}

	return 0;
}

int data_ldrsw(uint32_t ins, uint64_t sp, int64_t data_addr, int64_t data_patch_addr, int cpu_id) {
	uint32_t n, t;
	int64_t xn = 0, *xt, offset;
	bool write_back = false;
	int32_t data;

	n = (ins >> 5) & 0x1f;
	t = ins & 0x1f;

	xt = (int64_t *) (sp + (t * 0x8));

	if(data_patch_addr == 0x1) {
		data = *(int32_t *) data_addr;
	} else {
		data = *(int32_t *) data_patch_addr;
	}

	if (!(ins & ((1 << 24) | (1 << 21)))) {
		write_back = true;
		offset = (ins >> 12) & 0x1ff;
		if (offset >> 8) {
			offset |= 0xfffffffffffffe00;
		}
	}
	*xt = data;

	if(write_back) {
		if (n == 31) {
			switch (((read_spsr_el2() >> 2) & 0b11)) {
				case 0: 
					__asm__ volatile ("mrs %0, sp_el0": "=r" (xn));
					__asm__ volatile ("msr sp_el0, %0" : : "r" (xn + offset));
					break;

				case 1:
					__asm__ volatile ("mrs %0, sp_el1": "=r" (xn));
					__asm__ volatile ("msr sp_el1, %0" : : "r" (xn + offset));
					break;
			}
		} else {
			int64_t *xn_ptr;
			xn_ptr = (int64_t *) (sp + (n * 0x8));
			*xn_ptr += offset;
		}
	}

	return 0;
}

int data_str(uint32_t ins, uint64_t sp, int64_t data_addr, int64_t data_patch_addr, int cpu_id) {
	uint32_t n, t;
	int64_t xn = 0, *xt, offset, xzr = 0;
	bool write_back = false;

	t = ins & 0x1f;

	if (t == 31) {
		xt = (int64_t *) &xzr;
	} else {
		xt = (int64_t *) (sp + (t * 0x8));
	}
	
	if ((ins >> 30) & 0x1) {			//64-bit variant
		int64_t *write_byte;
		if(data_patch_addr == 0x1) {
			write_byte = (int64_t *) data_addr;
			*write_byte = *xt;
		} else {
			// ERROR("write patch data\n");
		}

		if (!(ins & ((1 << 24) | (1 << 21)))) {
			write_back = true;
			offset = (ins >> 12) & 0x1ff;
			if (offset >> 8) {
				offset |= 0xfffffffffffffe00;
			}
		}
	} else {
		int32_t *write_byte;		//32-bit variant
		if(data_patch_addr == 0x1) {
			write_byte = (int32_t *) data_addr;
			*write_byte = *xt;
		} else {
			// ERROR("write patch data\n");
		}

		if (!(ins & ((1 << 24) | (1 << 21)))) {
			write_back = true;
			offset = (ins >> 12) & 0x1ff;
			if (offset >> 8) {
				offset |= 0xfffffffffffffe00;
			}
		}
	}
	
	if(write_back) {
		n = (ins >> 5) & 0x1f;
		if (n == 31) {
			switch (((read_spsr_el2() >> 2) & 0b11)) {
				case 0:
					__asm__ volatile ("mrs %0, sp_el0": "=r" (xn));
					__asm__ volatile ("msr sp_el0, %0" : : "r" (xn + offset));
					break;

				case 1:
					__asm__ volatile ("msr sp_el1, %0" : : "r" (xn + offset));
					break;
			}
		} else {
			int64_t *xn_ptr;
			xn_ptr = (int64_t *) (sp + (n * 0x8));
			*xn_ptr += offset;
		}
	}

	return 0;
}

int data_stxr(uint32_t ins, uint64_t sp, int64_t data_addr, int64_t data_patch_addr, int cpu_id) {
	uint32_t t, s;
	int64_t *xt, *xs;

	t = ins & 0x1f;
	s = (ins >> 16) & 0x1f;
	xt = (int64_t *) (sp + (t * 0x8));
	xs = (int64_t *) (sp + (s * 0x8));
	
	if ((ins >> 30) & 0x1) {
		int64_t *data;
		if(data_patch_addr == 0x1) {
			data = (int64_t *) data_addr;
			*data = *xt;
		} else {
			data = (int64_t *) data_patch_addr;
			*data = *xt;
		}
	} else {
		int32_t *data;
		if(data_patch_addr == 0x1) {
			data = (int32_t *) data_addr;
			*data = (*xt & 0xffffffff);
		} else {
			data = (int32_t *) data_patch_addr;
			*data = (*xt & 0xffffffff);
		}
	}

	*xs = 0x0;

	return 0;
}
// DATA_ADDR_BASE_OFFSET 0x1d6000
uint64_t match_data_address(uint64_t addr) {		//todo
	uint64_t *data_num, *data_addr;
	int i, j;
	data_num = (uint64_t *) (0x32000000 + 0x1d6000);
	data_addr = (uint64_t *) (0x32000000 + 0x1d6000 + 0x10);
	for (i = 0; i < *data_num; i++)
	{
		uint64_t *data_patch_addr;
		data_patch_addr = (uint64_t *) *data_addr;
		if ((*data_patch_addr & 0xfffffffffffff000) == (addr & 0xfffffffffffff000))
		{
			for (j = i; j < *data_num; j++) {
				if(*data_patch_addr == addr) {
					return (uint64_t) (data_patch_addr + 1);
				}
				data_addr += 1;
				data_patch_addr = (uint64_t *) *data_addr;
			}

			return 1;
		}

		data_addr += 1;
	}

	return 0;
}

int match_special_instruction(uint32_t ins) {
	if ((ins & 0xbec00000) == 0xb8400000)		//LDR
	{
		return INS_TYPE_LDR;
	}

	if ((ins & 0x7e400000) == 0x28400000)		//LDP
	{
		return INS_TYPE_LDP;
	}

	switch (ins & 0xfec00000)
	{
		case 0x38400000:
			return INS_TYPE_LDRB;

		case 0x78400000:
			return INS_TYPE_LDRH;

		case 0xb8800000:
			return INS_TYPE_LDRSW;
		
		default:
			break;
	}

	if ((ins & 0xbe800000) == 0xb8000000)		//str
	{
		return INS_TYPE_STR;
	}

	if ((ins & 0xbffffc00) == 0x885F7C00)
	{
		return INS_TYPE_LDXR;	
	}

	if ((ins & 0xBFE0FC00) == 0x88007C00)
	{
		return INS_TYPE_STXR;	
	}

	return 0;
}

int data_proxy(uint64_t sp)
{
	uint64_t data_phy_addr, data_patch_addr;
	uint64_t far_el2, mpidr_el1, elr_el2;
	int cpu_id;
	uint32_t ins_str = 0x0;

	__asm__ volatile ("mrs %0, far_el2" : "=r" (far_el2));
	__asm__ volatile ("mrs %0, elr_el2" : "=r" (elr_el2));
	__asm__ volatile ("mrs %0, mpidr_el1" : "=r" (mpidr_el1));

	cpu_id = mpidr_el1 & 0xf;
	data_phy_addr = get_pa_by_va(far_el2);
	data_patch_addr = match_data_address(data_phy_addr);
	ins_str = *(uint32_t *) get_pa_by_va(elr_el2);

	if (data_patch_addr) {
		switch (match_special_instruction(ins_str))
		{
			case INS_TYPE_LDRB:
				data_ldrb(ins_str, sp, data_phy_addr, data_patch_addr, cpu_id);
				break;

			case INS_TYPE_LDP:
				data_ldp(ins_str, sp, data_phy_addr, data_patch_addr, cpu_id);
				break;

			case INS_TYPE_LDR:
				data_ldr(ins_str, sp, data_phy_addr, data_patch_addr, cpu_id);
				break;

			case INS_TYPE_LDRH:
				data_ldrh(ins_str, sp, data_phy_addr, data_patch_addr, cpu_id);
				break;

			case INS_TYPE_LDXR:
				data_ldxr(ins_str, sp, data_phy_addr, data_patch_addr, cpu_id);
				break;

			case INS_TYPE_LDRSW:
				data_ldrsw(ins_str, sp, data_phy_addr, data_patch_addr, cpu_id);
				break;

			case INS_TYPE_STR:
				data_str(ins_str, sp, data_phy_addr, data_patch_addr, cpu_id);
				break;

			case INS_TYPE_STXR:
				data_stxr(ins_str, sp, data_phy_addr, data_patch_addr, cpu_id);
				break;

			default:
				// ERROR("1 Data ins type other : %x  \nfar_el3 : 0x%016lx\n\n", ins_str, far_el3);
				break;
		}
	} else {
		// ERROR("Data access GPF!\n");
	}
	__asm__ volatile ("msr elr_el2, %0" : : "r" (elr_el2 + 0x4));

	return cpu_id;
}