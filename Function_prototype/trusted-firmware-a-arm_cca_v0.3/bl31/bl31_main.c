/*
 * Copyright (c) 2013-2020, ARM Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <assert.h>
#include <string.h>

#include <arch.h>
#include <arch_features.h>
#include <arch_helpers.h>
#include <bl31/bl31.h>
#include <bl31/ehf.h>
#include <common/bl_common.h>
#include <common/debug.h>
#include <common/runtime_svc.h>
#include <drivers/console.h>
#include <lib/gpt/gpt.h>
#include <lib/el3_runtime/context_mgmt.h>
#include <lib/pmf/pmf.h>
#include <lib/runtime_instr.h>
#include <plat/common/platform.h>
#include <services/std_svc.h>
#include <context.h>

#if ENABLE_RUNTIME_INSTRUMENTATION
PMF_REGISTER_SERVICE_SMC(rt_instr_svc, PMF_RT_INSTR_SVC_ID,
	RT_INSTR_TOTAL_IDS, PMF_STORE_ENABLE)
#endif

/*******************************************************************************
 * This function pointer is used to initialise the BL32 image. It's initialized
 * by SPD calling bl31_register_bl32_init after setting up all things necessary
 * for SP execution. In cases where both SPD and SP are absent, or when SPD
 * finds it impossible to execute SP, this pointer is left as NULL
 ******************************************************************************/
static int32_t (*bl32_init)(void);

uint64_t last_patch_pa[MAX_CORE_NUM];
// uint64_t patch_list[MAX_PATCH_NUM];
// int patch_num = 0;
int sec_num = 0;
int level_2_sec_num = 0;

/*******************************************************************************
 * Variable to indicate whether next image to execute after BL31 is BL33
 * (non-secure & default) or BL32 (secure).
 ******************************************************************************/
static uint32_t next_image_type = NON_SECURE;

#ifdef SUPPORT_UNKNOWN_MPID
/*
 * Flag to know whether an unsupported MPID has been detected. To avoid having it
 * landing on the .bss section, it is initialized to a non-zero value, this way
 * we avoid potential WAW hazards during system bring up.
 * */
volatile uint32_t unsupported_mpid_flag = 1;
#endif

/*
 * Implement the ARM Standard Service function to get arguments for a
 * particular service.
 */
uintptr_t get_arm_std_svc_args(unsigned int svc_mask)
{
	/* Setup the arguments for PSCI Library */
	DEFINE_STATIC_PSCI_LIB_ARGS_V1(psci_args, bl31_warm_entrypoint);

	/* PSCI is the only ARM Standard Service implemented */
	assert(svc_mask == PSCI_FID_MASK);

	return (uintptr_t)&psci_args;
}

/*******************************************************************************
 * Simple function to initialise all BL31 helper libraries.
 ******************************************************************************/
void __init bl31_lib_init(void)
{
	cm_init();
}

/*******************************************************************************
 * Setup function for BL31.
 ******************************************************************************/
void bl31_setup(u_register_t arg0, u_register_t arg1, u_register_t arg2,
		u_register_t arg3)
{
	/* Perform early platform-specific setup */
	bl31_early_platform_setup2(arg0, arg1, arg2, arg3);

	/* Perform late platform-specific setup */
	bl31_plat_arch_setup();

#if CTX_INCLUDE_PAUTH_REGS
	/*
	 * Assert that the ARMv8.3-PAuth registers are present or an access
	 * fault will be triggered when they are being saved or restored.
	 */
	assert(is_armv8_3_pauth_present());
#endif /* CTX_INCLUDE_PAUTH_REGS */

	// INFO("set another page table\n");
	// set_page_table_2();
}

/*******************************************************************************
 * BL31 is responsible for setting up the runtime services for the primary cpu
 * before passing control to the bootloader or an Operating System. This
 * function calls runtime_svc_init() which initializes all registered runtime
 * services. The run time services would setup enough context for the core to
 * switch to the next exception level. When this function returns, the core will
 * switch to the programmed exception level via an ERET.
 ******************************************************************************/
void bl31_main(void)
{
	NOTICE("BL31: %s\n", version_string);
	NOTICE("BL31: %s\n", build_message);

#ifdef SUPPORT_UNKNOWN_MPID
	if (unsupported_mpid_flag == 0) {
		NOTICE("Unsupported MPID detected!\n");
	}
#endif

	/* Perform platform setup in BL31 */
	bl31_platform_setup();

	/* Initialise helper libraries */
	bl31_lib_init();

#if EL3_EXCEPTION_HANDLING
	INFO("BL31: Initialising Exception Handling Framework\n");
	ehf_init();
#endif

	/* Initialize the runtime services e.g. psci. */
	INFO("BL31: Initializing runtime services\n");
	runtime_svc_init();

	/*
	 * All the cold boot actions on the primary cpu are done. We now need to
	 * decide which is the next image (BL32 or BL33) and how to execute it.
	 * If the SPD runtime service is present, it would want to pass control
	 * to BL32 first in S-EL1. In that case, SPD would have registered a
	 * function to initialize bl32 where it takes responsibility of entering
	 * S-EL1 and returning control back to bl31_main. Once this is done we
	 * can prepare entry into BL33 as normal.
	 */

	/*
	 * If SPD had registered an init hook, invoke it.
	 */
	if (bl32_init != NULL) {
		INFO("BL31: Initializing BL32\n");

		int32_t rc = (*bl32_init)();

		if (rc == 0)
			WARN("BL31: BL32 initialization failed\n");
	}
	/*
	 * We are ready to enter the next EL. Prepare entry into the image
	 * corresponding to the desired security state after the next ERET.
	 */
	bl31_prepare_next_image_entry();

	console_flush();

	/*
	 * Perform any platform specific runtime setup prior to cold boot exit
	 * from BL31
	 */
	bl31_plat_runtime_setup();
}

/*******************************************************************************
 * Accessor functions to help runtime services decide which image should be
 * executed after BL31. This is BL33 or the non-secure bootloader image by
 * default but the Secure payload dispatcher could override this by requesting
 * an entry into BL32 (Secure payload) first. If it does so then it should use
 * the same API to program an entry into BL33 once BL32 initialisation is
 * complete.
 ******************************************************************************/
void bl31_set_next_image_type(uint32_t security_state)
{
	assert(sec_state_is_valid(security_state));
	next_image_type = security_state;
}

uint32_t bl31_get_next_image_type(void)
{
	return next_image_type;
}

/*******************************************************************************
 * This function programs EL3 registers and performs other setup to enable entry
 * into the next image after BL31 at the next ERET.
 ******************************************************************************/
void __init bl31_prepare_next_image_entry(void)
{
	entry_point_info_t *next_image_info;
	uint32_t image_type;

#if CTX_INCLUDE_AARCH32_REGS
	/*
	 * Ensure that the build flag to save AArch32 system registers in CPU
	 * context is not set for AArch64-only platforms.
	 */
	if (el_implemented(1) == EL_IMPL_A64ONLY) {
		ERROR("EL1 supports AArch64-only. Please set build flag "
				"CTX_INCLUDE_AARCH32_REGS = 0\n");
		panic();
	}
#endif

	/* Determine which image to execute next */
	image_type = bl31_get_next_image_type();

	/* Program EL3 registers to enable entry into the next EL */
	next_image_info = bl31_plat_get_next_image_ep_info(image_type);
	assert(next_image_info != NULL);
	assert(image_type == GET_SECURITY_STATE(next_image_info->h.attr));

	INFO("BL31: Preparing for EL3 exit to %s world\n",
		(image_type == SECURE) ? "secure" : "normal");
	print_entry_point_info(next_image_info);
	cm_init_my_context(next_image_info);
	cm_prepare_el3_exit(image_type);
}

/*******************************************************************************
 * This function initializes the pointer to BL32 init function. This is expected
 * to be called by the SPD after it finishes all its initialization
 ******************************************************************************/
void bl31_register_bl32_init(int32_t (*func)(void))
{
	bl32_init = func;
}

uint64_t trap_meta_addr;
uint64_t trap_return_addr;

int tzc_exception(uint64_t esr_el2, uint64_t esr_el3) {
	INFO("esr_el2 : %llx, esr_el3 : %llx\n", esr_el2, esr_el3);
	return 0;
}

int smc_data_proxy(uint64_t sp) {
	uint64_t proxy_param, *param_ptr;
	uint64_t data_patch_addr, data_addr, kernel_regs;
	uint32_t ins_str;

	proxy_param = *(uint64_t *) (sp + CTX_GPREGS_OFFSET + CTX_GPREG_X1);
	INFO("param addr : %llx\n", proxy_param);

	param_ptr = (uint64_t *)get_pa_by_va(proxy_param);

	ins_str = (uint32_t)*param_ptr;
	data_addr = *(param_ptr + 1);
	kernel_regs = get_pa_by_va(*(param_ptr + 2));
	// INFO("param 1 : %llx\n", *param_ptr);
	// INFO("param 2 : %llx\n", *(param_ptr + 1));
	// INFO("param 3 : %llx\n", *(param_ptr + 2));
	// INFO("param 3 phys : %llx\n", kernel_regs);

	data_patch_addr = get_proxy_data(data_addr);
	if (data_patch_addr == 0) {
		data_patch_addr = get_pa_by_va(data_addr);
		INFO("not patch data or tag check failed\n");
	}

	switch (match_special_instruction(ins_str))
	{
		case INS_TYPE_LDRB:
			// data_ldrb(ins_str, sp, data_phy_addr, data_patch_addr, cpu_id);
			proxy_ldrb(ins_str, kernel_regs, data_patch_addr);
			break;

		case INS_TYPE_STRB:
			proxy_strb(ins_str, kernel_regs, data_patch_addr);
			break;

		// case INS_TYPE_STR:
		// 	data_str(ins_str, sp, data_phy_addr, data_patch_addr, cpu_id);
		// 	break;

		default:
			ERROR("1 Data ins type other : %x  \nfar_el3 : 0x%016llx\n\n", ins_str, data_addr);
			break;
	}
	//todo :
	//1. tag check
	// 1.1 tag check in match_data_address (if attacker can modify the tag, how to solve)
	// 1.2 判断是否返回到el2，还是在EL3中进行。
	//2. ins proxy
	return 0;
}

uint64_t update_page_table_mte(uint64_t va) {
    uint16_t va_region_1, va_region_2, va_region_3;
    uint64_t path_va, ttbr, *descriptor;
    
    va_region_1 = (va >> 30) & 0x1ff;
    va_region_2 = (va >> 21) & 0x1ff;
    va_region_3 = (va >> 12) & 0x1ff;

    __asm__ volatile ("mrs %0, ttbr1_el2" : "=r" (ttbr));

	path_va = (ttbr & 0xffffffffe0) | (va_region_1 << 3);
	INFO("descriptor addr : %llx\n", path_va);
    descriptor = (uint64_t *) path_va;
    path_va = *(uint64_t *) path_va;
	INFO("path va : %llx\n", path_va);
    if (!(path_va & 0x1)) {
        return -1;
    } else {
        if (!(path_va & 0x2)) {
    		*descriptor |= 0x4;
            return 1;
        }
    }

	path_va = (path_va & 0xffffffffe0) | (va_region_2 << 3);
	INFO("descriptor addr : %llx\n", path_va);
    descriptor = (uint64_t *) path_va;
    path_va = *(uint64_t *) path_va;
	INFO("path va 2: %llx\n", path_va);
    if (!(path_va & 0x1)) {
        return -1;
    } else {
        if (!(path_va & 0x2)) {
    		*descriptor |= 0x4;
            return 1;
        }
    }

	path_va = (path_va & 0xffffffffe0) | (va_region_3 << 3);
	INFO("descriptor addr : %llx\n", path_va);
    descriptor = (uint64_t *) path_va;
    path_va = *(uint64_t *)path_va;
	INFO("path va 3: %llx\n", path_va);
    if ((path_va & 0x3) != 0x3) {
        return -1;
    }
    
    *descriptor |= 0x4;

    return 1;
}

uint64_t update_el3_mte(uint64_t va) {
    uint16_t va_region_1, va_region_2, va_region_3;
    uint64_t path_va, ttbr, *descriptor;
    
    va_region_1 = (va >> 30) & 0x3;
    va_region_2 = (va >> 21) & 0x1ff;
    va_region_3 = (va >> 12) & 0x1ff;

    ttbr = read_ttbr0_el3();

	path_va = (ttbr & 0xffffffffe0) | (va_region_1 << 3);
	INFO("descriptor addr : %llx\n", path_va);
    descriptor = (uint64_t *) path_va;
    path_va = *(uint64_t *) path_va;
	INFO("path va : %llx\n", path_va);
    if (!(path_va & 0x1)) {
        return -1;
    } else {
        if (!(path_va & 0x2)) {
    		*descriptor |= 0x4;
            return 1;
        }
    }

	path_va = (path_va & 0xffffffffe0) | (va_region_2 << 3);
	INFO("descriptor addr : %llx\n", path_va);
    descriptor = (uint64_t *) path_va;
    path_va = *(uint64_t *) path_va;
	INFO("path va 2: %llx\n", path_va);
    if (!(path_va & 0x1)) {
        return -1;
    } else {
        if (!(path_va & 0x2)) {
    		*descriptor |= 0x4;
            return 1;
        }
    }

	path_va = (path_va & 0xffffffffe0) | (va_region_3 << 3);
	INFO("descriptor addr : %llx\n", path_va);
    descriptor = (uint64_t *) path_va;
    path_va = *(uint64_t *)path_va;
	INFO("path va 3: %llx\n", path_va);
    if ((path_va & 0x3) != 0x3) {
        return -1;
    }
    
    *descriptor |= 0x4;

    return 1;
}

#define set_tag(tagged_addr) do {                                \
	asm volatile("stg %0, [%0]" : : "r" (tagged_addr) : "memory"); \
} while (0)

uint8_t get_tag(void * addr) {
    asm volatile("ldg %0, [%0]": "+r" ((uint64_t)addr));
    return (uint8_t)((unsigned long)addr >> 56);
}

void setting_tag(uint64_t addr_begin, uint64_t addr_end) {
    uint64_t i;

    INFO("setting : %llx - %llx\n", addr_begin, addr_end);
    for(i = addr_begin; i < addr_end; i += 0x400) {
        set_tag(i);
        asm volatile("dc gva, %0" : : "r"(i) : "memory");
    }
}

void getting_tag(uint64_t addr_begin, uint64_t addr_end) {
    uint64_t i;

    for(i = (addr_begin & 0xffffffff); i < (addr_end & 0xffffffff); i += 0x10) {
        INFO("[%llx] get tag : %x\n", i, get_tag((void *)i));
    }
}

int smc_call_exception(uint64_t sp)
{
	uint32_t *work_ptr_32;

	trap_meta_addr = *(uint64_t *) (sp + CTX_GPREGS_OFFSET + CTX_GPREG_X1);

	if (trap_meta_addr == 0x1)
	{
		write_mdcr_el3(read_mdcr_el3() | MDCR_TPM_BIT);
		modify_ttbr_cnp();
		return 0;
	}

	if (trap_meta_addr == 0x2)
	{
		uint64_t va, pa;
		va = *(uint64_t *) (sp + CTX_GPREGS_OFFSET + CTX_GPREG_X2);
		pa = get_pa_by_va(va);
		INFO("va : %llx, pa: %llx\n", va, pa);
		gpt_set_pas(pa, GPI_ROOT);
		return 0;
	}

	if (trap_meta_addr == 0x3)
	{
		uint64_t va, pa, v, mair_el3, pa_page;
		va = *(uint64_t *) (sp + CTX_GPREGS_OFFSET + CTX_GPREG_X2);
		// INFO("update va : %llx\n", va);
		update_page_table_mte(va);

		__asm__ volatile ("mrs %0, tcr_el3" : "=r" (v));
		__asm__ volatile ("msr tcr_el3, %0" : : "r" (v | ((uint64_t)0b1 << 20)));

		__asm__ volatile ("mrs %0, sctlr_el3" : "=r" (v));
		__asm__ volatile ("msr sctlr_el3, %0" : : "r" (v | ((uint64_t)0b1 << 43)));

		__asm__ volatile ("mrs %0, mair_el3" : "=r" (mair_el3));
		__asm__ volatile ("msr mair_el3, %0" : : "r" ((mair_el3 & (0xffffffffffff00ff)) | (0xf000)));

		pa = get_pa_by_va(va);
		pa_page = pa & 0xfffffffffffff000;
		update_el3_mte(pa);
		pa_page |= 0x0f00000000000000;

    	setting_tag(pa_page, pa_page + 0x1000);

		pa |= 0x0600000000000000;
		set_tag(pa);
		return 0;
	}

	if (trap_meta_addr == 0x4)
	{
		uint64_t tzc_slot1 = 0x2a4a0174;
		work_ptr_32 = (uint32_t *) tzc_slot1;
		*work_ptr_32 &= 0x0000ffff;
    	
		dsbsy();
		tlbipaallos();
		INFO("set tzasc\n");

		return 0;
	}

	return 1; // trap vmalloc
}

int trap_return(uint64_t addr, uint64_t sp) {
	uint32_t *work_ptr_32;
	uint64_t *work_ptr_64, *current_patch_num, trampoline_list[5], patch_list[5], type_list[5], size_list[5];
	uint64_t base_addr, patch_func_num, data_patch_num, patch_base;
	int idx, jdx;

	base_addr = RESERVED_BASE;
	
	current_patch_num = (uint64_t *) base_addr;

	work_ptr_64 = (uint64_t *) get_pa_by_va(trap_meta_addr);
	patch_func_num = (uint64_t)*work_ptr_64;
	work_ptr_64 ++;
	for(idx = 0; idx < patch_func_num; idx++)
	{
		trampoline_list[idx] = *(work_ptr_64++);
		patch_list[idx] = addr;
		size_list[idx] = *(work_ptr_64++);
		type_list[idx] = *(work_ptr_64++);
		patch_base = *(work_ptr_64++);

		my_memcpy((char *) ((uint64_t *) get_pa_by_va(addr)), (char *) ((uint64_t *) get_pa_by_va(patch_base)), size_list[idx]);
		addr += size_list[idx];
	}

	data_patch_num = (uint64_t) *(work_ptr_64++);
	for(idx = 0; idx < data_patch_num; idx++)
	{
		uint64_t *current_data_num, *curren_data_ptr, data_addr, data_size;
		char *char_ptr;

		current_data_num = (uint64_t *) (base_addr + DATA_ADDR_BASE_OFFSET);
		curren_data_ptr = (current_data_num + 1);

		data_addr = get_pa_by_va(*(uint64_t *)work_ptr_64++);
		
		data_size = *(work_ptr_64++);
		char_ptr = (char *) ((uint64_t *) *curren_data_ptr);
		my_memcpy(char_ptr, work_ptr_64, data_size);

		work_ptr_64 = (uint64_t *) (base_addr + DATA_ADDR_BASE_OFFSET + 0x10 + (*current_data_num * 0x8));
		*work_ptr_64 = *curren_data_ptr;
		
		*current_data_num += 1;
		if(data_size % 8 == 0) {
			*curren_data_ptr += (data_size + 0x10);
		} else {
			*curren_data_ptr += (data_size + 0x14);
		}

		if(idx == 0) {		//todo
			gpt_set_pas(data_addr, GPI_ROOT);
			for(int i = 0; i < MAX_CORE_NUM; i++) {
				gpt_2_set_pas(data_addr, GPI_ROOT, i);
			}
			INFO("Set data addr : 0x%016llx to root world\n", data_addr);
			update_page_table_root(data_addr);
		}
	}

	for(idx = 0; idx < patch_func_num; idx++){
		work_ptr_64 = (uint64_t *) (base_addr + PATCH_META_OFFSET + (*current_patch_num * META_STRUCT_SIZE));

		*(work_ptr_64++) = trampoline_list[idx];
		*(work_ptr_64++) = patch_list[idx];
		*(work_ptr_64++) = size_list[idx];
		*(work_ptr_64++) = type_list[idx];

		work_ptr_32 = (uint32_t *)get_pa_by_va(patch_list[idx]);
		if (type_list[idx] == PATCH_TYPE_DELETE)
		{
			for (jdx = 0; jdx < size_list[idx]; jdx += 4) {
				*work_ptr_32 = 0x0;
				work_ptr_32++;
			}
		} else if (type_list[idx] == PATCH_TYPE_FUNCTION){
			for (jdx = 0; jdx < size_list[idx]; jdx += 4)
			{
				if (is_adrp(*work_ptr_32))
				{
					uint64_t offset, des_addr;
					uint32_t immlo_30_29, immhi_23_5;
					
					immlo_30_29 = (*work_ptr_32 >> 29) & 0x3;
					immhi_23_5 = (*work_ptr_32 >> 5) & 0x7ffff;
					offset = ((immhi_23_5 << 2) | immlo_30_29) << 12;
					if (offset & (0x80000000))
					{
						offset |= 0xffffffff00000000;
					}
					
					des_addr = offset + (trampoline_list[idx] & 0xfffffffffffff000);
					offset = (des_addr - (uint64_t)patch_list[idx]) >> 12;

					immlo_30_29 = (offset << 29) & 0x60000000;
					immhi_23_5 = (offset << 3) & 0xffffe0;

					*work_ptr_32 = (*work_ptr_32 & 0x9f00001f) | immlo_30_29 | immhi_23_5;
				}
				work_ptr_32++;
			}
			
			*current_patch_num += 1;

			change_to_kernel_gpt();
			work_ptr_32 = (uint32_t *)get_pa_by_va(trampoline_list[idx]);
			work_ptr_32[0] = 0xd4000003;
			change_to_normal_gpt();
		} else {
			ERROR("patch type undefind\n");
		}
	}
	
	for(idx = 0; idx < patch_func_num; idx++) {
		gpt_set_pas(get_pa_by_va(patch_list[idx]), GPI_ROOT);
	}

	work_ptr_64 = (uint64_t *) (sp + CTX_GPREGS_OFFSET + CTX_GPREG_LR);
	*work_ptr_64 = trap_return_addr;
	return 0;
}

bool is_adrp(uint32_t ins) {
	if (((ins >> 24) & 0x9f) == 0x90)
		return true;
	
	return false;
}

void *my_memcpy(void *dst, const void *src, uint32_t len)
{
	const char *s = src;
	char *d = dst;

	while (len--)
		*d++ = *s++;

	return dst;
}

uint64_t update_page_table_root(uint64_t va) {
    uint16_t va_region_1, va_region_2, va_region_3;
    uint64_t path_va, ttbr, *descriptor;
    
    va_region_1 = (va >> 30) & 0x3;
    va_region_2 = (va >> 21) & 0x1ff;
    va_region_3 = (va >> 12) & 0x1ff;

    ttbr = read_ttbr0_el3();

	path_va = (ttbr & 0xffffffffe0) | (va_region_1 << 3);
    descriptor = (uint64_t *) path_va;
    path_va = *(uint64_t *) path_va;
    if (!(path_va & 0x1)) {
        return -1;
    } else {
        if (!(path_va & 0x2)) {
			uint64_t descriptor_old, descriptor_new;
			descriptor_old = path_va & 0xffffff0000000ffc;
			descriptor_new = (descriptor_old & ~LOW_ATTR_NS) | LOW_ATTR_NG;

			uint64_t page_base, page_level_2;
			page_base = PAGE_TABLE_BASE + (PAGE_TABLE_PAGE_SIZE * sec_num);
			sec_num += 1;
			uint64_t *work_ptr, *work_ptr_2;
			work_ptr = (uint64_t *) page_base;
			for(int i = 0; i < PAGE_TABLE_ITEM_NUM; i++) {
				page_level_2 = PAGE_TABLE_LEVEL2_BASE + (PAGE_TABLE_PAGE_SIZE * level_2_sec_num);
				level_2_sec_num += 1;
				*work_ptr = descriptor_old | (page_level_2 & 0xfffffff000) | 0x3;

				work_ptr_2 = (uint64_t *) page_level_2;
				for(int j = 0; j < PAGE_TABLE_ITEM_NUM; j++) {
					uint64_t phy_addr;
					phy_addr = ((path_va & 0xffffc0000000) | ((i * PAGE_TABLE_OFFSET) + (j * PAGE_TABLE_LEVEL2_OFFSET)));
					if(phy_addr == (va & 0xfffffffffffff000)) {
						*work_ptr_2 = descriptor_new | (phy_addr & 0xfffffff000) | 0x3;
					} else {
						*work_ptr_2 = descriptor_old | (phy_addr & 0xfffffff000) | 0x3;
					}
					work_ptr_2 ++;
				}

				work_ptr ++;
			}
			*descriptor = (*descriptor & 0xffffff0000000ffc) | (page_base & 0xfffffff000) | 0x3;
            return 1;
        }
    }

	path_va = (path_va & 0xffffffffe0) | (va_region_2 << 3);
    descriptor = (uint64_t *) path_va;
    path_va = *(uint64_t *) path_va;
    if (!(path_va & 0x1)) {
        return -1;
    } else {
        if (!(path_va & 0x2)) {
			uint64_t descriptor_old, descriptor_new;
			descriptor_old = path_va & 0xffffff0000000ffc;
			descriptor_new = (descriptor_old & ~LOW_ATTR_NS) | LOW_ATTR_NG;

			uint64_t page_base = PAGE_TABLE_LEVEL2_BASE + (PAGE_TABLE_PAGE_SIZE * level_2_sec_num);
			level_2_sec_num += 1;
			uint64_t *work_ptr;
			work_ptr = (uint64_t *) page_base;
			for(int i = 0x0; i < PAGE_TABLE_ITEM_NUM; i++) {
				uint64_t phy_addr;
				phy_addr = ((path_va & 0xffffffe00000) | (i * PAGE_TABLE_LEVEL2_OFFSET));
				if(phy_addr == (va & 0xfffffffffffff000)) {
					*work_ptr = descriptor_new | (phy_addr & 0xfffffff000) | 0x3;
				} else {
					*work_ptr = descriptor_old | (phy_addr & 0xfffffff000) | 0x3;
				}
				work_ptr ++;
			}
			*descriptor = (*descriptor & 0xffffff0000000ffc) | (page_base & 0xfffffff000) | 0x3;
            return 1;
        }
    }

	path_va = (path_va & 0xffffffffe0) | (va_region_3 << 3);
    path_va = *(uint64_t *)path_va;
    if ((path_va & 0x3) != 0x3) {
        INFO("level 3 table descriptor invalid, pa : 0x%016llx\n", path_va);
        return -1;
    }
    
    uint64_t *desc_ptr = (uint64_t *)path_va;
    *desc_ptr &= ~LOW_ATTR_NS;
	*desc_ptr |= LOW_ATTR_NG;

    return 1;
}

int is_directly_change() {
	u_register_t far_el3, esr_el3, mpidr_el1;
	int cpu_id;

	far_el3 = read_far_el3();
	esr_el3 = read_esr_el3();
	mpidr_el1 = read_mpidr_el1();

	cpu_id = (((mpidr_el1 >> 16) & 0x1) * 4) + ((mpidr_el1 >> 8) & 0xf);

	if (esr_el3 & 0x100000) {				//esr_el3 InD bit[6] 0b0 data access  0b1 Ins access
		if (current_is_gpt_1(cpu_id)) {
			if (!(match_patch_address(far_el3))) {
				ERROR("patch address error! : %lx\n", far_el3);

				return 1;
			}
		} else {
			if (!(match_kernel_text(far_el3))) {
				ERROR("return address error!\n");

				return 1;
			}
		}

		change_gpt(cpu_id);
		return 0;
	}

	return 1;
}

void smc_change_gpt(int patch_number)
{
	int cpu_id;
	u_register_t mpidr_el1, elr_new;
	mpidr_el1 = read_mpidr_el1();
	cpu_id = (((mpidr_el1 >> 16) & 0x1) * 4) + ((mpidr_el1 >> 8) & 0xf);

	if (!current_is_gpt_1(cpu_id)) {
		change_gpt(cpu_id);
	}
	elr_new = *(uint64_t *)(RESERVED_BASE + PATCH_META_OFFSET + PATCH_OFFSET + ((patch_number-1) * META_STRUCT_SIZE));

	write_elr_el3(elr_new);
	change_gpt(cpu_id);
	return;
}

void smc_set_krpobe(uint64_t addr, uint32_t insn) {
	uint32_t *ptr;

	change_to_kernel_gpt();
	ptr = (uint32_t *) addr;
	*ptr = insn;
	change_to_normal_gpt();
	
	return;
}

void pmu_trap_handler() {
	INFO("get a pmu trap");
}
int count = 0;
void catch_gpc_exception(uint64_t sp)
{
	uint64_t data_phy_addr, data_patch_addr;
	u_register_t far_el3, mpidr_el1, elr_el3;
	int cpu_id;

	far_el3 = read_far_el3();
	elr_el3 = read_elr_el3();
	mpidr_el1 = read_mpidr_el1();
	// INFO("Data access GPF: [%lx]\n", far_el3);

	cpu_id = (((mpidr_el1 >> 16) & 0x1) * 4) + ((mpidr_el1 >> 8) & 0xf);
	data_phy_addr = get_pa_by_va(far_el3);
	// data_patch_addr = match_data_address(data_phy_addr);
	gpt_set_pas(data_phy_addr, GPI_NS);
	data_patch_addr = 0x1;
	uint32_t ins_str = 0x0;
	ins_str = *(uint32_t *) get_pa_by_va(elr_el3);

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
				ERROR("1 Data ins type other : %x  \nfar_el3 : 0x%016lx\n\n", ins_str, far_el3);
				break;
		}
	} else {
		ERROR("Data access GPF!\n");
	}
	gpt_set_pas(data_phy_addr, GPI_ROOT);
	count++;
	INFO("count : %d\n", count);
	write_elr_el3(elr_el3 + 0x4);
}


int proxy_ldr(uint32_t ins, uint64_t regs, int64_t data_addr) {
	uint32_t n, t;
	int64_t *xt, offset;
	bool write_back = false;

	t = ins & 0x1f;

	xt = (int64_t *) (regs + (t * 0x8));
	
	if ((ins >> 30) & 0x1) {
		int64_t data;
		data = *(int64_t *) data_addr;
		
		if (!(ins & ((1 << 24) | (1 << 21)))) {
			if (ins & (1 << 10)) {			//ldtr and ldur
				write_back = true;
				offset = (ins >> 12) & 0x1ff;
				if (offset >> 8) {
					offset |= 0xfffffffffffffe00;
				}
			}
		}
		*xt = data;
	} else {
		int32_t data;
		data = *(int32_t *) data_addr;

		if (!(ins & ((1 << 24) | (1 << 21)))) {
			if (ins & (1 << 10)) {			//ldtr and ldur
				write_back = true;
				offset = (ins >> 12) & 0x1ff;
				if (offset >> 8) {
					offset |= 0xfffffffffffffe00;
				}
			}
		}
		*xt = (data & 0xffffffff);
	}

	if(write_back) {
		int64_t *xn_ptr;

		n = (ins >> 5) & 0x1f;
		xn_ptr = (int64_t *) (regs + (n * 0x8));
		*xn_ptr += offset;
	}

	return 0;
}

int proxy_ldrb(uint32_t ins, uint64_t regs, int64_t data_addr) {
	uint32_t n, t;
	int64_t *xt, offset;
	bool write_back = false;
	int8_t data;

	t = ins & 0x1f;

	xt = (int64_t *) (regs + (t * 0x8));
	data = *(int8_t *) data_addr;
	

	if (!(ins & ((1 << 24) | (1 << 21)))) {
		write_back = true;
		offset = (ins >> 12) & 0x1ff;
		if (offset >> 8) {
			offset |= 0xfffffffffffffe00;
		}
	}
	*xt = (data & 0xffffffff);

	if(write_back) {
		int64_t *xn_ptr;

		n = (ins >> 5) & 0x1f;
		xn_ptr = (int64_t *) (regs + (n * 0x8));
		*xn_ptr += offset;
	}

	return 0;
}

int proxy_ldrh(uint32_t ins, uint64_t regs, int64_t data_addr) {
	uint32_t n, t;
	int64_t *xt, offset;
	bool write_back = false;
	int16_t data;

	t = ins & 0x1f;

	xt = (int64_t *) (regs + (t * 0x8));
	data = *(int16_t *) data_addr;

	if (!(ins & ((1 << 24) | (1 << 21)))) {
		write_back = true;
		offset = (ins >> 12) & 0x1ff;
		if (offset >> 8) {
			offset |= 0xfffffffffffffe00;
		}
	}
	*xt = (data & 0xffffffff);

	if(write_back) {
		int64_t *xn_ptr;

		n = (ins >> 5) & 0x1f;
		xn_ptr = (int64_t *) (regs + (n * 0x8));
		*xn_ptr += offset;
	}

	return 0;
}
						
int proxy_ldp(uint32_t ins, uint64_t regs, int64_t data_addr) {
	uint32_t n, t, t2;
	int64_t *xt, *xt2, offset;
	bool write_back = false;

	t2 = (ins >> 10) & 0x1f;
	t = ins & 0x1f;

	xt = (int64_t *) (regs + (t * 0x8));
	xt2 = (int64_t *) (regs + (t2 * 0x8));
	
	if ((ins >> 31) & 0x1) {
		int64_t data, data2;
		data = *(int64_t *) data_addr;
		data2 = *(int64_t *) (data_addr + 0x8);

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
		data = *(int64_t *) data_addr;
		data2 = *(int64_t *) (data_addr + 0x8);

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
		int64_t *xn_ptr;

		n = (ins >> 5) & 0x1f;
		xn_ptr = (int64_t *) (regs + (n * 0x8));
		*xn_ptr += offset;
	}

	return 0;
}

int proxy_str(uint32_t ins, uint64_t regs, int64_t data_addr) {
	uint32_t n, t;
	int64_t *xt, offset, xzr = 0;
	bool write_back = false;

	t = ins & 0x1f;

	if (t == 31) {
		xt = (int64_t *) &xzr;
	} else {
		xt = (int64_t *) (regs + (t * 0x8));
	}
	
	if ((ins >> 30) & 0x1) {			//64-bit variant
		int64_t *write_byte;
		write_byte = (int64_t *) data_addr;
		*write_byte = *xt;

		if (!(ins & ((1 << 24) | (1 << 21)))) {
			if (ins & (1 << 10)) {			//sttr and stur
				write_back = true;
				offset = (ins >> 12) & 0x1ff;
				if (offset >> 8) {
					offset |= 0xfffffffffffffe00;
				}
			}
		}
	} else {
		int32_t *write_byte;		//32-bit variant
		write_byte = (int32_t *) data_addr;
		*write_byte = *xt;

		if (!(ins & ((1 << 24) | (1 << 21)))) {
			if (ins & (1 << 10)) {			//sttr and stur
				write_back = true;
				offset = (ins >> 12) & 0x1ff;
				if (offset >> 8) {
					offset |= 0xfffffffffffffe00;
				}
			}
		}
	}
	
	if(write_back) {
		int64_t *xn_ptr;

		n = (ins >> 5) & 0x1f;
		xn_ptr = (int64_t *) (regs + (n * 0x8));
		*xn_ptr += offset;
	}

	return 0;
}

int proxy_strb(uint32_t ins, uint64_t regs, int64_t data_addr) {
	uint32_t n, t;
	int64_t *xt, offset, xzr = 0;
	bool write_back = false;
	int8_t *write_byte;

	t = ins & 0x1f;

	if (t == 31) {
		xt = (int64_t *) &xzr;
	} else {
		xt = (int64_t *) (regs + (t * 0x8));
	}

	write_byte = (int8_t *) data_addr;
	*write_byte = *xt;

	if (!(ins & ((1 << 24) | (1 << 21)))) {
		write_back = true;
		offset = (ins >> 12) & 0x1ff;
		if (offset >> 8) {
			offset |= 0xfffffffffffffe00;
		}
	}
	
	if(write_back) {
		int64_t *xn_ptr;

		n = (ins >> 5) & 0x1f;
		xn_ptr = (int64_t *) (regs + (n * 0x8));
		*xn_ptr += offset;
	}

	return 0;
}

int proxy_strh(uint32_t ins, uint64_t regs, int64_t data_addr) {
	uint32_t n, t;
	int64_t *xt, offset, xzr = 0;
	bool write_back = false;
	int16_t *write_byte;

	t = ins & 0x1f;

	if (t == 31) {
		xt = (int64_t *) &xzr;
	} else {
		xt = (int64_t *) (regs + (t * 0x8));
	}

	write_byte = (int16_t *) data_addr;
	*write_byte = *xt;

	if (!(ins & ((1 << 24) | (1 << 21)))) {
		write_back = true;
		offset = (ins >> 12) & 0x1ff;
		if (offset >> 8) {
			offset |= 0xfffffffffffffe00;
		}
	}
	
	if(write_back) {
		int64_t *xn_ptr;

		n = (ins >> 5) & 0x1f;
		xn_ptr = (int64_t *) (regs + (n * 0x8));
		*xn_ptr += offset;
	}

	return 0;
}

int proxy_stp(uint32_t ins, uint64_t regs, int64_t data_addr) {
	uint32_t n, t, t2;
	int64_t *xt, *xt2, offset, xzr = 0;
	bool write_back = false;

	t2 = (ins >> 10) & 0x1f;
	t = ins & 0x1f;

	if (t == 31) {
		xt = (int64_t *) &xzr;
	} else {
		xt = (int64_t *) (regs + (t * 0x8));
	}

	if (t2 == 31) {
		xt2 = (int64_t *) &xzr;
	} else {
		xt2 = (int64_t *) (regs + (t * 0x8));
	}
	
	if ((ins >> 30) & 0x1) {			//64-bit variant
		int64_t *write_byte;
		write_byte = (int64_t *) data_addr;
		*write_byte = *xt;
		write_byte += 1;
		*write_byte = *xt2;


		if (!(ins & ((1 << 24) | (1 << 21)))) {
			if (ins & (1 << 10)) {			//sttr and stur
				write_back = true;
				offset = (ins >> 12) & 0x1ff;
				if (offset >> 8) {
					offset |= 0xfffffffffffffe00;
				}
			}
		}
	} else {
		int32_t *write_byte;		//32-bit variant
		write_byte = (int32_t *) data_addr;
		*write_byte = *xt;
		write_byte += 1;
		*write_byte = *xt2;

		if (!(ins & ((1 << 24) | (1 << 21)))) {
			if (ins & (1 << 10)) {			//sttr and stur
				write_back = true;
				offset = (ins >> 12) & 0x1ff;
				if (offset >> 8) {
					offset |= 0xfffffffffffffe00;
				}
			}
		}
	}
	
	if(write_back) {
		int64_t *xn_ptr;

		n = (ins >> 5) & 0x1f;
		xn_ptr = (int64_t *) (regs + (n * 0x8));
		*xn_ptr += offset;
	}

	return 0;
}

int data_ldrb(uint32_t ins, uint64_t sp, int64_t data_addr, int64_t data_patch_addr, int cpu_id) {
	uint32_t n, t;
	int64_t xn = 0, *xt, offset;
	bool write_back = false;

	n = (ins >> 5) & 0x1f;
	t = ins & 0x1f;

	xt = (int64_t *) (sp + CTX_GPREGS_OFFSET + CTX_GPF_OFFSET + (t * 0x8));

	int8_t data;
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
			switch (((read_spsr_el3() >> 2) & 0b11)) {
				case 0: {
					int64_t *xn_ptr;
					xn_ptr = (int64_t *) (sp + CTX_GPREGS_OFFSET + CTX_GPF_OFFSET + (n * 0x8));
					*xn_ptr += offset;
					break;
				}

				case 1:
					__asm__ volatile ("mrs %0, sp_el1": "=r" (xn));
					__asm__ volatile ("msr sp_el1, %0" : : "r" (xn + offset));
					break;

				case 2:
					__asm__ volatile ("mrs %0, sp_el2": "=r" (xn));
					__asm__ volatile ("msr sp_el2, %0" : : "r" (xn + offset));
					break;

				default:
					ERROR("spsr el error!\n");
			}
		} else {
			int64_t *xn_ptr;
			xn_ptr = (int64_t *) (sp + CTX_GPREGS_OFFSET + CTX_GPF_OFFSET + (n * 0x8));
			*xn_ptr += offset;
		}
	}

	return 0;
}

int data_ldrh(uint32_t ins, uint64_t sp, int64_t data_addr, int64_t data_patch_addr, int cpu_id) {
	uint32_t n, t;
	int64_t xn = 0, *xt, offset;
	bool write_back = false;

	n = (ins >> 5) & 0x1f;
	t = ins & 0x1f;

	xt = (int64_t *) (sp + CTX_GPREGS_OFFSET + CTX_GPF_OFFSET + (t * 0x8));

	int16_t data;
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
			switch (((read_spsr_el3() >> 2) & 0b11)) {
				case 0: {
					int64_t *xn_ptr;
					xn_ptr = (int64_t *) (sp + CTX_GPREGS_OFFSET + CTX_GPF_OFFSET + (n * 0x8));
					*xn_ptr += offset;
					break;
				}

				case 1:
					__asm__ volatile ("mrs %0, sp_el1": "=r" (xn));
					__asm__ volatile ("msr sp_el1, %0" : : "r" (xn + offset));
					break;

				case 2:
					__asm__ volatile ("mrs %0, sp_el2": "=r" (xn));
					__asm__ volatile ("msr sp_el2, %0" : : "r" (xn + offset));
					break;

				default:
					ERROR("spsr el error!\n");
			}
		} else {
			int64_t *xn_ptr;
			xn_ptr = (int64_t *) (sp + CTX_GPREGS_OFFSET + CTX_GPF_OFFSET + (n * 0x8));
			*xn_ptr += offset;
		}
	}

	return 0;
}

int data_ldrsw(uint32_t ins, uint64_t sp, int64_t data_addr, int64_t data_patch_addr, int cpu_id) {
	uint32_t n, t;
	int64_t xn = 0, *xt, offset;
	bool write_back = false;

	n = (ins >> 5) & 0x1f;
	t = ins & 0x1f;

	xt = (int64_t *) (sp + CTX_GPREGS_OFFSET + CTX_GPF_OFFSET + (t * 0x8));

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
	*xt = data;

	if(write_back) {
		if (n == 31) {
			switch (((read_spsr_el3() >> 2) & 0b11)) {
				case 0: {
					int64_t *xn_ptr;
					xn_ptr = (int64_t *) (sp + CTX_GPREGS_OFFSET + CTX_GPF_OFFSET + (n * 0x8));
					*xn_ptr += offset;
					break;
				}

				case 1:
					__asm__ volatile ("mrs %0, sp_el1": "=r" (xn));
					__asm__ volatile ("msr sp_el1, %0" : : "r" (xn + offset));
					break;

				case 2:
					__asm__ volatile ("mrs %0, sp_el2": "=r" (xn));
					__asm__ volatile ("msr sp_el2, %0" : : "r" (xn + offset));
					break;

				default:
					ERROR("spsr el error!\n");
			}
		} else {
			int64_t *xn_ptr;
			xn_ptr = (int64_t *) (sp + CTX_GPREGS_OFFSET + CTX_GPF_OFFSET + (n * 0x8));
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

	xt = (int64_t *) (sp + CTX_GPREGS_OFFSET + CTX_GPF_OFFSET + (t * 0x8));
	xt2 = (int64_t *) (sp + CTX_GPREGS_OFFSET + CTX_GPF_OFFSET + (t2 * 0x8));
	
	if ((ins >> 31) & 0x1) {
		int64_t data, data2;
		if(data_patch_addr == 0x1) {
			data = *(int64_t *) data_addr;
			data2 = *(int64_t *) (data_addr + 0x8);
		} else {
			ERROR("handle ldp\n");
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
			ERROR("handle ldp\n");
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
			switch (((read_spsr_el3() >> 2) & 0b11)) {
				case 0:{
					int64_t *xn_ptr;
					xn_ptr = (int64_t *) (sp + CTX_GPREGS_OFFSET + CTX_GPF_OFFSET + (n * 0x8));
					*xn_ptr += offset;
					break;
				}

				case 1:
					__asm__ volatile ("mrs %0, sp_el1": "=r" (xn));
					__asm__ volatile ("msr sp_el1, %0" : : "r" (xn + offset));
					break;

				case 2:
					__asm__ volatile ("mrs %0, sp_el2": "=r" (xn));
					__asm__ volatile ("msr sp_el2, %0" : : "r" (xn + offset));
					break;

				default:
					ERROR("spsr el error!\n");
			}
		} else {
			int64_t *xn_ptr;
			xn_ptr = (int64_t *) (sp + CTX_GPREGS_OFFSET + CTX_GPF_OFFSET + (n * 0x8));
			*xn_ptr += offset;
		}
	}

	return 0;
}

int data_ldr(uint32_t ins, uint64_t sp, int64_t data_addr, int64_t data_patch_addr, int cpu_id) {
	uint32_t n, t;
	int64_t xn = 0, *xt, offset;
	bool write_back = false;

	t = ins & 0x1f;

	xt = (int64_t *) (sp + CTX_GPREGS_OFFSET + CTX_GPF_OFFSET + (t * 0x8));
	
	if ((ins >> 30) & 0x1) {
		int64_t data;
		if(data_patch_addr == 0x1) {
			data = *(int64_t *) data_addr;
		} else {
			data = *(int64_t *) data_patch_addr;
		}
		
		if (!(ins & ((1 << 24) | (1 << 21)))) {
			if (ins & (1 << 10)) {			//ldtr and ldur
				write_back = true;
				offset = (ins >> 12) & 0x1ff;
				if (offset >> 8) {
					offset |= 0xfffffffffffffe00;
				}
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
			if (ins & (1 << 10)) {			//ldtr and ldur
				write_back = true;
				offset = (ins >> 12) & 0x1ff;
				if (offset >> 8) {
					offset |= 0xfffffffffffffe00;
				}
			}
		}
		*xt = (data & 0xffffffff);
	}

	if(write_back) {
		n = (ins >> 5) & 0x1f;
		if (n == 31) {
			switch (((read_spsr_el3() >> 2) & 0b11)) {
				case 0:{
					__asm__ volatile ("mrs %0, sp_el0": "=r" (xn));
					__asm__ volatile ("msr sp_el0, %0" : : "r" (xn + offset));
					// int64_t *xn_ptr;
					// xn_ptr = (int64_t *) (sp + CTX_GPREGS_OFFSET + CTX_GPF_OFFSET + (n * 0x8));
					// *xn_ptr += offset;
					break;
				}

				case 1:
					__asm__ volatile ("mrs %0, sp_el1": "=r" (xn));
					__asm__ volatile ("msr sp_el1, %0" : : "r" (xn + offset));
					break;

				case 2:
					__asm__ volatile ("mrs %0, sp_el2": "=r" (xn));
					__asm__ volatile ("msr sp_el2, %0" : : "r" (xn + offset));
					break;

				default:
					ERROR("spsr el error!\n");
			}
		} else {
			int64_t *xn_ptr;
			xn_ptr = (int64_t *) (sp + CTX_GPREGS_OFFSET + CTX_GPF_OFFSET + (n * 0x8));
			*xn_ptr += offset;
		}
	}

	return 0;
}

int data_ldxr(uint32_t ins, uint64_t sp, int64_t data_addr, int64_t data_patch_addr, int cpu_id) {
	uint32_t t;
	int64_t *xt;

	t = ins & 0x1f;
	xt = (int64_t *) (sp + CTX_GPREGS_OFFSET + CTX_GPF_OFFSET + (t * 0x8));
	
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

int data_stxr(uint32_t ins, uint64_t sp, int64_t data_addr, int64_t data_patch_addr, int cpu_id) {
	uint32_t t, s;
	int64_t *xt, *xs;

	t = ins & 0x1f;
	s = (ins >> 16) & 0x1f;
	xt = (int64_t *) (sp + CTX_GPREGS_OFFSET + CTX_GPF_OFFSET + (t * 0x8));
	xs = (int64_t *) (sp + CTX_GPREGS_OFFSET + CTX_GPF_OFFSET + (s * 0x8));
	
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

int data_str(uint32_t ins, uint64_t sp, int64_t data_addr, int64_t data_patch_addr, int cpu_id) {
	uint32_t n, t;
	int64_t xn = 0, *xt, offset, xzr = 0;
	bool write_back = false;

	t = ins & 0x1f;

	if (t == 31) {
		xt = (int64_t *) &xzr;
	} else {
		xt = (int64_t *) (sp + CTX_GPREGS_OFFSET + CTX_GPF_OFFSET + (t * 0x8));
	}
	
	if ((ins >> 30) & 0x1) {			//64-bit variant
		int64_t *write_byte;
		if(data_patch_addr == 0x1) {
			write_byte = (int64_t *) data_addr;
			*write_byte = *xt;
		} else {
			ERROR("write patch data\n");
		}

		if (!(ins & ((1 << 24) | (1 << 21)))) {
			if (ins & (1 << 10)) {			//sttr and stur
				write_back = true;
				offset = (ins >> 12) & 0x1ff;
				if (offset >> 8) {
					offset |= 0xfffffffffffffe00;
				}
			}
		}
	} else {
		int32_t *write_byte;		//32-bit variant
		if(data_patch_addr == 0x1) {
			write_byte = (int32_t *) data_addr;
			*write_byte = *xt;
		} else {
			ERROR("write patch data\n");
		}

		if (!(ins & ((1 << 24) | (1 << 21)))) {
			if (ins & (1 << 10)) {			//sttr and stur
				write_back = true;
				offset = (ins >> 12) & 0x1ff;
				if (offset >> 8) {
					offset |= 0xfffffffffffffe00;
				}
			}
		}
	}
	
	if(write_back) {
		n = (ins >> 5) & 0x1f;
		if (n == 31) {
			switch (((read_spsr_el3() >> 2) & 0b11)) {
				case 0:{
					int64_t *xn_ptr;
					xn_ptr = (int64_t *) (sp + CTX_GPREGS_OFFSET + CTX_GPF_OFFSET + (n * 0x8));
					*xn_ptr += offset;
					break;
				}

				case 1:
					__asm__ volatile ("msr sp_el1, %0" : : "r" (xn + offset));
					break;

				case 2:
					__asm__ volatile ("msr sp_el2, %0" : : "r" (xn + offset));
					break;

				default:
					ERROR("spsr el error!\n");
			}
		} else {
			int64_t *xn_ptr;
			xn_ptr = (int64_t *) (sp + CTX_GPREGS_OFFSET + CTX_GPF_OFFSET + (n * 0x8));
			*xn_ptr += offset;
		}
	}

	return 0;
}

int match_patch_address(uint64_t va) {
	uint64_t *patch_num, trampoline_addr;
	patch_num = (uint64_t *) RESERVED_BASE;

	for (int i = 0; i < *patch_num; i++)
	{
		trampoline_addr = *(uint64_t *)(RESERVED_BASE + PATCH_META_OFFSET + PATCH_OFFSET + (i * META_STRUCT_SIZE));
		if ((trampoline_addr & 0xfffffffffffff000) == (va & 0xfffffffffffff000))
		{
			return 1;
		}
	}

	return 0;
}

uint64_t match_data_address(uint64_t addr) {
	uint64_t *data_num, *data_addr;
	data_num = (uint64_t *) (RESERVED_BASE + DATA_ADDR_BASE_OFFSET);
	data_addr = (uint64_t *) (RESERVED_BASE + DATA_ADDR_BASE_OFFSET + 0x10);
	for (int i = 0; i < *data_num; i++)
	{
		uint64_t *data_patch_addr;
		data_patch_addr = (uint64_t *) *data_addr;
		if ((*data_patch_addr & 0xfffffffffffff000) == (addr & 0xfffffffffffff000))
		{
			for (int j = i; j < *data_num; j++) {
				if(*data_patch_addr == addr) {
					return (uint64_t) (data_patch_addr + 1);
				}
				data_addr += 1;
				data_patch_addr = (uint64_t *) *data_addr;
			}

			return 1;		// data in old place.
		}

		data_addr += 1;
	}

	return 0;
}

uint64_t get_proxy_data(uint64_t addr) {
	uint64_t *data_num, *data_addr;
	data_num = (uint64_t *) (RESERVED_BASE + DATA_ADDR_BASE_OFFSET);
	data_addr = (uint64_t *) (RESERVED_BASE + DATA_ADDR_BASE_OFFSET + 0x10);
	for (int i = 0; i < *data_num; i++)
	{
		uint64_t *data_patch_addr;
		data_patch_addr = (uint64_t *) *data_addr;
		if ((*data_patch_addr & 0xf0ffffffffffffff) == (addr & 0xf0ffffffffffffff))	//mask tag
		{
			if(((*data_patch_addr >> 56) & 0xf) == ((addr >> 56) & 0xf)) {
				return (uint64_t) (data_patch_addr + 1);
			}

			INFO("tag check failed\n");
			return 0;
		}

		data_addr += 1;
	}

	return 0;
}

int match_kernel_text(uint64_t addr) {
	if (addr >= KERNEL_INS_VA_BASE && addr < KERNEL_INS_VA_END)
	{
		return 1;
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

	if ((ins & 0xbe800000) == 0xb8000000)		//str
	{
		if ((ins & 0x1008c1f) == 0x1f) {
			switch ((ins >> 12) & 0x7) {
				case 0b011:
					if ((ins >> 22) & 0x1) {
						return INS_TYPE_STSETL;
					} else {
						return INS_TYPE_STSET;
					}
				
				case 0b001:
					if ((ins >> 22) & 0x1) {
						return INS_TYPE_STCLRL;
					} else {
						return INS_TYPE_STCLR;
					}

				default:
					ERROR("st atomic option error : %x\n", ins);
					return -1;
			}
		} else {
			return INS_TYPE_STR;
		}
	}

	if ((ins & 0xfec00000) == 0x38000000)		//strb
	{
		return INS_TYPE_STRB;	
	}

	if ((ins & 0xfec00000) == 0x78000000)		//strh
	{
		return INS_TYPE_STRH;	
	}

	if ((ins & 0x7e400000) == 0x28000000)		//stp
	{
		return INS_TYPE_STP;	
	}

	return 0;
}

uint64_t get_pa_by_va(uint64_t va) {
	__asm__ volatile ("AT S1E2R, %0" : : "r" (va));

	return (read_par_el1() & 0xfffffffff000) | (va & 0xfff);
}

uint64_t get_pa_page_by_va(uint64_t va) {
	__asm__ volatile ("AT S1E2R, %0" : : "r" (va));

	return (read_par_el1() & 0xfffffffff000);
}

void log_switch(uint64_t num) {
	INFO("Patch function executed %lld times\n", num);
	return;
}

void get_pmu_count() {
	uint64_t count_1, count_2, count_3, count_4, count_5, count_6;

    INFO("get count\n");
    __asm__ volatile ("mrs %0, PMEVCNTR0_EL0": "=r" (count_1));
    __asm__ volatile ("mrs %0, PMEVCNTR1_EL0": "=r" (count_2));
    __asm__ volatile ("mrs %0, PMEVCNTR2_EL0": "=r" (count_3));
    __asm__ volatile ("mrs %0, PMEVCNTR3_EL0": "=r" (count_4));
    __asm__ volatile ("mrs %0, PMEVCNTR4_EL0": "=r" (count_5));
    __asm__ volatile ("mrs %0, PMCCNTR_EL0": "=r" (count_6));
    INFO("el3 result : 0: %lld, 1: %lld, 2: %lld, 3: %lld, 4: %lld, 5: %lld\n", count_1, count_2, count_3, count_4, count_5, count_6);
}
