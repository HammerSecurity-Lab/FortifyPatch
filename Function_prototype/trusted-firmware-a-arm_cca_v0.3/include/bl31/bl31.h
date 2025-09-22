/*
 * Copyright (c) 2013-2019, ARM Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef BL31_H
#define BL31_H

#include <stdint.h>
#include <lib/xlat_tables/xlat_tables_v2.h>

/*******************************************************************************
 * Function prototypes
 ******************************************************************************/
void bl31_setup(u_register_t arg0, u_register_t arg1, u_register_t arg2,
		u_register_t arg3);
void bl31_next_el_arch_setup(uint32_t security_state);
void bl31_set_next_image_type(uint32_t security_state);
uint32_t bl31_get_next_image_type(void);
void bl31_prepare_next_image_entry(void);
void bl31_register_bl32_init(int32_t (*func)(void));
void bl31_warm_entrypoint(void);
void bl31_main(void);
void bl31_lib_init(void);

int set_level0_translate_path_by_va(uint64_t va, int cpu_id);
int set_level1_translate_path_by_va(uint64_t va, uint64_t ttbr, int cpu_id);
int match_patch_address(uint64_t addr);
uint64_t match_data_address(uint64_t addr);
uint64_t match_trampoline_address(uint64_t addr);
int match_kernel_text(uint64_t addr);
uint64_t get_pa_page_by_va(uint64_t va);
uint64_t get_pa_by_va(uint64_t va);
int64_t get_pa_by_va_signed(int64_t va);
int set_gpt_2_by_va(uint64_t va, int cpu_id);
uint64_t get_ipa_by_descriptor(uint64_t desc, uint16_t va_region, int cpu_id);

uint64_t set_memory_to_rw_by_level1(uint64_t va);
uint64_t set_descriptor(uint64_t desc, uint16_t va_region);

uint64_t pagetable_walk(uint64_t va);
uint64_t get_descriptor(uint64_t desc, uint16_t va_region);

uint64_t update_page_table_root(uint64_t va);
uint64_t update_page_table_ns(uint64_t va);
// uint64_t descriptor_32(uint64_t desc);

void *my_memcpy(void *dst, const void *src, uint32_t len);
int match_special_instruction(uint32_t ins);

bool is_adrp(uint32_t ins);

uint64_t get_proxy_data(uint64_t addr);

int proxy_ldr (uint32_t ins, uint64_t regs, int64_t data_addr);
int proxy_ldrb(uint32_t ins, uint64_t regs, int64_t data_addr);
int proxy_ldrh(uint32_t ins, uint64_t regs, int64_t data_addr);
int proxy_ldp (uint32_t ins, uint64_t regs, int64_t data_addr);

int proxy_str (uint32_t ins, uint64_t regs, int64_t data_addr);
int proxy_strb(uint32_t ins, uint64_t regs, int64_t data_addr);
int proxy_strh(uint32_t ins, uint64_t regs, int64_t data_addr);
int proxy_stp (uint32_t ins, uint64_t regs, int64_t data_addr);
// int proxy_stp(uint32_t ins, uint64_t sp);
// int proxy_str(uint32_t ins, uint64_t sp);
// int proxy_stset(uint32_t ins, uint64_t sp);
// int proxy_stclr(uint32_t ins, uint64_t sp);
int data_stxr(uint32_t ins, uint64_t sp, int64_t data_addr, int64_t data_patch_addr, int cpu_id);
int data_str(uint32_t ins, uint64_t sp, int64_t data_addr, int64_t data_patch_addr, int cpu_id);

int data_ldr(uint32_t ins, uint64_t sp, int64_t data_phy_addr, int64_t data_patch_addr, int cpu_id);
int data_ldxr(uint32_t ins, uint64_t sp, int64_t data_phy_addr, int64_t data_patch_addr, int cpu_id);
int data_ldrh(uint32_t ins, uint64_t sp, int64_t data_phy_addr, int64_t data_patch_addr, int cpu_id);
int data_ldrsw(uint32_t ins, uint64_t sp, int64_t data_phy_addr, int64_t data_patch_addr, int cpu_id);
int data_ldrb(uint32_t ins, uint64_t sp, int64_t data_phy_addr, int64_t data_patch_addr, int cpu_id);
int data_ldp(uint32_t ins, uint64_t sp, int64_t data_phy_addr, int64_t data_patch_addr, int cpu_id);

void get_pmu_count();
#endif /* BL31_H */
