/*
 * Copyright (c) 2021, Arm Limited. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef GPT_H
#define GPT_H

#include <stdint.h>

#include <arch.h>

#include "gpt_defs.h"

#define GPT_DESC_ATTRS(_type, _gpi)		\
	((((_type) & PAS_REG_DESC_TYPE_MASK)	\
	  << PAS_REG_DESC_TYPE_SHIFT) |		\
	(((_gpi) & PAS_REG_GPI_MASK)		\
	 << PAS_REG_GPI_SHIFT))

/*
 * Macro to create a GPT entry for this PAS range either as a L0 block
 * descriptor or L1 table descriptor depending upon the size of the range.
 */
#define MAP_GPT_REGION(_pa, _sz, _gpi)					\
	{								\
		.base_pa = (_pa),					\
		.size = (_sz),						\
		.attrs = GPT_DESC_ATTRS(PAS_REG_DESC_TYPE_ANY, (_gpi)),	\
	}

/*
 * Special macro to create a L1 table descriptor at L0 for a 1GB region as
 * opposed to creating a block mapping by default.
 */
#define MAP_GPT_REGION_TBL(_pa, _sz, _gpi)				\
	{								\
		.base_pa = (_pa),					\
		.size = (_sz),						\
		.attrs = GPT_DESC_ATTRS(PAS_REG_DESC_TYPE_TBL, (_gpi)),	\
	}

#define PAGE_TABLE_BASE				0xfff00000
#define PAGE_TABLE_OFFSET			0x200000
#define PAGE_TABLE_LEVEL2_BASE		0xfff50000
#define PAGE_TABLE_LEVEL2_OFFSET	0x1000
#define PAGE_TABLE_ITEM_NUM			0x200
#define PAGE_TABLE_PAGE_SIZE		0x1000

#define META_STRUCT_SIZE 			0x20
#define PATCH_META_OFFSET 			0x10
#define TRAMPOLINE_OFFSET 			0x0
#define PATCH_OFFSET 				0x8
#define SIZE_OFFSET 				0x10
#define TYPE_OFFSET 				0x18

#define PATCH_BASE_OFFSET 			0x200
#define DATA_ADDR_BASE_OFFSET 		0x8000
#define DATA_ADDR_SIZE 				0x8
#define DATA_META_OFFSET 			0xa0
#define DATA_BASE_OFFSET 			0x200

#define HIGH_ATTR_PXN				(0xffdfffffffffffff)
#define LOW_ATTR_ADDR_INDEX_4		ULL(1 << 4)
#define LOW_ATTR_ADDR_INDEX_3		~(ULL(1 << 3))
#define LOW_ATTR_ADDR_INDEX_2		~(ULL(1 << 2))

#define LOW_ATTR_NS					(ULL(1 << 5))
#define LOW_ATTR_NG					(ULL(1 << 11))

#define MAX_PATCH_NUM 10

#define PATCH_TYPE_FUNCTION 	0x1
#define PATCH_TYPE_DELETE 		0x2
// #define PATCH_TYPE_FUNC			0x2
// #define PATCH_TYPE_FUNC			0x3

// #define INS_GET_BIT_LDR
#define INS_TYPE_LDRB				0x1
#define INS_TYPE_LDP				0X2
#define INS_TYPE_LDR				0X3
#define INS_TYPE_LDRH				0X4
#define INS_TYPE_LDXR				0X5
#define INS_TYPE_LDRSW				0X6

#define INS_TYPE_STRB				0X11
#define INS_TYPE_STP				0X12
#define INS_TYPE_STR				0X13
#define INS_TYPE_STRH				0X14
#define INS_TYPE_STSET				0X15
#define INS_TYPE_STSETL				0X16
#define INS_TYPE_STCLR				0X17
#define INS_TYPE_STCLRL				0X18
#define INS_TYPE_STXR				0X19

// typedef struct patch_meta {
// 	unsigned long long	base_pa;
// 	size_t				size;
// 	unsigned int 		type;
// 	unsigned long long	associated_base_pa;
// } patch_meta_t;

// extern patch_meta_t patch_lists[MAX_PATCH_NUM];
// extern int patch_num;
extern uint64_t phys_va_base;

/*
 * Structure for specifying a Granule range and its properties
 */
typedef struct pas_region {
	unsigned long long	base_pa;	/**< Base address for PAS. */
	size_t			size;		/**< Size of the PAS. */
	unsigned int		attrs;		/**< PAS GPI and entry type. */
} pas_region_t;

/*
 * Structure to initialise the Granule Protection Tables.
 */
typedef struct gpt_init_params {
	unsigned int pgs;	/**< Address Width of Phisical Granule Size. */
	unsigned int pps;	/**< Protected Physical Address Size.	     */
	unsigned int l0gptsz;	/**< Granule size on L0 table entry.	     */
	pas_region_t *pas_regions; /**< PAS regions to protect.		     */
	unsigned int pas_count;	/**< Number of PAS regions to initialise.    */
	uintptr_t l0_mem_base;	/**< L0 Table base address.		     */
	size_t l0_mem_size;	/**< Size of memory reserved for L0 tables.  */
	uintptr_t l1_mem_base;	/**< L1 Table base address.		     */
	size_t l1_mem_size;	/**< Size of memory reserved for L1 tables.  */
} gpt_init_params_t;

/** @brief Initialise the Granule Protection tables.
 */
int gpt_init(gpt_init_params_t *params);

int gpt_2_init(gpt_init_params_t *params, int cpu_id);

/** @brief Enable the Granule Protection Checks.
 */
void gpt_enable(void);

/** @brief Disable the Granule Protection Checks.
 */
void gpt_disable(void);

/** @brief Transition a granule between security states.
 */
int gpt_transition_pas(uint64_t pa,
			unsigned int src_sec_state,
			unsigned int target_pas);

int gpt_set_pas(uint64_t pa, unsigned int attrs);
int gpt_2_set_pas(uint64_t pa, unsigned int attrs, int cpu_id);

void change_gpt(int cpu_id);
void change_to_kernel_gpt();
void change_to_normal_gpt();

void modify_ttbr_cnp();
void modify_sctlr();
void modify_hcr_ata();
void modify_tco();

void print_gpt();

bool current_is_gpt_1(int cpu_id);
#endif /* GPT_H */
