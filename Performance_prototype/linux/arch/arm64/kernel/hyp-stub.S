/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Hypervisor stub
 *
 * Copyright (C) 2012 ARM Ltd.
 * Author:	Marc Zyngier <marc.zyngier@arm.com>
 */

#include <linux/init.h>
#include <linux/linkage.h>
#include <linux/irqchip/arm-gic-v3.h>

#include <asm/assembler.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_asm.h>
#include <asm/ptrace.h>
#include <asm/virt.h>

	.text
	.pushsection	.hyp.text, "ax"

	.align 11

ENTRY(__hyp_stub_vectors)
	ventry	el2_sync_invalid		// Synchronous EL2t
	ventry	el2_irq_invalid			// IRQ EL2t
	ventry	el2_fiq_invalid			// FIQ EL2t
	ventry	el2_error_invalid		// Error EL2t

	ventry	el2_sync_invalid		// Synchronous EL2h
	ventry	el2_irq_invalid			// IRQ EL2h
	ventry	el2_fiq_invalid			// FIQ EL2h
	ventry	el2_error_invalid		// Error EL2h

	ventry	el1_sync				// Synchronous 64-bit EL1
	ventry	el1_irq_invalid			// IRQ 64-bit EL1
	ventry	el1_fiq_invalid			// FIQ 64-bit EL1
	ventry	el1_error_invalid		// Error 64-bit EL1

	ventry	el1_sync_invalid		// Synchronous 32-bit EL1
	ventry	el1_irq_invalid			// IRQ 32-bit EL1
	ventry	el1_fiq_invalid			// FIQ 32-bit EL1
	ventry	el1_error_invalid		// Error 32-bit EL1
ENDPROC(__hyp_stub_vectors)

	.align 11

save_register:
	stp	x0, x1, [sp, #0x0]
	stp	x2, x3, [sp, #0x10]
	stp	x4, x5, [sp, #0x20]
	stp	x6, x7, [sp, #0x30]
	stp	x8, x9, [sp, #0x40]
	stp	x10, x11, [sp, #0x50]
	stp	x12, x13, [sp, #0x60]
	stp	x14, x15, [sp, #0x70]
	stp	x16, x17, [sp, #0x80]
	stp	x18, x19, [sp, #0x90]
	stp	x20, x21, [sp, #0xa0]
	stp	x22, x23, [sp, #0xb0]
	stp	x24, x25, [sp, #0xc0]
	stp	x26, x27, [sp, #0xd0]
	stp	x28, x29, [sp, #0xe0]

	ret
ENDPROC(save_register)

restore_register:
	ldp	x0, x1, [sp, #0x0]
	ldp	x2, x3, [sp, #0x10]
	ldp	x4, x5, [sp, #0x20]
	ldp	x6, x7, [sp, #0x30]
	ldp	x8, x9, [sp, #0x40]
	ldp	x10, x11, [sp, #0x50]
	ldp	x12, x13, [sp, #0x60]
	ldp	x14, x15, [sp, #0x70]
	ldp	x16, x17, [sp, #0x80]
	ldp	x18, x19, [sp, #0x90]
	ldp	x20, x21, [sp, #0xa0]
	ldp	x22, x23, [sp, #0xb0]
	ldp	x24, x25, [sp, #0xc0]
	ldp	x26, x27, [sp, #0xd0]
	ldp	x28, x29, [sp, #0xe0]

	ret
ENDPROC(restore_register)

el1_sync:
	dsb	sy
	msr	daifclr, #4
	isb
	dmb	sy

1:
	str x30, [sp, #0xf0]

	ldr x30, =0xff0f0000
	cmp x0, x30
	b.eq kernel_map_detect

	mrs 	x30, esr_el2
	ubfx	x30, x30, #ESR_ELx_EC_SHIFT, #6		//length

	cmp x30, #ESR_ELx_EC_IABT_LOW			//el2 : ins : 100000   data : 100100
	b.eq ins_handler

	cmp x30, #ESR_ELx_EC_DABT_LOW
	b.eq data_handler 

	cmp x30, #ESR_ELx_EC_HVC64
	b.eq hvc_handler

	b el2_exit

ins_handler:
	stp	x0, x1, [sp, #0x0]
	stp	x2, x3, [sp, #0x10]
	stp	x4, x5, [sp, #0x20]

	bl is_directly_change
	cmp x0, #4
	b.ne change_return

	b el2_exit

change_return:
	tlbi alle1

	ldr x1, =0x321d5000
	add x1, x1, x0, lsl #3
	ldr x2, [x1]
	add x2, x2, #1
	str x2, [x1]

	ldp	x0, x1, [sp, #0x0]
	ldp	x2, x3, [sp, #0x10]
	ldp	x4, x5, [sp, #0x20]

	ldr x30, [sp, #0xf0]
	
	isb
	eret
	dsb	nsh
	isb

data_handler:
	bl save_register

	mov x0, sp
	bl data_proxy

	ldr x1, =0x321d5100
	add x1, x1, x0, lsl #3
	ldr x2, [x1]
	add x2, x2, #1
	str x2, [x1]

	b el2_exit

hvc_handler:
	stp	x0, x1, [sp, 0x0]
	stp	x2, x3, [sp, 0x10]
	stp	x4, x5, [sp, 0x20]
	stp	x6, x7, [sp, 0x30]
	
	mrs x0, elr_el2
	sub x5, x0, #4

	mov x0, 0x32000000
	mov x1, #0x10
	add x3, x0, x1
	ldr x2, [x0]
	
	mov	x0, #0x0
loop_cmp:
	cmp	x2, x0
	b.eq other_hvc

	add	x0, x0, #0x1

	ldr x4, [x3], #0x20
	cmp x4, x5
	b.ne loop_cmp

	bl hvc_change_ttbr

	tlbi alle1
	
	ldr x1, =0x321d5020
	add x1, x1, x0, lsl #3
	ldr x2, [x1]
	add x2, x2, #1
	str x2, [x1]

	ldp	x0, x1, [sp, 0x0]
	ldp	x2, x3, [sp, 0x10]
	ldp	x4, x5, [sp, 0x20]
	ldp	x6, x7, [sp, 0x30]
	ldr	x30, [sp, 0xf0]

	isb
	eret
other_hvc:
	ldr	x0, [sp, 0x0]
	mov x1, 0xfe0f0000
	cmp x0, x1

	b.ne normal_hvc

	ldp	x0, x1, [sp, 0x8]
	bl hvc_set_krpobe


	ldp	x0, x1, [sp, 0x0]
	ldp	x2, x3, [sp, 0x10]
	ldp	x4, x5, [sp, 0x20]
	ldp	x6, x7, [sp, 0x30]
	ldr	x30, [sp, 0xf0]

	isb
	eret
normal_hvc:
	ldp	x0, x1, [sp, 0x0]
	ldp	x2, x3, [sp, 0x10]
	ldp	x4, x5, [sp, 0x20]
	ldp	x6, x7, [sp, 0x30]

	bl save_register

	mov x0, 0x1
	cmp x1, x0
	b.ne patch_hvc

	mov x0, x2
	bl handler_hvc_1
	str x0, [sp]
	tlbi alle1

	b el2_exit

patch_hvc:
	ldp	x0, x1, [sp, 0x0]
	mov x0, x1
	bl handler_hvc_2
	str x0, [sp]
	tlbi alle1

	b el2_exit

kernel_map_detect:
	stp	x0, x1, [sp, 0x0]
	stp	x2, x3, [sp, 0x10]
	stp	x4, x5, [sp, 0x20]
	
	ldr x1, =0x321d5228
	ldr x0, [x1]
	cmp x0, #10
	b.hs execute_detect
	add x0, x0, #1
	str x0, [x1]
	b detect_exit

execute_detect:
	ldr x0, =0x0
	str x0, [x1]
	bl detect_kernel_map

	ldr x1, =0x321d5230
	ldr x0, [x1]
	add x0, x0, #1
	str x0, [x1]

detect_exit:
	ldp	x0, x1, [sp, 0x0]
	ldp	x2, x3, [sp, 0x10]
	ldp	x4, x5, [sp, 0x20]
	ldr x30, [sp, #0xf0]
	isb
	eret

data_p:
	mov x0, sp
	bl data_patch
	tlbi alle1

	b el2_exit

el2_exit:
	bl restore_register
	ldr x30, [sp, #0xf0]
	isb
	eret

93:
	mrs x0, hcr_el2
	mov x1, sp
	mrs x2, mpidr_el1
	mrs x3, mdcr_el2
	ldr x4, =0x123456fab

	ldr	x30, [sp, 0xf0]
	isb
	eret
ENDPROC(el1_sync)

.macro invalid_vector	label
\label:
	b \label
ENDPROC(\label)
.endm

	invalid_vector	el2_sync_invalid
	invalid_vector	el2_irq_invalid
	invalid_vector	el2_fiq_invalid
	invalid_vector	el2_error_invalid
	invalid_vector	el1_sync_invalid
	invalid_vector	el1_irq_invalid
	invalid_vector	el1_fiq_invalid
	invalid_vector	el1_error_invalid

/*
 * __hyp_set_vectors: Call this after boot to set the initial hypervisor
 * vectors as part of hypervisor installation.  On an SMP system, this should
 * be called on each CPU.
 *
 * x0 must be the physical address of the new vector table, and must be
 * 2KB aligned.
 *
 * Before calling this, you must check that the stub hypervisor is installed
 * everywhere, by waiting for any secondary CPUs to be brought up and then
 * checking that is_hyp_mode_available() is true.
 *
 * If not, there is a pre-existing hypervisor, some CPUs failed to boot, or
 * something else went wrong... in such cases, trying to install a new
 * hypervisor is unlikely to work as desired.
 *
 * When you call into your shiny new hypervisor, sp_el2 will contain junk,
 * so you will need to set that to something sensible at the new hypervisor's
 * initialisation entry point.
 */

ENTRY(__hyp_set_vectors)
	mov	x1, x0
	mov	x0, #HVC_SET_VECTORS
	hvc	#0
	ret
ENDPROC(__hyp_set_vectors)

ENTRY(__hyp_reset_vectors)
	mov	x0, #HVC_RESET_VECTORS
	hvc	#0
	ret
ENDPROC(__hyp_reset_vectors)
