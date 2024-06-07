/*-------------------------------------------------------------------------
 *
 * Copyright (c) 2017, Microchip Technology Inc. and its subsidiaries ("Microchip")
 * All rights reserved.
 *
 * This software is developed by Microchip Technology Inc. and its
 * subsidiaries ("Microchip").
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1.      Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 * 2.      Redistributions in binary form must reproduce the above
 *         copyright notice, this list of conditions and the following
 *         disclaimer in the documentation and/or other materials provided
 *         with the distribution. Publication is not required when this 
 *         file is used in an embedded application.
 * 3.      Microchip's name may not be used to endorse or promote products
 *         derived from this software without specific prior written
 *         permission.
 *
 * THIS SOFTWARE IS PROVIDED BY MICROCHIP "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL MICROCHIP BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING BUT NOT LIMITED TO
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWSOEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *-------------------------------------------------------------------------*/        
#include <xc.h>
#include <cp0defs.h>

        .weak _dinit_addr

        .section        .text,code
        .align          2
        .local  __dummy_decode_dinit
        .set nomips16
#if defined(__mips_micromips) || defined(__USE_MICROMIPS)
        .set micromips
#else
        .set nomicromips
#endif
        .ent    __dummy_decode_dinit
        .type   __dummy_decode_dinit, @function
__dummy_decode_dinit:
        .set    noreorder
        .set    nomacro
        jr       $31
        nop
        .end    __dummy_decode_dinit
.LFE0:
        .size   __dummy_decode_dinit, .-__dummy_decode_dinit
        .weak   __dinit_copy
        __dinit_copy            = __dummy_decode_dinit
        .weak   __dinit_clear
        __dinit_clear           = __dummy_decode_dinit
        .weak   __dinit_copy_emb
        __dinit_copy_emb        = __dummy_decode_dinit
        .weak   __dinit_copy_val_data
        __dinit_copy_val_data   = __dummy_decode_dinit
        .weak   __dinit_decompress
        __dinit_decompress      = __dummy_decode_dinit

        .section	.rodata,code
        .align	2
        .type	_dinit_func_table, @object
        .size	_dinit_func_table, 20
_dinit_func_table:
        .word	__dinit_clear
        .word	__dinit_copy
        .word	__dinit_copy_emb
        .word	__dinit_copy_val_data
        .word	__dinit_decompress

#define save_ra v1

        .section	.text,code
        .align  	2
        .globl	__pic32_data_init

        .set noreorder
        .set noat
        .set nomips16
#if defined(__mips_micromips) || defined(__USE_MICROMIPS)
        .set micromips
#else
        .set nomicromips
#endif


        .ent	__pic32_data_init
        .type	__pic32_data_init, @function

__pic32_data_init:
        move save_ra,ra

#define INIT_DATA
#if defined(INIT_DATA)
        ##################################################################
        # Initialize data using the linker-generated .dinit table
        ##################################################################
        .equiv FMT_CLEAR,0
        .equiv FMT_COPY,1
        .equiv FMT_COPY_VAL_EMB,2
        .equiv FMT_COPY_VAL_DATA,3
        .equiv FMT_COMPRESSED,4
_dinit_init:
        la      a0,_dinit_addr
	/*workaround for .ramfunc instruction cache coherency issue - JLG */
	li      t4, 0xA0000000
        or      a0, a0, t4
#define SRC a0
#define DST a1
#define LEN a2
#define FMT t3
        beq     SRC,$0,9f
        nop
0:      lw      DST,0(SRC)
	/*workaround for .ramfunc instruction cache coherency issue - JLG*/
	li      t4, 0xA0000000
        or      DST, DST, t4
	
        beqz    DST,9f
        addu    SRC,4
        lw      LEN,0(SRC)
        addu    SRC,4
        lh      FMT,0(SRC)

        addu    SRC,4

        lui	t4,%hi(_dinit_func_table)
        addiu	t4,t4,%lo(_dinit_func_table)
        sll	FMT,FMT, 2	
        addu	t4,FMT,t4	
        lw	t4,0(t4)	

        jalr t4
        nop

        move    SRC, v0

        addu    SRC,3
        addiu   LEN,$0,-4
        and     SRC,LEN,SRC
        lw      DST,0(SRC)
        bne     DST,$0,0b
        nop
9:
#endif
        move ra, save_ra
        jr ra
        nop
        .set	macro
        .set	reorder
        .end	__pic32_data_init
        .size	__pic32_data_init, .-__pic32_data_init
