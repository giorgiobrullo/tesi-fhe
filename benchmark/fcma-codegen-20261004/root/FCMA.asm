
/workspace/research/tmp/current-fcma-codegen-20261004/bin/codegen-probe:	file format mach-o arm64

Disassembly of section __TEXT,__text:

0000000100000c98 <_fcma_update>:
100000c98:     	sub	sp, sp, #0x20
100000c9c:     	stp	x29, x30, [sp, #0x10]
100000ca0:     	add	x29, sp, #0x10
100000ca4:     	str	x1, [sp, #0x8]
100000ca8:     	cmp	x1, #0x800
100000cac:     	b.ne	0x100000d88 <_fcma_update+0xf0>
100000cb0:     	str	x3, [sp, #0x8]
100000cb4:     	cmp	x3, #0x800
100000cb8:     	b.ne	0x100000da8 <_fcma_update+0x110>
100000cbc:     	str	x5, [sp, #0x8]
100000cc0:     	cmp	x5, #0x400
100000cc4:     	b.ne	0x100000dc8 <_fcma_update+0x130>
100000cc8:     	mov	x8, #0x0                ; =0
100000ccc:     	tbz	w6, #0x0, 0x100000d28 <_fcma_update+0x90>
100000cd0:     	ldr	q0, [x2, x8]
100000cd4:     	ldr	q1, [x4, x8]
100000cd8:     	movi.2d	v2, #0000000000000000
100000cdc:     	fcmla.2d	v2, v0, v1, #0
100000ce0:     	fcmla.2d	v2, v0, v1, #90
100000ce4:     	str	q2, [x0, x8]
100000ce8:     	add	x8, x8, #0x10
100000cec:     	cmp	x8, #0x4, lsl #12       ; =0x4000
100000cf0:     	b.ne	0x100000cd0 <_fcma_update+0x38>
100000cf4:     	mov	x8, #0x0                ; =0
100000cf8:     	add	x9, x0, #0x4, lsl #12   ; =0x4000
100000cfc:     	add	x10, x2, #0x4, lsl #12  ; =0x4000
100000d00:     	ldr	q0, [x10, x8]
100000d04:     	ldr	q1, [x4, x8]
100000d08:     	movi.2d	v2, #0000000000000000
100000d0c:     	fcmla.2d	v2, v0, v1, #0
100000d10:     	fcmla.2d	v2, v0, v1, #90
100000d14:     	str	q2, [x9, x8]
100000d18:     	add	x8, x8, #0x10
100000d1c:     	cmp	x8, #0x4, lsl #12       ; =0x4000
100000d20:     	b.ne	0x100000d00 <_fcma_update+0x68>
100000d24:     	b	0x100000d7c <_fcma_update+0xe4>
100000d28:     	ldr	q0, [x0, x8]
100000d2c:     	ldr	q1, [x2, x8]
100000d30:     	ldr	q2, [x4, x8]
100000d34:     	fcmla.2d	v0, v1, v2, #0
100000d38:     	fcmla.2d	v0, v1, v2, #90
100000d3c:     	str	q0, [x0, x8]
100000d40:     	add	x8, x8, #0x10
100000d44:     	cmp	x8, #0x4, lsl #12       ; =0x4000
100000d48:     	b.ne	0x100000d28 <_fcma_update+0x90>
100000d4c:     	mov	x8, #0x0                ; =0
100000d50:     	add	x9, x0, #0x4, lsl #12   ; =0x4000
100000d54:     	add	x10, x2, #0x4, lsl #12  ; =0x4000
100000d58:     	ldr	q0, [x9, x8]
100000d5c:     	ldr	q1, [x10, x8]
100000d60:     	ldr	q2, [x4, x8]
100000d64:     	fcmla.2d	v0, v1, v2, #0
100000d68:     	fcmla.2d	v0, v1, v2, #90
100000d6c:     	str	q0, [x9, x8]
100000d70:     	add	x8, x8, #0x10
100000d74:     	cmp	x8, #0x4, lsl #12       ; =0x4000
100000d78:     	b.ne	0x100000d58 <_fcma_update+0xc0>
100000d7c:     	ldp	x29, x30, [sp, #0x10]
100000d80:     	add	sp, sp, #0x20
100000d84:     	ret
100000d88:     	adrp	x2, 0x100037000 <GCC_except_table392+0x4>
100000d8c:     	add	x2, x2, #0xd10
100000d90:     	adrp	x5, 0x100048000 <dyld_stub_binder+0x100048000>
100000d94:     	add	x5, x5, #0x60
100000d98:     	add	x1, sp, #0x8
100000d9c:     	mov	w0, #0x0                ; =0
100000da0:     	mov	x3, #0x0                ; =0
100000da4:     	bl	0x100035f78 <__RINvNtCsedRpiqSkYaQ_4core9panicking13assert_failedjjEB4_>
100000da8:     	adrp	x2, 0x100037000 <GCC_except_table392+0x4>
100000dac:     	add	x2, x2, #0xd10
100000db0:     	adrp	x5, 0x100048000 <dyld_stub_binder+0x100048000>
100000db4:     	add	x5, x5, #0x48
100000db8:     	add	x1, sp, #0x8
100000dbc:     	mov	w0, #0x0                ; =0
100000dc0:     	mov	x3, #0x0                ; =0
100000dc4:     	bl	0x100035f78 <__RINvNtCsedRpiqSkYaQ_4core9panicking13assert_failedjjEB4_>
100000dc8:     	adrp	x2, 0x100037000 <GCC_except_table392+0x4>
100000dcc:     	add	x2, x2, #0xd18
100000dd0:     	adrp	x5, 0x100048000 <dyld_stub_binder+0x100048000>
100000dd4:     	add	x5, x5, #0x30
100000dd8:     	add	x1, sp, #0x8
100000ddc:     	mov	w0, #0x0                ; =0
100000de0:     	mov	x3, #0x0                ; =0
100000de4:     	bl	0x100035f78 <__RINvNtCsedRpiqSkYaQ_4core9panicking13assert_failedjjEB4_>
