
/workspace/research/tmp/current-fcma-codegen-20261004/bin/codegen-probe:	file format mach-o arm64

Disassembly of section __TEXT,__text:

0000000100000de8 <_neon_update>:
100000de8:     	sub	sp, sp, #0x20
100000dec:     	stp	x29, x30, [sp, #0x10]
100000df0:     	add	x29, sp, #0x10
100000df4:     	str	x1, [sp, #0x8]
100000df8:     	cmp	x1, #0x800
100000dfc:     	b.ne	0x100000f44 <_neon_update+0x15c>
100000e00:     	str	x3, [sp, #0x8]
100000e04:     	cmp	x3, #0x800
100000e08:     	b.ne	0x100000f64 <_neon_update+0x17c>
100000e0c:     	str	x5, [sp, #0x8]
100000e10:     	cmp	x5, #0x400
100000e14:     	b.ne	0x100000f84 <_neon_update+0x19c>
100000e18:     	mov	x8, #0x0                ; =0
100000e1c:     	add	x9, x2, #0x8
100000e20:     	adrp	x10, 0x100037000 <GCC_except_table392+0x4>
100000e24:     	ldr	q0, [x10, #0xd00]
100000e28:     	tbz	w6, #0x0, 0x100000eb0 <_neon_update+0xc8>
100000e2c:     	lsl	x10, x8, #4
100000e30:     	ldr	q1, [x4, x10]
100000e34:     	mov	d2, v1[1]
100000e38:     	mov.d	v2[1], v1[0]
100000e3c:     	add	x8, x8, #0x1
100000e40:     	ldp	d3, d4, [x9, #-0x8]
100000e44:     	dup.2d	v4, v4[0]
100000e48:     	eor.16b	v4, v4, v0
100000e4c:     	fmul.2d	v2, v4, v2
100000e50:     	fmla.2d	v2, v1, v3[0]
100000e54:     	str	q2, [x0, x10]
100000e58:     	add	x9, x9, #0x10
100000e5c:     	cmp	x8, #0x400
100000e60:     	b.ne	0x100000e2c <_neon_update+0x44>
100000e64:     	mov	x8, #0x0                ; =0
100000e68:     	add	x9, x0, #0x4, lsl #12   ; =0x4000
100000e6c:     	mov	w10, #0x4008            ; =16392
100000e70:     	add	x10, x2, x10
100000e74:     	lsl	x11, x8, #4
100000e78:     	ldr	q1, [x4, x11]
100000e7c:     	mov	d2, v1[1]
100000e80:     	mov.d	v2[1], v1[0]
100000e84:     	add	x8, x8, #0x1
100000e88:     	ldp	d3, d4, [x10, #-0x8]
100000e8c:     	dup.2d	v4, v4[0]
100000e90:     	eor.16b	v4, v4, v0
100000e94:     	fmul.2d	v2, v4, v2
100000e98:     	fmla.2d	v2, v1, v3[0]
100000e9c:     	str	q2, [x9, x11]
100000ea0:     	add	x10, x10, #0x10
100000ea4:     	cmp	x8, #0x400
100000ea8:     	b.ne	0x100000e74 <_neon_update+0x8c>
100000eac:     	b	0x100000f38 <_neon_update+0x150>
100000eb0:     	lsl	x10, x8, #4
100000eb4:     	ldr	q1, [x4, x10]
100000eb8:     	ldr	q2, [x0, x10]
100000ebc:     	mov	d3, v1[1]
100000ec0:     	mov.d	v3[1], v1[0]
100000ec4:     	add	x8, x8, #0x1
100000ec8:     	ldp	d4, d5, [x9, #-0x8]
100000ecc:     	dup.2d	v5, v5[0]
100000ed0:     	eor.16b	v5, v5, v0
100000ed4:     	fmla.2d	v2, v3, v5
100000ed8:     	fmla.2d	v2, v1, v4[0]
100000edc:     	str	q2, [x0, x10]
100000ee0:     	add	x9, x9, #0x10
100000ee4:     	cmp	x8, #0x400
100000ee8:     	b.ne	0x100000eb0 <_neon_update+0xc8>
100000eec:     	mov	x8, #0x0                ; =0
100000ef0:     	add	x9, x0, #0x4, lsl #12   ; =0x4000
100000ef4:     	mov	w10, #0x4008            ; =16392
100000ef8:     	add	x10, x2, x10
100000efc:     	lsl	x11, x8, #4
100000f00:     	ldr	q1, [x4, x11]
100000f04:     	ldr	q2, [x9, x11]
100000f08:     	mov	d3, v1[1]
100000f0c:     	mov.d	v3[1], v1[0]
100000f10:     	add	x8, x8, #0x1
100000f14:     	ldp	d4, d5, [x10, #-0x8]
100000f18:     	dup.2d	v5, v5[0]
100000f1c:     	eor.16b	v5, v5, v0
100000f20:     	fmla.2d	v2, v3, v5
100000f24:     	fmla.2d	v2, v1, v4[0]
100000f28:     	str	q2, [x9, x11]
100000f2c:     	add	x10, x10, #0x10
100000f30:     	cmp	x8, #0x400
100000f34:     	b.ne	0x100000efc <_neon_update+0x114>
100000f38:     	ldp	x29, x30, [sp, #0x10]
100000f3c:     	add	sp, sp, #0x20
100000f40:     	ret
100000f44:     	adrp	x2, 0x100037000 <GCC_except_table392+0x4>
100000f48:     	add	x2, x2, #0xd10
100000f4c:     	adrp	x5, 0x100048000 <dyld_stub_binder+0x100048000>
100000f50:     	add	x5, x5, #0x60
100000f54:     	add	x1, sp, #0x8
100000f58:     	mov	w0, #0x0                ; =0
100000f5c:     	mov	x3, #0x0                ; =0
100000f60:     	bl	0x100035f78 <__RINvNtCsedRpiqSkYaQ_4core9panicking13assert_failedjjEB4_>
100000f64:     	adrp	x2, 0x100037000 <GCC_except_table392+0x4>
100000f68:     	add	x2, x2, #0xd10
100000f6c:     	adrp	x5, 0x100048000 <dyld_stub_binder+0x100048000>
100000f70:     	add	x5, x5, #0x48
100000f74:     	add	x1, sp, #0x8
100000f78:     	mov	w0, #0x0                ; =0
100000f7c:     	mov	x3, #0x0                ; =0
100000f80:     	bl	0x100035f78 <__RINvNtCsedRpiqSkYaQ_4core9panicking13assert_failedjjEB4_>
100000f84:     	adrp	x2, 0x100037000 <GCC_except_table392+0x4>
100000f88:     	add	x2, x2, #0xd18
100000f8c:     	adrp	x5, 0x100048000 <dyld_stub_binder+0x100048000>
100000f90:     	add	x5, x5, #0x30
100000f94:     	add	x1, sp, #0x8
100000f98:     	mov	w0, #0x0                ; =0
100000f9c:     	mov	x3, #0x0                ; =0
100000fa0:     	bl	0x100035f78 <__RINvNtCsedRpiqSkYaQ_4core9panicking13assert_failedjjEB4_>
