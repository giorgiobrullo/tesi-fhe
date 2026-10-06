
/workspace/research/tmp/current-fcma-public-gate-20261004/bin/public-gate:	file format mach-o arm64

Disassembly of section __TEXT,__text:

00000001000034bc <_neon_update>:
1000034bc:     	sub	sp, sp, #0x20
1000034c0:     	stp	x29, x30, [sp, #0x10]
1000034c4:     	add	x29, sp, #0x10
1000034c8:     	str	x1, [sp, #0x8]
1000034cc:     	cmp	x1, #0x800
1000034d0:     	b.ne	0x100003618 <_neon_update+0x15c>
1000034d4:     	str	x3, [sp, #0x8]
1000034d8:     	cmp	x3, #0x800
1000034dc:     	b.ne	0x100003638 <_neon_update+0x17c>
1000034e0:     	str	x5, [sp, #0x8]
1000034e4:     	cmp	x5, #0x400
1000034e8:     	b.ne	0x100003658 <_neon_update+0x19c>
1000034ec:     	mov	x8, #0x0                ; =0
1000034f0:     	add	x9, x2, #0x8
1000034f4:     	adrp	x10, 0x100039000 <__RNvNtNtCskP2HG43Jt7g_3std6thread7current12init_current+0x98>
1000034f8:     	ldr	q0, [x10, #0xf80]
1000034fc:     	tbz	w6, #0x0, 0x100003584 <_neon_update+0xc8>
100003500:     	lsl	x10, x8, #4
100003504:     	ldr	q1, [x4, x10]
100003508:     	mov	d2, v1[1]
10000350c:     	mov.d	v2[1], v1[0]
100003510:     	add	x8, x8, #0x1
100003514:     	ldp	d3, d4, [x9, #-0x8]
100003518:     	dup.2d	v4, v4[0]
10000351c:     	eor.16b	v4, v4, v0
100003520:     	fmul.2d	v2, v4, v2
100003524:     	fmla.2d	v2, v1, v3[0]
100003528:     	str	q2, [x0, x10]
10000352c:     	add	x9, x9, #0x10
100003530:     	cmp	x8, #0x400
100003534:     	b.ne	0x100003500 <_neon_update+0x44>
100003538:     	mov	x8, #0x0                ; =0
10000353c:     	add	x9, x0, #0x4, lsl #12   ; =0x4000
100003540:     	mov	w10, #0x4008            ; =16392
100003544:     	add	x10, x2, x10
100003548:     	lsl	x11, x8, #4
10000354c:     	ldr	q1, [x4, x11]
100003550:     	mov	d2, v1[1]
100003554:     	mov.d	v2[1], v1[0]
100003558:     	add	x8, x8, #0x1
10000355c:     	ldp	d3, d4, [x10, #-0x8]
100003560:     	dup.2d	v4, v4[0]
100003564:     	eor.16b	v4, v4, v0
100003568:     	fmul.2d	v2, v4, v2
10000356c:     	fmla.2d	v2, v1, v3[0]
100003570:     	str	q2, [x9, x11]
100003574:     	add	x10, x10, #0x10
100003578:     	cmp	x8, #0x400
10000357c:     	b.ne	0x100003548 <_neon_update+0x8c>
100003580:     	b	0x10000360c <_neon_update+0x150>
100003584:     	lsl	x10, x8, #4
100003588:     	ldr	q1, [x4, x10]
10000358c:     	ldr	q2, [x0, x10]
100003590:     	mov	d3, v1[1]
100003594:     	mov.d	v3[1], v1[0]
100003598:     	add	x8, x8, #0x1
10000359c:     	ldp	d4, d5, [x9, #-0x8]
1000035a0:     	dup.2d	v5, v5[0]
1000035a4:     	eor.16b	v5, v5, v0
1000035a8:     	fmla.2d	v2, v3, v5
1000035ac:     	fmla.2d	v2, v1, v4[0]
1000035b0:     	str	q2, [x0, x10]
1000035b4:     	add	x9, x9, #0x10
1000035b8:     	cmp	x8, #0x400
1000035bc:     	b.ne	0x100003584 <_neon_update+0xc8>
1000035c0:     	mov	x8, #0x0                ; =0
1000035c4:     	add	x9, x0, #0x4, lsl #12   ; =0x4000
1000035c8:     	mov	w10, #0x4008            ; =16392
1000035cc:     	add	x10, x2, x10
1000035d0:     	lsl	x11, x8, #4
1000035d4:     	ldr	q1, [x4, x11]
1000035d8:     	ldr	q2, [x9, x11]
1000035dc:     	mov	d3, v1[1]
1000035e0:     	mov.d	v3[1], v1[0]
1000035e4:     	add	x8, x8, #0x1
1000035e8:     	ldp	d4, d5, [x10, #-0x8]
1000035ec:     	dup.2d	v5, v5[0]
1000035f0:     	eor.16b	v5, v5, v0
1000035f4:     	fmla.2d	v2, v3, v5
1000035f8:     	fmla.2d	v2, v1, v4[0]
1000035fc:     	str	q2, [x9, x11]
100003600:     	add	x10, x10, #0x10
100003604:     	cmp	x8, #0x400
100003608:     	b.ne	0x1000035d0 <_neon_update+0x114>
10000360c:     	ldp	x29, x30, [sp, #0x10]
100003610:     	add	sp, sp, #0x20
100003614:     	ret
100003618:     	adrp	x2, 0x10003a000 <dyld_stub_binder+0x10003a000>
10000361c:     	add	x2, x2, #0x208
100003620:     	adrp	x5, 0x10004c000 <dyld_stub_binder+0x10004c000>
100003624:     	add	x5, x5, #0x168
100003628:     	add	x1, sp, #0x8
10000362c:     	mov	w0, #0x0                ; =0
100003630:     	mov	x3, #0x0                ; =0
100003634:     	bl	0x100039450 <__RINvNtCsedRpiqSkYaQ_4core9panicking13assert_failedjjEB4_>
100003638:     	adrp	x2, 0x10003a000 <dyld_stub_binder+0x10003a000>
10000363c:     	add	x2, x2, #0x208
100003640:     	adrp	x5, 0x10004c000 <dyld_stub_binder+0x10004c000>
100003644:     	add	x5, x5, #0x150
100003648:     	add	x1, sp, #0x8
10000364c:     	mov	w0, #0x0                ; =0
100003650:     	mov	x3, #0x0                ; =0
100003654:     	bl	0x100039450 <__RINvNtCsedRpiqSkYaQ_4core9panicking13assert_failedjjEB4_>
100003658:     	adrp	x2, 0x10003a000 <dyld_stub_binder+0x10003a000>
10000365c:     	add	x2, x2, #0x210
100003660:     	adrp	x5, 0x10004c000 <dyld_stub_binder+0x10004c000>
100003664:     	add	x5, x5, #0x138
100003668:     	add	x1, sp, #0x8
10000366c:     	mov	w0, #0x0                ; =0
100003670:     	mov	x3, #0x0                ; =0
100003674:     	bl	0x100039450 <__RINvNtCsedRpiqSkYaQ_4core9panicking13assert_failedjjEB4_>
