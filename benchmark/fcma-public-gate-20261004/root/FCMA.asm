
/workspace/research/tmp/current-fcma-public-gate-20261004/bin/public-gate:	file format mach-o arm64

Disassembly of section __TEXT,__text:

000000010000336c <_fcma_update>:
10000336c:     	sub	sp, sp, #0x20
100003370:     	stp	x29, x30, [sp, #0x10]
100003374:     	add	x29, sp, #0x10
100003378:     	str	x1, [sp, #0x8]
10000337c:     	cmp	x1, #0x800
100003380:     	b.ne	0x10000345c <_fcma_update+0xf0>
100003384:     	str	x3, [sp, #0x8]
100003388:     	cmp	x3, #0x800
10000338c:     	b.ne	0x10000347c <_fcma_update+0x110>
100003390:     	str	x5, [sp, #0x8]
100003394:     	cmp	x5, #0x400
100003398:     	b.ne	0x10000349c <_fcma_update+0x130>
10000339c:     	mov	x8, #0x0                ; =0
1000033a0:     	tbz	w6, #0x0, 0x1000033fc <_fcma_update+0x90>
1000033a4:     	ldr	q0, [x2, x8]
1000033a8:     	ldr	q1, [x4, x8]
1000033ac:     	movi.2d	v2, #0000000000000000
1000033b0:     	fcmla.2d	v2, v0, v1, #0
1000033b4:     	fcmla.2d	v2, v0, v1, #90
1000033b8:     	str	q2, [x0, x8]
1000033bc:     	add	x8, x8, #0x10
1000033c0:     	cmp	x8, #0x4, lsl #12       ; =0x4000
1000033c4:     	b.ne	0x1000033a4 <_fcma_update+0x38>
1000033c8:     	mov	x8, #0x0                ; =0
1000033cc:     	add	x9, x0, #0x4, lsl #12   ; =0x4000
1000033d0:     	add	x10, x2, #0x4, lsl #12  ; =0x4000
1000033d4:     	ldr	q0, [x10, x8]
1000033d8:     	ldr	q1, [x4, x8]
1000033dc:     	movi.2d	v2, #0000000000000000
1000033e0:     	fcmla.2d	v2, v0, v1, #0
1000033e4:     	fcmla.2d	v2, v0, v1, #90
1000033e8:     	str	q2, [x9, x8]
1000033ec:     	add	x8, x8, #0x10
1000033f0:     	cmp	x8, #0x4, lsl #12       ; =0x4000
1000033f4:     	b.ne	0x1000033d4 <_fcma_update+0x68>
1000033f8:     	b	0x100003450 <_fcma_update+0xe4>
1000033fc:     	ldr	q0, [x0, x8]
100003400:     	ldr	q1, [x2, x8]
100003404:     	ldr	q2, [x4, x8]
100003408:     	fcmla.2d	v0, v1, v2, #0
10000340c:     	fcmla.2d	v0, v1, v2, #90
100003410:     	str	q0, [x0, x8]
100003414:     	add	x8, x8, #0x10
100003418:     	cmp	x8, #0x4, lsl #12       ; =0x4000
10000341c:     	b.ne	0x1000033fc <_fcma_update+0x90>
100003420:     	mov	x8, #0x0                ; =0
100003424:     	add	x9, x0, #0x4, lsl #12   ; =0x4000
100003428:     	add	x10, x2, #0x4, lsl #12  ; =0x4000
10000342c:     	ldr	q0, [x9, x8]
100003430:     	ldr	q1, [x10, x8]
100003434:     	ldr	q2, [x4, x8]
100003438:     	fcmla.2d	v0, v1, v2, #0
10000343c:     	fcmla.2d	v0, v1, v2, #90
100003440:     	str	q0, [x9, x8]
100003444:     	add	x8, x8, #0x10
100003448:     	cmp	x8, #0x4, lsl #12       ; =0x4000
10000344c:     	b.ne	0x10000342c <_fcma_update+0xc0>
100003450:     	ldp	x29, x30, [sp, #0x10]
100003454:     	add	sp, sp, #0x20
100003458:     	ret
10000345c:     	adrp	x2, 0x10003a000 <dyld_stub_binder+0x10003a000>
100003460:     	add	x2, x2, #0x208
100003464:     	adrp	x5, 0x10004c000 <dyld_stub_binder+0x10004c000>
100003468:     	add	x5, x5, #0x168
10000346c:     	add	x1, sp, #0x8
100003470:     	mov	w0, #0x0                ; =0
100003474:     	mov	x3, #0x0                ; =0
100003478:     	bl	0x100039450 <__RINvNtCsedRpiqSkYaQ_4core9panicking13assert_failedjjEB4_>
10000347c:     	adrp	x2, 0x10003a000 <dyld_stub_binder+0x10003a000>
100003480:     	add	x2, x2, #0x208
100003484:     	adrp	x5, 0x10004c000 <dyld_stub_binder+0x10004c000>
100003488:     	add	x5, x5, #0x150
10000348c:     	add	x1, sp, #0x8
100003490:     	mov	w0, #0x0                ; =0
100003494:     	mov	x3, #0x0                ; =0
100003498:     	bl	0x100039450 <__RINvNtCsedRpiqSkYaQ_4core9panicking13assert_failedjjEB4_>
10000349c:     	adrp	x2, 0x10003a000 <dyld_stub_binder+0x10003a000>
1000034a0:     	add	x2, x2, #0x210
1000034a4:     	adrp	x5, 0x10004c000 <dyld_stub_binder+0x10004c000>
1000034a8:     	add	x5, x5, #0x138
1000034ac:     	add	x1, sp, #0x8
1000034b0:     	mov	w0, #0x0                ; =0
1000034b4:     	mov	x3, #0x0                ; =0
1000034b8:     	bl	0x100039450 <__RINvNtCsedRpiqSkYaQ_4core9panicking13assert_failedjjEB4_>
