#!/usr/bin/env python3
"""Writes vex_cases.S: one small function per instruction form, for vex_ops.c.

Run by build.sh. Each case starts from the fixed register and memory state of vex_ops.c and runs
one instruction (rsi and rdi point at 64 readable and writable bytes). A trailing mask names the
flags the instruction defines; the rest are left out of the comparison.
"""
import sys

ALL = 0x8d5  # OF SF ZF AF PF CF
ZC = 0x41  # ZF CF
C = 0x01  # CF
Z = 0x40
ZSC = 0xc1
ZSOC = 0x8c1

cases = []


def c(text, mask=ALL):
    cases.append((text, mask))


def three(op):
    c(f"{op} xmm1, xmm2")
    c(f"{op} xmm1, [rsi]")
    c(f"v{op} xmm1, xmm2, xmm3")
    c(f"v{op} xmm1, xmm2, [rsi]")
    c(f"v{op} ymm1, ymm2, ymm3")
    c(f"v{op} ymm1, ymm2, [rsi]")


def fp3(op):
    c(f"{op} xmm9, xmm10")
    c(f"v{op} xmm1, xmm9, xmm10")
    c(f"v{op} ymm1, ymm9, ymm10")
    c(f"v{op} ymm1, ymm9, [rsi+0]")


def dp3(op):
    c(f"{op} xmm13, xmm14")
    c(f"v{op} xmm1, xmm13, xmm14")
    c(f"v{op} ymm1, ymm13, ymm14")


for op in """paddb paddw paddd paddq psubb psubw psubd psubq paddsb paddsw paddusb paddusw psubsb
    psubsw psubusb psubusw pavgb pavgw pmaxsb pmaxsw pmaxsd pmaxub pmaxuw pmaxud pminsb pminsw
    pminsd pminub pminuw pminud pcmpeqb pcmpeqw pcmpeqd pcmpeqq pcmpgtb pcmpgtw pcmpgtd pcmpgtq
    pand pandn por pxor pmullw pmulld pmulhw pmulhuw pmulhrsw pmuldq pmuludq pmaddwd pmaddubsw
    psadbw psignb psignw psignd punpcklbw punpcklwd punpckldq punpcklqdq punpckhbw punpckhwd
    punpckhdq punpckhqdq packsswb packuswb packssdw packusdw pshufb phaddw phaddd phaddsw phsubw
    phsubd phsubsw""".split():
    three(op)

for op in "pabsb pabsw pabsd".split():
    c(f"{op} xmm1, xmm2")
    c(f"v{op} xmm1, xmm2")
    c(f"v{op} ymm1, ymm2")
    c(f"v{op} ymm1, [rsi]")

for op in """pmovzxbw pmovzxbd pmovzxbq pmovzxwd pmovzxwq pmovzxdq pmovsxbw pmovsxbd pmovsxbq
    pmovsxwd pmovsxwq pmovsxdq""".split():
    c(f"{op} xmm1, xmm2")
    c(f"v{op} xmm1, xmm2")
    c(f"v{op} ymm1, xmm2")
    c(f"v{op} ymm1, [rsi]")

for op in "psllw pslld psllq psrlw psrld psrlq psraw psrad".split():
    for n in (3, 40):
        c(f"{op} xmm1, {n}")
        c(f"v{op} xmm1, xmm2, {n}")
        c(f"v{op} ymm1, ymm2, {n}")
    c(f"{op} xmm1, xmm5")
    c(f"v{op} ymm1, ymm2, xmm5")
    c(f"v{op} ymm1, ymm2, [rsi]")

for op in "pslldq psrldq".split():
    for n in (3, 15, 20):
        c(f"{op} xmm1, {n}")
        c(f"v{op} xmm1, xmm2, {n}")
        c(f"v{op} ymm1, ymm2, {n}")

for op in "vpsllvd vpsllvq vpsrlvd vpsrlvq vpsravd".split():
    c(f"{op} xmm1, xmm2, xmm4")
    c(f"{op} ymm1, ymm2, ymm4")
    c(f"{op} ymm1, ymm2, [rsi]")

for op in "pshufd pshuflw pshufhw".split():
    c(f"{op} xmm1, xmm2, 0x1b")
    c(f"v{op} xmm1, xmm2, 0x1b")
    c(f"v{op} ymm1, ymm2, 0x72")
    c(f"v{op} ymm1, [rsi], 0x72")

for n in (3, 17, 40):
    c(f"palignr xmm1, xmm2, {n}")
    c(f"vpalignr xmm1, xmm2, xmm3, {n}")
    c(f"vpalignr ymm1, ymm2, ymm3, {n}")
c("vpalignr ymm1, ymm2, [rsi], 5")

for op in "pblendw blendps blendpd".split():
    c(f"{op} xmm1, xmm2, 0xa5" if op == "pblendw" else f"{op} xmm1, xmm2, 5")
    c(f"v{op} xmm1, xmm2, xmm3, 5")
    c(f"v{op} ymm1, ymm2, ymm3, 0xa5" if op != "blendpd" else f"v{op} ymm1, ymm2, ymm3, 5")
c("vpblendd xmm1, xmm2, xmm3, 5")
c("vpblendd ymm1, ymm2, ymm3, 0xa5")
c("vpblendd ymm1, ymm2, [rsi], 0x3c")
c("pblendvb xmm1, xmm2, xmm0")
c("blendvps xmm1, xmm2, xmm0")
c("blendvpd xmm1, xmm2, xmm0")
for op in "vpblendvb vblendvps vblendvpd".split():
    c(f"{op} xmm1, xmm2, xmm3, xmm4")
    c(f"{op} ymm1, ymm2, ymm3, ymm4")
    c(f"{op} ymm1, ymm2, [rsi], ymm4")

for op in "shufps shufpd".split():
    c(f"{op} xmm1, xmm2, 0x1b")
    c(f"v{op} xmm1, xmm2, xmm3, 0x1b")
    c(f"v{op} ymm1, ymm2, ymm3, 0x72")
for op in "unpcklps unpcklpd unpckhps unpckhpd".split():
    c(f"{op} xmm1, xmm2")
    c(f"v{op} xmm1, xmm2, xmm3")
    c(f"v{op} ymm1, ymm2, ymm3")
for op in "andps andpd orps orpd xorps xorpd andnps andnpd".split():
    c(f"{op} xmm1, xmm2")
    c(f"v{op} xmm1, xmm2, xmm3")
    c(f"v{op} ymm1, ymm2, ymm3")
    c(f"v{op} ymm1, ymm2, [rsi]")

c("vpermq ymm1, ymm2, 0x1b")
c("vpermq ymm1, [rsi], 0x72")
c("vpermpd ymm1, ymm2, 0x1b")
c("vpermd ymm1, ymm2, ymm3")
c("vpermd ymm1, ymm2, [rsi]")
c("vpermps ymm1, ymm2, ymm3")
c("vperm2i128 ymm1, ymm2, ymm3, 0x21")
c("vperm2i128 ymm1, ymm2, ymm3, 0x08")
c("vperm2i128 ymm1, ymm2, [rsi], 0x31")
c("vperm2f128 ymm1, ymm2, ymm3, 0x12")
c("vpermilps xmm1, xmm2, 0x1b")
c("vpermilps ymm1, ymm2, 0x72")
c("vpermilps ymm1, ymm2, ymm3")
c("vpermilpd xmm1, xmm2, 1")
c("vpermilpd ymm1, ymm2, 5")
c("vpermilpd ymm1, ymm2, ymm3")
c("vinserti128 ymm1, ymm2, xmm3, 1")
c("vinserti128 ymm1, ymm2, xmm3, 0")
c("vinserti128 ymm1, ymm2, [rsi], 1")
c("vinsertf128 ymm1, ymm2, xmm3, 1")
c("vinsertf128 ymm1, ymm2, [rsi], 0")
c("vextracti128 xmm1, ymm2, 1")
c("vextracti128 xmm1, ymm2, 0")
c("vextracti128 [rdi], ymm2, 1")
c("vextractf128 xmm1, ymm2, 1")
c("vextractf128 [rdi], ymm2, 1")
for op, m in (("vpbroadcastb", "byte ptr"), ("vpbroadcastw", "word ptr"), ("vpbroadcastd", "dword ptr"),
              ("vpbroadcastq", "qword ptr")):
    c(f"{op} xmm1, xmm2")
    c(f"{op} ymm1, xmm2")
    c(f"{op} ymm1, {m} [rsi]")
c("vbroadcastss xmm1, xmm2")
c("vbroadcastss ymm1, xmm2")
c("vbroadcastss ymm1, dword ptr [rsi]")
c("vbroadcastsd ymm1, xmm2")
c("vbroadcastsd ymm1, qword ptr [rsi]")
c("vbroadcastf128 ymm1, [rsi]")
c("vbroadcasti128 ymm1, [rsi]")

c("ptest xmm1, xmm2")
c("vptest xmm1, xmm2")
c("vptest ymm1, ymm2")
c("vptest ymm0, ymm0")
c("vptest ymm1, [rsi]")
c("vtestps xmm1, xmm2")
c("vtestps ymm1, ymm2")
c("vtestpd ymm1, ymm2")
c("pmovmskb eax, xmm2")
c("vpmovmskb eax, xmm2")
c("vpmovmskb eax, ymm2")
c("movmskps eax, xmm2")
c("vmovmskps eax, xmm2")
c("vmovmskps eax, ymm2")
c("movmskpd eax, xmm2")
c("vmovmskpd eax, ymm2")

for t in """vmovd xmm1, eax|vmovd xmm1, dword ptr [rsi]|vmovd eax, xmm2|vmovd dword ptr [rdi], xmm2
    vmovq xmm1, rax|vmovq xmm1, qword ptr [rsi]|vmovq rax, xmm2|vmovq qword ptr [rdi], xmm2
    vmovq xmm1, xmm2|vmovdqa xmm1, xmm2|vmovdqa ymm1, ymm2|vmovdqa ymm1, [rsi]|vmovdqa [rdi], ymm2
    vmovdqu xmm1, [rsi+1]|vmovdqu ymm1, [rsi+1]|vmovdqu [rdi+1], ymm2|vmovdqu [rdi+1], xmm2
    vmovaps ymm1, ymm2|vmovaps ymm1, [rsi]|vmovaps [rdi], ymm2|vmovups ymm1, [rsi+1]
    vmovups [rdi+1], ymm2|vmovups xmm1, [rsi+1]|vmovapd ymm1, [rsi]|vmovupd ymm1, [rsi+1]
    vmovss xmm1, xmm2, xmm3|vmovss xmm1, dword ptr [rsi]|vmovss dword ptr [rdi], xmm2
    vmovsd xmm1, xmm2, xmm3|vmovsd xmm1, qword ptr [rsi]|vmovsd qword ptr [rdi], xmm2
    vmovhps xmm1, xmm2, qword ptr [rsi]|vmovhps qword ptr [rdi], xmm2|vmovlps xmm1, xmm2, qword ptr [rsi]
    vmovlps qword ptr [rdi], xmm2|vmovhpd xmm1, xmm2, qword ptr [rsi]|vmovhpd qword ptr [rdi], xmm2
    vmovlpd xmm1, xmm2, qword ptr [rsi]|vmovlpd qword ptr [rdi], xmm2
    vmovhlps xmm1, xmm2, xmm3|vmovlhps xmm1, xmm2, xmm3
    vmovntdq [rdi], ymm2|vmovntdq [rdi], xmm2|vmovntdqa ymm1, [rsi]|vmovntdqa xmm1, [rsi]
    vmovntps [rdi], ymm2|vmovntpd [rdi], ymm2|vlddqu ymm1, [rsi+1]|vlddqu xmm1, [rsi+1]
    vmovshdup ymm1, ymm2|vmovshdup xmm1, xmm2|vmovsldup ymm1, ymm2|vmovsldup xmm1, xmm2
    vmovddup ymm1, ymm2|vmovddup xmm1, xmm2|movshdup xmm1, xmm2|movsldup xmm1, xmm2|movddup xmm1, xmm2
    lddqu xmm1, [rsi+1]|movntdqa xmm1, [rsi]
    vpinsrb xmm1, xmm2, eax, 5|vpinsrw xmm1, xmm2, eax, 5|vpinsrd xmm1, xmm2, eax, 2
    vpinsrq xmm1, xmm2, rax, 1|vpinsrb xmm1, xmm2, byte ptr [rsi], 15
    vpinsrw xmm1, xmm2, word ptr [rsi], 7|vpinsrd xmm1, xmm2, dword ptr [rsi], 3
    vpinsrq xmm1, xmm2, qword ptr [rsi], 0
    vpextrb eax, xmm2, 5|vpextrw eax, xmm2, 5|vpextrd eax, xmm2, 2|vpextrq rax, xmm2, 1
    vpextrb byte ptr [rdi], xmm2, 15|vpextrw word ptr [rdi], xmm2, 7|vpextrd dword ptr [rdi], xmm2, 3
    vpextrq qword ptr [rdi], xmm2, 0|vextractps eax, xmm2, 2|vextractps dword ptr [rdi], xmm2, 1
    vinsertps xmm1, xmm2, xmm3, 0x9c|vinsertps xmm1, xmm2, dword ptr [rsi], 0x13
    pinsrb xmm1, eax, 5|pinsrd xmm1, eax, 2|pinsrq xmm1, rax, 1|pinsrw xmm1, eax, 5
    pextrb eax, xmm2, 5|pextrd eax, xmm2, 2|pextrq rax, xmm2, 1|pextrw eax, xmm2, 5
    insertps xmm1, xmm2, 0x9c|extractps eax, xmm2, 2
    vmaskmovps ymm1, ymm2, [rsi]|vmaskmovps xmm1, xmm2, [rsi]|vmaskmovpd ymm1, ymm4, [rsi]
    vmaskmovps [rdi], ymm2, ymm3|vmaskmovpd [rdi], ymm4, ymm3|vpmaskmovd ymm1, ymm2, [rsi]
    vpmaskmovd xmm1, xmm2, [rsi]|vpmaskmovq ymm1, ymm4, [rsi]|vpmaskmovq xmm1, xmm4, [rsi]
    vpmaskmovd [rdi], ymm2, ymm3|vpmaskmovq [rdi], ymm4, ymm3|vpmaskmovd [rdi], xmm2, xmm3
    vzeroupper|vzeroall""".replace("\n", "|").split("|"):
    c(t.strip())

for op in "add sub mul div min max".split():
    fp3(op + "ps")
    dp3(op + "pd")
    c(f"{op}ss xmm9, xmm10")
    c(f"v{op}ss xmm1, xmm9, xmm10")
    c(f"{op}sd xmm13, xmm14")
    c(f"v{op}sd xmm1, xmm13, xmm14")
fp3("addsubps")
fp3("haddps")
fp3("hsubps")
dp3("addsubpd")
dp3("haddpd")
dp3("hsubpd")
c("sqrtps xmm1, xmm9")
c("vsqrtps xmm1, xmm9")
c("vsqrtps ymm1, ymm9")
c("vsqrtpd xmm1, xmm13")
c("vsqrtpd ymm1, ymm13")
c("vsqrtss xmm1, xmm2, xmm9")
c("vsqrtsd xmm1, xmm2, xmm13")
for p in range(32):
    c(f"vcmpps ymm1, ymm9, ymm10, {p}")
    c(f"vcmppd ymm1, ymm13, ymm14, {p}")
    c(f"vcmpss xmm1, xmm9, xmm11, {p}")
    c(f"vcmpsd xmm1, xmm13, xmm15, {p}")
c("vcmpps xmm1, xmm9, xmm10, 1")
c("vcmppd xmm1, xmm13, xmm14, 2")
c("cmpps xmm9, xmm10, 1")
c("cmpsd xmm13, xmm14, 2")
for t in ("comiss xmm9, xmm10", "vcomiss xmm9, xmm10", "vucomiss xmm9, xmm11", "vcomisd xmm13, xmm14",
          "vucomisd xmm13, xmm15"):
    c(t)
for imm in (0, 1, 2, 3, 4, 9):
    c(f"vroundps ymm1, ymm9, {imm}")
    c(f"vroundps xmm1, xmm9, {imm}")
    c(f"vroundpd ymm1, ymm13, {imm}")
    c(f"vroundss xmm1, xmm2, xmm9, {imm}")
    c(f"vroundsd xmm1, xmm2, xmm13, {imm}")
    c(f"roundps xmm1, xmm9, {imm}")
    c(f"roundsd xmm1, xmm13, {imm}")
for t in """vcvtdq2ps ymm1, ymm2|vcvtdq2ps xmm1, xmm2|vcvtdq2pd ymm1, xmm2|vcvtdq2pd xmm1, xmm2
    vcvtps2dq ymm1, ymm9|vcvtps2dq xmm1, xmm9|vcvttps2dq ymm1, ymm9|vcvttps2dq xmm1, xmm9
    vcvtpd2dq xmm1, ymm13|vcvtpd2dq xmm1, xmm13|vcvttpd2dq xmm1, ymm13|vcvttpd2dq xmm1, xmm13
    vcvtps2pd ymm1, xmm9|vcvtps2pd xmm1, xmm9|vcvtpd2ps xmm1, ymm13|vcvtpd2ps xmm1, xmm13
    vcvtsi2ss xmm1, xmm2, eax|vcvtsi2sd xmm1, xmm2, rax|vcvtss2sd xmm1, xmm2, xmm9
    vcvtsd2ss xmm1, xmm2, xmm13|vcvtsd2si rax, xmm13|vcvttsd2si rax, xmm13|vcvtss2si eax, xmm9
    vcvttss2si eax, xmm9|vcvtph2ps ymm1, xmm2|vcvtph2ps xmm1, xmm2|vcvtps2ph xmm1, ymm9, 0
    vcvtps2ph xmm1, xmm9, 0|vdppd xmm1, xmm13, xmm14, 0x31|vdpps xmm1, xmm9, xmm10, 0xf1
    vdpps ymm1, ymm9, ymm10, 0x7f|vmpsadbw xmm1, xmm2, xmm3, 5|vmpsadbw ymm1, ymm2, ymm3, 0x2d
    vphminposuw xmm1, xmm2|phminposuw xmm1, xmm2|mpsadbw xmm1, xmm2, 5
    dppd xmm13, xmm14, 0x31|dpps xmm9, xmm10, 0xf1""".replace("\n", "|").split("|"):
    c(t.strip())

for kind in "madd msub nmadd nmsub".split():
    for order in "132 213 231".split():
        c(f"vf{kind}{order}ps ymm9, ymm10, ymm11")
        c(f"vf{kind}{order}ps xmm9, xmm10, xmm11")
        c(f"vf{kind}{order}pd ymm13, ymm14, ymm15")
        c(f"vf{kind}{order}pd xmm13, xmm14, xmm15")
        c(f"vf{kind}{order}ss xmm9, xmm10, xmm11")
        c(f"vf{kind}{order}sd xmm13, xmm14, xmm15")
for kind in "maddsub msubadd".split():
    for order in "132 213 231".split():
        c(f"vf{kind}{order}ps ymm9, ymm10, ymm11")
        c(f"vf{kind}{order}pd ymm13, ymm14, ymm15")

for t, m in (("andn r8, rax, rbx", ZSOC), ("andn r8d, eax, ebx", ZSOC), ("bextr r8, rax, rcx", Z),
             ("blsi r8, rax", ZSOC), ("blsmsk r8, rax", 0x881), ("blsr r8, rax", ZSOC),
             ("bzhi r8, rax, rcx", ZSOC), ("mulx r8, r9, rax", 0), ("pdep r8, rax, rbx", 0),
             ("pext r8, rax, rbx", 0), ("rorx r8, rax, 13", 0), ("rorx r8d, eax, 13", 0),
             ("sarx r8, rax, rcx", 0), ("shlx r8, rax, rcx", 0), ("shrx r8, rax, rcx", 0),
             ("shlx r8d, eax, ecx", 0), ("shrx r8d, eax, ecx", 0), ("sarx r8d, eax, ecx", 0),
             ("tzcnt r8, rax", ZC), ("tzcnt r8d, ebx", ZC), ("lzcnt r8, rax", ZC),
             ("lzcnt r8d, ebx", ZC), ("popcnt r8, rax", ALL), ("movbe r8, [rsi]", 0),
             ("movbe r8d, [rsi]", 0), ("movbe [rdi], rax", 0), ("movbe [rdi], eax", 0),
             ("crc32 r8d, al", 0), ("crc32 r8, rax", 0), ("crc32 r8d, eax", 0),
             ("cmpxchg16b [rdi]", Z),
             # The destination is also the source, or the register of its address.
             ("lzcnt rax, rax", ZC), ("lzcnt ebx, ebx", ZC), ("tzcnt rax, rax", ZC),
             ("tzcnt ebx, ebx", ZC), ("mov rax, rsi\n\tlzcnt rax, [rax]", ZC),
             ("mov rax, rsi\n\ttzcnt rax, [rax]", ZC), ("blsi rax, rax", ZSOC),
             ("blsr rax, rax", ZSOC), ("blsmsk rax, rax", 0x881), ("mulx rax, rbx, rax", 0),
             ("pdep rax, rax, rax", 0), ("pext rax, rax, rax", 0), ("rorx rax, rax, 5", 0),
             ("andn rax, rax, rbx", ZSOC), ("bzhi rax, rax, rcx", ZSOC), ("shlx rax, rax, rax", 0),
             ("popcnt rax, rax", ALL), ("movbe rax, [rsi]", 0)):
    c(t, m)

for t in ("pcmpistri xmm2, xmm3, 0", "pcmpistri xmm2, xmm3, 0x1a", "pcmpistrm xmm2, xmm3, 0x40",
          "pcmpestri xmm2, xmm3, 0x0c", "pcmpestrm xmm2, xmm3, 0x40", "vpcmpistri xmm2, xmm3, 0",
          "vpcmpistri xmm6, xmm7, 0x08", "vpcmpistri xmm6, xmm7, 0x1a", "vpcmpistrm xmm6, xmm7, 0x40",
          "vpcmpestri xmm6, xmm7, 0x0c", "vpcmpestrm xmm6, xmm7, 0x40"):
    c(t, 0x8c1)

# XSAVE and XRSTOR restore what the code between them clobbered.
c("mov eax, 6\n\txor edx, edx\n\tlea r8, [rip + xarea]\n\txsave [r8]\n\tvpxor ymm1, ymm1, ymm1\n"
  "\tvpxor xmm9, xmm9, xmm9\n\txrstor [r8]\n\txor r8d, r8d\n\tmov eax, 0x33\n\txor edx, edx")

for t in ("vpgatherdd ymm1, [r10 + ymm5*4], ymm6", "vpgatherdq ymm1, [r10 + xmm5*2], ymm6",
          "vpgatherqq ymm1, [r10 + ymm5*2], ymm6", "vgatherdps ymm1, [r10 + ymm5*4], ymm6",
          "vgatherdpd ymm1, [r10 + xmm5*2], ymm6", "vpgatherdd xmm1, [r10 + xmm5*4], xmm6"):
    c(t)

# The mask forms write xmm0, which may also be an operand the flags depend on.
for setup, op in (("vmovdqa xmm0, xmm6", "pcmpistrm xmm0, xmm7, 0x40"),
                  ("vmovdqa xmm0, xmm3", "pcmpistrm xmm0, xmm2, 0x40"),
                  ("vmovdqa xmm0, xmm3", "pcmpistrm xmm0, xmm2, 0x48"),
                  ("vmovdqa xmm0, xmm7", "pcmpistrm xmm6, xmm0, 0x40"),
                  ("vmovdqa xmm0, xmm6", "vpcmpistrm xmm0, xmm7, 0x40"),
                  ("vmovdqa xmm0, xmm3", "vpcmpistrm xmm0, xmm2, 0x40"),
                  ("vmovdqa xmm0, xmm3\n\tmov eax, 16\n\tmov edx, 16", "pcmpestrm xmm0, xmm2, 0x40"),
                  ("vmovdqa xmm0, xmm3\n\tmov eax, 16\n\tmov edx, 16", "vpcmpestrm xmm0, xmm2, 0x40")):
    c(f"{setup}\n\t{op}", ZSOC)

# Explicit lengths are signed, 32 bits of them without REX.W.
for lengths, op in (("mov eax, -1\n\tmov edx, 5", "pcmpestri xmm6, xmm7, 0x0c"),
                    ("mov eax, 5\n\tmov edx, -3", "pcmpestrm xmm6, xmm7, 0x40"),
                    ("mov eax, 0x80000000\n\tmov edx, 5", "pcmpestri xmm6, xmm7, 0x0c"),
                    ("mov eax, -2\n\tmov edx, 5", "vpcmpestri xmm6, xmm7, 0x0c"),
                    ("movabs rax, 0x100000003\n\tmov edx, 5", "pcmpestri xmm6, xmm7, 0x0c"),
                    ("mov rax, -1\n\tmov rdx, 5", ".byte 0x66, 0x48, 0x0f, 0x3a, 0x61, 0xf7, 0x0c"),
                    ("movabs rax, 0x100000003\n\tmov rdx, 5", ".byte 0x66, 0x48, 0x0f, 0x3a, 0x61, 0xf7, 0x0c"),
                    ("mov rax, -1\n\tmov rdx, 5", ".byte 0xc4, 0xe3, 0xf9, 0x61, 0xf7, 0x0c")):
    c(f"{lengths}\n\t{op}", ZSOC)

# Two pairs of 0x8000 wrap to the most negative value.
c("mov eax, 0x80008000\n\tvmovd xmm1, eax\n\tvpbroadcastd ymm1, xmm1\n\tvpmaddwd ymm2, ymm1, ymm1")
c("mov eax, 0x80008000\n\tvmovd xmm1, eax\n\tvpshufd xmm1, xmm1, 0\n\tpmaddwd xmm1, xmm1")

# A memory source has one element, whatever the source index says.
c("vinsertps xmm1, xmm2, dword ptr [rsi], 0xd3")
c("insertps xmm1, dword ptr [rsi], 0x50")

# Both control forms. The status bits are masked: they are sticky on a CPU and never set here.
c("stmxcsr [rdi]\n\tand dword ptr [rdi], 0xffc0")
c("vstmxcsr [rdi]\n\tand dword ptr [rdi], 0xffc0")
c("mov dword ptr [rdi], 0x3f80\n\tvldmxcsr [rdi]\n\tvstmxcsr [rdi + 4]\n\t"
  "mov dword ptr [rdi], 0x1f80\n\tvldmxcsr [rdi]")

# `tail` is the last 16 bytes before an unmapped page, so these need the mask to hold accesses
# back; ymm2 selects its low half. A store writes through, and the last case reads it back.
LOW = "mov rax, [rip + tail]\n\tvpcmpeqd xmm2, xmm2, xmm2\n\t"
for t in ("vmaskmovps ymm1, ymm2, [rax]", "vmaskmovpd ymm1, ymm2, [rax]",
          "vpmaskmovd ymm1, ymm2, [rax]", "vpmaskmovq ymm1, ymm2, [rax]"):
    c(f"{LOW}{t}\n\txor eax, eax", 0)
for t in ("vmaskmovps [rax], ymm2, ymm3", "vmaskmovpd [rax], ymm2, ymm5",
          "vpmaskmovd [rax], ymm2, ymm7", "vpmaskmovq [rax], ymm2, ymm3"):
    c(f"{LOW}{t}\n\tvmovdqu xmm1, [rax]\n\txor eax, eax", 0)

# With a clear mask nothing is touched: not an unmapped page, not read-only memory.
CLEAR = "vpxor xmm2, xmm2, xmm2\n\t"
c(f"mov rax, [rip + tail]\n\tadd rax, 16\n\t{CLEAR}vmaskmovps ymm1, ymm2, [rax]\n\txor eax, eax", 0)
c(f"mov rax, [rip + tail]\n\tadd rax, 16\n\t{CLEAR}vpmaskmovq [rax], ymm2, ymm3\n\txor eax, eax", 0)
c(f"lea rax, [rip + name_0]\n\t{CLEAR}vmaskmovps [rax], ymm2, ymm3\n\txor eax, eax", 0)
c(f"lea rax, [rip + name_0]\n\t{CLEAR}vpmaskmovd [rax], ymm2, ymm3\n\txor eax, eax", 0)

out = [".intel_syntax noprefix", ".text"]
for i, (t, _) in enumerate(cases):
    out += [f"case_{i}:", f"\t{t}", "\tret"]
out += [".bss", ".p2align 6", "xarea:", "\t.space 4096"]
out += [".section .rodata"]
for i, (t, _) in enumerate(cases):
    label = t.replace("\n\t", "; ")
    out += [f"name_{i}:", f'\t.asciz "{label}"']
out += [".data", ".globl cases", ".p2align 3", "cases:"]
for i, (_, m) in enumerate(cases):
    out += [f"\t.quad case_{i}, name_{i}, {m}"]
out += ["\t.quad 0, 0, 0", ""]
open(sys.argv[1], "w").write("\n".join(out))
print(len(cases), "cases")
