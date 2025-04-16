# Extracts Mirai config (SORA)
# @author: gemesa
# @runtime PyGhidra

import typing

if typing.TYPE_CHECKING:
    from ghidra.ghidra_builtins import *
    from ghidra.program.model.listing import *
import sys
import jpype

from typing import List

function_manager = currentProgram.getFunctionManager()
functions = function_manager.getFunctions(False)  # type: typing.Iterable[Function]
listing = currentProgram.getListing()
memory = currentProgram.getMemory()
ref_manager = currentProgram.getReferenceManager()

"""
    00013218 80 01 a0 e1     mov        r0,r0, lsl #0x3
    0001321c f0 40 2d e9     stmdb      sp!,{r4,r5,r6,r7,lr}
    00013220 07 00 c0 e3     bic        r0,r0,#0x7
    00013224 9c 30 9f e5     ldr        r3,[DAT_000132c8]                                = 00020E64h
    00013228 80 0a a0 e1     mov        r0,r0, lsl #0x15
    0001322c a0 0a a0 e1     mov        r0,r0, lsr #0x15
    00013230 03 e0 80 e0     add        lr,r0,r3
    00013234 90 30 9f e5     ldr        r3,[DAT_000132cc]                                = 00020B80h
    00013238 04 70 8e e2     add        r7,lr,#0x4
    0001323c 00 20 93 e5     ldr        r2,[r3,#0x0]=>mw_key                             = DEDEFBAFh
    00013240 04 10 de e5     ldrb       r1,[lr,#0x4]=>DAT_00020e68                       = ??
    00013244 01 30 d7 e5     ldrb       r3,[r7,#0x1]=>DAT_00020e69                       = ??
"""

pattern_decrypt = ["mov", "stmdb", "bic", "ldr", "mov", "mov", "add"]


def locate_function_by_pattern(pattern):
    idx = 0
    for func in functions:
        function_body = func.getBody()
        instrs = listing.getInstructions(function_body, True)

        instr: Instruction
        for instr in instrs:
            mnemonic = instr.getMnemonicString()

            if mnemonic == pattern[idx]:
                idx += 1

                if idx == len(pattern):
                    return func

            else:
                idx = 0

                if mnemonic == pattern[idx]:
                    idx += 1


target_function = locate_function_by_pattern(pattern_decrypt)

if not target_function:
    print("could not locate decryption function")
    sys.exit(1)

print(f"located decryption function: {target_function.getName()}")

from qiling import Qiling
from qiling.const import QL_VERBOSE

offset = 0
size = 0


def decrypt_enter_hook(ql: Qiling):
    global offset, size, offsets
    offset = ql.arch.regs.r0
    size = ql.unpack16(ql.mem.read(0x20E68 + offset * 8, 2))
    # print(f"offset: 0x{offset:x}")
    # print(f"size: {size}")
    data_ptr = ql.unpack32(ql.mem.read(0x20E64 + offset * 8, 4))
    data = ql.mem.read(data_ptr, size)

    # print(f"encrypted data_ptr: {data_ptr}")
    print(f"encrypted data ({offset:x}): {data}")


def decrypt_leave_hook(ql: Qiling):
    data_ptr = ql.unpack32(ql.mem.read(0x20E64 + offset * 8, 4))
    data = ql.mem.read(data_ptr, size)
    print(f"decrypted data ({offset:x}): {data}")


file = askFile("FILE", "Choose file")
rootfs = askDirectory("ROOTFS", "Choose rootfs dir")

ql = Qiling([file.getAbsolutePath()], rootfs.getAbsolutePath(), verbose=QL_VERBOSE.OFF)

# 0xdeadbeef is the encryption key hardcoded into the leaked source code used to decrypt the configuration.
# Authors often leave some configuration data encrypted with 0xdeadbeef in their variant.
# This data cannot be decrypted with other encryption keys,
# but it is worth it to run the decryption with 0xdeadbeef as well,
# if we see garbled data after decrypting with the hardcoded key (e.g. 0xdedefbaf)
# to make sure our decryption algorithm works properly,
# and some of the data may have been encrypted with just a different key (e.g. 0xdeadbeef).
# ql.mem.write(0x20b80, ql.pack32(0xdeadbeef))

ql.hook_address(decrypt_enter_hook, 0x13218)
ql.hook_address(decrypt_leave_hook, 0x132C4)

# initialize encrypted data in memory
ql.run(end=0x141BC)

# get the references of the decryption function
# and execute each paramater setup and function call
#        0000c2bc 54 00 a0 e3     mov        r0,#0x54
#        0000c2c0 d4 1b 00 eb     bl         mw_decrypt_with_key                              undefined mw_decrypt_with_key()

refs = ref_manager.getReferencesTo(target_function.getEntryPoint())

# edgecase:
# sometimes it is not enough to execute 1 instruction before the call
#        0000fcac 1c 00 a0 e3     mov        r0,#0x1c
#        0000fcb0 01 90 a0 e1     cpy        r9,r1
#        0000fcb4 57 0d 00 eb     bl         mw_decrypt_with_key                              undefined mw_decrypt_with_key()
#
# sometimes it is too much to execute more than 1 instruction before the call
#        0000e238 f6 13 00 eb     bl         mw_decrypt_with_key                              undefined mw_decrypt_with_key()
#        0000e23c 0e 00 a0 e3     mov        r0,#0xe
#        0000e240 f4 13 00 eb     bl         mw_decrypt_with_key                              undefined mw_decrypt_with_key()

# so for now we just ignore this problem,
# which means we will not decrypt some strings
exclude = [0x0000C2EC, 0x0000E238, 0x0000F418, 0x0000FCB4]

for ref in refs:
    addr = ref.getFromAddress()
    if addr.getOffset() in exclude:
        continue
    # print(hex(addr.getOffset()))
    ql.run(begin=addr.getOffset() - 4, end=addr.getOffset() + 4)
