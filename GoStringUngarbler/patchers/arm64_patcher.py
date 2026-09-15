# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# ----------------------------------------------------------------------

from .base_patcher import Patcher, Function, Patch
from patterns import GarblerPattern
import re
import struct

class PatcherARM64(Patcher):
    """
    Class for arm64 patcher

    """

    def __init__(self, garble_pattern: GarblerPattern):
        """
        Constructor for the patcher engine
        """
        super().__init__(garble_pattern)

    def generate_patch(self, func: Function):
        """
        Generate a patch for a Function object

        Args:
            func (Function): String decrypting function to patch
        """

        slicebytetostring_va = 0

        # get runtime_sliceByteToString virtual address
        epilogue_pattern = self.garble_pattern.get_epilogue_pattern(func.type).pattern
        epilogue_pattern = epilogue_pattern[:epilogue_pattern.find(rb'\x97\xFD\xFB\x7F\xA9')]

        match = re.search(epilogue_pattern, func.data)

        if match is None:
            raise Exception('Can not find epilogue')

        # the truncated pattern ends 3 bytes into the bl instruction
        # (arm64 bl has its opcode 0x97 in the LAST byte), so the call
        # actually starts 3 bytes before match.end()
        slicebytetostring_call_offset = match.end() - 3
        bl_insn = struct.unpack('<I', func.data[slicebytetostring_call_offset:slicebytetostring_call_offset + 4])[0]

        # arm64 bl: target = PC + sign_extend(imm26) * 4 (PC is address of the bl itself)
        imm26 = bl_insn & 0x3FFFFFF
        if imm26 & (1 << 25):
            imm26 -= (1 << 26)
        slicebytetostring_va = func.func_start_va + slicebytetostring_call_offset + (imm26 << 2)

        str_len = len(func.decrypted_string)

        # layout of the patch (all instructions 4 bytes):
        #   0:  str  x30, [sp, #-16]!     ; save the return address, the bl
        #                                  ; below clobbers x30 (arm64 LR)
        #   4:  adr  x1, <string>         ; string placed right after ret
        #   8:  mov  x2, #len
        #   12: mov  x0, xzr
        #   16: bl   runtime.slicebytetostring
        #   20: ldr  x30, [sp], #16       ; restore return address & sp
        #   24: ret
        #   28: <decrypted string bytes>
        string_offset_in_patch = 28
        string_va = func.func_start_va + string_offset_in_patch

        patch_data = b''

        # str x30, [sp, #-16]! (pre-index store with writeback, keeps sp 16-byte aligned)
        patch_data += b'\xFE\x0F\x1F\xF8'

        # adr x1, #imm21 (PC-relative, must be 4-byte aligned target)
        imm21 = string_va - (func.func_start_va + 4)
        if imm21 < 0 or imm21 > (1 << 21) - 1:
            raise Exception('adr offset out of range')
        immlo = imm21 & 0x3
        immhi = (imm21 >> 2) & 0x7FFFF
        adr = 0x10000000 | (immlo << 29) | (immhi << 5) | 1
        patch_data += struct.pack('<I', adr)

        # movz x2, #len
        movz = 0xD2800000 | ((str_len & 0xFFFF) << 5) | 2
        patch_data += struct.pack('<I', movz)

        # mov x0, xzr
        patch_data += b'\xE0\x03\x1F\xAA'

        # bl runtime.slicebytetostring (imm26 is in 4-byte instruction words)
        next_pc = func.func_start_va + 16
        offset_words = (slicebytetostring_va - next_pc) >> 2
        if not (-(1 << 25) <= offset_words < (1 << 25)):
            raise Exception('bl offset out of range')
        bl = 0x94000000 | (offset_words & 0x3FFFFFF)
        patch_data += struct.pack('<I', bl)

        # ldr x30, [sp], #16 (post-index load with writeback, restores original sp)
        patch_data += b'\xFE\x07\x41\xF8'

        # ret
        patch_data += b'\xC0\x03\x5F\xD6'

        # append decrypted string right behind function
        patch_data += bytes(func.decrypted_string.encode('utf-8')) + b'\x00'

        func_len = func.func_end_va - func.func_start_va + 1

        if len(patch_data) > func_len:
            raise Exception('Patch too large for function body')

        patch_data += b'\x1f\x20\x03\xd5' * ((func_len - len(patch_data)) // 4)
        remaining = (func_len - len(patch_data)) % 4
        patch_data += b'\x00' * remaining

        patch = Patch(patch_data, func.func_start_offset)

        self.patches.append(patch)
