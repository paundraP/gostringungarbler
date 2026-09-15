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

import struct
from typing import List
from unicorn import *
from unicorn.arm64_const import *
from capstone import *
from capstone.arm64 import *
import logging as logger
import re
import lief
from ..patchers import Function
from .base_ungarbler import GoStringUngarbler
from ..patterns import GarblerPattern, STACK_STRING_DECRYPTION, SPLIT_STRING_DECRYPTION, SEED_STRING_DECRYPTION

class GoStringUngarblerARM64(GoStringUngarbler):
    """
    Class for the arm64 string ungarbler engine (Mach-O / ELF arm64)
    """

    def __init__(self, lief_binary: lief.Binary, binary_data: bytes):
        """
        Constructors for the string ungarbler

        Args:
            lief_binary (lief.Binary): Binary object of the Mach-O / ELF

            binary_data (bytes): Content of the input executable
        """
        super().__init__(lief_binary, binary_data)
        self.unicorn_emu = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
        self.unicorn_emu.detail = True

        # initialize binary in memory
        if self.lief_binary.format == lief.Binary.FORMATS.MACHO:
            for segment in self.lief_binary.segments:
                if segment.virtual_size == 0 or segment.init_protection == 0:
                    # __PAGEZERO and other non-accessible segments
                    continue
                seg_base = segment.virtual_address & ~0xFFF
                seg_end = segment.virtual_address + segment.virtual_size
                seg_end = (seg_end + 0xFFF) & ~0xFFF
                seg_perm = 0
                # macho vm protections: 1=READ 2=WRITE 4=EXEC
                init_prot = int(segment.init_protection)
                if init_prot & 1:
                    seg_perm |= UC_PROT_READ
                if init_prot & 2:
                    seg_perm |= UC_PROT_WRITE
                if init_prot & 4:
                    seg_perm |= UC_PROT_EXEC
                self.unicorn_emu.mem_map(seg_base, seg_end - seg_base, seg_perm)
                if segment.file_size > 0:
                    self.unicorn_emu.mem_write(segment.virtual_address, bytes(segment.content)[:segment.file_size])
        elif self.lief_binary.format == lief.Binary.FORMATS.ELF:
            self.unicorn_emu.mem_map(self.lief_binary.imagebase, self.lief_binary.virtual_size)
            for segment in self.lief_binary.segments:
                self.unicorn_emu.mem_write(segment.virtual_address, bytes(segment.content))
        else:
            raise Exception('Non-supported file type')

        # map the stack into memory & clear it out
        self.unicorn_emu.mem_map(self.stack_base, self.stack_size, UC_PROT_READ | UC_PROT_WRITE)

        # map the heap into memory & clear it out
        self.unicorn_emu.mem_map(self.heap_base, self.heap_size, UC_PROT_READ | UC_PROT_WRITE)

        # fake 'g' (goroutine) struct: the prologue loads the stack bound
        # from [x28, #0x10]; point x28 at a scratch region with a huge limit
        self.g_base = self.stack_base + self.stack_size + 0x1000
        self.unicorn_emu.mem_map(self.g_base, 0x1000, UC_PROT_READ | UC_PROT_WRITE)
        # stackguard0/stackguard1 slots ([g+0x10], [g+0x14]...) = 0 so the
        # `cmp sp, [x28,#0x10]; b.ls morestack` prologue check never triggers
        self.unicorn_emu.mem_write(self.g_base + 0x10, struct.pack('<Q', 0x0))

        # throw initial SP and FP into middle of the stack
        self.reset_stack_and_heap()

        # initialize capstone disassembler in arm64 mode
        self.capstone = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        self.capstone.detail = True

        # resolved addresses of runtime helpers, filled lazily by the hooks
        self.slicebytetostring_va = 0
        self.newobject_va = 0
        self.growslice_va = 0

        # resolve runtime helper addresses from the gopclntab (garble strips
        # the symbol table, but runtime.* function names survive in it)
        self._resolve_runtime_addresses()

    def _resolve_runtime_addresses(self) -> None:
        """
        Parse the Go pclntab to find virtual addresses of runtime helpers:
        runtime.newobject, runtime.growslice, runtime.slicebytetostring
        """
        pclntab_data = None
        pclntab_va = 0
        for section in self.lief_binary.sections:
            if section.name in ('__gopclntab', '.gopclntab', 'gopclntab'):
                pclntab_data = bytes(section.content)
                pclntab_va = section.virtual_address
                break
        # fallback: search segments for the pclntab magic
        if pclntab_data is None:
            for segment in self.lief_binary.segments:
                content = bytes(segment.content)
                for magic in (b'\xf1\xff\xff\xff', b'\xf0\xff\xff\xff'):
                    idx = content.find(magic)
                    if idx != -1 and segment.virtual_address != 0:
                        pclntab_data = content[idx:]
                        pclntab_va = segment.virtual_address + idx
                        break
                if pclntab_data is not None:
                    break
        if pclntab_data is None:
            logger.debug('Can not find gopclntab to resolve runtime helpers')
            return

        try:
            if (len(pclntab_data) < 72 or
                    pclntab_data[4:6] != b'\x00\x00' or
                    pclntab_data[6] not in (1, 2, 4) or
                    pclntab_data[7] != 8):
                logger.debug('Invalid 64-bit gopclntab header')
                return

            # go 1.18+ header layout (after magic, pad, minLC, ptrSize):
            nfunc, nfiles, textStart, funcnameOff, cuOff, filetabOff, pctabOff, pclnOff = struct.unpack(
                '<QQQQQQQQ', pclntab_data[8:8 + 64])

            # Garble may replace the standard pclntab magic. Validate the
            # structural fields instead of rejecting an otherwise valid table.
            if (nfunc == 0 or nfunc > len(pclntab_data) // 8 or
                    textStart == 0 or
                    any(offset >= len(pclntab_data) for offset in
                        (funcnameOff, cuOff, filetabOff, pctabOff, pclnOff)) or
                    pclnOff + nfunc * 8 > len(pclntab_data)):
                logger.debug('Invalid gopclntab offsets')
                return

            targets = {
                'runtime.newobject': 0,
                'runtime.growslice': 0,
                'runtime.slicebytetostring': 0,
            }

            for i in range(nfunc):
                entryoff, funcoff = struct.unpack(
                    '<II', pclntab_data[pclnOff + i * 8: pclnOff + i * 8 + 8])
                if pclnOff + funcoff + 8 > len(pclntab_data):
                    continue
                nameoff = struct.unpack(
                    '<i', pclntab_data[pclnOff + funcoff + 4: pclnOff + funcoff + 8])[0]
                if not 0 <= funcnameOff + nameoff < len(pclntab_data):
                    continue
                name_end = pclntab_data.find(b'\x00', funcnameOff + nameoff)
                if name_end == -1:
                    continue
                name = pclntab_data[funcnameOff + nameoff:name_end].decode('utf-8', 'replace')
                if name in targets:
                    targets[name] = textStart + entryoff

            self.newobject_va = targets['runtime.newobject']
            self.growslice_va = targets['runtime.growslice']
            self.slicebytetostring_va = targets['runtime.slicebytetostring']
            logger.debug('runtime.newobject: %s, runtime.growslice: %s, runtime.slicebytetostring: %s',
                         hex(self.newobject_va), hex(self.growslice_va), hex(self.slicebytetostring_va))
        except Exception as e:
            logger.debug('gopclntab parsing error: %s', str(e))

    def resolve_runtime_helper(self, target_va: int) -> str:
        """
        Identify a runtime helper by looking for the Go function name
        in __gopclntab / symbol names if available, else by heuristics

        Args:
            target_va (int): Virtual address of the call target

        Returns:
            str: helper name ('newobject', 'growslice', 'slicebytetostring') or ''
        """
        return ''

    def reset_stack_and_heap(self):
        """Reset stack and base pointers to the middle of stack

        Zero out stack and heap
        """

        if self.unicorn_emu is None:
            logger.debug('Unicorn emulator is not initialized')
            return

        # Unicorn retains register state between emulations. Clear the general
        # registers so input-dependent branches do not inherit values from the
        # previously decoded function.
        for register in range(UC_ARM64_REG_X0, UC_ARM64_REG_X28):
            self.unicorn_emu.reg_write(register, 0)

        self.unicorn_emu.reg_write(UC_ARM64_REG_SP, self.stack_base + self.stack_size // 2)
        self.unicorn_emu.reg_write(UC_ARM64_REG_FP, self.stack_base + self.stack_size // 2)
        self.unicorn_emu.reg_write(UC_ARM64_REG_LR, 0)

        # R28 is the Go 'g' register on arm64
        self.unicorn_emu.reg_write(UC_ARM64_REG_X28, self.g_base)

        # zero out stack and heap
        self.unicorn_emu.mem_write(self.stack_base, b'\x00' * self.stack_size)
        self.unicorn_emu.mem_write(self.heap_base, b'\x00' * self.heap_size)

        self.heap_alloc_offset = 0

    def instruction_hook_seed(self, uc, address, size, user_data) -> None:
        """
        Hook function to handle garble's seed decryption

        Args:
            uc (Uc): unicorn emulator
            address (int): Adress of instruction
            size (int): Size of instruction
            user_data (object): User data
        """

        instruction = next(self.capstone.disasm(uc.mem_read(address, size), address))

        if instruction.mnemonic == 'bl':
            target = int(instruction.op_str[1:], 16)

            # runtime.newobject: do a manual heap alloc & return the pointer in x0
            if target == self.newobject_va:
                heap_allocated_mem = self.heap_alloc(0x100)
                self.unicorn_emu.reg_write(UC_ARM64_REG_X0, heap_allocated_mem)
                self.unicorn_emu.reg_write(UC_ARM64_REG_PC, instruction.address + 4)

                if self.runtime_newobject_call_count == 1:
                    # second buffer allocated will contain the pointer to the string + its length
                    self.call_result_struct_ptr = heap_allocated_mem
                self.runtime_newobject_call_count += 1
            elif target == self.growslice_va:
                # runtime.growslice: just return the pointer to the old buffer
                self.unicorn_emu.reg_write(UC_ARM64_REG_X0, self.heap_base + self.heap_alloc_offset)
                self.unicorn_emu.reg_write(UC_ARM64_REG_X2, 8)
                self.unicorn_emu.reg_write(UC_ARM64_REG_PC, instruction.address + 4)

    def instruction_hook(self, uc: Uc, address: int, size: int, user_data: object) -> None:
        """
        Hook function to debug and print executed instructions by unicorn engine

        Args:
            uc (Uc): unicorn emulator
            address (int): Adress of instruction
            size (int): Size of instruction
            user_data (object): User data
        """

        # Get the current instruction
        instruction = next(self.capstone.disasm(uc.mem_read(address, size), address))

        if instruction.mnemonic == 'bl':
            target = int(instruction.op_str[1:], 16)

            # runtime.growslice: just return a buffer in x0, the length and
            # capacity arguments already sit in x1/x2 and pass through
            if target == self.growslice_va:
                self.unicorn_emu.reg_write(UC_ARM64_REG_X0, self.heap_base + self.heap_alloc_offset)

                # skip call since we already emulate
                self.unicorn_emu.reg_write(UC_ARM64_REG_PC, instruction.address + 4)

        # Very noisy
        # logger.debug("0x%x:\t%s\t%s" % (instruction.address, instruction.mnemonic, instruction.op_str))

    def emulate(self, func: Function) -> str:
        """
        Emulate a function from function start to stop address (bl runtime_slicebytetostring)

        Extract the decrypted string
        Args:
            func (Function): Function to emulate

        Returns:
            str: Decrypted string
        """

        # emulate setup
        self.reset_stack_and_heap()

        # set hook function
        if func.type == SEED_STRING_DECRYPTION:
            hook_func = self.instruction_hook_seed
            self.runtime_newobject_call_count = 0
            self.call_result_struct_ptr = 0x0
        else:
            hook_func = self.instruction_hook

        # hooking
        hook_handle = self.unicorn_emu.hook_add(UC_HOOK_CODE, hook_func)

        # start emulate
        try:
            self.unicorn_emu.emu_start(func.func_start_emu_va, func.emu_stop_va, UC_SECOND_SCALE * self.MAX_EMU_TIME, 0)
        except Exception as e:
            self.unicorn_emu.hook_del(hook_handle)
            raise Exception(e)

        # get string pointer and size
        if func.type == SEED_STRING_DECRYPTION:
            decrypted_str_ptr = struct.unpack('<q', self.unicorn_emu.mem_read(self.call_result_struct_ptr, 8))[0]
            decrypted_str_size = struct.unpack('<q', self.unicorn_emu.mem_read(self.call_result_struct_ptr + 8, 8))[0]
        else:
            # at the bl runtime.slicebytetostring boundary:
            #   x0 = buf pointer (0), x1 = data pointer, x2 = length
            decrypted_str_ptr = self.unicorn_emu.reg_read(UC_ARM64_REG_X1)
            decrypted_str_size = self.unicorn_emu.reg_read(UC_ARM64_REG_X2)

        # delete hook
        self.unicorn_emu.hook_del(hook_handle)

        # extract strings
        if decrypted_str_ptr == 0:
            return ''

        decrypted_str_bytes = self.unicorn_emu.mem_read(decrypted_str_ptr, decrypted_str_size)
        decrypted_str_bytes = decrypted_str_bytes.replace(b'\x00', b'')
        decrypted_string = decrypted_str_bytes.decode('utf-8')

        # Check if the character is a printable character or a specific control character
        for character in decrypted_string:
            if not (
                # Printable ASCII characters
                (32 <= ord(character) <= 126) or
                # Specific whitespace and control characters we want to allow
                character in '\r\n\t'
            ):
                raise Exception('Contain not readable character')

        return decrypted_string

    def _contains_bl_to(self, func_data: bytes, func_start_va: int, target_va: int) -> bool:
        """
        Check if a function body contains a bl instruction targeting target_va

        Args:
            func_data (bytes): Function body data
            func_start_va (int): Function start virtual address
            target_va (int): Call target virtual address

        Returns:
            bool: True if the function calls target_va
        """
        for instruction in self.capstone.disasm(func_data, func_start_va):
            if instruction.mnemonic == 'bl':
                if int(instruction.op_str[1:].strip('#'), 16) == target_va:
                    return True
        return False

    def _loads_from_rodata(self, func_data: bytes, func_start_va: int) -> bool:
        """
        Check if a function body loads data from a read-only data section
        via adrp (garble's split string type stores key/data in rodata)

        Args:
            func_data (bytes): Function body data
            func_start_va (int): Function start virtual address

        Returns:
            bool: True if the function references a data section
        """
        for instruction in self.capstone.disasm(func_data, func_start_va):
            if instruction.mnemonic == 'adrp':
                page = int(instruction.op_str.split('#')[-1].strip(), 16)
                for section in self.lief_binary.sections:
                    if section.virtual_address <= page < section.virtual_address + section.size:
                        if section.name in ('__rodata', '.rodata', '__DATA_CONST', '.data.rel.ro'):
                            return True
        return False

    def find_string_decryption_routine(self, decrypt_type: int, garble_pattern: GarblerPattern):
        """
        Function to find all decryption routine (arm64)

        On arm64 all three decryption flavors share the same epilogue, so
        this only scans on the first (STACK) pass and classifies each
        function by inspecting its body afterwards.

        Args:
            decrypt_type (int): Type of string decryption routine to find

                STACK_STRING_DECRYPTION, SPLIT_STRING_DECRYPTION, or SEED_STRING_DECRYPTION

            garble_pattern (pattern.GarblerPattern): garbler pattern object
        """

        if decrypt_type != STACK_STRING_DECRYPTION:
            # everything is found and classified in the STACK pass
            return

        # get __text section virtual address & data
        text_section_va = 0
        text_section_data = None
        text_section_offset = 0
        for section in self.lief_binary.sections:
            if section.name not in ('__text', '.text'):
                continue
            if self.lief_binary.format == lief.Binary.FORMATS.PE:
                text_section_va = self.lief_binary.imagebase + section.virtual_address
            elif self.lief_binary.format == lief.Binary.FORMATS.ELF:
                text_section_va = section.virtual_address
            elif self.lief_binary.format == lief.Binary.FORMATS.MACHO:
                text_section_va = section.virtual_address
            else:
                raise Exception('Non-supported file type')
            text_section_data = bytes(section.content)
            text_section_offset = section.offset
            break

        if text_section_data is None:
            return None

        # set the appropriate function's epilogue pattern based on the type
        string_decrypt_epilogue_pattern = garble_pattern.get_epilogue_pattern(decrypt_type)

        last_func_end_offset = 0

        for match in string_decrypt_epilogue_pattern.finditer(text_section_data):
            # locate each function epilogue through regex
            func_end_offset = match.end()

            # locate current function's prologue from the last function end to the current function end
            prologue_matches = garble_pattern.prologue_pattern.findall(
                text_section_data, pos=last_func_end_offset, endpos=func_end_offset)

            if len(prologue_matches) == 0:
                logger.debug('[+] Error finding function prologue')
                continue

            # function's prologue is the last regex match before the epilogue
            func_prologue_data = prologue_matches[-1]

            # relative from text section
            func_start_relative_offset = text_section_data.rfind(
                func_prologue_data, last_func_end_offset, func_end_offset)

            # get virtual address of the function
            func_start_va = func_start_relative_offset + text_section_va

            # get function data
            func_data = text_section_data[func_start_relative_offset:func_end_offset]

            # find virtual address to stop emulation (at bl runtime_slicebytetostring)

            epilogue_pattern = string_decrypt_epilogue_pattern.pattern
            epilogue_pattern = epilogue_pattern[:epilogue_pattern.find(rb'\x97\xFD\xFB\x7F\xA9')]

            match = re.search(epilogue_pattern, func_data)

            if match is None:
                raise Exception('Can not find epilogue')

            # the truncated pattern ends 3 bytes into the bl instruction
            # (arm64 bl has its opcode 0x97 in the LAST byte), so the call
            # actually starts 3 bytes before match.end()
            slicebytetostring_call_offset = match.end() - 3

            emu_stop_va = func_start_va + slicebytetostring_call_offset

            # we want to skip the stack check prologue during emulation:
            #   ldr x16, [x28, #0x10]
            #   cmp sp, x16        (or sub x17, sp, #imm; cmp x17, x16)
            #   b.ls <morestack>
            #
            # prologue variant 1 is 12 bytes, variant 2 is 16 bytes
            if len(func_prologue_data) == 12:
                func_start_emu_va = func_start_va + 12
            else:
                func_start_emu_va = func_start_va + 16

            # update last function end offset
            last_func_end_offset = func_end_offset

            # end at address of the ret instruction
            func_end_va = func_end_offset + text_section_va - 1

            # offset to patch the new string resolving subroutine in
            func_start_offset = text_section_offset + func_start_relative_offset

            # classify the actual decryption type from the function body:
            #   - seed functions call runtime.newobject for their result
            #   - split functions load key/data from rodata via adrp
            #   - everything else is stack-string (immediates into locals)
            if self.newobject_va != 0 and self._contains_bl_to(func_data, func_start_va, self.newobject_va):
                actual_type = SEED_STRING_DECRYPTION
            elif self._loads_from_rodata(func_data, func_start_va):
                actual_type = SPLIT_STRING_DECRYPTION
            else:
                actual_type = STACK_STRING_DECRYPTION

            # append the function into the list
            self.decrypt_func_list.append(Function(func_data, func_start_offset, func_start_va, func_start_emu_va, func_end_va, emu_stop_va, actual_type))

            # Update counter
            if actual_type == STACK_STRING_DECRYPTION:
                self.stack_func_count += 1
            elif actual_type == SPLIT_STRING_DECRYPTION:
                self.split_func_count += 1
            elif actual_type == SEED_STRING_DECRYPTION:
                self.seed_func_count += 1
            else:
                raise Exception('Wrong decryption type')
