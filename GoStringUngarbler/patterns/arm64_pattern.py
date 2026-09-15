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

from abc import ABC
import re
from .base_pattern import GarblerPattern

# arm64 Go function prologue stack check, two variants:
#
#   ldr x16, [x28, #0x10]   ; 90 0B 40 F9
#   cmp sp, x16             ; FF 63 30 EB
#   b.ls <morestack>        ; xx xx xx 54
#
#   ldr x16, [x28, #0x10]   ; 90 0B 40 F9
#   sub x17, sp, #imm12     ; xx xx xx D1
#   cmp x17, x16            ; 3F 02 10 EB
#   b.ls <morestack>        ; xx xx xx 54

PROLOGUE_PATTERN = rb'\x90\x0B\x40\xF9\xFF\x63\x30\xEB[\x00-\xFF]{3}\x54|\x90\x0B\x40\xF9[\x00-\xFF]{3}\xD1\x3F\x02\x10\xEB[\x00-\xFF]{3}\x54'

# =====================================================================
# Epilogue: every garble string decryption function ends with a call to
# runtime.slicebytetostring followed by the standard Go epilogue:
#
#   mov x0, xzr                   ; E0 03 1F AA
#   add x1, sp, #imm              ; E1 xx xx 91
#   mov x2, #len                  ; movz: xx xx 80 D2 | orr: xx xx 40/60 B2
#   bl runtime.slicebytetostring  ; xx xx xx 97
#   ldp x29, x30, [sp, #-8]       ; FD FB 7F A9
#   add sp, sp, #imm              ; xx xx xx 91
#   ret                           ; C0 03 5F D6
#
# The differences between decrypt types (stack/split/seed) happen in the
# function body, not the epilogue, so one epilogue pattern covers all three.

EPILOGUE_PATTERN = rb'\xE0\x03\x1F\xAA\xE1[\x00-\xFF]{2}\x91[\x02\x22\x42\x62\x82\xA2\xC2\xE2][\x00-\xFF][\x80\x40\x60][\xD2\xB2][\x00-\xFF]{3}\x97\xFD\xFB\x7F\xA9[\x00-\xFF]{3}\x91\xC0\x03\x5F\xD6'

# =====================================================================

class GarblerPatternARM64(GarblerPattern):
    """
    Class for garble patterns of arm64 Go binaries

    Attributes
    ----------
    go_version: str

        Detected go version of the garble-obfuscated sample (based on regex)
    """
    go_version: str

    def __init__(self, pe_data: bytes=None):
        """
        Constructor for GarblerPattern

        Args:
            pe_data (bytes, optional): Garble-obfuscated file data. Defaults to None.
        """
        super().__init__(pe_data)

        # arm64 epilogues are stable across garble/go versions: the calling
        # convention (x0/x1/x2 arguments) is fixed by the Go runtime ABI
        epilogue = re.compile(EPILOGUE_PATTERN)
        self.stack_epilogue_pattern = epilogue
        self.split_epilogue_pattern = epilogue
        self.seed_epilogue_pattern = epilogue

        self.go_version = 'arm64'

        self.prologue_pattern = re.compile(PROLOGUE_PATTERN)
