"""
go_goroutines.py — Volatility 3 plugin: Go goroutine stack trace and
                   argument recovery from Linux memory dumps.

Finds all goroutines via runtime.allgs, unwinds each stack using PCSP
tables, and extracts argument values from every frame using a 5-tier
type resolution cascade:

  1. Type methods   — full type info from binary's uncommonType tables
  2. Runtime/stdlib — parameter names/types from external go_func_lines DB
  3. Third-party    — signatures from third_party_analyzer module
  4. ArgInfo (1.17+)— offset/size bytecode + pointer bitmap heuristics
  5. ArgsPointerMaps— raw slot scanning, composite pattern matching

Phase 1 pre-caches type method arguments (tier 1) across all goroutines
to populate data_to_type_map. Phase 2 walks stacks and falls through
tiers 2–5 with cache-assisted pointer resolution.

Pipeline: ELF base (VMAs) → program headers → Go version → pclntab →
moduledata → cached ELF via page cache → functions/types/itabs → allgs →
goroutine parsing → stack unwinding → argument extraction.

Supported Go Versions:
    - Go 1.2–1.15  (stack-based ABI, legacy pclntab, no ArgInfo)
    - Go 1.16–1.17 (stack-based ABI, pcHeader with uintptr offsets, no ArgInfo)
    - Go 1.18–1.24 (register-based ABI, pcHeader with uint32 offsets, ArgInfo)
    - Go 1.25+     (register-based ABI, same layout as 1.18+)

    Goroutine struct offsets (atomicstatus, goid, waitreason, gopc, startpc)
    are version-specific and handled for each minor release from 1.15 to 1.25.

Dependencies:
    - pefile library (ELF parsing for cached binary)
    - External: go_file_classifier, third_party_analyzer modules
    - Pre-built function DB: go_func_lines_v<VERSION>.json
    - Pre-built heap addresses: heap_strings_pid_<PID>.json
 
       
Usage:
    vol.py -f <image> linux.go_goroutines.Go_Goroutines --pid <PID>
     
References:
    - Go runtime goroutine struct: https://go.dev/src/runtime/runtime2.go
    - Go runtime symtab (pclntab/moduledata): https://go.dev/src/runtime/symtab.go
    - Go ABI specification: https://go.dev/src/internal/abi/
    - Go register ABI (1.17+): https://go.dev/src/cmd/compile/abi-internal.md
    - Go scheduler internals: https://go.dev/src/runtime/proc.go

"""

import logging
from typing import List, Tuple, Generator, Optional, Dict, Set
from volatility3.framework import interfaces, exceptions, constants, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.linux.extensions import elf
from volatility3.framework import objects
from volatility3.plugins.linux import pslist
from volatility3.plugins.linux.pagecache import Files, InodePages
from io import BytesIO
from volatility3.plugins.linux.go_file_classifier import classify_go_filepath
from volatility3.plugins.linux.go_classifier import _strip_wrapper_suffix
import re
import json
import os
import pandas as pd
from datetime import datetime
from openai import OpenAI

vollog = logging.getLogger(__name__)


class Go_Goroutines(interfaces.plugins.PluginInterface):
    _required_framework_version = (2, 0, 0)
    _version = (2, 0, 0)

    # ELF Constants
    ET_NONE = 0
    ET_REL = 1
    ET_EXEC = 2
    ET_DYN = 3
    ET_CORE = 4

    PT_NULL = 0
    PT_LOAD = 1
    PT_DYNAMIC = 2
    PT_INTERP = 3
    PT_NOTE = 4
    PT_SHLIB = 5
    PT_PHDR = 6
    PT_TLS = 7
    PT_GNU_EH_FRAME = 0x6474e550
    PT_GNU_STACK = 0x6474e551
    PT_GNU_RELRO = 0x6474e552

    PF_X = 0x1
    PF_W = 0x2
    PF_R = 0x4

    # Go version magic bytes
    GO_MAGIC_120 = b'\xf1\xff\xff\xff'
    GO_MAGIC_118 = b'\xf0\xff\xff\xff'
    GO_MAGIC_116 = b'\xfa\xff\xff\xff'
    GO_MAGIC_12 = b'\xfb\xff\xff\xff'

    GO_MAGICS = {
        GO_MAGIC_120: {'version': 'Go 1.20+', 'has_textstart': True},
        GO_MAGIC_118: {'version': 'Go 1.18-1.19', 'has_textstart': True},
        GO_MAGIC_116: {'version': 'Go 1.16-1.17', 'has_textstart': False},
        GO_MAGIC_12: {'version': 'Go 1.2-1.15', 'has_textstart': False},
    }
    
    #FUNCDATA indices (Go 1.18+)
    FUNCDATA_ArgsPointerMaps = 0
    FUNCDATA_LocalsPointerMaps = 1
    FUNCDATA_StackObjects = 2
    FUNCDATA_InlTree = 3
    FUNCDATA_OpenCodedDeferInfo = 4
    FUNCDATA_ArgInfo = 5          
    FUNCDATA_ArgLiveInfo = 6
    FUNCDATA_WrapInfo = 7

    FUNCDATA_NAMES = {
    0: "ArgsPointerMaps",
    1: "LocalsPointerMaps",
    2: "StackObjects",
    3: "InlTree",
    4: "OpenCodedDeferInfo",
    5: "ArgInfo",            
    6: "ArgLiveInfo",
    7: "WrapInfo",
    }
     # Type kind constants (from reflect/type.go)
    TYPE_KINDS = {
        1: "bool",
        2: "int",
        3: "int8",
        4: "int16",
        5: "int32",
        6: "int64",
        7: "uint",
        8: "uint8",
        9: "uint16",
        10: "uint32",
        11: "uint64",
        12: "uintptr",
        13: "float32",
        14: "float64",
        15: "complex64",
        16: "complex128",
        17: "array",
        18: "chan",
        19: "func",
        20: "interface",
        21: "map",
        22: "pointer",
        23: "slice",
        24: "string",
        25: "struct",
        26: "unsafe.Pointer",
    }

    # PCDATA indices (Go 1.18+)
    PCDATA_UnsafePoint   = 0
    PCDATA_StackMapIndex = 1
    PCDATA_InlTreeIndex  = 2
    PCDATA_ArgLiveIndex  = 3

    PCDATA_NAMES = {
        0: "UnsafePoint",
        1: "StackMapIndex",
        2: "InlTreeIndex",
        3: "ArgLiveIndex",
    }
    
    VALID_G_STATUS = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
    G_STATUS_NAMES = {
        0: "idle", 1: "runnable", 2: "running", 3: "syscall",
        4: "waiting", 5: "moribund", 6: "dead", 7: "enqueue",
        8: "copystack", 9: "preempted",
    }
    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.ListRequirement(
                name="pid",
                description="PID(s) of the process(es) to analyze",
                element_type=int,
                optional=False,
            ),
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.types_cache: Dict[int, Dict] = {}
        self.moduledata: Optional[Dict] = None
        self.types_start: int = 0
        self.layer_name: str = ""
        self.pclntab: Optional[Dict] = None 
        self.data_to_type_map = {}
        self.locals = {}
        self.go_version_str = "unknown"     
        self.go_version_tuple = (0, 0, 0)
        self.goroutine_data = {} 
        self.type_method_arguments = {}   # {func_pc: {frame_key: {arg_idx: {...}}}}
        self.non_type_method_arguments = {}  # {func_pc: {frame_key: {arg_idx: {...}}}}
   
    # =========================================================================
    # Load LOcal DB based on the version
    # =========================================================================

    def _load_external_func_db(self, go_version: str) -> Dict:
      """Load pre-built function line database."""
      version_str = go_version.replace(".", "")
      db_file = f"/home/hala/file_func_params_extractor/go_func_lines_v1125.json"  # Update this path
    
      if os.path.exists(db_file):
        with open(db_file, 'r') as f:
            return json.load(f)
      return {}
    
    def _load_heap_addresses(self):
        filepath = "/home/hala/volatility3/heap_strings_pid_2795.json"
        with open(filepath, 'r') as f:
            data = json.load(f)
        heap_addresses= {}
        for struct_addr_hex, info in data.items():
            struct_addr = int(struct_addr_hex, 16)
            heap_addresses[struct_addr] = info

        return heap_addresses
    
 
    # =========================================================================
    # Helper Methods
    # =========================================================================
    
    def _decode_p_type(self, p_type: int) -> str:
        """Decode program header type."""
        types = {
            self.PT_NULL: "PT_NULL",
            self.PT_LOAD: "PT_LOAD",
            self.PT_DYNAMIC: "PT_DYNAMIC",
            self.PT_INTERP: "PT_INTERP",
            self.PT_NOTE: "PT_NOTE",
            self.PT_PHDR: "PT_PHDR",
            self.PT_TLS: "PT_TLS",
            self.PT_GNU_EH_FRAME: "PT_GNU_EH_FRAME",
            self.PT_GNU_STACK: "PT_GNU_STACK",
            self.PT_GNU_RELRO: "PT_GNU_RELRO",
        }
        return types.get(p_type, f"0x{p_type:x}")

    def _decode_p_flags(self, p_flags: int) -> str:
        """Decode program header flags to RWX string."""
        flags = ""
        flags += "R" if p_flags & self.PF_R else "-"
        flags += "W" if p_flags & self.PF_W else "-"
        flags += "X" if p_flags & self.PF_X else "-"
        return flags

    def _read_cstring(self, address: int, max_length: int = 512) -> str:
        """Read a null-terminated string from memory."""
        try:
            layer = self.context.layers[self.layer_name]
            data = layer.read(address, max_length, pad=True)
            null_idx = data.find(b"\x00")
            if null_idx != -1:
                data = data[:null_idx]
            return data.decode("utf-8", errors="replace")
        except:
            return "<unreadable>"

   
    def _read_pointer(self, addr: int) -> int:
        """Read a pointer (8 bytes on 64-bit)."""
        layer = self.context.layers[self.layer_name]
        data = layer.read(addr, 8, pad=True)
        return int.from_bytes(data, 'little')
    
    def _read_uint32(self, addr: int) -> int:
        """Read 4-byte uint32."""
        layer = self.context.layers[self.layer_name]
        data = layer.read(addr, 4, pad=True)
        return int.from_bytes(data, 'little')
    
    def _read_uint16(self, addr: int) -> int:
        """Read 2-byte uint16."""
        layer = self.context.layers[self.layer_name]
        data = layer.read(addr, 2, pad=True)
        return int.from_bytes(data, 'little')
    
    def _read_uint8(self, addr: int) -> int:
        """Read 1-byte uint8."""
        layer = self.context.layers[self.layer_name]
        data = layer.read(addr, 1, pad=True)
        return data[0]

    
    # =========================================================================
    # ELF Parsing
    # =========================================================================

    def _parse_elf_header(self, elf_table_name: str, base_addr: int) -> Optional[Dict]:
        """Parse ELF header and extract metadata."""
        result = {"valid": False, "base_addr": base_addr}

        try:
            layer = self.context.layers[self.layer_name]
            e_ident = layer.read(base_addr, 16, pad=True)

            if e_ident[:4] != b"\x7fELF":
                return result

            ei_class = e_ident[4]  # 1=32-bit, 2=64-bit
            ei_data = e_ident[5]   # 1=little-endian, 2=big-endian

            result["ei_class"] = ei_class
            result["ei_data"] = ei_data

            # Select appropriate header type
            header_type = "Elf64_Ehdr" if ei_class == 2 else "Elf32_Ehdr"
            full_type = elf_table_name + constants.BANG + header_type

            ehdr = self.context.object(
                full_type,
                offset=base_addr,
                layer_name=self.layer_name,
            )

            result["e_type"] = int(ehdr.e_type)
            result["e_machine"] = int(ehdr.e_machine)
            result["e_entry"] = int(ehdr.e_entry)
            result["e_phoff"] = int(ehdr.e_phoff)
            result["e_phentsize"] = int(ehdr.e_phentsize)
            result["e_phnum"] = int(ehdr.e_phnum)
            result["valid"] = True

        except Exception as e:
            vollog.debug(f"Error parsing ELF header: {e}")

        return result

    def _parse_program_headers(self, elf_table_name: str, header_info: Dict) -> List[Dict]:
        """
        Parse ELF program headers into a list of segment dicts.
        Each segment dict contains: index, p_type, p_flags_str (R/W/X),
        runtime_vaddr, runtime_end, and p_memsz. For PIE binaries (ET_DYN),
        runtime_vaddr is rebased to base_addr + p_vaddr.
        """
        segments = []

        if not header_info.get("valid"):
            return segments

        base_addr = header_info["base_addr"]
        ei_class = header_info["ei_class"]
        e_type = header_info["e_type"]
        ph_offset = header_info["e_phoff"]
        ph_size = header_info["e_phentsize"]
        ph_count = header_info["e_phnum"]

        phdr_type = "Elf64_Phdr" if ei_class == 2 else "Elf32_Phdr"
        full_type = elf_table_name + constants.BANG + phdr_type

        for idx in range(ph_count):
            try:
                ph_addr = base_addr + ph_offset + (idx * ph_size)

                phdr = self.context.object(
                    full_type,
                    offset=ph_addr,
                    layer_name=self.layer_name,
                )

                p_type = int(phdr.p_type)
                p_flags = int(phdr.p_flags)
                p_vaddr = int(phdr.p_vaddr)
                p_memsz = int(phdr.p_memsz)

                # Calculate runtime address
                if e_type == self.ET_DYN:
                    runtime_vaddr = base_addr + p_vaddr
                else:
                    runtime_vaddr = p_vaddr

                segment = {
                    "index": idx,
                    "p_type": p_type,
                    "p_type_str": self._decode_p_type(p_type),
                    "p_flags": p_flags,
                    "p_flags_str": self._decode_p_flags(p_flags),
                    "runtime_vaddr": runtime_vaddr,
                    "runtime_end": runtime_vaddr + p_memsz,
                    "p_memsz": p_memsz,
                }

                segments.append(segment)

            except:
                break

        return segments

    # =========================================================================
    # Go Runtime Structure Discovery
    # =========================================================================
# =========================================================================
    # Go Runtime Structure Discovery
    # =========================================================================

    
    def _find_pclntab(self, segments: List[Dict]) -> Optional[Dict]:
        """
        Find the Go pclntab (PC-line table) in read-only sections.

        Two-pass strategy: first scans for known magic bytes (works for
        standard Go binaries), then falls back to structural validation
        (works for Garble-obfuscated binaries with randomized magic).
        Returns pcHeader dict or None.
        """
        result = self._find_pclntab_by_magic(segments)
        if result:
            return result
        print("[*] Standard magic bytes not found, trying structural detection")
        result = self._find_pclntab_structural(segments)
        if result:
            print(f"[+] Found pclntab via structural detection")
            return result
        return None

    def _find_pclntab_by_magic(self, segments: List[Dict]) -> Optional[Dict]:
        """Original magic-byte based pclntab detection."""
        rodata_segment = None
        for seg in segments:
            if seg["p_type"] == self.PT_LOAD and seg["p_flags_str"] == "R--":
                rodata_segment = seg
                break
        if not rodata_segment:
            return None
        start = rodata_segment["runtime_vaddr"]
        end = rodata_segment["runtime_end"]
        print(f"\n[*] Scanning for pclntab (magic bytes) in RODATA: {hex(start)}-{hex(end)}")
        layer = self.context.layers[self.layer_name]
        magic_bytes_list = list(self.GO_MAGICS.keys())
        chunk_size = 0x10000
        current = start
        while current < end:
            try:
                read_size = min(chunk_size, end - current)
                data = layer.read(current, read_size, pad=True)
                for magic_bytes in magic_bytes_list:
                    pos = 0
                    while True:
                        pos = data.find(magic_bytes, pos)
                        if pos == -1:
                            break
                        candidate_addr = current + pos
                        result = self._validate_pcheader(candidate_addr)
                        if result:
                            print(f"[+] Found pclntab at {hex(candidate_addr)}")
                            return result
                        pos += 4
                current += chunk_size - 4
            except:
                current += chunk_size
        return None

    
    
    
    def _validate_pcheader(self, address: int) -> Optional[Dict]:
        """Validate a potential pcHeader structure."""
        try:
            layer = self.context.layers[self.layer_name]
            header = layer.read(address, 32, pad=True)

            if len(header) < 16:
                return None

            magic = header[0:4]
            if magic not in self.GO_MAGICS:
                return None

            version_info = self.GO_MAGICS[magic]

            # Validate padding
            if header[4] != 0 or header[5] != 0:
                return None

            # Validate minLC and ptrSize
            minLC = header[6]
            ptrSize = header[7]

            if minLC not in (1, 2, 4) or ptrSize not in (4, 8):
                return None

            # Parse counts
            nfunc = int.from_bytes(header[8:12], 'little')
            nfiles = int.from_bytes(header[12:16], 'little')

            if nfunc == 0 or nfunc > 50000000 or nfiles > 10000000:
                return None

            return {
                "address": address,
                "magic": magic,
                "version": version_info['version'],
                "has_textstart": version_info['has_textstart'],
                "minLC": minLC,
                "ptrSize": ptrSize,
                "nfunc": nfunc,
                "nfiles": nfiles,
            }

        except:
            return None

    def _find_pclntab_structural(self, segments: List[Dict]) -> Optional[Dict]:
        """
        Find pclntab using structural validation - works with Garble'd binaries.

        Garble (since v0.9.0) randomizes the magic bytes, but the rest of the
        pcHeader structure remains valid:
        - Bytes [4:6] must be 0x00, 0x00 (padding)
        - Byte [6] (minLC) must be 1, 2, or 4
        - Byte [7] (ptrSize) must be 4 or 8
        - Bytes [8:12] (nfunc) must be reasonable
        - Bytes [12:16] (nfiles) must be reasonable
        """
        rodata_segment = None
        for seg in segments:
            if seg["p_type"] == self.PT_LOAD and seg["p_flags_str"] == "R--":
                rodata_segment = seg
                break

        if not rodata_segment:
            return None

        start = rodata_segment["runtime_vaddr"]
        end = rodata_segment["runtime_end"]

        print(f"\n[*] Scanning for pclntab (structural) in RODATA: {hex(start)}-{hex(end)}")

        layer = self.context.layers[self.layer_name]

        alignment = 4
        chunk_size = 0x10000
        current = start
        candidates_checked = 0

        while current < end:
            try:
                read_size = min(chunk_size, end - current)
                data = layer.read(current, read_size, pad=True)

                for offset in range(0, read_size - 32, alignment):
                    if data[offset + 4] != 0 or data[offset + 5] != 0:
                        continue

                    minLC = data[offset + 6]
                    if minLC not in (1, 2, 4):
                        continue

                    ptrSize = data[offset + 7]
                    if ptrSize not in (4, 8):
                        continue

                    nfunc = int.from_bytes(data[offset + 8:offset + 12], 'little')
                    nfiles = int.from_bytes(data[offset + 12:offset + 16], 'little')

                    if nfunc == 0 or nfunc > 50000000:
                        continue
                    if nfiles > 10000000:
                        continue

                    candidate_addr = current + offset
                    candidates_checked += 1

                    result = self._validate_pcheader_structural(candidate_addr, data[offset:offset + 64])
                    if result:
                        print(f"[+] Found pclntab (structural) at {hex(candidate_addr)}")
                        print(f"    Version: {result['version']}")
                        print(f"    Functions: {result['nfunc']}")
                        print(f"    Candidates checked: {candidates_checked}")
                        return result

                current += chunk_size - 64

            except Exception as e:
                vollog.debug(f"Error scanning chunk at {hex(current)}: {e}")
                current += chunk_size

        print(f"[*] Structural scan complete, checked {candidates_checked} candidates")
        return None

    def _validate_pcheader_structural(self, address: int, header: bytes) -> Optional[Dict]:
        """Validate a potential pcHeader using structural checks (no magic dependency)."""
        try:
            if len(header) < 80:
                layer = self.context.layers[self.layer_name]
                header = layer.read(address, 80, pad=True)

            if len(header) < 80:
                return None

            if header[4] != 0 or header[5] != 0:
                return None

            minLC = header[6]
            ptrSize = header[7]

            if minLC not in (1, 2, 4) or ptrSize not in (4, 8):
                return None

            if ptrSize == 8:
                nfunc = int.from_bytes(header[8:16], 'little')
                nfiles = int.from_bytes(header[16:24], 'little')
                textStart = int.from_bytes(header[24:32], 'little')
                funcnameOffset = int.from_bytes(header[32:40], 'little')
                cuOffset = int.from_bytes(header[40:48], 'little')
                filetabOffset = int.from_bytes(header[48:56], 'little')
                pctabOffset = int.from_bytes(header[56:64], 'little')
                pclnOffset = int.from_bytes(header[64:72], 'little')
            else:
                nfunc = int.from_bytes(header[8:12], 'little')
                nfiles = int.from_bytes(header[12:16], 'little')
                textStart = int.from_bytes(header[16:20], 'little')
                funcnameOffset = int.from_bytes(header[20:24], 'little')
                cuOffset = int.from_bytes(header[24:28], 'little')
                filetabOffset = int.from_bytes(header[28:32], 'little')
                pctabOffset = int.from_bytes(header[32:36], 'little')
                pclnOffset = int.from_bytes(header[36:40], 'little')

            if nfunc == 0 or nfunc > 50000000 or nfiles > 10000000:
                return None

            magic = header[0:4]

            has_textstart = False
            version_str = "unknown"

            if ptrSize == 8:
                if textStart > 0x100000 and funcnameOffset < 0x1000000:
                    has_textstart = True
                    version_str = "Go 1.20+"
                elif textStart < 0x100000 and textStart > 0:
                    has_textstart = False
                    version_str = "Go 1.16-1.17"
                else:
                    has_textstart = True
                    version_str = "Go 1.20+"
            else:
                has_textstart = textStart > 0x100000
                version_str = "Go 1.18+ (32-bit)" if has_textstart else "Go 1.16-1.17 (32-bit)"

            if not self._validate_funcnametab_heuristic(address, ptrSize, nfunc):
                return None

            return {
                "address": address,
                "magic": magic,
                "version": version_str,
                "has_textstart": has_textstart,
                "minLC": minLC,
                "ptrSize": ptrSize,
                "nfunc": nfunc,
                "nfiles": nfiles,
                "textStart": textStart if has_textstart else 0,
                "funcnameOffset": funcnameOffset,
                "cuOffset": cuOffset,
                "filetabOffset": filetabOffset,
                "pctabOffset": pctabOffset,
                "pclnOffset": pclnOffset,
            }

        except Exception as e:
            vollog.debug(f"Error validating pcheader @ {hex(address)}: {e}")
            return None

    def _validate_funcnametab_heuristic(self, pclntab_addr: int, ptrSize: int, nfunc: int) -> bool:
        """
        Heuristic validation: check if funcnametab contains valid-looking function names.
        Helps filter false positives from structural matching.
        """
        try:
            layer = self.context.layers[self.layer_name]

            header_size = 64 if ptrSize == 8 else 32
            header = layer.read(pclntab_addr, header_size, pad=True)

            if ptrSize == 8:
                funcname_offset = int.from_bytes(header[24:32], 'little')
                if funcname_offset > 0x400000:
                    funcname_offset = int.from_bytes(header[32:40], 'little')
            else:
                funcname_offset = int.from_bytes(header[16:20], 'little')

            if funcname_offset == 0 or funcname_offset > 0x10000000:
                return True

            funcnametab_addr = pclntab_addr + funcname_offset
            sample_data = layer.read(funcnametab_addr, 256, pad=True)

            valid_chars = 0
            null_count = 0

            for b in sample_data:
                if b == 0:
                    null_count += 1
                elif 0x20 <= b <= 0x7E:
                    valid_chars += 1

            if null_count < 2:
                return False
            if valid_chars < len(sample_data) * 0.3:
                return False

            return True

        except Exception:
            return True
    
    def _extract_go_version(self, segments: List[Dict]) -> str:
      """
      Extract exact Go version string from binary.
      Works with stripped binaries - searches RODATA for "go1.X.Y" pattern.
      """
      try:
        layer = self.context.layers[self.layer_name]
        
        # Search in RODATA segment only
        for seg in segments:
            if seg["p_type"] == self.PT_LOAD and seg["p_flags_str"] == "R--":
                start = seg["runtime_vaddr"]
                end = seg["runtime_end"]
                
                # Read the entire RODATA (typically < 2MB)
                size = end - start
                if size > 0x400000:  # Skip if > 4MB (safety check)
                    continue
                
                try:
                    data = layer.read(start, size, pad=True)
                    
                    # Search for "go1." pattern
                    pos = data.find(b'go1.')
                    if pos != -1:
                        # Extract version (next 10 chars after "go1.")
                        version_bytes = data[pos:pos+15]
                        
                        # Find end (null, space, newline, or non-ASCII)
                        end_pos = 4  # Start after "go1."
                        while end_pos < len(version_bytes):
                            c = version_bytes[end_pos]
                            if c in [0, 0x20, 0x0a, 0x0d] or c > 127:
                                break
                            end_pos += 1
                        
                        version_str = version_bytes[:end_pos].decode('ascii', errors='ignore')
                        
                        # Validate: must be "go1.XX" or "go1.XX.Y"
                        if len(version_str) >= 6 and version_str[4].isdigit():
                            return version_str
                
                except:
                    continue
        
        # Fallback: return pclntab detection
        return "unknown"
        
      except Exception as e:
        return "unknown"

    def _parse_go_version(self, version_str: str) -> tuple:
      """
      Parse "go1.XX.Y" to (1, XX, Y).
      Examples: "go1.24.0" → (1, 24, 0), "go1.20" → (1, 20, 0)
      """
      if version_str == "unknown":
        return (0, 0, 0)
    
      try:
        # Remove "go" prefix
        version_str = version_str.replace('go', '')
        parts = version_str.split('.')
        
        major = int(parts[0])
        minor = int(''.join(c for c in parts[1] if c.isdigit()))
        patch = int(''.join(c for c in parts[2] if c.isdigit())) if len(parts) >= 3 else 0
        
        return (major, minor, patch)
      except:
        return (0, 0, 0)
   
   
     
    def _find_moduledata(self, segments: List[Dict], pclntab_addr: int, ptrSize: int, go_version: str) -> Optional[Dict]:

        """
        Locate the runtime.moduledata struct by scanning RW sections.

        Searches for a pointer to pclntab_addr in writable memory, then
        validates the surrounding fields as a moduledata struct. Dispatches
        to version-specific validators: _validate_moduledata for Go 1.16+,
        _validate_moduledata_go115 for Go 1.2-1.15.
        """
        major, minor, _ = self.go_version_tuple
        is_go_116_plus = (major == 1 and minor >= 16) or major > 1
       
        rw_segment = None
        for seg in segments:
            if seg["p_type"] == self.PT_LOAD and seg["p_flags_str"] == "RW-":
                rw_segment = seg
                break

        if not rw_segment:
            return None

        start = rw_segment["runtime_vaddr"]
        end = rw_segment["runtime_end"]

       
        print(f"\n[*] Scanning for moduledata in RW segment: {hex(start)}-{hex(end)}")

        layer = self.context.layers[self.layer_name]

        if ptrSize == 8:
            target_bytes = pclntab_addr.to_bytes(8, 'little')
        else:
            target_bytes = pclntab_addr.to_bytes(4, 'little')

        chunk_size = 0x10000
        current = start

        while current < end:
            try:
                read_size = min(chunk_size, end - current)
                data = layer.read(current, read_size, pad=True)

                pos = 0
                while True:
                    pos = data.find(target_bytes, pos)
                    if pos == -1:
                        break

                    candidate_addr = current + pos
                    if candidate_addr % ptrSize != 0:
                        pos += 1
                        continue

                    if is_go_116_plus:
                        result = self._validate_moduledata(candidate_addr, pclntab_addr, ptrSize, go_version, segments)
                    else:
                        result = self._validate_moduledata_go115(candidate_addr, pclntab_addr, ptrSize, segments)
               
                    if result:
                        return result

                    pos += ptrSize

                current += chunk_size - ptrSize

            except:
                current += chunk_size

        return None
    
    
    def _validate_moduledata(self, address: int, pclntab_addr: int, ptrSize: int, go_version: str, segments: List[Dict]) -> Optional[Dict]:
      """
      Validate and parse a moduledata candidate for Go 1.16+.

      Reads 600 bytes at address and parses version-specific fields:
      Go 1.16-1.17: no etypes/rodata/gofunc fields, derives rodata from segments.
      Go 1.18-1.19: adds etypes, rodata, gofunc, itablink.
      Go 1.20+: adds covctrs/ecovctrs before the end field.
      Returns parsed moduledata dict or None if validation fails.
      https://go.dev/src/runtime/symtab.go
      """
      
      try:
        layer = self.context.layers[self.layer_name]
        data = layer.read(address, 600, pad=True)

        if len(data) < 600:
            return None

        def read_ptr(offset: int) -> int:
            if ptrSize == 8:
                return int.from_bytes(data[offset:offset+8], 'little')
            else:
                return int.from_bytes(data[offset:offset+4], 'little')

        def read_slice(offset: int) -> Tuple[int, int, int]:
            ptr = read_ptr(offset)
            length = read_ptr(offset + ptrSize)
            cap = read_ptr(offset + ptrSize * 2)
            return (ptr, length, cap)

        # Field 0: pcHeader pointer - MUST match
        pcHeader_ptr = read_ptr(0)
        if pcHeader_ptr != pclntab_addr:
            return None

        # Parse slices
        offset = ptrSize
        slice_size = ptrSize * 3

        slices = {}
        slice_names = ['funcnametab', 'cutab', 'filetab', 'pctab', 'pclntable', 'ftab']

        for name in slice_names:
            ptr, length, cap = read_slice(offset)
            
            # Validate slice
            if length > cap or cap > 0x40000000:
                return None

            slices[name] = {'ptr': ptr, 'len': length, 'cap': cap}
            offset += slice_size

        # Parse key pointers
        findfunctab = read_ptr(offset)
        offset += ptrSize

        minpc = read_ptr(offset)
        offset += ptrSize
        maxpc = read_ptr(offset)
        offset += ptrSize

        text = read_ptr(offset)
        offset += ptrSize
        etext = read_ptr(offset)
        offset += ptrSize

        noptrdata = read_ptr(offset)
        offset += ptrSize
        enoptrdata = read_ptr(offset)
        offset += ptrSize

        data_start = read_ptr(offset)
        offset += ptrSize
        edata = read_ptr(offset)
        offset += ptrSize

        bss = read_ptr(offset)
        offset += ptrSize
        ebss = read_ptr(offset)
        offset += ptrSize

        noptrbss = read_ptr(offset)
        offset += ptrSize
        enoptrbss = read_ptr(offset)
        offset += ptrSize
        
        # Determine Go version
        is_go_118_plus = False
        is_go_120_plus = False
        major, minor, patch = self.go_version_tuple
        is_go_118_plus = (major == 1 and minor >= 18) 
        is_go_120_plus= (major == 1 and minor >= 20)
        is_go_116_117= (major == 1 and minor >= 16 and minor <18) 
        if is_go_116_117:
            # end, gcdata, gcbss
            end = read_ptr(offset)
            offset += ptrSize
            gcdata = read_ptr(offset)
            offset += ptrSize
            gcbss = read_ptr(offset)
            offset += ptrSize

            # types, etypes - Go 1.16 HAS these fields
            types = read_ptr(offset)
            offset += ptrSize
            etypes = read_ptr(offset)
            offset += ptrSize

            # Go 1.16-1.17: NO rodata/gofunc - goes directly to textsectmap
            # Derive rodata from RODATA segment
            rodata = 0
            erodata = 0
            gofunc = 0
            for seg in segments:
                if seg["p_type"] == self.PT_LOAD and seg["p_flags_str"] == "R--":
                    rodata = seg["runtime_vaddr"]
                    erodata = seg["runtime_end"]
                    break

            # textsectmap (slice)
            textsectmap_ptr, textsectmap_len, textsectmap_cap = read_slice(offset)
            offset += slice_size

            # typelinks (slice) - contains int32 offsets from types
            typelinks_ptr, typelinks_len, typelinks_cap = read_slice(offset)
            offset += slice_size

            # itablinks (slice of *itab)
            itablinks_ptr, itablinks_len, itablinks_cap = read_slice(offset)
            offset += slice_size

            # Fix funcnametab length for Go 1.16
            funcnametab_start = slices['funcnametab']['ptr']
            cutab_start = slices['cutab']['ptr']
            actual_funcnametab_len = cutab_start - funcnametab_start
            slices['funcnametab']['len'] = actual_funcnametab_len

            print(f"\n ========== MODULEDATA ==========")
            print(f"  Go Version: {go_version}")
            print(f"  moduledata: {hex(address)}")
            print(f"  text: {hex(text)} - {hex(etext)}")
            print(f"  types: {hex(types)} - {hex(etypes)}")
            print(f"  rodata (from segment): {hex(rodata)} - {hex(erodata)}")
            print(f"  data: {hex(data_start)} - {hex(edata)}")
            print(f"  typelinks: {typelinks_len} entries @ {hex(typelinks_ptr)}")
            print(f"  itablinks: {itablinks_len} entries @ {hex(itablinks_ptr)}")

            # Validate
            valid_ranges = 0
            if minpc != 0 and maxpc != 0 and minpc < maxpc:
                valid_ranges += 1
            if text != 0 and etext != 0 and text < etext:
                valid_ranges += 1
            if types != 0 and etypes != 0 and types < etypes:
                valid_ranges += 1

            if valid_ranges < 2:
                return None

            print(f"[+] Found moduledata at {hex(address)}")

            return {
                'address': address,
                'pcHeader': pcHeader_ptr,
                'funcnametab': slices['funcnametab'],
                'filetab': slices['filetab'],
                'pctab': slices['pctab'],
                'pclntable': slices['pclntable'],
                'cutab': slices['cutab'],  
                'ftab': slices['ftab'],
                'minpc': minpc,
                'maxpc': maxpc,
                'text': text,
                'etext': etext,
                'noptrbss':noptrbss,
                'enoptrbss':enoptrbss,
                'bss': bss,
                'ebss': ebss,
                'types': types,
                'etypes': etypes,
                'data_start': data_start,
                'edata': edata,
                'rodata': rodata,
                'erodata': erodata,
                'gofunc': gofunc,
                'typelinks': {'ptr': typelinks_ptr, 'len': typelinks_len, 'cap': typelinks_cap},
                'itablink': {'ptr': itablinks_ptr, 'len': itablinks_len, 'cap': itablinks_cap},
                'mheap_ptr': 0
            }
       
        if is_go_120_plus:
            offset += ptrSize * 2  # Skip covctrs and ecovctrs

        end = read_ptr(offset)
        offset += ptrSize
        gcdata = read_ptr(offset)
        offset += ptrSize
        gcbss = read_ptr(offset)
        offset += ptrSize

        types = read_ptr(offset)
        offset += ptrSize
        
        
        if is_go_118_plus:
            # Go 1.18+: etypes field exists, read it first
            etypes = read_ptr(offset)
            offset += ptrSize
            
        else:
            # Go 1.16-1.17: NO etypes field, estimate it
            etypes = 0  # Will estimate below 
            
        rodata = read_ptr(offset)
        offset += ptrSize
       
        erodata = None
        for seg in segments:
            if seg["p_type"] == self.PT_LOAD and seg["p_flags_str"] == "R--":
               seg_start = seg["runtime_vaddr"]
               seg_end = seg["runtime_end"]
               if seg_start <= rodata < seg_end:
                  erodata = seg_end
                  break
        
        # Fallback if not found
        if erodata is None:
            erodata = etypes
        
        gofunc = read_ptr(offset)
        offset += ptrSize

        # Field 29: textsectmap (slice)
        textsectmap_ptr, textsectmap_len, textsectmap_cap = read_slice(offset)
        offset += slice_size

        # Field 30: typelinks (slice)
        typelinks_ptr, typelinks_len, typelinks_cap = read_slice(offset)
        offset += slice_size
        
        # Field 31: itablink (slice) - ONLY IN GO 1.18+
        if is_go_118_plus:
            itablink_ptr, itablink_len, itablink_cap = read_slice(offset)
            offset += slice_size
            
        else:
            itablink_ptr = 0
            itablink_len = 0
            itablink_cap = 0

        mheap_ptr = 0
        print(f"\n========== SLICE POINTER ANALYSIS ==========")
        print(f" Go Version: {go_version}")
        print(f" Is Go 1.18+: {is_go_118_plus}")
        print(f"\n Base addresses:")
        print(f"  moduledata: {hex(address)}")
        print("-------------------")
        print(f"  text: {hex(text)}")
        print(f"  text: {hex(etext)}")
        print("-------------------")
        print(f"  bss: {hex(bss)}")
        print(f"  ebss: {hex(ebss)}")
        print("-------------------")
        print(f"  types: {hex(types)}")
        print(f"  etypes: {hex(etypes)}")
        print("-------------------")
        print("Types and RODATA overlapping is NORMAL:In Go binaries, the types section is embedded within the RODATA section. This is by design.")
        print(f"  rodata: {hex(rodata)}")
        print(f"  erodata: {hex(erodata)}")  
        print("-------------------")
        print(f"  data: {hex(data_start )}")
        print(f"  edata: {hex(edata)}")
        print("-------------------")
        print(f"  gofunc: {hex(gofunc)}")

        # In Go 1.16-1.17, slice pointers are OFFSETS, not addresses
        if not is_go_118_plus:
          print(f"\n Converting Go 1.16-1.17 offsets to addresses...") 
          funcnametab_start = slices['funcnametab']['ptr']
          cutab_start = slices['cutab']['ptr']
          actual_funcnametab_len = cutab_start - funcnametab_start
    
          print(f"  funcnametab: {hex(funcnametab_start)}")
          print(f"  cutab: {hex(cutab_start)}")
          print(f"  Stored length: {slices['funcnametab']['len']}")
          print(f"  Calculated actual length: {actual_funcnametab_len}")
          slices['funcnametab']['len'] = actual_funcnametab_len

            

        for name in ['funcnametab', 'cutab', 'filetab', 'pctab', 'pclntable', 'ftab']:
            s = slices[name]
            print(f"  {name}: ptr={hex(s['ptr'])}, len={s['len']}, cap={s['cap']}")
        # Validate ranges
        valid_ranges = 0
        if minpc != 0 and maxpc != 0 and minpc < maxpc:
            valid_ranges += 1
        if text != 0 and etext != 0 and text < etext:
            valid_ranges += 1
        if types != 0 and etypes != 0 and types < etypes:
            valid_ranges += 1

        if valid_ranges < 2:
            return None

        print(f"[+] Found moduledata at {hex(address)}")
        print(f"    text: {hex(text)}-{hex(etext)}")
        print(f"    types: {hex(types)}-{hex(etypes)}")
        print(f"    data: {hex(data_start)}-{hex(edata)}")   
        print(f"    rodata: {hex(rodata)}-{hex(erodata)}")
        print(f"    typelinks: {typelinks_len} entries @ {hex(typelinks_ptr)}")
        print(f"    itablink: {itablink_len} entries @ {hex(itablink_ptr)}")
        print(f"\n{'='*80}")
        print(f"FUNCNAMETAB RAW DATA INSPECTION")
        print(f"{'='*80}")
        print(f"funcnametab ptr: {hex(slices['funcnametab']['ptr'])}")
        print(f"funcnametab len: {slices['funcnametab']['len']}")

        try:
           layer = self.context.layers[self.layer_name]
        except Exception as e:
           print(f"ERROR during inspection: {e}")

        print(f"{'='*80}\n")
        # ========== END FUNCNAMETAB RAW INSPECTION ==========
        return {
            'address': address,
            'pcHeader': pcHeader_ptr,
            'funcnametab': slices['funcnametab'],
            'filetab': slices['filetab'],
            'pctab': slices['pctab'],
            'pclntable': slices['pclntable'],
            'cutab': slices['cutab'],  
            'ftab': slices['ftab'],
            'minpc': minpc,
            'maxpc': maxpc,
            'text': text,
            'etext': etext,
            'noptrbss':noptrbss,
            'enoptrbss':enoptrbss,
            'bss': bss,
            'ebss': ebss,
            'types': types,
            'etypes': etypes,
            'data_start': data_start,
            'edata': edata,
            'rodata': rodata,
            'erodata': erodata,
            'gofunc': gofunc,
            'typelinks': {'ptr': typelinks_ptr, 'len': typelinks_len, 'cap': typelinks_cap},
            'itablink': {'ptr': itablink_ptr, 'len': itablink_len, 'cap': itablink_cap},
            'mheap_ptr': mheap_ptr
        }

      except Exception as e:
        vollog.debug(f"Error validating moduledata: {e}")
        return None
    

    
    def _validate_moduledata_go115(self, address: int, pclntab_addr: int, ptrSize: int, segments) -> dict:
      """
      Validate and parse a moduledata candidate for Go 1.2-1.15.

      Go 1.15 moduledata starts with pclntable (not pcHeader pointer),
      has fixed offsets for all fields, and uses filetab as uint32 offsets
      into pclntab for filenames. funcnametab and pctab are aliased to
      pclntable since Go 1.15 stores everything in one contiguous blob.
      """
      try:
        layer = self.context.layers[self.layer_name]
        
        # Read enough data
        data = layer.read(address, 0x130, pad=True)
        
        if len(data) < 0x130:
            return None
        
        def read_ptr(offset: int) -> int:
            if ptrSize == 8:
                return int.from_bytes(data[offset:offset+8], 'little')
            else:
                return int.from_bytes(data[offset:offset+4], 'little')
        
        def read_slice(offset: int):
            ptr = read_ptr(offset)
            length = read_ptr(offset + ptrSize)
            cap_val = read_ptr(offset + ptrSize * 2)
            return (ptr, length, cap_val)
        
        slice_size = ptrSize * 3
        
        # Field 0: pclntable []byte - MUST match pclntab_addr
        pclntable_ptr, pclntable_len, pclntable_cap = read_slice(0x00)
        
        if pclntable_ptr != pclntab_addr:
            return None
        
        # Validate pclntable slice
        if pclntable_len == 0 or pclntable_len > pclntable_cap:
            return None
        if pclntable_cap > 0x10000000:  # 256MB max
            return None
        
        # Field 1: ftab []functab
        ftab_ptr, ftab_len, ftab_cap = read_slice(0x18)
        
        if ftab_len == 0 or ftab_len > ftab_cap:
            return None
        
        # Field 2: filetab []uint32
        filetab_ptr, filetab_len, filetab_cap = read_slice(0x30)
        
        # Field 3: findfunctab uintptr
        findfunctab = read_ptr(0x48)
        
        # Field 4-5: minpc, maxpc
        minpc = read_ptr(0x50)
        maxpc = read_ptr(0x58)
        
        if minpc == 0 or maxpc == 0 or minpc >= maxpc:
            return None
        
        # Field 6-7: text, etext
        text = read_ptr(0x60)
        etext = read_ptr(0x68)
        
        if text == 0 or etext == 0 or text >= etext:
            return None
        
        # Field 8-9: noptrdata, enoptrdata
        noptrdata = read_ptr(0x70)
        enoptrdata = read_ptr(0x78)
        
        # Field 10-11: data, edata
        data_start = read_ptr(0x80)
        edata = read_ptr(0x88)
        
        # Field 12-13: bss, ebss
        bss = read_ptr(0x90)
        ebss = read_ptr(0x98)
        
        # Field 14-15: noptrbss, enoptrbss
        noptrbss = read_ptr(0xa0)
        enoptrbss = read_ptr(0xa8)
        
        # Field 16: end
        end_addr = read_ptr(0xb0)
        
        # Field 17-18: gcdata, gcbss
        gcdata = read_ptr(0xb8)
        gcbss = read_ptr(0xc0)
        
        # Field 19-20: types, etypes
        types = read_ptr(0xc8)
        etypes = read_ptr(0xd0)
        
        if types == 0 or etypes == 0 or types >= etypes:
            return None
        
        # Field 21: textsectmap []textsect (skip)
        
        # Field 22: typelinks []int32
        typelinks_ptr, typelinks_len, typelinks_cap = read_slice(0xf0)
        
        # Field 23: itablinks []*itab
        itablinks_ptr, itablinks_len, itablinks_cap = read_slice(0x108)
        
        # Derive rodata from sections
        rodata = None
        erodata = None
        
        for seg in segments:
          if seg["p_type"] == self.PT_LOAD and seg["p_flags_str"] == "R--":
             rodata = seg["runtime_vaddr"]
             erodata = seg["runtime_end"]
             break

        
        
        if rodata is None:
            rodata = types
            erodata = etypes
        
        print(f"[+] Found moduledata (Go 1.15) at {hex(address)}")
        print(f"    pclntable: ptr={hex(pclntable_ptr)}, len={pclntable_len}")
        print(f"    text: {hex(text)}-{hex(etext)}")
        print(f"    types: {hex(types)}-{hex(etypes)}")
        print(f"    data: {hex(data_start)}-{hex(edata)}")
        print(f"    typelinks: {typelinks_len} entries @ {hex(typelinks_ptr)}")
        print(f"    itablinks: {itablinks_len} entries @ {hex(itablinks_ptr)}")
        
        return {
            'address': address,
            'pcHeader': pclntab_addr,
            'pclntable': {'ptr': pclntable_ptr, 'len': pclntable_len, 'cap': pclntable_cap},
            'ftab': {'ptr': ftab_ptr, 'len': ftab_len, 'cap': ftab_cap},
            'funcnametab': {'ptr': pclntable_ptr, 'len': pclntable_len, 'cap': pclntable_cap},  # Same as pclntable in Go 1.15
            'pctab': {'ptr': pclntable_ptr, 'len': pclntable_len, 'cap': pclntable_cap},
            'minpc': minpc,
            'maxpc': maxpc,
            'text': text,
            'etext': etext,
            'noptrbss':noptrbss,
            'enoptrbss':enoptrbss,
            'noptrdata': noptrdata,
            'enoptrdata': enoptrdata, 
            'bss': bss,
            'ebss': ebss,
            'types': types,
            'etypes': etypes,
            'data_start': data_start,
            'edata': edata,
            'rodata': rodata,
            'erodata': erodata,
            'gofunc': 0,
            'typelinks': {'ptr': typelinks_ptr, 'len': typelinks_len, 'cap': typelinks_cap},
            'itablink': {'ptr': itablinks_ptr, 'len': itablinks_len, 'cap': itablinks_cap},
            'mheap_ptr': 0
        }
        
      except Exception as e:
        import traceback
        traceback.print_exc()
        return None
    
    def _extract_itabs(self, ptrSize: int) -> Dict[int, Dict]:
      """
      Extract all interface tables (itabs) via moduledata.itablink.
    
      An itab maps a concrete type to an interface it implements. Each itab
      contains: the interface type pointer, the concrete type pointer, a hash
      for fast type assertion, and an array of function pointers (the virtual
      method table) that dispatches interface method calls to the concrete
      type's implementations.
    
      We extract itabs to:
      1. Resolve interface values on goroutine stacks, when a stack slot
         holds [itab_ptr, data_ptr], the itab tells us which concrete type
         the data_ptr points to and which interface it satisfies.
      2. Provide method dispatch context,  the fun[] array in each itab
         maps interface method indices to actual code addresses, enabling
         us to trace which concrete method an interface call would invoke.
      3. Cross-reference with type methods,  itab function pointers overlap
         with type_methods PCs, connecting stack frame argument recovery
         to the correct parameter signatures.
    
      Returns:
        Dict mapping itab address → parsed itab info dict.
      """
      itablink_ptr = self.moduledata['itablink']['ptr']
      itablink_len = self.moduledata['itablink']['len']
    
      if itablink_len == 0 or itablink_ptr == 0:
        print("[!] No itabs found (itablink empty)")
        return {}
    
      print(f"\n[*] Extracting {itablink_len} itabs from itablink @ {hex(itablink_ptr)}")
    
      layer = self.context.layers[self.layer_name]
      itabs = {}
      
      try:
        # Read array of itab pointers
        array_size = itablink_len * ptrSize
        array_data = layer.read(itablink_ptr, array_size, pad=True)
        
        for i in range(itablink_len):
            offset = i * ptrSize
            if ptrSize == 8:
                itab_addr = int.from_bytes(array_data[offset:offset+8], 'little')
            else:
                itab_addr = int.from_bytes(array_data[offset:offset+4], 'little')
            
            if itab_addr == 0:
                continue
            
            itab_info = self._parse_itab(itab_addr, ptrSize)
            if itab_info:
                itabs[itab_addr] = itab_info
        
        print(f"[+] Successfully parsed {len(itabs)} itabs")
        
      except Exception as e:
        print(f"[!] Error extracting itabs: {e}")
    
      return itabs
   
   
    def _parse_itab(self, itab_addr: int, ptrSize: int) -> Optional[Dict]:
      """
      Parse an itab (interface table) structure.
    
      Structure (Go 1.18+, 64-bit):
        interfacetype* inter;   // +0: pointer to interface type
        _type*         _type;   // +8: pointer to concrete type  
        uint32         hash;    // +16: hash value
        uint8          _[4];    // +20: padding
        void*          fun[];   // +24: function pointers array
      """
      try:
        layer = self.context.layers[self.layer_name]
        
        # Read itab header (24 bytes for 64-bit)
        header_size = 24 if ptrSize == 8 else 16
        data = layer.read(itab_addr, header_size, pad=True)
        
        if len(data) < header_size:
            return None
        
        if ptrSize == 8:
            inter_ptr = int.from_bytes(data[0:8], 'little')
            type_ptr = int.from_bytes(data[8:16], 'little')
            hash_val = int.from_bytes(data[16:20], 'little')
        else:
            inter_ptr = int.from_bytes(data[0:4], 'little')
            type_ptr = int.from_bytes(data[4:8], 'little')
            hash_val = int.from_bytes(data[8:12], 'little')
        
        # Validate pointers are in types section
        types_start = self.types_start
        etypes = self.moduledata.get('etypes', types_start + 0x1000000)
        
        if not (types_start <= inter_ptr < etypes):
            return None
        if not (types_start <= type_ptr < etypes):
            return None
        
        # Parse interface type to get method count
        if inter_ptr not in self.types_cache:
            self._parse_single_type(inter_ptr, ptrSize)
        
        if type_ptr not in self.types_cache:
            self._parse_single_type(type_ptr, ptrSize)
        
        # Get interface methods count
        inter_info = self.types_cache.get(inter_ptr)
        if not inter_info or inter_info.get('kind') != 20:  # Must be interface
            return None
        
        interface_methods = inter_info.get('interface_methods', [])
        method_count = len(interface_methods)
        
        # Parse fun[] array - starts at offset 24 (64-bit) or 16 (32-bit)
        fun_offset = 24 if ptrSize == 8 else 16
        fun_array_size = method_count * ptrSize
        
        fun_pointers = []
        if method_count > 0:
            fun_data = layer.read(itab_addr + fun_offset, fun_array_size, pad=True)
            
            for i in range(method_count):
                ptr_offset = i * ptrSize
                if ptrSize == 8:
                    fun_pc = int.from_bytes(fun_data[ptr_offset:ptr_offset+8], 'little')
                else:
                    fun_pc = int.from_bytes(fun_data[ptr_offset:ptr_offset+4], 'little')
                
                # Get method name from interface
                method_name = "<unknown>"
                if i < len(interface_methods):
                    method_name = interface_methods[i].get('name', '<unknown>')
                
                fun_pointers.append({
                    'index': i,
                    'method_name': method_name,
                    'pc': fun_pc,
                })
        
        # Get type names
        type_info = self.types_cache.get(type_ptr)
        concrete_type_name = type_info.get('name', '<unknown>') if type_info else '<unknown>'
        interface_name = inter_info.get('name', '<unknown>')
        
        return {
            'address': itab_addr,
            'inter_ptr': inter_ptr,
            'type_ptr': type_ptr,
            'hash': hash_val,
            'interface_name': interface_name,
            'concrete_type_name': concrete_type_name,
            'method_count': method_count,
            'fun_pointers': fun_pointers,
        }
        
      except Exception as e:
        vollog.debug(f"Error parsing itab @ {hex(itab_addr)}: {e}")
        return None
    
   
   
   
   
   
   
   
    def _extract_functions(self, layer_name: str, pclntab: Dict, moduledata: Dict) -> Generator[Dict, None, None]:
      """
      Extract all functions from Go binary via ftab iteration.
      For each function, also extracts:
      - PCDATA tables (UnsafePoint, StackMapIndex, InlTreeIndex, ArgLiveIndex)
      - FUNCDATA pointers (ArgsPointerMaps, LocalsPointerMaps, StackObjects,
        InlTree, ArgInfo, ArgLiveInfo)

      Yields dict per function with pc, name, size, args, and parsed metadata.
      """
    
      
      FUNC_ID_NAMES = {
        0: "normal",
        1: "runtime_main",
        2: "goexit",
        3: "jmpdefer", 
        4: "mcall",
        5: "morestack",
        6: "mstart",
        7: "rt0_go",
        8: "asmcgocall",
        9: "sigpanic",
        10: "runfinq",
        11: "gcBgMarkWorker",
        12: "systemstack_switch",
        13: "systemstack",
        14: "cgocallback",
        15: "gogo",
        16: "externalthreadhandler",
        17: "debugCallV2",
        18: "gopanic",
        19: "panicwrap",
        20: "handleAsyncEvent",
        21: "asyncPreempt",
        22: "wrapper",
      }
      
      
      # Flag constants
      FLAG_TOPFRAME = 1
      FLAG_SPWRITE = 2
      FLAG_ASM = 4
    
      ptrSize = pclntab["ptrSize"]
      go_version = pclntab["version"]
    
      # Get table addresses from moduledata
      ftab_ptr = moduledata["ftab"]["ptr"]
      ftab_len = moduledata["ftab"]["len"]
      funcnametab_ptr = moduledata["funcnametab"]["ptr"]
      funcnametab_len = moduledata["funcnametab"]["len"] 
      funcnametab_cap = moduledata["funcnametab"]["cap"] 
      pclntable_ptr = moduledata["pclntable"]["ptr"]
      pclntable_len = moduledata["pclntable"]["len"]
      text_start = moduledata["text"]
      layer = self.context.layers[layer_name]
     
      # Detect version and format
      major, minor, patch = self.go_version_tuple
    
      # Determine format based on version
      is_go_125 = (major == 1 and minor == 25)
      is_go_118_plus = (major == 1 and minor >= 18 and minor < 25)
      is_go_116_117 = (major == 1 and minor >= 16 and minor < 18)
      is_go_115 = (major == 1 and minor == 15)
      is_go_pre_115 = (major == 1 and minor < 15)
      
  
      if is_go_118_plus or is_go_125:
        functab_entry_size = 8
        use_offset_format = True
        print(f"[*] Using Go 1.18+ ftab format (8 bytes per entry)")
      else:
        functab_entry_size = 2 * ptrSize
        use_offset_format = False
        print(f"[*] Using Go 1.2-1.17 ftab format ({functab_entry_size} bytes per entry)")
   
      if is_go_118_plus or is_go_125:
         # Go 1.18+: 44 bytes base (same for 32-bit and 64-bit)
         func_struct_base_size = 44
      elif is_go_116_117:
         # Go 1.16-1.17
         if ptrSize == 8:
            func_struct_base_size = 44  # 64-bit: entry(8) + fields(36)
         else:
            func_struct_base_size = 40  # 32-bit: entry(4) + fields(36)
      elif is_go_115:
         # Go 1.15: No cuOffset or startLine
         if ptrSize == 8:
            func_struct_base_size = 40  # 64-bit
         else:
            func_struct_base_size = 36  # 32-bit
      else:
         # Pre-1.15: Similar to 1.15
         if ptrSize == 8:
            func_struct_base_size = 40
         else:
            func_struct_base_size = 36

      
     
      # ============== DEBUG HELPER FUNCTION ==============
        
      extracted = 0
      errors = 0
      empty_names = 0
    
      for i in range(ftab_len - 1):
        try:
            # Read functab entry
            entry_addr = ftab_ptr + (i * functab_entry_size)
            entry_data = layer.read(entry_addr, functab_entry_size, pad=True)
            
            if len(entry_data) < functab_entry_size:
                errors += 1
                continue
            
            # Parse based on format
            if use_offset_format:
                # Go 1.18+: {uint32 entryoff, uint32 funcoff}
                entryoff = int.from_bytes(entry_data[0:4], 'little')
                funcoff = int.from_bytes(entry_data[4:8], 'little')
                func_pc = text_start + entryoff
            else:
                # Go 1.2-1.17: {uintptr entry, uintptr funcoff}
                if ptrSize == 8:
                    func_pc = int.from_bytes(entry_data[0:8], 'little')
                    funcoff = int.from_bytes(entry_data[8:16], 'little')
                else:
                    func_pc = int.from_bytes(entry_data[0:4], 'little')
                    funcoff = int.from_bytes(entry_data[4:8], 'little')
                entryoff = func_pc - text_start
            
            # Read _func structure - SIZE AND LAYOUT DIFFER BY VERSION
            func_struct_addr = pclntable_ptr + funcoff
            func_base_data = layer.read(func_struct_addr, func_struct_base_size, pad=True)
            if len(func_base_data) < func_struct_base_size:
                errors += 1
                continue
            
            if is_go_125:
                # ftab entry: {uint32 entryoff, uint32 funcoff}
                entryoff = int.from_bytes(entry_data[0:4], 'little')
                funcoff = int.from_bytes(entry_data[4:8], 'little')
                func_pc = text_start + entryoff
                
                # CRITICAL: funcoff is offset from pcHeader (pclntable_ptr)
                func_struct_addr = pclntable_ptr + funcoff
                
                # Debug first few functions
               
                
                # Read _func struct
                func_base_data = layer.read(func_struct_addr, func_struct_base_size, pad=True)
                
                   
                if len(func_base_data) < func_struct_base_size:
                    errors += 1
                    continue
                
                # Parse Go 1.25 _func layout (44 bytes)
                func_entryOff = int.from_bytes(func_base_data[0:4], 'little')
                nameoff = int.from_bytes(func_base_data[4:8], 'little', signed=True)
                args = int.from_bytes(func_base_data[8:12], 'little', signed=True)
                deferreturn = int.from_bytes(func_base_data[12:16], 'little')
                pcsp = int.from_bytes(func_base_data[16:20], 'little')
                pcfile = int.from_bytes(func_base_data[20:24], 'little')
                pcln = int.from_bytes(func_base_data[24:28], 'little')
                npcdata = int.from_bytes(func_base_data[28:32], 'little')
                cuOffset = int.from_bytes(func_base_data[32:36], 'little')
                startLine = int.from_bytes(func_base_data[36:40], 'little', signed=True)
                funcID = func_base_data[40]
                flag = func_base_data[41]
                # byte 42 is padding
                nfuncdata = func_base_data[43]
                
          
            elif is_go_118_plus:
                # Parse Go 1.18+ layout
                func_entryOff = int.from_bytes(func_base_data[0:4], 'little')
                nameoff = int.from_bytes(func_base_data[4:8], 'little', signed=True)
                args = int.from_bytes(func_base_data[8:12], 'little', signed=False)
                deferreturn = int.from_bytes(func_base_data[12:16], 'little')
                pcsp = int.from_bytes(func_base_data[16:20], 'little')
                pcfile = int.from_bytes(func_base_data[20:24], 'little')
                pcln = int.from_bytes(func_base_data[24:28], 'little')
                npcdata = int.from_bytes(func_base_data[28:32], 'little')
                cuOffset = int.from_bytes(func_base_data[32:36], 'little')
                startLine = int.from_bytes(func_base_data[36:40], 'little', signed=True)
                funcID = func_base_data[40]
                flag = func_base_data[41]
                nfuncdata = func_base_data[43]
               
            elif is_go_116_117:
                # Go 1.16-1.17: entryOff is uintptr (8 bytes on 64-bit, 4 on 32-bit)
                if ptrSize == 8:
                    # Parse Go 1.16-1.17 64-bit layout
                    func_entryOff = int.from_bytes(func_base_data[0:8], 'little')
                    nameoff = int.from_bytes(func_base_data[8:12], 'little', signed=True)
                    args = int.from_bytes(func_base_data[12:16], 'little', signed=True)
                    deferreturn = int.from_bytes(func_base_data[16:20], 'little')
                    pcsp = int.from_bytes(func_base_data[20:24], 'little')
                    pcfile = int.from_bytes(func_base_data[24:28], 'little')
                    pcln = int.from_bytes(func_base_data[28:32], 'little')
                    npcdata = int.from_bytes(func_base_data[32:36], 'little')
                    cuOffset = int.from_bytes(func_base_data[36:40], 'little')
                    funcID = func_base_data[40]
                    # bytes 41-42 are padding
                    nfuncdata = func_base_data[43]
                    startLine = 0  # Not present in 1.16-1.17
                    flag = 0  # Not present in 1.16-1.17
                    
                else:
                    # 32-bit: entry is 4 bytes
                    func_entryOff = int.from_bytes(func_base_data[0:4], 'little')
                    nameoff = int.from_bytes(func_base_data[4:8], 'little', signed=True)
                    args = int.from_bytes(func_base_data[8:12], 'little', signed=True)
                    deferreturn = int.from_bytes(func_base_data[12:16], 'little')
                    pcsp = int.from_bytes(func_base_data[16:20], 'little')
                    pcfile = int.from_bytes(func_base_data[20:24], 'little')
                    pcln = int.from_bytes(func_base_data[24:28], 'little')
                    npcdata = int.from_bytes(func_base_data[28:32], 'little')
                    cuOffset = int.from_bytes(func_base_data[32:36], 'little')
                    funcID = func_base_data[36]
                    # bytes 37-38 are padding
                    nfuncdata = func_base_data[39]
                    startLine = 0
                    flag = 0

            elif is_go_115:
                # Go 1.15 layout - NO cuOffset, NO startLine
                # pcsp, pcfile, pcln, npcdata are int32 (signed)
                if ptrSize == 8:
                    # 64-bit
                    func_entryOff = int.from_bytes(func_base_data[0:8], 'little')
                    nameoff = int.from_bytes(func_base_data[8:12], 'little', signed=True)
                    args = int.from_bytes(func_base_data[12:16], 'little', signed=True)
                    deferreturn = int.from_bytes(func_base_data[16:20], 'little')
                    pcsp = int.from_bytes(func_base_data[20:24], 'little', signed=True)  # int32!
                    pcfile = int.from_bytes(func_base_data[24:28], 'little', signed=True)  # int32!
                    pcln = int.from_bytes(func_base_data[28:32], 'little', signed=True)  # int32!
                    npcdata = int.from_bytes(func_base_data[32:36], 'little', signed=True)  # int32!
                    funcID = func_base_data[36]
                    # bytes 37-38 are padding
                    nfuncdata = func_base_data[39]
                    cuOffset = 0  # Not present in 1.15
                    startLine = 0  # Not present in 1.15
                    flag = 0  # Not present in 1.15
                else:
                    # 32-bit
                    func_entryOff = int.from_bytes(func_base_data[0:4], 'little')
                    nameoff = int.from_bytes(func_base_data[4:8], 'little', signed=True)
                    args = int.from_bytes(func_base_data[8:12], 'little', signed=True)
                    deferreturn = int.from_bytes(func_base_data[12:16], 'little')
                    pcsp = int.from_bytes(func_base_data[16:20], 'little', signed=True)
                    pcfile = int.from_bytes(func_base_data[20:24], 'little', signed=True)
                    pcln = int.from_bytes(func_base_data[24:28], 'little', signed=True)
                    npcdata = int.from_bytes(func_base_data[28:32], 'little', signed=True)
                    funcID = func_base_data[32]
                    # bytes 33-34 are padding
                    nfuncdata = func_base_data[35]
                    cuOffset = 0
                    startLine = 0
                    flag = 0
                   
            
            else:
                    # Pre-1.15 fallback (similar to 1.15)
                    if ptrSize == 8:
                      func_entryOff = int.from_bytes(func_base_data[0:8], 'little')
                      nameoff = int.from_bytes(func_base_data[8:12], 'little', signed=True)
                      args = int.from_bytes(func_base_data[12:16], 'little', signed=True)
                      deferreturn = int.from_bytes(func_base_data[16:20], 'little')
                      pcsp = int.from_bytes(func_base_data[20:24], 'little', signed=True)
                      pcfile = int.from_bytes(func_base_data[24:28], 'little', signed=True)
                      pcln = int.from_bytes(func_base_data[28:32], 'little', signed=True)
                      npcdata = int.from_bytes(func_base_data[32:36], 'little', signed=True)
                      funcID = func_base_data[36]
                      nfuncdata = func_base_data[39]
                      cuOffset = 0
                      startLine = 0
                      flag = 0
                    else:
                      func_entryOff = int.from_bytes(func_base_data[0:4], 'little')
                      nameoff = int.from_bytes(func_base_data[4:8], 'little', signed=True)
                      args = int.from_bytes(func_base_data[8:12], 'little', signed=True)
                      deferreturn = int.from_bytes(func_base_data[12:16], 'little')
                      pcsp = int.from_bytes(func_base_data[16:20], 'little', signed=True)
                      pcfile = int.from_bytes(func_base_data[20:24], 'little', signed=True)
                      pcln = int.from_bytes(func_base_data[24:28], 'little', signed=True)
                      npcdata = int.from_bytes(func_base_data[28:32], 'little', signed=True)
                      funcID = func_base_data[32]
                      nfuncdata = func_base_data[35]
                      cuOffset = 0
                      startLine = 0
                      flag = 0
                   
            # Validate nameoff
            if nameoff < 0:
                  errors += 1
                  continue
           
            if args == 0x80000000 or args == -2147483648:
                args = None  

            
  
            if nameoff >= funcnametab_len:
                func_name = f"<out_of_bounds_{i}>"
            else:
                name_addr = funcnametab_ptr + nameoff
                func_name = self._read_cstring(name_addr, 256)
             
             
            funcID_name = FUNC_ID_NAMES.get(funcID, f"unknown_{funcID}")
            
            # Decode flags
            flags_list = []
            if flag & FLAG_TOPFRAME:
                flags_list.append("TOPFRAME")
            if flag & FLAG_SPWRITE:
                flags_list.append("SPWRITE")
            if flag & FLAG_ASM:
                flags_list.append("ASM")
            flags_str = "|".join(flags_list) if flags_list else "none"
            
            # Calculate function size
            func_size = 0
            try:
                next_entry_addr = ftab_ptr + ((i + 1) * functab_entry_size)
                
                if use_offset_format:
                    # Go 1.18+: read next entryoff (uint32)
                    next_entry_data = layer.read(next_entry_addr, 4, pad=True)
                    if len(next_entry_data) == 4:
                        next_entryoff = int.from_bytes(next_entry_data[0:4], 'little')
                        if next_entryoff > entryoff:
                            func_size = next_entryoff - entryoff
                else:
                    # Go 1.2-1.17: read next entry (uintptr)
                    next_entry_data = layer.read(next_entry_addr, ptrSize, pad=True)
                    if len(next_entry_data) == ptrSize:
                        if ptrSize == 8:
                            next_func_pc = int.from_bytes(next_entry_data[0:8], 'little')
                        else:
                            next_func_pc = int.from_bytes(next_entry_data[0:4], 'little')
                        if next_func_pc > func_pc:
                            func_size = next_func_pc - func_pc
            except Exception as e:
                vollog.debug(f"Error calculating size for function {i}: {e}")
            

            pcdata_tables = self._extract_pcdata(layer, moduledata, func_struct_addr, npcdata, func_struct_base_size, nfuncdata)
            
            funcdata_ptrs = []
            extracted += 1
           
            argsmap_data = None
            localsmap_data = None
            stackobj_data = None
            inltree_data= None
            arginfo_data = None
            arglive_data = None
            stackmap_idx= 0
           
            if nfuncdata > 0:
               funcdata_array_offset = func_struct_base_size + (npcdata * 4)
               funcdata_array_addr = func_struct_addr + funcdata_array_offset
             
               is_go_116_or_earlier = (major == 1 and minor <= 16) 
               is_go_117_plus = (major == 1 and minor >= 17)
               
               if is_go_116_or_earlier:
                  funcdata_entry_size = ptrSize  # 8 bytes on 64-bit
                  if ptrSize == 8 and (funcdata_array_addr % 8) != 0:
                     # Add 4 bytes padding for 8-byte alignment
                     funcdata_array_addr += 4
               else:
                  funcdata_entry_size = 4
              
                 
               funcdata_array_size = nfuncdata * funcdata_entry_size
               funcdata_data = layer.read(funcdata_array_addr, funcdata_array_size, pad=True)
            
                
               if len(funcdata_data) >= funcdata_array_size:
                     gofunc = moduledata.get('gofunc', 0)
                     for fd_idx in range(nfuncdata):
                        offset = fd_idx * funcdata_entry_size
                        if is_go_116_or_earlier:
                            if ptrSize == 8:
                               data_addr = int.from_bytes(funcdata_data[offset:offset+8], "little")
                            else:
                               data_addr = int.from_bytes(funcdata_data[offset:offset+4], "little")
                              
                            name = self.FUNCDATA_NAMES.get(fd_idx, f"Unknown_{fd_idx}")
                           
      
                            if data_addr == 0:
                               funcdata_ptrs.append(0)
                            else:
                               funcdata_ptrs.append(data_addr)
                        
                        else:
                          off_val = int.from_bytes(funcdata_data[offset:offset+4], "little", signed=False)
                          if off_val == 0xFFFFFFFF:
                            funcdata_ptrs.append(0)
                          elif off_val == 0:
                            if gofunc != 0:
                                funcdata_ptrs.append(gofunc) 
                            else:
                                funcdata_ptrs.append(0)
                          else:
                            if gofunc != 0:
                                data_addr = gofunc + off_val
                            else:
                                data_addr = moduledata['pclntable']['ptr'] + off_val
                            funcdata_ptrs.append(data_addr)
                       
                    
                 

               # Parse ArgsPointerMaps
               if len(funcdata_ptrs) > self.FUNCDATA_ArgsPointerMaps and funcdata_ptrs[self.FUNCDATA_ArgsPointerMaps] != 0:
                   argsmap_addr = funcdata_ptrs[self.FUNCDATA_ArgsPointerMaps]
                  
                   argsmap_data = self._parse_args_from_stackmap(layer, argsmap_addr, ptrSize)
            
               # Parse LocalsPointerMaps 
               if len(funcdata_ptrs) > self.FUNCDATA_LocalsPointerMaps and funcdata_ptrs[self.FUNCDATA_LocalsPointerMaps] != 0:
                  localsmap_data = self._parse_locals_stackmap(layer, funcdata_ptrs[self.FUNCDATA_LocalsPointerMaps],ptrSize)
            
               # Parse StackObjects
               if len(funcdata_ptrs) > self.FUNCDATA_StackObjects and funcdata_ptrs[self.FUNCDATA_StackObjects] != 0:
                  stackobj_data = self._parse_stack_objects(layer, funcdata_ptrs[self.FUNCDATA_StackObjects], ptrSize)
               
               
               # Parse InlTree
               if len(funcdata_ptrs) > self.FUNCDATA_InlTree and funcdata_ptrs[self.FUNCDATA_InlTree] != 0:
                  inltree_data = self._parse_inl_tree(layer,funcdata_ptrs[self.FUNCDATA_InlTree],ptrSize)
               
               
               is_go_117_plus = (major == 1 and minor >= 17)
               if is_go_117_plus:
                  # Parse ArgInfo
                  if len(funcdata_ptrs) > self.FUNCDATA_ArgInfo and funcdata_ptrs[self.FUNCDATA_ArgInfo] != 0:
                     arginfo_data = self._parse_arginfo_bytecode(layer,funcdata_ptrs[self.FUNCDATA_ArgInfo], func_name)
           
                  # Parse ArgLiveInfo
                  if len(funcdata_ptrs) > self.FUNCDATA_ArgLiveInfo and funcdata_ptrs[self.FUNCDATA_ArgLiveInfo] != 0:
                     arglive_data = self._parse_arglive_info(layer,funcdata_ptrs[self.FUNCDATA_ArgLiveInfo],ptrSize)
   
               if (localsmap_data and localsmap_data.get('num_bitmaps', 0) > 0  and self.PCDATA_StackMapIndex in pcdata_tables):
                    # Correct: StackMapIndex comes from PCDATA index 1
                     stackmap_idx = self._pcvalue(pcdata_tables[self.PCDATA_StackMapIndex],target_pc=func_pc, entry_pc=func_pc,
                     func_name=f"{func_name} [PCDATA_StackMapIndex]")
               
               
           
                    
            yield {
                "index": i,
                "pc": func_pc,
                "name": func_name,
                "size": func_size,
                "args": args,
                "deferreturn": deferreturn,
                "startLine": startLine,
                "funcID": funcID,
                "funcID_name": funcID_name,
                "flag": flag,
                "flags_str": flags_str,
                "npcdata": npcdata,
                "nfuncdata": nfuncdata,
                "cuOffset": cuOffset,
                "pcsp": pcsp,
                "pcfile": pcfile,
                "pcln": pcln,
                "funcoff": funcoff,
                "nameoff": nameoff,
                "argsmap_data":argsmap_data if argsmap_data else None,
                "localsmap_data":localsmap_data if localsmap_data else None,
                "stackobj_data":stackobj_data if stackobj_data else None,
                "inltree_data":inltree_data if inltree_data else None,
                "arginfo_data":arginfo_data if arginfo_data else None,
                "arglive_data":arglive_data if arglive_data else None,
                "stackmap_idx":stackmap_idx if stackmap_idx else None,
            }
            
        except exceptions.InvalidAddressException as e:
            errors += 1
            if errors < 5:  
                vollog.debug(f" Error reading function {i}: {e}")
            continue
    
    
     
    
    
    def _parse_arglive_info(self, layer, arglive_addr: int, ptrSize: int) -> Optional[Dict]:
      """
      Parse ArgLiveInfo (FUNCDATA_ArgLiveInfo).
    
      Structure (similar to stackmaps):
        n      int32     // number of bitmaps (one per PC range)
        nbit   int32     // bits per bitmap (number of arguments tracked)
        bitmap[0]        // first bitmap (nbit bits, rounded to bytes)
        bitmap[1]        // second bitmap
        ...
        bitmap[n-1]      // last bitmap
    
      Each bit indicates if an argument is LIVE (still referenced) at that PC.
      Bit k = 1 means argument k is live.
    
      Note: Which bitmap applies depends on PC via PCDATA_ArgLiveIndex.
      For static analysis, we extract all bitmaps showing argument liveness patterns.
      """
      try:
      
        if arglive_addr == 0:
            return None
        
        # Read header
        header = layer.read(arglive_addr, 8, pad=True)
        if len(header) < 8:
            return None
        
        n = int.from_bytes(header[0:4], 'little', signed=True)
        nbit = int.from_bytes(header[4:8], 'little', signed=True)
        
        # Validate
        if n < 0 or n > 1000 or nbit < 0 or nbit > 100:
            return None
        
        # Calculate bitmap size
        bitmap_bytes = (nbit + 7) // 8
        
        # Read all bitmaps
        bitmaps = []
        for bitmap_idx in range(n):
            offset = 8 + (bitmap_idx * bitmap_bytes)
            bitmap_data = layer.read(arglive_addr + offset, bitmap_bytes, pad=True)
            
            if len(bitmap_data) >= bitmap_bytes:
                bitmap_int = int.from_bytes(bitmap_data[:bitmap_bytes], 'little')
                
                # Decode which arguments are live
                live_args = []
                for bit_idx in range(nbit):
                    if (bitmap_int >> bit_idx) & 1:
                        live_args.append(bit_idx)
                
                bitmaps.append({
                    'index': bitmap_idx,
                    'bitmap_hex': bitmap_data[:bitmap_bytes].hex(),
                    'live_args': live_args,
                    'num_live': len(live_args)
                })
        
        return {
            'address': arglive_addr,
            'num_bitmaps': n,
            'num_args_tracked': nbit,
            'bitmaps': bitmaps,
        }
        
      except Exception as e:
        vollog.debug(f"Error parsing ArgLiveInfo: {e}")
        return None
    
    def _parse_inl_tree(self, layer, inltree_addr: int, ptrSize: int) -> Optional[Dict]:
      """
      Parse InlTree (FUNCDATA_InlTree).
    
      Structure (from runtime/symtab.go):
        count    int32              // number of inlined call records
        records  []inlinedCall
    
      inlinedCall (Go 1.20+):
        funcID   uint8      // function ID being inlined
        _        [3]uint8   // padding
        nameOff  int32      // offset into funcnametab for inlined function name
        parentPC int32      // PC in parent where this was inlined
        startLine int32     // line number where inlining starts
    
      This tells us which functions were inlined and where.
      """
      try:
        if inltree_addr == 0:
            return None
        
        # Read count
        count_bytes = layer.read(inltree_addr, 4, pad=True)
        if len(count_bytes) < 4:
            return None
        
        count = int.from_bytes(count_bytes, 'little', signed=True)
        
        # Validate
        if count < 0 or count > 10000:
            return None
        
        if count == 0:
            return {
                'address': inltree_addr,
                'count': 0,
                'inlined_calls': []
            }
        
        # Each record is 16 bytes (Go 1.20+)
        record_size = 16
        
        inlined_calls = []
        for i in range(count):
            offset = 4 + (i * record_size)
            record_data = layer.read(inltree_addr + offset, record_size, pad=True)
            
            if len(record_data) < record_size:
                break
            
            # Parse record
            funcID = record_data[0]
            # bytes 1-3 are padding
            nameOff = int.from_bytes(record_data[4:8], 'little', signed=True)
            parentPC = int.from_bytes(record_data[8:12], 'little', signed=True)
            startLine = int.from_bytes(record_data[12:16], 'little', signed=True)
            
            inlined_calls.append({
                'index': i,
                'funcID': funcID,
                'nameOff': nameOff,
                'parentPC': parentPC,
                'startLine': startLine,
            })
        
        return {
            'address': inltree_addr,
            'count': count,
            'inlined_calls': inlined_calls,
        }
        
      except Exception as e:
        vollog.debug(f"Error parsing InlTree: {e}")
        return None
    
    
    def _pcvalue(self, pctab_data: bytes, target_pc: int, entry_pc: int, func_name: str = "") -> Optional[int]:
      """
      Decode a PC-value table to find the value at target_pc.

      Go's pcvalue encoding: zigzag-varint value deltas interleaved with
      unsigned varint PC deltas (scaled by pcQuantum). Special case:
      val_delta == 0 means advance PC by one quantum without consuming
      a pc_delta. Iteration stops when accumulated PC exceeds target_pc.
      Returns the value (e.g., SP delta, file index, line number) or None.
      """
      if not pctab_data or len(pctab_data) == 0:
        return None
    
      # Get pcQuantum from pclntab header (typically 1 for x86-64)
      pc_quantum = self.pclntab.get("minLC", 1)
    
      try:
        pc = entry_pc
        value = -1
        idx = 0
        '''
        print(f"\n[PCVALUE DEBUG] {func_name}")
        print(f"  entry_pc: {hex(entry_pc)}, target_pc: {hex(target_pc)}")
        print(f"  pc_quantum: {pc_quantum}")
        print(f"  pctab_data: {pctab_data[:min(32, len(pctab_data))].hex()}")
        print(f"  Starting: pc={hex(pc)}, value={value}")
        '''
        step = 0
        while idx < len(pctab_data) and step < 50:
            step += 1
           # print(f"\n  Step {step}: idx={idx}, pc={hex(pc)}, value={value}")
            
            # Read value delta (zigzag varint)
            val_delta, consumed = self._read_varint_zigzag(pctab_data[idx:])
            if consumed == 0:
                #print(f"    → val_delta consumed=0, END")
                break
           # print(f"    → val_delta={val_delta} (consumed {consumed} bytes)")
            idx += consumed
            
            # CRITICAL: Special case for val_delta == 0
            if val_delta == 0:
                # Advance PC by exactly 1 quantum, do NOT consume another varint
                pc += pc_quantum
               # print(f"    → SPECIAL: val_delta=0, pc += {pc_quantum} → pc={hex(pc)}")
                
                # Check if we passed target
                if target_pc < pc:
                   # print(f"    → target_pc {hex(target_pc)} < pc {hex(pc)}, RETURN value={value}")
                    return value
                continue  # Go to next iteration WITHOUT reading pc_delta
            
            # Apply value delta
            value += val_delta
            # print(f"    → value += {val_delta} → value={value}")
            
            # Read PC delta (unsigned varint)
            if idx >= len(pctab_data):
               # print(f"    → End of data, RETURN value={value}")
                return value
            
            pc_delta, consumed = self._read_varint(pctab_data[idx:])
            if consumed == 0:
               # print(f"    → pc_delta consumed=0, RETURN value={value}")
                return value
            #print(f"    → pc_delta={pc_delta} (consumed {consumed} bytes)")
            idx += consumed
            
            # Advance PC by pc_delta * pc_quantum
            pc += pc_delta * pc_quantum
            #print(f"    → pc += ({pc_delta} * {pc_quantum}) → pc={hex(pc)}")
            
            # Check if we passed target
            if target_pc < pc:
                # print(f"    → target_pc {hex(target_pc)} < pc {hex(pc)}, RETURN value={value}")
                return value
        
       # print(f"\n  Final: RETURN value={value}")
        return value
        
      except Exception as e:
        print(f"[PCVALUE ERROR] {func_name}: {e}")
        import traceback
        traceback.print_exc()
        return None
    
 
    def _read_varint_zigzag(self, data: bytes) -> Tuple[int, int]:
      """
      Read a zigzag-encoded signed varint.
      Zigzag encoding: -1 = 1, 1 = 2, -2 = 3, 2 = 4, etc.
      """
      uval, consumed = self._read_varint(data)
      if consumed == 0:
        return (0, 0)
    
      # Decode zigzag: (uval >> 1) ^ -(uval & 1)
      if uval & 1:
        value = -((uval >> 1) + 1)
      else:
        value = uval >> 1
    
      return (value, consumed)
    
    def _extract_pcdata(self, layer, moduledata: Dict, func_struct_addr: int, npcdata: int, func_struct_base_size: int, nfuncdata: int) -> Dict[int, bytes]:
      """
      Extract PCDATA tables for one function.

      PCDATA entries are uint32 offsets into pctab, stored as an array
      right after the _func base struct. Length of each PCDATA blob is
      determined by finding the next higher offset among all PCDATA and
      FUNCDATA offsets (PCDATA is NOT null-terminated). Returns dict
      mapping pcdata_index to raw bytes.
      """
      pcdata_tables = {}
      pctab_base = moduledata["pctab"]["ptr"]
      pctab_len = moduledata["pctab"]["len"]

      try:
        # Step 1: Read PCDATA offsets (uint32 array right after base _func structure)
        pcdata_offset_array_addr = func_struct_addr + func_struct_base_size
        pcdata_offsets_size = npcdata * 4
        pcdata_offsets_data = layer.read(pcdata_offset_array_addr, pcdata_offsets_size, pad=True)
        
        if len(pcdata_offsets_data) < pcdata_offsets_size:
            print(f"  [WARNING] Could not read full PCDATA offsets array")
            return pcdata_tables
        
        # Step 2: Read FUNCDATA offsets (uint32 array after PCDATA offsets)
        funcdata_offset_array_addr = pcdata_offset_array_addr + pcdata_offsets_size
        funcdata_offsets_size = nfuncdata * 4
        funcdata_offsets_data = layer.read(funcdata_offset_array_addr, funcdata_offsets_size, pad=True)
        
        # Step 3: Collect all VALID offsets to determine boundaries
        all_offsets = []
        
        # Parse PCDATA offsets
        pcdata_offsets = []
        for i in range(npcdata):
            offset = int.from_bytes(pcdata_offsets_data[i*4:(i+1)*4], "little")
            pcdata_offsets.append(offset)
            
            # Validate and collect
            if offset == 0:
                continue  # Missing/unused
            if offset >= pctab_len:
                #print(f"  [WARNING] PCDATA[{i}] offset {offset} >= pctab_len {pctab_len}, ignoring")
                continue
            all_offsets.append(offset)
        
        # Parse FUNCDATA offsets (if available)
        funcdata_offsets = []
        if len(funcdata_offsets_data) >= funcdata_offsets_size:
            for i in range(nfuncdata):
                offset = int.from_bytes(funcdata_offsets_data[i*4:(i+1)*4], "little")
                funcdata_offsets.append(offset)
                
                # Validate and collect
                # Sentinel values: 0 = missing, 0xFFFFFFFF = missing
                if offset == 0 or offset == 0xFFFFFFFF:
                    continue
                if offset >= pctab_len:
                    #print(f"  [WARNING] FUNCDATA[{i}] offset {offset} >= pctab_len {pctab_len}, ignoring")
                    continue
                all_offsets.append(offset)
        
        # Sort all valid offsets to find boundaries
        all_offsets_sorted = sorted(set(all_offsets))
        '''
        print(f"  PCDATA offsets: {pcdata_offsets}")
        print(f"  FUNCDATA offsets: {funcdata_offsets}")
        print(f"  All valid offsets (sorted): {all_offsets_sorted}")
        '''
        # Step 4: Extract each PCDATA table using offset boundaries
        for i in range(npcdata):
            offset = pcdata_offsets[i]
            
            if offset == 0:
                # print(f"  [PCDATA {i}] offset is 0, skipping")
                continue
            
            # Validate offset (should already be validated above, but double-check)
            if offset >= pctab_len:
                # print(f"  [PCDATA {i}] offset {offset} >= pctab_len {pctab_len}, skipping")
                continue
            
            # Find next higher offset to determine length
            next_offset = None
            for next_off in all_offsets_sorted:
                if next_off > offset:
                    next_offset = next_off
                    break
            
            # Calculate length
            if next_offset is not None:
                length = next_offset - offset
            else:
                # No next offset, use remaining pctab space
                length = pctab_len - offset
            
            # Sanity check length
            if length <= 0:
                # print(f"  [PCDATA {i}] ERROR: offset={offset}, next={next_offset}, length={length} <= 0, skipping")
                continue
            if length > 100000:  # Reasonable upper bound for a single pcdata table
                # print(f"  [PCDATA {i}] WARNING: offset={offset}, next={next_offset}, length={length} seems too large")
                # Continue anyway, but cap it
                length = min(length, 100000)
            
            # Validate address range
            pctab_addr = pctab_base + offset
            pctab_end_addr = pctab_base + offset + length
            
            if pctab_end_addr > pctab_base + pctab_len:
                # print(f"  [PCDATA {i}] ERROR: range [{hex(pctab_addr)}, {hex(pctab_end_addr)}) exceeds pctab bounds")
                continue
            
            # print(f"  [PCDATA {i}] offset={offset}, next_offset={next_offset}, length={length}")
            # print(f"  [PCDATA {i}] address range: [{hex(pctab_addr)}, {hex(pctab_end_addr)})")
            
            # Read the PCDATA blob
            data = layer.read(pctab_addr, length, pad=True)
            
            if len(data) < length:
                # print(f"  [PCDATA {i}] WARNING: Could only read {len(data)}/{length} bytes")
                pcdata_tables[i] = data
            else:
                pcdata_tables[i] = data[:length]
            
            if length > 16:
               preview = pcdata_tables[i][:16].hex()
            # Show data preview
            '''
            if length <= 64:
                 print(f"  [PCDATA {i}] Full data ({length} bytes): {pcdata_tables[i].hex()}")
            else:
                preview = pcdata_tables[i][:64].hex()
                # print(f"  [PCDATA {i}] First 64 bytes: {preview}... (total: {length} bytes)")
            '''
        # print(f"  Successfully extracted {len(pcdata_tables)} PCDATA tables")
        return pcdata_tables
        
      except Exception as e:
        # print(f"[ERROR] _extract_pcdata failed: {e}")
        import traceback
        traceback.print_exc()
        return pcdata_tables
    
    
    
    def _parse_stack_objects(self, layer, stackobj_addr: int, ptrSize: int) -> Optional[Dict]:
      """
      Parse StackObjects (FUNCDATA_StackObjects).
    
      Structure (from runtime/stack.go):
      n          uintptr  // number of objects
      objects[]  stackObjectRecord
    
      stackObjectRecord:
      off        int32    // offset from stack pointer (negative = above SP)
      size       int32    // size of object in bytes
      _type      *_type   // pointer to type information (ptrSize bytes)
    
      This describes stack-allocated objects that may need special handling
      (e.g., objects with finalizers, large objects that escaped to heap initially).
      """
      try:
        if stackobj_addr == 0:
            return None
        
        # Read number of objects
        n_bytes = layer.read(stackobj_addr, ptrSize, pad=True)
        if len(n_bytes) < ptrSize:
            return None
        
        if ptrSize == 8:
            n = int.from_bytes(n_bytes, 'little')
        else:
            n = int.from_bytes(n_bytes, 'little')
        
        # Validate
        if n < 0 or n > 1000:
            return None
        
        if n == 0:
            return {
                'address': stackobj_addr,
                'num_objects': 0,
                'objects': []
            }
        
        # Each record is: off(4) + size(4) + type_ptr(ptrSize)
        record_size = 8 + ptrSize
        
        # Read all records
        objects = []
        for obj_idx in range(n):
            offset = ptrSize + (obj_idx * record_size)
            record_data = layer.read(stackobj_addr + offset, record_size, pad=True)
            
            if len(record_data) < record_size:
                break
            
            # Parse record
            off = int.from_bytes(record_data[0:4], 'little', signed=True)
            size = int.from_bytes(record_data[4:8], 'little', signed=True)
            
            if ptrSize == 8:
                type_ptr = int.from_bytes(record_data[8:16], 'little')
            else:
                type_ptr = int.from_bytes(record_data[8:12], 'little')
            
            objects.append({
                'index': obj_idx,
                'offset': off,
                'size': size,
                'type_ptr': type_ptr,
            })
        
        return {
            'address': stackobj_addr,
            'num_objects': n,
            'objects': objects,
        }
        
      except Exception as e:
        vollog.debug(f"Error parsing StackObjects: {e}")
        return None
    
    
    def _parse_arginfo_bytecode(self, layer, arginfo_addr: int, func_name: str) -> Optional[Dict]:
      """
      Parse ArgInfo bytecode (Go 1.18+/1.20+).

      Format from src/internal/abi/type.go:
      - Stream of bytes with offset/size pairs for args
      - Operators (all >= 0xf0):
      0xff: end of sequence
      0xfe: start aggregate '{'
      0xfd: end aggregate '}'
      0xfc: dotdotdot '...'
      0xfb: offset too large '_'
      - Regular args: offset_byte (< 0xf0) followed by size_byte
      """


      TraceArgsEndSeq = 0xff
      TraceArgsStartAgg = 0xfe
      TraceArgsEndAgg = 0xfd
      TraceArgsDotdotdot = 0xfc
      TraceArgsOffsetTooLarge = 0xfb
      TraceArgsSpecial = 0xf0

      try:
        data = layer.read(arginfo_addr, 256, pad=True)
        if len(data) < 1:
            return None
        
        args = []
        idx = 0
        agg_depth = 0
        
        while idx < len(data):
            op = data[idx]
            idx += 1
            
            if op == TraceArgsEndSeq:
                # 0xff - stop immediately
                break
            
            elif op == TraceArgsStartAgg:
                # 0xfe - '{'
                agg_depth += 1
                args.append({'type': 'start_agg'})
            
            elif op == TraceArgsEndAgg:
                # 0xfd - '}'
                agg_depth -= 1
                args.append({'type': 'end_agg'})
            
            elif op == TraceArgsDotdotdot:
                # 0xfc - '...'
                args.append({'type': 'variadic'})
            
            elif op == TraceArgsOffsetTooLarge:
                # 0xfb - '_'
                args.append({'type': 'offset_too_large'})
            
            elif op < TraceArgsSpecial:
                # Regular arg: op is offset, next byte is size
                if idx >= len(data):
                    break
                
                size = data[idx]
                idx += 1
                
                args.append({
                    'type': 'arg',
                    'offset': op,
                    'size': size,
                    'in_aggregate': agg_depth > 0
                })
            
            else:
                # Unknown operator - stop
                break
        
        # Parse into logical Go arguments structure
        # Format: [arg1, arg2, [field1, field2], arg3, ...]
        # Simple args are dicts, aggregates are lists of field dicts
        logical_args = []
        all_args = [a for a in args if a.get('type') == 'arg']
        
        i = 0
        
        while i < len(args):
            entry = args[i]
            
            if entry.get('type') == 'start_agg':
                # Start of aggregate - collect all fields into a list
                agg_fields = []
                i += 1
                depth = 1
                
                while i < len(args) and depth > 0:
                    inner = args[i]
                    if inner.get('type') == 'start_agg':
                        depth += 1
                    elif inner.get('type') == 'end_agg':
                        depth -= 1
                        if depth == 0:
                            break
                    elif inner.get('type') == 'arg':
                        agg_fields.append({
                            'offset': inner['offset'],
                            'size': inner['size'],
                        })
                    i += 1
                
                # Add the aggregate as a list
                logical_args.append(agg_fields)
            
            elif entry.get('type') == 'arg':
                # Standalone arg - add as single dict
                logical_args.append({
                    'offset': entry['offset'],
                    'size': entry['size'],
                })
            
            i += 1
        
        if all_args:
            total_frame_size = max((a['offset'] + a['size']) for a in all_args)
        else:
            total_frame_size = 0
        
        return {
            'address': arginfo_addr,
            'num_args': len(logical_args),
            'args': logical_args,  # Clean structure: [arg, [field, field], arg, ...]
            'total_arg_frame_size': total_frame_size,
            'raw_bytecode_hex': data[:idx].hex(),
        }
        
      except Exception as e:
        vollog.debug(f"Error parsing ArgInfo: {e}")
        return None
   
    def _parse_args_from_stackmap(self, layer, stackmap_addr: int, ptrSize: int) -> Optional[Dict]:
      try:
        if stackmap_addr == 0:
            return None
        
        header = layer.read(stackmap_addr, 16, pad=True)
        if len(header) < 8:
            return None
        
        n = int.from_bytes(header[0:4], 'little', signed=True)
        nbit = int.from_bytes(header[4:8], 'little', signed=True)
        
        
        if n < 0 or n > 1000 or nbit < 0 or nbit > 100:
            return None
        
        # Calculate total argument bytes
        total_arg_bytes = nbit * ptrSize
        
        # Parse bitmaps to find which slots contain pointers
        pointer_slots = []
        if n > 0 and nbit > 0:
            bitmap_bytes = (nbit + 7) // 8  # Round up to bytes
            
            # Read first bitmap (bitmap 0 is typically for function entry)
            bitmap_data = layer.read(stackmap_addr + 8, bitmap_bytes, pad=True)
            
            if len(bitmap_data) >= bitmap_bytes:
                bitmap_int = int.from_bytes(bitmap_data[:bitmap_bytes], 'little')
              
                # Each bit indicates if that slot contains a pointer
                for bit_idx in range(nbit):
                    if (bitmap_int >> bit_idx) & 1:
                        slot_offset = bit_idx * ptrSize
                        pointer_slots.append(slot_offset)
                    else:
                        slot_offset = bit_idx * ptrSize
                      
        
        result = {
            'total_arg_bytes': total_arg_bytes,
            'num_slots': nbit,
            'pointer_slots': pointer_slots,
            'num_pointers': len(pointer_slots),
        }
        
       # print(f"  Result: {result}")
        return result
        
      except Exception as e:
        print(f"[ERROR] _parse_args_from_stackmap: {e}")
        import traceback
        traceback.print_exc()
        return None
   
   
   
    def _parse_locals_stackmap(self, layer, stackmap_addr: int, ptrSize: int) -> Optional[Dict]:
      """
      Parse LocalsPointerMaps stackmap set.
    
      Structure:
      n      int32     // number of bitmaps in the set
      nbit   int32     // bits per bitmap (pointer slots)
      bitmap[0]        // first bitmap (nbit bits, rounded up to bytes)
      bitmap[1]        // second bitmap
      ...
      bitmap[n-1]      // last bitmap
    
      Note: Which bitmap applies depends on PC via PCDATA_StackMapIndex.
      For static analysis, we extract all bitmaps without PC context.
      """
      try:
        if stackmap_addr == 0:
            return None
        
        # Read header
        header = layer.read(stackmap_addr, 8, pad=True)
        if len(header) < 8:
            return None
        
        n = int.from_bytes(header[0:4], 'little', signed=True)
        nbit = int.from_bytes(header[4:8], 'little', signed=True)
        
        # Validate
        if n < 0 or n > 1000 or nbit < 0 or nbit > 100:
            return None
        
        # Calculate bitmap size
        bitmap_bytes = (nbit + 7) // 8
        total_local_area = nbit * ptrSize
        
        # Read all bitmaps
        bitmaps = []
        for bitmap_idx in range(n):
            offset = 8 + (bitmap_idx * bitmap_bytes)
            bitmap_data = layer.read(stackmap_addr + offset, bitmap_bytes, pad=True)
            
            if len(bitmap_data) >= bitmap_bytes:
                bitmap_int = int.from_bytes(bitmap_data, 'little')
                
                # Decode pointer slots for this bitmap
                pointer_offsets = []
                for bit_idx in range(nbit):
                    if (bitmap_int >> bit_idx) & 1:
                        slot_offset = bit_idx * ptrSize
                        pointer_offsets.append(slot_offset)
                
                bitmaps.append({
                    'index': bitmap_idx,
                    'bitmap_hex': bitmap_data[:bitmap_bytes].hex(),
                    'pointer_offsets': pointer_offsets,
                    'num_pointers': len(pointer_offsets)
                })
        
        return {
            'address': stackmap_addr,
            'num_bitmaps': n,
            'num_slots': nbit,
            'total_local_area': total_local_area,
            'bitmaps': bitmaps,
        }
        
      except Exception as e:
        vollog.debug(f"Error parsing LocalsPointerMaps: {e}")
        return None
   
   
    
   
    def _read_varint(self, data: bytes) -> Tuple[int, int]:
      """Read a varint from bytes, return (value, bytes_consumed)."""
      if len(data) == 0:
        return (0, 0)
    
      value = 0
      shift = 0
      consumed = 0
    
      for b in data[:10]:  # Max 10 bytes for varint
        consumed += 1
        value |= (b & 0x7F) << shift
        if (b & 0x80) == 0:  # High bit not set = last byte
            return (value, consumed)
        shift += 7
    
      return (value, consumed)

    def calculate_frame_size(self, func_info: Dict, target_pc: int) -> Optional[int]:
      """
      Calculate frame size at a specific PC within a function.
    
      Args:
        func_info: Function info dict from _extract_functions (must contain 'pc', 'pcsp')
        target_pc: The PC where you want to know the frame size
    
      Returns:
        Frame size in bytes, or None if calculation fails
      """
      if not self.pclntab or not self.moduledata:
        print("[ERROR] pclntab or moduledata not initialized")
        return None
    
      entry_pc = func_info.get('pc')
      pcsp_offset = func_info.get('pcsp')
    
      if entry_pc is None or pcsp_offset is None:
        print("[ERROR] Function missing pc or pcsp field")
        return None
    
      # Validate target_pc is within function bounds
      if target_pc < entry_pc:
        print(f"[ERROR] target_pc {hex(target_pc)} < entry_pc {hex(entry_pc)}")
        return None
    
      # Get PCSP table data
      pctab_base = self.moduledata["pctab"]["ptr"]
      pctab_len = self.moduledata["pctab"]["len"]
    
      if pcsp_offset >= pctab_len:
        print(f"[ERROR] pcsp_offset {pcsp_offset} >= pctab_len {pctab_len}")
        return None
    
      # Read PCSP data (we need to find its length)
      # Use similar logic to _extract_pcdata
      try:
        layer = self.context.layers[self.layer_name]
        
        # Read up to 1KB (PCSP tables are typically small)
        pcsp_addr = pctab_base + pcsp_offset
        pcsp_data = layer.read(pcsp_addr, 1024, pad=True)
        
        if len(pcsp_data) == 0:
            print("[ERROR] Could not read PCSP data")
            return None
        
        # Decode PCSP to get SP delta at target_pc
        sp_delta = self._pcvalue(
            pcsp_data, 
            target_pc=target_pc, 
            entry_pc=entry_pc,
            func_name=f"{func_info.get('name', '<unknown>')} [PCSP]"
        )
        
        if sp_delta is None:
            print("[ERROR] Failed to decode PCSP")
            return None
        
        # sp_delta is how much SP has moved from caller's SP
        # Frame size = sp_delta
        return sp_delta
        
      except Exception as e:
        print(f"[ERROR] calculate_frame_size failed: {e}")
        import traceback
        traceback.print_exc()
        return None


    def _find_allgs_via_scan(self, layer_name: str, segments: List[Dict], ptrSize: int) -> Optional[Dict]:
      """
      Find runtime.allgs by scanning the RW data segment for a valid goroutine slice.
    
      runtime.allgs is a global []* g slice maintained by the Go scheduler that
      holds pointers to every goroutine ever created (including dead ones). Its
      structure is a standard Go slice header: {ptr, len, cap} where ptr points
      to a heap-allocated array of *g pointers, len is the current goroutine
      count, and cap is the allocated capacity.
    
      We locate it by scanning the RW segment for any 3-word tuple that:
      1. Has valid slice invariants (0 < len <= cap, cap < 10000, aligned ptr)
      2. Points to an array where each entry is a valid *g pointer
      3. Each *g has valid stack bounds (lo < hi, size < 1MB, 8-byte aligned)
      4. Each *g has a valid atomicstatus (0-9) and reasonable goid (0-100000)
    
      Version-aware: uses _validate_g_array which checks version-specific
      offsets for atomicstatus and goid (these shift between Go 1.16, 1.18, 1.24) and _validate_g_array_go115 for Go 1.15.
    
      When multiple candidates match, the one with the most validated goroutines
      wins. Requires at least 50% of entries to pass strict validation.
    
      Returns:
        Dict with {address, ptr, len, cap} or None if not found.
      """
      print("Searching for runtime.allgs...")

      rw_seg = None
      for seg in segments:
        if seg["p_type"] == self.PT_LOAD and seg["p_flags_str"] == "RW-":
            rw_seg = seg
            break

      if not rw_seg:
        return None

      start = rw_seg["runtime_vaddr"]
      end = rw_seg["runtime_end"]

      layer = self.context.layers[layer_name]
      slice_size = ptrSize * 3

      best_candidate = None
      best_valid_count = 0

      current = start

      while current < end - slice_size:
        try:
            data = layer.read(current, slice_size, pad=True)

            if ptrSize == 8:
                ptr = int.from_bytes(data[0:8], 'little')
                length = int.from_bytes(data[8:16], 'little')
                cap = int.from_bytes(data[16:24], 'little')
            else:
                ptr = int.from_bytes(data[0:4], 'little')
                length = int.from_bytes(data[4:8], 'little')
                cap = int.from_bytes(data[8:12], 'little')

            # Basic slice validation
            if length == 0 or length > cap or cap > 10000 or ptr < 0x10000:
                current += ptrSize
                continue

            # Goroutine count should be reasonable (1-1000 typically)
            if length > 1000:
                current += ptrSize
                continue

            # Pointer should be aligned
            if ptr % ptrSize != 0:
                current += ptrSize
                continue

            # Validate ALL goroutines 
            major, minor, _ = self.go_version_tuple
            is_go_115 = (major == 1 and minor == 15)
       
            if is_go_115:
               valid_count = self._validate_g_array_go115(layer_name, ptr, length, ptrSize)
            else:
               valid_count = self._validate_g_array(layer_name, ptr, length, ptrSize)
            # Require at least 50% valid goroutines AND at least 1 valid
            if valid_count > 0 and valid_count >= length * 0.5:
                if valid_count > best_valid_count:
                    best_valid_count = valid_count
                    best_candidate = {
                        "address": current,
                        "ptr": ptr,
                        "len": length,
                        "cap": cap,
                    }

            current += ptrSize

        except:
            current += ptrSize

      if best_candidate and best_valid_count >= 1:
        print(f"Found allgs at {hex(best_candidate['address'])}, "
              f"{best_candidate['len']} goroutines ({best_valid_count} valid)")
        return best_candidate

      print("[!] Could not find valid runtime.allgs")
      return None

    
    def _validate_g_array_go115(self, layer_name: str, ptr: int, count: int, ptrSize: int) -> int:
      """
      Validate goroutine array for Go 1.15.
      Similar to _validate_g_array but uses Go 1.15-specific offsets.
    
      Returns: Number of valid goroutines found
      """
      layer = self.context.layers[layer_name]
      valid_count = 0
    
      try:
        # Read array of g pointers
        array_data = layer.read(ptr, count * ptrSize, pad=True)
        
        for i in range(count):
            if ptrSize == 8:
                g_ptr = int.from_bytes(array_data[i*8:(i+1)*8], 'little')
            else:
                g_ptr = int.from_bytes(array_data[i*4:(i+1)*4], 'little')
            
            if g_ptr == 0:
                continue
            
            try:
                # Read g struct (first 0x150 bytes is enough)
                g_data = layer.read(g_ptr, 0x150, pad=True)
                
                if len(g_data) < 0x150:
                    continue
                
                # Validate stack fields (same for all versions)
                stack_lo = int.from_bytes(g_data[0x00:0x08], 'little')
                stack_hi = int.from_bytes(g_data[0x08:0x10], 'little')
                
                # Stack validation
                if stack_hi <= stack_lo:
                    continue
                if (stack_hi - stack_lo) > 0x100000:  # > 1MB
                    continue
                if stack_lo % 8 != 0 or stack_hi % 8 != 0:
                    continue
                
                # Go 1.15 specific offsets (from runtime2.go source):
                # atomicstatus at 0x90
                # goid at 0x98 (int64)
                atomicstatus = int.from_bytes(g_data[0x90:0x94], 'little') & 0xFFF
                goid = int.from_bytes(g_data[0x98:0xA0], 'little', signed=True)
                
                # Validate
                if atomicstatus in self.VALID_G_STATUS and 0 <= goid <= 100000:
                    valid_count += 1
                
            except:
                continue
    
      except:
        pass
    
      return valid_count
    def _validate_g_array(self, layer_name: str, ptr: int, count: int, ptrSize: int) -> int:
      """
      Validation of goroutine array.
      Tests version-specific offsets.
      """
      layer = self.context.layers[layer_name]
      valid_count = 0
    
      major, minor, _ = self.go_version_tuple

      try:
        array_data = layer.read(ptr, count * ptrSize, pad=True)

        for i in range(count):
            g_ptr = int.from_bytes(array_data[i*ptrSize:(i+1)*ptrSize], 'little')

            if g_ptr == 0:
                continue

            try:
                g_data = layer.read(g_ptr, 0x150, pad=True)

                if len(g_data) < 0x150:
                    continue

                # Parse stack fields (same for all versions)
                stack_lo = int.from_bytes(g_data[0x00:0x08], 'little')
                stack_hi = int.from_bytes(g_data[0x08:0x10], 'little')
                
                # Validate stack
                if stack_hi <= stack_lo:
                    continue
                if (stack_hi - stack_lo) > 0x100000:  # > 1MB
                    continue
                if stack_lo % 8 != 0 or stack_hi % 8 != 0:
                    continue
                
                # Version-specific validation
                if major == 1 and minor >= 16 and minor < 18:
                    # Go 1.16-1.17 offsets
                    status = int.from_bytes(g_data[0x90:0x94], 'little') & 0xFFF
                    goid = int.from_bytes(g_data[0x98:0xA0], 'little')
                elif major == 1 and minor >= 24:
                    # Go 1.24+ offsets
                    status = int.from_bytes(g_data[0x90:0x94], 'little') & 0xFFF
                    goid = int.from_bytes(g_data[0x98:0xA0], 'little')
                else:
                    # Go 1.18-1.23 offsets
                    status = int.from_bytes(g_data[0x98:0x9C], 'little') & 0xFFF
                    goid = int.from_bytes(g_data[0xA0:0xA8], 'little')
                
                # Validate
                if status in self.VALID_G_STATUS and 0 <= goid <= 100000:
                    valid_count += 1

            except:
                continue

      except:
        pass

      return valid_count
   
    
   
    
    
    def _map_waitreason_enum(self, enum_val: int) -> str:
      """Map waitReason enum to string."""
      WAIT_REASON = {
        0: "",                              # waitReasonZero
        1: "GC assist marking",             # waitReasonGCAssistMarking
        2: "IO wait",                       # waitReasonIOWait
        3: "chan receive (nil chan)",       # waitReasonChanReceiveNilChan
        4: "chan send (nil chan)",          # waitReasonChanSendNilChan
        5: "dumping heap",                  # waitReasonDumpingHeap
        6: "garbage collection",            # waitReasonGarbageCollection
        7: "garbage collection scan",       # waitReasonGarbageCollectionScan
        8: "panicwait",                     # waitReasonPanicWait
        9: "select",                        # waitReasonSelect
        10: "select (no cases)",            # waitReasonSelectNoCases
        11: "GC assist wait",               # waitReasonGCAssistWait
        12: "GC sweep wait",                # waitReasonGCSweepWait
        13: "GC scavenge wait",             # waitReasonGCScavengeWait
        14: "chan receive",                 # waitReasonChanReceive
        15: "chan send",                    # waitReasonChanSend
        16: "finalizer wait",               # waitReasonFinalizerWait
        17: "force gc (idle)",              # waitReasonForceGCIdle
        18: "semacquire",                   # waitReasonSemacquire
        19: "sleep",                        # waitReasonSleep
        20: "sync.Cond.Wait",               # waitReasonSyncCondWait
        21: "sync.Mutex.Lock",              # waitReasonSyncMutexLock
        22: "sync.RWMutex.RLock",           # waitReasonSyncRWMutexRLock
        23: "sync.RWMutex.Lock",            # waitReasonSyncRWMutexLock
        24: "sync.WaitGroup.Wait",          # waitReasonSyncWaitGroupWait
        25: "trace reader (blocked)",       # waitReasonTraceReaderBlocked
        26: "wait for GC cycle",            # waitReasonWaitForGCCycle
        27: "GC worker (idle)",             # waitReasonGCWorkerIdle
        28: "GC worker (active)",           # waitReasonGCWorkerActive
        29: "preempted",                    # waitReasonPreempted
        30: "debug call",                   # waitReasonDebugCall
        31: "GC mark termination",          # waitReasonGCMarkTermination
        32: "stopping the world",           # waitReasonStoppingTheWorld
        33: "flushing proc caches",         # waitReasonFlushProcCaches
        34: "trace goroutine status",       # waitReasonTraceGoroutineStatus
        35: "trace proc status",            # waitReasonTraceProcStatus
        36: "page trace flush",             # waitReasonPageTraceFlush
        37: "coroutine",                    # waitReasonCoroutine
        38: "GC weak to strong wait",       # waitReasonGCWeakToStrongWait
        39: "synctest.Run",                 # waitReasonSynctestRun
        40: "synctest.Wait",                # waitReasonSynctestWait
        41: "chan receive (synctest)",      # waitReasonSynctestChanReceive
        42: "chan send (synctest)",         # waitReasonSynctestChanSend
        43: "select (synctest)",            # waitReasonSynctestSelect
    }
      return WAIT_REASON.get(enum_val, f"unknown_{enum_val}")
   
    def _parse_goroutine(self, layer_name: str, g_ptr: int, ptrSize: int) -> Optional[Dict]:
      """
      Parse a runtime.g struct at g_ptr with version-specific offsets.

      The g struct layout changes across Go versions due to added/removed
      fields (e.g., syscallbp added in 1.18, removed in 1.24). Key fields
      extracted: stack bounds, sched (sp/pc/bp), atomicstatus, goid,
      waitreason, gopc, startpc. Returns None if validation fails
      (invalid stack bounds, bad status, unreasonable goid).
      """
      try:
        layer = self.context.layers[layer_name]
        g_data = layer.read(g_ptr, 0x180, pad=True)

        if len(g_data) < 0x140:
            return None

        # Common fields (same across all versions)
        stack_lo = int.from_bytes(g_data[0x00:0x08], 'little')
        stack_hi = int.from_bytes(g_data[0x08:0x10], 'little')
        
        # Validate stack
        if stack_hi <= stack_lo:
            return None
        if (stack_hi - stack_lo) > 0x100000:  # > 1MB
            return None
        if stack_lo % 8 != 0 or stack_hi % 8 != 0:
            return None
        
        # sched gobuf at offset 0x38 (SAME FOR ALL VERSIONS)
        sched_sp = int.from_bytes(g_data[0x38:0x40], 'little')
        sched_pc = int.from_bytes(g_data[0x40:0x48], 'little')
        sched_bp = int.from_bytes(g_data[0x68:0x70], 'little')
        
        # Initialize variables
        atomicstatus = None
        goid = 0
        waitsince = 0
        waitreason_enum = 0
        waitreason = ""
        lockedm = 0
        gopc = 0
        startpc = 0
        
        # Get Go version
        major, minor, patch = self.go_version_tuple
        
        # =================================================================
        # Go 1.15: Based on runtime2.go source code
        # =================================================================
        if major == 1 and minor == 15:
           atomicstatus = int.from_bytes(g_data[0x90:0x94], 'little') & 0xFFF
           goid = int.from_bytes(g_data[0x98:0xA0], 'little', signed=True)
            
           # Validate
           if atomicstatus not in self.VALID_G_STATUS:
              return None
           if goid < 0 or goid > 100000:
              if goid != 0:  # goid can be 0 for g0 (scheduler goroutine)
                    return None
            
           waitsince = int.from_bytes(g_data[0xA8:0xB0], 'little', signed=True)
           waitreason_enum = g_data[0xB0]  # uint8
           waitreason = self._map_waitreason_enum(waitreason_enum)
            
           # For lockedm, gopc, startpc - estimate offsets
           # These are further down in the struct
           # lockedm is of type muintptr (uintptr wrapper)
           # Need to count through the struct carefully...
           # After waitreason (0xB0), there are many bool/uint8 fields
           # Then larger fields like tracelastp, lockedm, etc.
            
           # Rough estimate based on struct layout:
           lockedm = int.from_bytes(g_data[0xD8:0xE0], 'little')
           gopc = int.from_bytes(g_data[0x118:0x120], 'little')
           startpc = int.from_bytes(g_data[0x120:0x128], 'little')
        # =================================================================
        # Go 1.16-1.17: NO syscallbp field, different offsets
        # =================================================================
        if major == 1 and minor >= 16 and minor < 18:
            
            
            atomicstatus = int.from_bytes(g_data[0x90:0x94], 'little') & 0xFFF
            goid = int.from_bytes(g_data[0x98:0xA0], 'little')
            
            # Validate
            if atomicstatus not in self.VALID_G_STATUS:
                return None
            if goid < 0 or goid > 100000:
                # goid can be 0 for g0 (scheduler goroutine)
                if goid != 0:
                    return None
            
            waitsince = int.from_bytes(g_data[0xA8:0xB0], 'little')
            waitreason_enum = g_data[0xB0]
            waitreason = self._map_waitreason_enum(waitreason_enum)
            lockedm = int.from_bytes(g_data[0xD8:0xE0], 'little')
            gopc = int.from_bytes(g_data[0x118:0x120], 'little')
            startpc = int.from_bytes(g_data[0x128:0x130], 'little')
        
        # =================================================================
        # Go 1.18-1.19: Has syscallbp, slightly different layout
        # =================================================================
        elif major == 1 and minor >= 18 and minor < 20:
           
            
            atomicstatus = int.from_bytes(g_data[0x98:0x9C], 'little') & 0xFFF
            goid = int.from_bytes(g_data[0xA0:0xA8], 'little')
            
            if atomicstatus not in self.VALID_G_STATUS:
                return None
            if goid < 0 or goid > 100000:
                if goid != 0:
                    return None
            
            waitsince = int.from_bytes(g_data[0xB0:0xB8], 'little')
            waitreason_enum = g_data[0xB8]
            waitreason = self._map_waitreason_enum(waitreason_enum)
            lockedm = int.from_bytes(g_data[0xE0:0xE8], 'little')
            gopc = int.from_bytes(g_data[0x120:0x128], 'little')
            startpc = int.from_bytes(g_data[0x130:0x138], 'little')
        
        # =================================================================
        # Go 1.20-1.22: Similar to 1.18-1.19
        # =================================================================
        elif major == 1 and minor >= 20 and minor < 23:
            atomicstatus = int.from_bytes(g_data[0x98:0x9C], 'little') & 0xFFF
            goid = int.from_bytes(g_data[0xA0:0xA8], 'little')
            
            if atomicstatus not in self.VALID_G_STATUS:
                return None
            if goid < 0 or goid > 100000:
                if goid != 0:
                    return None
            
            waitsince = int.from_bytes(g_data[0xB0:0xB8], 'little')
            waitreason_enum = g_data[0xB8]
            waitreason = self._map_waitreason_enum(waitreason_enum)
            lockedm = int.from_bytes(g_data[0xE0:0xE8], 'little')
            gopc = int.from_bytes(g_data[0x120:0x128], 'little')
            startpc = int.from_bytes(g_data[0x130:0x138], 'little')
        
        # =================================================================
        # Go 1.23: Slightly different from 1.24
        # =================================================================
        elif major == 1 and minor == 23:
            atomicstatus = int.from_bytes(g_data[0x98:0x9C], 'little') & 0xFFF
            goid = int.from_bytes(g_data[0xA0:0xA8], 'little')
            
            if atomicstatus not in self.VALID_G_STATUS:
                return None
            if goid < 0 or goid > 100000:
                if goid != 0:
                    return None
            
            waitsince = int.from_bytes(g_data[0xB0:0xB8], 'little')
            waitreason_enum = g_data[0xB8]
            waitreason = self._map_waitreason_enum(waitreason_enum)
            lockedm = int.from_bytes(g_data[0xD8:0xE0], 'little')
            gopc = int.from_bytes(g_data[0x120:0x128], 'little')
            startpc = int.from_bytes(g_data[0x130:0x138], 'little')
        
        # =================================================================
        # Go 1.24+: Current layout (your existing code)
        # =================================================================
        elif major == 1 and minor >= 24:
            # Go 1.24 removed syscallbp, back to similar layout as 1.16
            atomicstatus = int.from_bytes(g_data[0x90:0x94], 'little') & 0xFFF
            goid = int.from_bytes(g_data[0x98:0xA0], 'little')
            
            if atomicstatus not in self.VALID_G_STATUS:
                return None
            if goid < 0 or goid > 100000:
                if goid != 0:
                    return None
            
            waitsince = int.from_bytes(g_data[0xA8:0xB0], 'little')
            waitreason_enum = g_data[0xB0]
            waitreason = self._map_waitreason_enum(waitreason_enum)
            lockedm = int.from_bytes(g_data[0xD0:0xD8], 'little')
            gopc = int.from_bytes(g_data[0x118:0x120], 'little')
            startpc = int.from_bytes(g_data[0x128:0x130], 'little')
        
        # =================================================================
        # Fallback: Try Go 1.16 offsets as default
        # =================================================================
        else:
            atomicstatus = int.from_bytes(g_data[0x90:0x94], 'little') & 0xFFF
            goid = int.from_bytes(g_data[0x98:0xA0], 'little')
            
            if atomicstatus not in self.VALID_G_STATUS:
                return None
            
            waitsince = int.from_bytes(g_data[0xA8:0xB0], 'little')
            waitreason_enum = g_data[0xB0]
            waitreason = self._map_waitreason_enum(waitreason_enum)
            lockedm = int.from_bytes(g_data[0xD8:0xE0], 'little')
            gopc = int.from_bytes(g_data[0x118:0x120], 'little')
            startpc = int.from_bytes(g_data[0x128:0x130], 'little')
        
        status_name = self.G_STATUS_NAMES.get(atomicstatus, f"unknown_{atomicstatus}")
        stack_size = stack_hi - stack_lo
        
        return {
            "g_ptr": g_ptr,
            "goid": goid,
            "status": atomicstatus,
            "status_name": status_name,
            "stack_lo": stack_lo,
            "stack_hi": stack_hi,
            "stack_size": stack_size,
            "sched_sp": sched_sp,
            "sched_pc": sched_pc,
            "sched_bp": sched_bp,
            "startpc": startpc,
            "gopc": gopc,
            "waitreason_enum": waitreason_enum,
            "waitreason": waitreason,
            "waitsince": waitsince,
            "lockedm": lockedm,
        }

      except Exception as e:
        print(f"G @ {hex(g_ptr)}: Exception: {e}")
        import traceback
        traceback.print_exc()
        return None
   
   
   
    def _unwind_goroutine_stack(self, g_info: Dict, func_lookup: Dict, max_frames: int = 1024) -> List[Dict]:
      """
      
      Unwind goroutine stack and return call frames.

      Notes (amd64 Go ABIInternal):
      - return PC slot is at: ret_pc_addr = sp + frame_size   (frame_size from PCSP)
      - stack-passed args start at: arg_base = ret_pc_addr + ptrSize
      - next frame SP (caller SP) is: arg_base
    
    
      Args:
        g_info: Goroutine info from _parse_goroutine
        func_lookup: Dict mapping PC ranges to function info
        max_frames: Maximum number of frames to unwind
        
      Returns:
        List of frame dicts with {depth, function, pc, sp, frame_size}
      """
      layer = self.context.layers[self.layer_name]
      ptrSize = self.pclntab["ptrSize"]
      self._current_func_lookup = func_lookup
      current_pc = g_info["sched_pc"]
      current_sp = g_info["sched_sp"]
      stack_lo = g_info["stack_lo"]
      stack_hi = g_info["stack_hi"]
    
      text_start = self.moduledata["text"]
      text_end = self.moduledata["etext"]
    
      
      # Go amd64: MinFrameSize = 0, so arg_base == fp. (Still keep as variable for portability)  
      min_frame_size = 0
      frames = []
      for depth in range(max_frames):
        # Validate SP
        if current_sp < stack_lo or current_sp >= stack_hi:
            break
        
        # Find function
        func_info = self._find_function_by_pc(current_pc, func_lookup)
        if not func_info:
            break
        
        func_name = func_info.get("name", "")
        if not func_name:
            func_name = f"<func@{hex(func_info['pc'])}>"
        
        # Calculate SP delta from PCSP
        sp_delta = self.calculate_frame_size(func_info, current_pc)
        if sp_delta is None or sp_delta < 0:
            break
        
        ret_pc_addr = current_sp + sp_delta
        if ret_pc_addr < stack_lo or ret_pc_addr + ptrSize > stack_hi:
            break
        try:
            return_pc_bytes = layer.read(ret_pc_addr, ptrSize, pad=True)
            return_pc = int.from_bytes(return_pc_bytes, "little")
        except Exception:
            break
        
        fp = ret_pc_addr + ptrSize
        arg_base = fp + min_frame_size
        
        if arg_base < stack_lo or arg_base > stack_hi:
            break
        
        
        
      
        frames.append({
            "depth": depth,
            "function": func_name,
            "pc": current_pc,
            "sp": current_sp,
            "sp_delta": sp_delta,
            "ret_pc_addr": ret_pc_addr,
            "arg_base": arg_base,
            "return_pc": return_pc,
            "func_info":func_info,
        })
        
        if return_pc == 0 or not (text_start <= return_pc < text_end):
            break
        
        # Move to next frame
        # After return, SP would be sp_entry + ptrSize (pop the return address)
        current_sp = fp     # == ret_pc_addr + ptrSize 
        current_pc = return_pc
    
        
        
      return frames




    def _find_function_by_pc(self, pc: int, func_lookup: Dict) -> Optional[Dict]:
      """Find function that contains the given PC."""
   
      for func_pc, func_info in func_lookup.items():
        func_start = func_info["pc"]
        func_end = func_start + func_info.get("size", 0)
        
        if func_start <= pc < func_end:
            return func_info
    
      print(f" No function found for PC {hex(pc)}")
      return None
    
    
  

    def _extract_types_by_scanning(self, ptrSize: int) -> Dict[int, Dict]:
      """
      Extract types by scanning the entire types section.
      This is more robust than relying on typelinks.
      """
      types_start = self.moduledata['types']
      types_end = self.moduledata['etypes']
    
      print(f"[*] Scanning types section: {hex(types_start)}-{hex(types_end)}")
    
      layer = self.context.layers[self.layer_name]
      types_size = types_end - types_start
    
      if types_size <= 0 or types_size > 0x10000000:  # Sanity check
        print(f"[!] Invalid types section size: {types_size}")
        return {}
    
      print(f"[*] Types section size: {types_size} bytes")
    
      # Scan through types section
      # Type structures are aligned (usually 8-byte boundary on 64-bit)
      alignment = ptrSize
    
      extracted = 0
      errors = 0
      current_addr = types_start
    
      # We'll scan with a sliding window, trying to parse at each aligned address
      while current_addr < types_end:
        # Try to parse type at this address
        try:
            # Check if already parsed
            if current_addr not in self.types_cache:
                type_info = self._parse_single_type(current_addr, ptrSize)
                
                if type_info and 'kind_str' in type_info:
                    extracted += 1
                    
                    # Skip ahead by the base type size
                    # This prevents parsing the same type multiple times
                    current_addr += 48 if ptrSize == 8 else 32
                    
                    # Add kind-specific size
                    kind = type_info.get('kind', 0)
                    if kind == 22:  # pointer
                        current_addr += ptrSize
                    elif kind == 23:  # slice
                        current_addr += ptrSize
                    elif kind == 17:  # array
                        current_addr += ptrSize * 3
                    elif kind == 25:  # struct
                        # Struct size varies, skip to next alignment
                        current_addr = ((current_addr + alignment - 1) // alignment) * alignment
                    elif kind == 21:  # map
                        major, minor, patch = self.go_version_tuple
                        is_go_118_plus = (major == 1 and minor >= 18)
                        if is_go_118_plus and ptrSize == 8:
                            current_addr += 32  # Go 1.18+: 3×8-byte pointers + 8 bytes metadata
                        else:
                            current_addr += 24 
                    elif kind == 20:  # interface
                        current_addr += 8 + (ptrSize * 3)
                    elif kind == 19:  # func
                        # Func size varies, skip to next alignment
                        current_addr = ((current_addr + alignment - 1) // alignment) * alignment
                    
                    continue
                else:
                    # Failed to parse, move forward by alignment
                    current_addr += alignment
            else:
                # Already cached, skip ahead
                current_addr += alignment
                
        except Exception as e:
            errors += 1
            current_addr += alignment
            
            # Stop if too many consecutive errors
            if errors > 100:
                vollog.debug(f"Too many errors scanning types, stopping")
                break
    
      #print(f"[+] Scanned types section (Direct Scan ): extracted {extracted} types, {errors} errors")
      return self.types_cache.copy()

    
    def _parse_single_type(self, type_addr: int, ptrSize: int) -> Optional[Dict]:
      """
      Parse a single type at a known address.
      This is the main entry point for parsing one type.
      """
      # Check cache first
      if type_addr in self.types_cache:
        cached = self.types_cache[type_addr]
        # Don't return incomplete entries
        if cached.get('_parsing'):
            return None
        return cached
    
      self.types_cache[type_addr] = {'_parsing': True}
      try:
        # Parse base type
        base_type = self._parse_base_type(type_addr, ptrSize)
        if not base_type:      
          del self.types_cache[type_addr]
          return None

        # Resolve name
        if base_type['str_offset'] != 0:
          base_type['name'] = self._resolve_name(base_type['str_offset'])

        # Parse kind-specific data
        kind = base_type['kind']

        if kind == 22:  # Pointer
          result = self._parse_ptr_type(type_addr, ptrSize, base_type)
        elif kind == 23:  # Slice
          result = self._parse_slice_type(type_addr, ptrSize, base_type)
        elif kind == 17:  # Array
          result = self._parse_array_type(type_addr, ptrSize, base_type)
        elif kind == 25:  # Struct
          result = self._parse_struct_type(type_addr, ptrSize, base_type)
        elif kind == 21:  # Map
           result = self._parse_map_type(type_addr, ptrSize, base_type)
        elif kind == 20:  # Interface
          result = self._parse_interface_type(type_addr, ptrSize, base_type)
        elif kind == 19:  # Func
          result = self._parse_func_type(type_addr, ptrSize, base_type)
        else:
          result = base_type

        if result.get('has_uncommon', False):
          # print("yes")
           result['methods'] = self._parse_uncommon_type_methods(type_addr, ptrSize, result)

        # Only cache if we have a valid result with all required fields
        if result and 'kind_str' in result:
           self.types_cache[type_addr] = result
           return result
        else:
            # Invalid result, clean up cache
            del self.types_cache[type_addr]
            return None
    
      except Exception as e:
        if type_addr in self.types_cache:
          del self.types_cache[type_addr]
        vollog.debug(f"Failed to parse type @ {hex(type_addr)}: {e}")
        return None  # Don't re-raise, just return None
    
    
    def _parse_base_type(self, type_addr: int, ptrSize: int) -> Optional[Dict]:
        """Parse the base _type structure common to all types.
        Common Base Fields (Present in EVERY Type)python{
          'address': 6331296,      # ← Memory address of this type
          'size': 24,              # ← Size of values of this type (in bytes)
          'ptrdata': 8,            # ← Bytes in prefix containing pointers
          'hash': 628083693,       # ← Hash value for this type
          'tflag': 2,              # ← Type flags
          'align': 8,              # ← Alignment requirement
          'fieldAlign': 8,         # ← Field alignment
          'kind': 23,              # ← Type kind (23 = slice)
          'kind_str': 'slice',     # ← Human-readable kind
          'str_offset': ...,       # ← Offset to type name string
          'ptrToThis': ...,        # ← Offset to pointer-to-this-type
          'name': '...',           # ← Resolved type name
          'has_uncommon': ...,     # ← Whether it has methods
          }
        """
        try:
            layer = self.context.layers[self.layer_name]
            base_size = 48 if ptrSize == 8 else 32
            data = layer.read(type_addr, base_size, pad=True)

            if len(data) < base_size:
                return None
            if ptrSize == 8:
                size = int.from_bytes(data[0:8], 'little')
                ptrdata = int.from_bytes(data[8:16], 'little')
                hash_val = int.from_bytes(data[16:20], 'little')
                tflag = data[20]
                align = data[21]
                fieldAlign = data[22]
                kind = data[23]
                # Skip equal, gcdata (8 bytes)
                str_offset = int.from_bytes(data[40:44], 'little', signed=True)
                ptrToThis = int.from_bytes(data[44:48], 'little', signed=True)
            else:
                size = int.from_bytes(data[0:4], 'little')
                ptrdata = int.from_bytes(data[4:8], 'little')
                hash_val = int.from_bytes(data[8:12], 'little')
                tflag = data[12]
                align = data[13]
                fieldAlign = data[14]
                kind = data[15]
                str_offset = int.from_bytes(data[24:28], 'little', signed=True)
                ptrToThis = int.from_bytes(data[28:32], 'little', signed=True)

            kind_val = kind & 0x1F
            has_uncommon = (tflag & 0x01) != 0
            # Validate
            if kind_val == 0 or kind_val > 26:
                return None

            # Size sanity check - reject obviously invalid sizes
            if size > 0x10000000:  # 256MB max
                return None

            # Alignment must be power of 2 or zero
            if align > 8:
                return None
            if align > 0 and (align & (align - 1)) != 0:
                return None

            return {
                'address': type_addr,
                'size': size,
                'ptrdata': ptrdata,
                'hash': hash_val,
                'tflag': tflag,
                'align': align,
                'fieldAlign': fieldAlign,
                'kind': kind_val,
                'kind_str': self.TYPE_KINDS.get(kind_val, f"unknown_{kind_val}"),
                'str_offset': str_offset,
                'ptrToThis': ptrToThis,
                'name': "",  # Will be filled in
                'has_uncommon': has_uncommon,
            }

        except:
            return None


    def _parse_ptr_type(self, type_addr: int, ptrSize: int, base_type: Dict) -> Dict:
      """Parse ptrtype structure."""
      try:
        layer = self.context.layers[self.layer_name]
        base_size = 48 if ptrSize == 8 else 32
        ptrtype_addr = type_addr + base_size
        data = layer.read(ptrtype_addr, ptrSize, pad=True)
        elem_ptr = int.from_bytes(data[0:ptrSize], 'little')
        etypes = self.moduledata.get('etypes', self.types_start + 0x1000000)
        if elem_ptr:
            # Only parse if within valid types section bounds
            if elem_ptr >= self.types_start and elem_ptr < etypes:
                if elem_ptr not in self.types_cache:
                    try:
                        self._parse_single_type(elem_ptr, ptrSize)
                    except:
                        pass  
         
        elem_offset = (elem_ptr - self.types_start) if elem_ptr else 0
        return {
            **base_type,
            'elem_type_ptr': elem_ptr,      
            'elem_type_offset': elem_offset, 
        }
      except Exception:
        return base_type
       
    
    def _parse_slice_type(self, type_addr: int, ptrSize: int, base_type: Dict) -> Dict:
      """Parse slicetype structure (rtype + elem *rtype)."""
      try:
        layer = self.context.layers[self.layer_name]
        base_size = 48 if ptrSize == 8 else 32
        slicetype_addr = type_addr + base_size

        data = layer.read(slicetype_addr, ptrSize, pad=True)
        if len(data) < ptrSize:
            return base_type

        elem_ptr = int.from_bytes(data[0:ptrSize], "little")

        elem_offset = 0
        if elem_ptr:
            types_start = self.types_start
            etypes = self.moduledata.get("etypes", types_start + 0x1000000)

            if types_start <= elem_ptr < etypes:
                elem_offset = elem_ptr - types_start

                if elem_ptr not in self.types_cache:
                    try:
                        self._parse_single_type(elem_ptr, ptrSize)
                    except Exception:
                        pass
            else:
                elem_ptr = 0

        return {
            **base_type,
            "elem_type_ptr": elem_ptr,
            "elem_type_offset": elem_offset,
        }

      except Exception:
        return base_type

    def _parse_array_type(self, type_addr: int, ptrSize: int, base_type: Dict) -> Dict:
        """Parse arraytype structure - uses DIRECT POINTERS."""
        try:
            layer = self.context.layers[self.layer_name]
            base_size = 48 if ptrSize == 8 else 32
            arraytype_addr = type_addr + base_size

            data_size = ptrSize * 3
            data = layer.read(arraytype_addr, data_size, pad=True)

            if len(data) < data_size:
                return base_type

            # Arrays use DIRECT POINTERS (not offsets)
            if ptrSize == 8:
                elem_ptr = int.from_bytes(data[0:8], 'little')
                slice_ptr = int.from_bytes(data[8:16], 'little')
                length = int.from_bytes(data[16:24], 'little')
            else:
                elem_ptr = int.from_bytes(data[0:4], 'little')
                slice_ptr = int.from_bytes(data[4:8], 'little')
                length = int.from_bytes(data[8:12], 'little')

            # Recursively parse element type with bounds validation
            if elem_ptr and elem_ptr not in self.types_cache:
                if elem_ptr >= self.types_start and elem_ptr < self.moduledata.get('etypes', self.types_start + 0x1000000):
                    self._parse_single_type(elem_ptr, ptrSize)

            return {
                **base_type,
                'elem_type_ptr': elem_ptr,
                'slice_type_ptr': slice_ptr,
                'length': length,
            }

        except Exception:
            return base_type

    def _parse_struct_type(self, type_addr: int, ptrSize: int, base_type: Dict) -> Dict:
      """Parse structtype structure (Go 1.16+ layout)."""
      try:
        layer = self.context.layers[self.layer_name]
        base_size = 48 if ptrSize == 8 else 32
        structtype_addr = type_addr + base_size

        data_size = 8 + (ptrSize * 3)
        data = layer.read(structtype_addr, data_size, pad=True)
        if len(data) < data_size:
            return base_type

        # pkgPath is a 'name'. For now, keep it as an offset-like token.
        pkgpath_raw = int.from_bytes(data[0:4], "little", signed=True)

        # Slice header for []structField starts at offset 8:
        slice_offset = 8
        if ptrSize == 8:
            fields_ptr = int.from_bytes(data[slice_offset : slice_offset + 8], "little")
            fields_len = int.from_bytes(data[slice_offset + 8 : slice_offset + 16], "little")
        else:
            fields_ptr = int.from_bytes(data[slice_offset : slice_offset + 4], "little")
            fields_len = int.from_bytes(data[slice_offset + 4 : slice_offset + 8], "little")

        fields = []
        if 0 < fields_len < 100 and fields_ptr != 0:
            
            field_size = ptrSize * 3

            types_start = self.types_start
            etypes = self.moduledata.get("etypes", types_start + 0x1000000)

            # Detect Go version for name resolution
            major, minor, patch = self.go_version_tuple
            is_go_118_plus = (major == 1 and minor >= 18) or major > 1

            for i in range(fields_len):
                try:
                    field_addr = fields_ptr + (i * field_size)
                    field_data = layer.read(field_addr, field_size, pad=True)
                    if len(field_data) < field_size:
                        continue

                    # --- name ---
                    # In ALL Go versions, structfield.name is a `name` struct
                    # The `name` struct contains `bytes *byte` - a POINTER to name data
                    # So the first field is always a pointer to the name bytes
                    name_ptr = int.from_bytes(field_data[0:ptrSize], "little")
                    
                    if name_ptr > 0x1000:  # Valid pointer check
                        field_name = self._resolve_name_direct(name_ptr)
                    else:
                        field_name = ""

                    # --- typ (*rtype) ---
                    typ_ptr = int.from_bytes(field_data[ptrSize : 2 * ptrSize], "little")

                    type_offset = 0
                    if types_start <= typ_ptr < etypes:
                        type_offset = typ_ptr - types_start
                        if typ_ptr not in self.types_cache:
                            try:
                                self._parse_single_type(typ_ptr, ptrSize)
                            except Exception:
                                pass
                    else:
                        # Out of types section → unknown type
                        typ_ptr = 0

                    # --- offsetEmbed ---
                    offset_embed = int.from_bytes(field_data[2 * ptrSize : 3 * ptrSize], "little")
                    # CRITICAL: offsetEmbed encoding depends on Go version
                    # Go 1.18+: offset is stored directly (not shifted)
                    # Go 1.16-1.17: offset is shifted left by 1, embedded flag in bit 0
                    if is_go_118_plus:
                        # Go 1.18+: offset is direct, no shifting
                        field_offset = offset_embed
                        is_embedded = False  # Check a different field for embedded flag
                    else:
                        # Go 1.16-1.17: offset is shifted
                        field_offset = offset_embed >> 1
                        is_embedded = (offset_embed & 1) == 1

                    fields.append(
                        {
                            "name": field_name,
                            "type_offset": type_offset,
                            "type_ptr": typ_ptr,
                            "offset": field_offset,
                            "embedded": is_embedded,
                        }
                    )
                  
                except Exception:
                    continue

       
        return {
            **base_type,
            "pkgpath_offset": pkgpath_raw,
            "fields": fields,
        }

      except Exception:
        return base_type



    def _resolve_name_direct(self, name_addr: int) -> str:

      if name_addr == 0:
        return ""

      try:
        layer = self.context.layers[self.layer_name]
        data = layer.read(name_addr, 256, pad=True)
        
        if len(data) < 4:
            return ""
        
        major, minor, patch = self.go_version_tuple
        is_go_118_plus = (major == 1 and minor >= 18) or major > 1

        if is_go_118_plus:
            # Go 1.18+: [flags:1][varint_length][name_bytes]
            offset = 0
            flags = data[offset]
            offset += 1
            
            # Decode varint length
            name_len = 0
            shift = 0
            while offset < len(data):
                b = data[offset]
                offset += 1
                name_len |= (b & 0x7F) << shift
                if (b & 0x80) == 0:
                    break
                shift += 7
                if shift > 28:
                    return ""
            
            if name_len == 0:
                return ""
            if name_len > 512:
                return ""
            if offset + name_len > len(data):
                return ""
            
            name_bytes = data[offset:offset + name_len]
            name = name_bytes.decode('utf-8', errors='replace').rstrip('\x00')
            return name if name and name.isprintable() else ""
            
        else:
            # Go 1.15-1.17: [flags:1][length_hi:1][length_lo:1][name_bytes]
            # From Go source: int(uint16(*n.data(1))<<8 | uint16(*n.data(2)))
            # This is BIG-ENDIAN: high byte at offset 1, low byte at offset 2
            flags = data[0]
            name_len = (data[1] << 8) | data[2]  # Big-endian uint16
            name_start = 3
            
            if name_len == 0:
                return ""
            if name_len > 512:
                return ""
            if name_start + name_len > len(data):
                return ""
            
            name_bytes = data[name_start:name_start + name_len]
            name = name_bytes.decode('utf-8', errors='replace').rstrip('\x00')
            
            # Validate the name is printable
            if name and all(c.isprintable() or c in ' \t' for c in name):
                return name
            
            return ""

      except Exception as e:
        return ""
    
    
    
    def _resolve_name(self, name_offset: int) -> str:
      """Resolve name from offset in types section."""
      if name_offset == 0 or name_offset == -1:
        return ""
    
      try:
        layer = self.context.layers[self.layer_name]
        name_addr = self.types_start + name_offset
        data = layer.read(name_addr, 256, pad=True)
        major, minor, patch = self.go_version_tuple
        is_go_118_plus = (major == 1 and minor >= 18)
        #print(f"is_go_118_plus: {is_go_118_plus}")
        
        if is_go_118_plus:
            offset = 0
            flags = data[offset]
            offset += 1

            # Decode varint length
            name_len = 0
            shift = 0
            while offset < len(data):
                b = data[offset]
                offset += 1
                name_len |= (b & 0x7F) << shift
                if (b & 0x80) == 0:
                    break
                shift += 7
                if shift > 28:
                    return "<varint_overflow>"
           # print(f"name_len: {name_len}")
            # Sanity check
            if name_len == 0:
                return ""
            if name_len > 512:
                return f"<badlen_{name_len}>"

            if offset + name_len > len(data):
                return "<truncated>"
                
            # Decode UTF-8
            name_bytes = data[offset:offset + name_len]
            name = name_bytes.decode('utf-8', errors='replace')
            # Clean up any null bytes
            name = name.rstrip('\x00')
            return name if name else "<empty>"
        else:
            # Go 1.15-1.17: [flags:1][length_hi:1][length_lo:1][name_bytes]
            # Length is BIG-ENDIAN uint16 stored in bytes 1 and 2
            # See: func (n name) nameLen() int { return int(uint16(*n.data(1))<<8 | uint16(*n.data(2))) }
            flags = data[0]
            name_len = (data[1] << 8) | data[2]  # Big-endian uint16
            name_start = 3
            
            # Validate length
            if name_len == 0:
                return ""
            if name_len > 512:
                return f"<badlen_{name_len}>"
            if name_start + name_len > len(data):
                return "<truncated>"
            
            name_bytes = data[name_start:name_start + name_len]
            name = name_bytes.decode('utf-8', errors='replace').rstrip('\x00')
            
            if name and all(c.isprintable() or c in ' \t' for c in name):
                return name
            
            return ""
        
        return ""
        
      except Exception:
        return ""
   
    
   
   
   
    def _parse_map_type(self, type_addr: int, ptrSize: int, base_type: Dict) -> Dict:
      """Parse maptype structure for Go 1.15-1.17 and Go 1.18+."""
      try:
        layer = self.context.layers[self.layer_name]
        base_size = 48 if ptrSize == 8 else 32
        maptype_addr = type_addr + base_size
        
        major, minor, patch = self.go_version_tuple
        is_go_118_plus = (major == 1 and minor >= 18)
        
        # Initialize variables
        key_ptr = 0
        elem_ptr = 0
        key_offset = 0
        elem_offset = 0
        keysize = 0
        valuesize = 0
        bucketsize = 0
        
        if is_go_118_plus and ptrSize == 8:
            # Go 1.18+: Different layout with additional fields
            data = layer.read(maptype_addr, 32, pad=True)
            key_ptr = int.from_bytes(data[0:8], 'little')
            elem_ptr = int.from_bytes(data[8:16], 'little')
            keysize = data[24]
            valuesize = data[25]
            bucketsize = int.from_bytes(data[26:28], 'little')
            
        else:
               
            data = layer.read(maptype_addr, 40, pad=True)
            
            if len(data) < 40:
                return base_type
            
            key_ptr = int.from_bytes(data[0:8], 'little')
            elem_ptr = int.from_bytes(data[8:16], 'little')
            # bucket_ptr = int.from_bytes(data[16:24], 'little')  # if needed
            # hasher at offset 24, skip it
            
            
            keysize = data[32]
            valuesize = data[33]
            bucketsize = int.from_bytes(data[34:36], 'little')
        
        # Calculate offsets from types_start for debugging
        if key_ptr and key_ptr >= self.types_start:
            key_offset = key_ptr - self.types_start
        if elem_ptr and elem_ptr >= self.types_start:
            elem_offset = elem_ptr - self.types_start
        
        # Validate pointers are within types section
        etypes = self.moduledata.get('etypes', self.types_start + 0x1000000)
        
        if key_ptr and not (self.types_start <= key_ptr < etypes):
            vollog.debug(f"key_ptr {hex(key_ptr)} outside types [{hex(self.types_start)}-{hex(etypes)}]")
            key_ptr = 0
            key_offset = 0
        
        if elem_ptr and not (self.types_start <= elem_ptr < etypes):
            vollog.debug(f"elem_ptr {hex(elem_ptr)} outside types [{hex(self.types_start)}-{hex(etypes)}]")
            elem_ptr = 0
            elem_offset = 0
        
        # Recursively parse key and element types
        if key_ptr and key_ptr not in self.types_cache:
            try:
                self._parse_single_type(key_ptr, ptrSize)
            except:
                pass
        
        if elem_ptr and elem_ptr not in self.types_cache:
            try:
                self._parse_single_type(elem_ptr, ptrSize)
            except:
                pass
        
        return {
            **base_type,
            'key_type_offset': key_offset,
            'key_type_ptr': key_ptr,
            'elem_type_offset': elem_offset,
            'elem_type_ptr': elem_ptr,
            'keysize': keysize,
            'valuesize': valuesize,
            'bucketsize': bucketsize,
        }
        
      except Exception as e:
        vollog.debug(f"Exception in _parse_map_type: {e}")
        import traceback
        traceback.print_exc()
        return base_type

    def _parse_interface_type(self, type_addr: int, ptrSize: int, base_type: Dict) -> Dict:
        """Parse interfacetype structure."""
        try:
            layer = self.context.layers[self.layer_name]
            base_size = 48 if ptrSize == 8 else 32
            interfacetype_addr = type_addr + base_size

            data_size = 8 + (ptrSize * 3)
            data = layer.read(interfacetype_addr, data_size, pad=True)

            if len(data) < data_size:
                return base_type

            pkgpath_offset = int.from_bytes(data[0:4], 'little', signed=True)

            slice_offset = 8
            if ptrSize == 8:
                methods_ptr = int.from_bytes(data[slice_offset:slice_offset+8], 'little')
                methods_len = int.from_bytes(data[slice_offset+8:slice_offset+16], 'little')
            else:
                methods_ptr = int.from_bytes(data[slice_offset:slice_offset+4], 'little')
                methods_len = int.from_bytes(data[slice_offset+4:slice_offset+8], 'little')

            methods = []
            if methods_len > 0 and methods_len < 100:
                method_size = 8
                types_start = self.types_start
                etypes = self.moduledata.get('etypes', types_start + 0x1000000)

                for i in range(methods_len):
                    try:
                        method_addr = methods_ptr + (i * method_size)
                        method_data = layer.read(method_addr, method_size, pad=True)

                        if len(method_data) < method_size:
                            continue

                        name_offset = int.from_bytes(method_data[0:4], 'little', signed=True)
                        type_offset = int.from_bytes(method_data[4:8], 'little', signed=True)

                        method_name = self._resolve_name(name_offset)
                        method_type_ptr = 0
                        if type_offset != 0:
                            method_type_ptr = self.types_start + type_offset   
                            if types_start <= method_type_ptr < etypes:
                               if method_type_ptr not in self.types_cache:
                                  try:
                                    self._parse_single_type(method_type_ptr, ptrSize)
                                  except Exception:
                                    pass
                            else:
                               method_type_ptr = 0
                        
                        methods.append({
                            'name': method_name,
                            'type_offset': type_offset,
                            'type_ptr': method_type_ptr,
                        })

                    except:
                        continue

            return {
                **base_type,
                'pkgpath_offset': pkgpath_offset,
                'interface_methods': methods,
            }

        except Exception:
            return base_type

    def _parse_func_type(self, type_addr: int, ptrSize: int, base_type: Dict) -> Dict:
      
      try:
        layer = self.context.layers[self.layer_name]
        base_size = 48 if ptrSize == 8 else 32
        functype_addr = type_addr + base_size

        # --- header: inCount / outCount ---
        header_data = layer.read(functype_addr, 8, pad=True)
        if len(header_data) < 8:
            return base_type

        inCount = int.from_bytes(header_data[0:2], "little")
        out_raw = int.from_bytes(header_data[2:4], "little")
        # high bit may be used as flag; mask it off
        outCount = out_raw & 0x7FFF

        if inCount > 50 or outCount > 50:
            return base_type

        total_params = inCount + outCount
        param_types: List[Dict] = []
        return_types: List[Dict] = []

        if total_params > 0:
            entry_size = ptrSize                                 
            param_array_addr = functype_addr + 8                 
            param_array_size = total_params * entry_size       

            param_data = layer.read(param_array_addr, param_array_size, pad=True)
            if len(param_data) < param_array_size:
                return base_type

            types_start = self.types_start
            etypes = self.moduledata.get("etypes", types_start + 0x1000000)

            def decode_entry(idx: int) -> Tuple[int, int]:
                """Return (type_ptr, type_offset) for entry idx."""
                off = idx * entry_size
                raw_ptr = int.from_bytes(param_data[off:off + entry_size], "little")
             
                # Validate pointer is inside [types, etypes)
                if types_start <= raw_ptr < etypes:
                    type_ptr = raw_ptr
                    type_offset = type_ptr - types_start
                    # Recursively parse if not already in cache
                    if type_ptr not in self.types_cache:
                        try:
                            self._parse_single_type(type_ptr, ptrSize)
                        except Exception as e:
                            print(f"Failed to parse type @ {hex(type_ptr)}: {e}")
                            import traceback
                            traceback.print_exc()
                else:
                    type_ptr = 0
                    type_offset = 0

                return type_ptr, type_offset

            # Inputs
            for i in range(inCount):
                type_ptr, type_offset = decode_entry(i)
                param_types.append(
                    {
                        "index": i,
                        "type_ptr": type_ptr,
                        "type_offset": type_offset,
                    }
                )

            # Outputs
            for i in range(outCount):
                type_ptr, type_offset = decode_entry(inCount + i)
                return_types.append(
                    {
                        "index": i,
                        "type_ptr": type_ptr,
                        "type_offset": type_offset,
                    }
                )


        return {
            **base_type,
            "inCount": inCount,
            "outCount": outCount,
            "param_types": param_types,
            "return_types": return_types,
        }

      except Exception:
        return base_type
    
    
    def _parse_uncommon_type_methods(self, type_addr: int, ptrSize: int, base_type: Dict) -> List[Dict]:
      """
      Parse methods from uncommonType structure.
      Returns list of method dictionaries with complete info INCLUDING signatures.
      """
     
      if not base_type.get('has_uncommon', False):
        return []
     
     
      layer = self.context.layers[self.layer_name]
      base_size = 48 if ptrSize == 8 else 32
      kind = base_type['kind']
      type_name = base_type.get('name', '<unknown>')
      # Calculate kind_specific_size
      kind_specific_size = 0
      if kind == 22:  # pointer
        kind_specific_size = ptrSize
      elif kind == 23:  # slicefv
        kind_specific_size = ptrSize
      elif kind == 17:  # array
          kind_specific_size = ptrSize * 3
      elif kind == 25:  # struct
        kind_specific_size = 8 + (ptrSize * 3)
      elif kind == 21:  # map
         major, minor, patch = self.go_version_tuple
         is_go_118_plus = (major == 1 and minor >= 18)
         if is_go_118_plus and ptrSize == 8:
            kind_specific_size = 32  # Go 1.18+: 3 pointers (24) + sizes (8)
         else:
            kind_specific_size = 24 
      elif kind == 20:  # interface
        kind_specific_size = 8 + (ptrSize * 3)
      elif kind == 19:  # func
        inCount = base_type.get('inCount', 0)
        outCount = base_type.get('outCount', 0)
        kind_specific_size = 8 + ((inCount + outCount) * ptrSize)
      elif kind == 18:  # chan
        kind_specific_size = ptrSize
    
      uncommon_addr = type_addr + base_size + kind_specific_size
      #print(f"uncommon_addr: {uncommon_addr}")
      #print(f"self.types_start: {self.types_start}")
      try:
        uncommon_data = layer.read(uncommon_addr, 16, pad=True)
       # print(f"uncommon_data: {uncommon_data}")
        if len(uncommon_data) < 16:
            return []
        
        pkgpath_offset = int.from_bytes(uncommon_data[0:4], 'little', signed=True)
        mcount = int.from_bytes(uncommon_data[4:6], 'little')
        xcount = int.from_bytes(uncommon_data[6:8], 'little')
        moff = int.from_bytes(uncommon_data[8:12], 'little')
        methods_addr = uncommon_addr + moff
        method_size = 16
        #print(f"pkgpath_offset: {pkgpath_offset}")
        #print(f"mcount: {mcount}")
        #print(f"xcount: {xcount}")
        pkgpath = ""
        if pkgpath_offset != 0 and pkgpath_offset != -1:
           pkgpath = self._resolve_name(pkgpath_offset)
            
        if mcount == 0:
            return []

        # Calculate methods array address
       # print(f"\n{'='*100}")
       # print(f"TYPE: '{type_name}' @ {hex(type_addr)}")
        #print(f"  mcount: {mcount}")

        text_base = self.moduledata.get('text', 0)
        methods = []
        # Read all methods
        for i in range(mcount):
            method_offset = methods_addr + (i * method_size)
            method_data = layer.read(method_offset, method_size, pad=True)
            name_offset = int.from_bytes(method_data[0:4], 'little', signed=True)
            if len(method_data) < method_size:
                break
            
            # Parse runtime.method struct
            name_offset = int.from_bytes(method_data[0:4], 'little', signed=True)
            
            mtyp_offset = int.from_bytes(method_data[4:8], 'little', signed=True)
            ifn_offset = int.from_bytes(method_data[8:12], 'little', signed=True)
            tfn_offset = int.from_bytes(method_data[12:16], 'little', signed=True)
            
            # Resolve method name
            method_name = self._resolve_name(name_offset)
           # print(f"method_name: {method_name}")
            if not method_name or method_name.startswith('<'):
                method_name = f"<method_{i}>"
            
            # Determine if exported (first xcount methods are exported)
            is_exported = i < xcount
            
            # Calculate method signature pointer (funcType)
            method_type_ptr = None
            if mtyp_offset != -1 and self.types_start:
                method_type_ptr = self.types_start + mtyp_offset
            
            # Calculate PCs
            ifn_pc = None
            tfn_pc = None
            
            if text_base:
                if ifn_offset != -1:
                    ifn_pc = text_base + ifn_offset
                if tfn_offset != -1:
                    tfn_pc = text_base + tfn_offset
            
            # Determine primary PC (prefer tfn, fallback to ifn)
            primary_pc = tfn_pc if tfn_pc is not None else ifn_pc
            
            # Classify method type
            method_class = self._classify_method(tfn_offset, ifn_offset, mtyp_offset)
            
            # Extract method signature from funcType
            signature = None
            if mtyp_offset != -1 and method_type_ptr:
                etypes = self.moduledata.get('etypes', self.types_start + 0x1000000)
                
                # Validate funcType address is in types section
                if self.types_start <= method_type_ptr < etypes:
                    # Parse funcType if not already cached
                    if method_type_ptr not in self.types_cache:
                        try:
                            self._parse_single_type(method_type_ptr, ptrSize)
                        except Exception as e:
                            vollog.debug(f"Could not parse funcType @ {hex(method_type_ptr)}: {e}")
                    
                    # Get signature from cache
                    if method_type_ptr in self.types_cache:
                        functype_info = self.types_cache[method_type_ptr]
                        
                        # Verify it's actually a function type
                        if functype_info.get('kind') == 19:  # func
                            signature = {
                                'functype_addr': method_type_ptr,
                                'inCount': functype_info.get('inCount', 0),
                                'outCount': functype_info.get('outCount', 0),
                                'param_types': functype_info.get('param_types', []),
                                'return_types': functype_info.get('return_types', []),
                            }
            
            method_info = {
                'name': method_name,
                'pkgpath': pkgpath, 
                'exported': is_exported,
                'name_offset': name_offset,
                'type_offset': mtyp_offset,
                'type_ptr': method_type_ptr,
                'ifn_offset': ifn_offset,
                'tfn_offset': tfn_offset,
                'ifn_pc': ifn_pc,
                'tfn_pc': tfn_pc,
                'pc': primary_pc,
                'class': method_class,
                'signature': signature,
            }
            
            methods.append(method_info)
        
        return methods
      except Exception as e:
        vollog.debug(f"Error parsing methods for type @ {hex(type_addr)}: {e}")
        return []
    
    def _classify_method(self, tfn: int, ifn: int, mtyp: int) -> str:
     
   
      # Check if offsets are valid (Go uses -1 as sentinel for "not present")
      tfn_valid = (tfn != -1)
      ifn_valid = (ifn != -1)
      mtyp_valid = (mtyp != -1)
    
      # Case 1: Both function pointers present
      if tfn_valid and ifn_valid:
        if tfn == ifn:
            # Simple method: direct call == interface call
            # No wrapper needed, same implementation for both paths
            return 'simple'
        else:
            # Normal method: different implementations
            # Wrapper exists (e.g., for receiver adjustment, type conversion)
            return 'normal'
    
      # Case 2: Only interface function present (rare)
      elif ifn_valid and not tfn_valid:
        # Method only callable through interface
        # Unusual but theoretically possible
        return 'interface_only'
    
      # Case 3: Only text function present (rare)
      elif tfn_valid and not ifn_valid:
        # Method only callable directly, not through interface
        # Unusual but theoretically possible
        return 'direct_only'
    
      # Case 4: No function pointers (both -1)
      else:
        if mtyp_valid:
            # Has type signature but no implementation
            # This is a promoted/embedded method from a parent type
            # The actual implementation is in the embedded field's type
            return 'embedded'
        else:
            # No function pointers, no type signature
            # Compiler intrinsic or type assertion method
            # Examples: ArrayType(), FuncType(), In(), Out()
            # These are handled specially by the runtime/compiler
            return 'intrinsic'
    
    
    
    def _parse_cached_elf_sections(self, elf_bytes: bytes) -> List[Dict]:
      """Parse sections from cached ELF bytes."""
      try:
        if len(elf_bytes) < 64:
            print("[!] ELF too small")
            return []
        
        # Verify ELF magic
        if elf_bytes[:4] != b'\x7fELF':
            print("[!] Not a valid ELF file")
            return []
        
        # Parse ELF header
        ei_class = elf_bytes[4]  # 1 = 32-bit, 2 = 64-bit
        ei_data = elf_bytes[5]   # 1 = little endian, 2 = big endian
        
        is_64bit = (ei_class == 2)
        is_little = (ei_data == 1)
        endian = 'little' if is_little else 'big'
        
        print(f"[*] ELF: {'64-bit' if is_64bit else '32-bit'}, {'little' if is_little else 'big'} endian")
        
        if is_64bit:
            # 64-bit ELF header
            e_shoff = int.from_bytes(elf_bytes[40:48], endian)      # Section header offset
            e_shentsize = int.from_bytes(elf_bytes[58:60], endian)  # Section header entry size
            e_shnum = int.from_bytes(elf_bytes[60:62], endian)      # Number of section headers
            e_shstrndx = int.from_bytes(elf_bytes[62:64], endian)   # Section name string table index
        else:
            # 32-bit ELF header
            e_shoff = int.from_bytes(elf_bytes[32:36], endian)
            e_shentsize = int.from_bytes(elf_bytes[46:48], endian)
            e_shnum = int.from_bytes(elf_bytes[48:50], endian)
            e_shstrndx = int.from_bytes(elf_bytes[50:52], endian)
        
        if e_shoff == 0 or e_shnum == 0:
            print("[!] No section headers found")
            return []
        
        # Read section header string table
        shstrtab_offset = e_shoff + (e_shstrndx * e_shentsize)
        if is_64bit:
            shstrtab_file_offset = int.from_bytes(elf_bytes[shstrtab_offset + 24:shstrtab_offset + 32], endian)
            shstrtab_size = int.from_bytes(elf_bytes[shstrtab_offset + 32:shstrtab_offset + 40], endian)
        else:
            shstrtab_file_offset = int.from_bytes(elf_bytes[shstrtab_offset + 16:shstrtab_offset + 20], endian)
            shstrtab_size = int.from_bytes(elf_bytes[shstrtab_offset + 20:shstrtab_offset + 24], endian)
        
        shstrtab = elf_bytes[shstrtab_file_offset:shstrtab_file_offset + shstrtab_size]
        
        sections = []
        
        print(f"\n[*] Cached ELF Sections:")
        print(f"{'Name':<20} {'VirtAddr':<18} {'Size':<12} {'FileOff':<12} {'Flags'}")
        print("-" * 80)
        
        for i in range(e_shnum):
            sh_offset = e_shoff + (i * e_shentsize)
            
            if is_64bit:
                sh_name_idx = int.from_bytes(elf_bytes[sh_offset:sh_offset + 4], endian)
                sh_type = int.from_bytes(elf_bytes[sh_offset + 4:sh_offset + 8], endian)
                sh_flags = int.from_bytes(elf_bytes[sh_offset + 8:sh_offset + 16], endian)
                sh_addr = int.from_bytes(elf_bytes[sh_offset + 16:sh_offset + 24], endian)
                sh_file_offset = int.from_bytes(elf_bytes[sh_offset + 24:sh_offset + 32], endian)
                sh_size = int.from_bytes(elf_bytes[sh_offset + 32:sh_offset + 40], endian)
            else:
                sh_name_idx = int.from_bytes(elf_bytes[sh_offset:sh_offset + 4], endian)
                sh_type = int.from_bytes(elf_bytes[sh_offset + 4:sh_offset + 8], endian)
                sh_flags = int.from_bytes(elf_bytes[sh_offset + 8:sh_offset + 12], endian)
                sh_addr = int.from_bytes(elf_bytes[sh_offset + 12:sh_offset + 16], endian)
                sh_file_offset = int.from_bytes(elf_bytes[sh_offset + 16:sh_offset + 20], endian)
                sh_size = int.from_bytes(elf_bytes[sh_offset + 20:sh_offset + 24], endian)
            
            # Get section name
            name_end = shstrtab.find(b'\x00', sh_name_idx)
            if name_end == -1:
                name_end = sh_name_idx + 64
            name = shstrtab[sh_name_idx:name_end].decode('utf-8', errors='replace')
            
            # Build flags string
            flags_str = ""
            if sh_flags & 0x1: flags_str += "W"  # SHF_WRITE
            if sh_flags & 0x2: flags_str += "A"  # SHF_ALLOC
            if sh_flags & 0x4: flags_str += "X"  # SHF_EXECINSTR
            
            sect_info = {
                'name': name,
                'type': sh_type,
                'flags': sh_flags,
                'virtual_address': sh_addr,
                'file_offset': sh_file_offset,
                'size': sh_size,
                'flags_str': flags_str,
            }
            sections.append(sect_info)
            
            if name:  # Only print named sections
                print(f"{name:<20} {hex(sh_addr):<18} {sh_size:<12} {hex(sh_file_offset):<12} {flags_str}")
        
        return sections
        
      except Exception as e:
        print(f"[!] Error parsing cached ELF: {e}")
        import traceback
        traceback.print_exc()
        return []


    
    def _build_funcname_cache_from_elf(self, elf_bytes: bytes, elf_base: int, cached_sections: List[Dict]) -> Tuple[Dict[int, str], Dict[int, str]]:
      
        
      """
      Build function name and filename caches from the on-disk ELF in page cache.

      Parses pclntab from raw ELF bytes to recover names stripped from memory.
      Version-aware: Go 1.18+ (uint32 entryoff/funcoff in ftab, separate
      funcnametab), Go 1.16-1.17 (uintptr entries, pcHeader with uintptr
      offsets), Go 1.2-1.15 (names stored directly in pclntab).

      Returns (func_names, filenames) both as {runtime_pc: str}.
      """
      
      func_names = {}
      filenames = {}
      # Determine ELF bitness
      is_64bit = (elf_bytes[4] == 2)
      ptrSize = 8 if is_64bit else 4
      endian = 'little' if elf_bytes[5] == 1 else 'big'

      # Find .gopclntab or .rodata section
      pclntab_section = None
      rodata_section = None

      for sect in cached_sections:
        if sect['name'] == '.gopclntab':
            pclntab_section = sect
            break
        elif sect['name'] in ['.rodata', '.noptrdata']:
            rodata_section = sect

      # Determine search range
      if pclntab_section:
        search_start = pclntab_section['file_offset']
        search_end = search_start + pclntab_section['size']
        section_va = pclntab_section['virtual_address']
        print(f"[*] Searching .gopclntab section")
      elif rodata_section:
        search_start = rodata_section['file_offset']
        search_end = search_start + rodata_section['size']
        section_va = rodata_section['virtual_address']
        print(f"[*] Searching .rodata section for pclntab")
      else:
        print("[!] No suitable section found for pclntab")
        return func_names, filenames

      # Search for pclntab magic
      for magic_bytes, version_info in self.GO_MAGICS.items():
        pos = elf_bytes.find(magic_bytes, search_start, search_end)
        if pos == -1:
            continue

        # Validate header
        header = elf_bytes[pos:pos + 80]
        if len(header) < 64:
            continue
        if header[4] != 0 or header[5] != 0:
            continue

        minLC = header[6]
        hdr_ptrSize = header[7]
        if minLC not in (1, 2, 4) or hdr_ptrSize not in (4, 8):
            continue

        # Use header's ptrSize for parsing
        ptrSize = hdr_ptrSize

        major, minor, patch = self.go_version_tuple
        is_go_118_plus = (major == 1 and minor >= 18)
        is_go_116_117 = (major == 1 and minor >= 16 and minor <= 17)
        is_go_115 = (major == 1 and minor >= 12 and minor <= 15)
       
        # Parse nfunc based on version
        if ptrSize == 8:
            nfunc = int.from_bytes(header[8:16], endian)
        else:
            nfunc = int.from_bytes(header[8:12], endian)

        print(f"[+] Found pclntab in cached ELF at file offset {hex(pos)}")
        print(f"    Version: {version_info['version']}, Functions: {nfunc}, ptrSize: {ptrSize}")

        # =====================================================
        # Go 1.18+: Parse pcHeader with offsets (uint32)
        # =====================================================
        if is_go_118_plus:
            if ptrSize == 8:
                nfunc = int.from_bytes(header[8:16], 'little')
                nfiles = int.from_bytes(header[16:24], 'little')
                text_start = int.from_bytes(header[24:32], 'little')
                funcname_offset = int.from_bytes(header[32:40], 'little')
                cu_offset = int.from_bytes(header[40:48], 'little')
                filetab_offset = int.from_bytes(header[48:56], 'little')
                pctab_offset = int.from_bytes(header[56:64], 'little')
                pcln_offset = int.from_bytes(header[64:72], 'little')
            else:
                nfunc = int.from_bytes(header[8:12], 'little')
                nfiles = int.from_bytes(header[12:16], 'little')
                text_start = int.from_bytes(header[16:20], 'little')
                funcname_offset = int.from_bytes(header[20:24], 'little')
                cu_offset = int.from_bytes(header[24:28], 'little')
                filetab_offset = int.from_bytes(header[28:32], 'little')
                pctab_offset = int.from_bytes(header[32:36], 'little')
                pcln_offset = int.from_bytes(header[36:40], 'little')
             

          
            # funcnametab is at pclntab + funcname_offset
            funcnametab_file = pos + funcname_offset
            pctab_file = pos + pctab_offset
            filetab_file = pos + filetab_offset
            cutab_file = pos + cu_offset
            ftab_file = pos + pcln_offset + 8
            pclntable_file = pos + pcln_offset
            functab_entry_size = 8
            print(f"    textStart: {hex(text_start)}")
            print(f"    funcnameOffset: {hex(funcname_offset)}")
            print(f"    pclnOffset: {hex(pcln_offset)}")
            print(f"    ftab_file: {hex(ftab_file)}")

            # Go 1.18+: ftab entry is [uint32 entryoff, uint32 funcoff]
            functab_entry_size = 8

            for i in range(nfunc):
                entry_offset = ftab_file + (i * functab_entry_size)

                if entry_offset + functab_entry_size > len(elf_bytes):
                    break

                entryoff = int.from_bytes(elf_bytes[entry_offset:entry_offset + 4], endian)
                funcoff = int.from_bytes(elf_bytes[entry_offset + 4:entry_offset + 8], endian)

                func_pc = text_start + entryoff

                # _func struct: entryOff(4) + nameoff(4) at offset 4
                func_struct_file = pos + funcoff
                if func_struct_file + 8 > len(elf_bytes):
                    continue

                nameoff = int.from_bytes(elf_bytes[func_struct_file + 4:func_struct_file + 8], endian, signed=True)

                if nameoff < 0:
                    continue

                name_offset = funcnametab_file + nameoff
                if name_offset >= len(elf_bytes):
                    continue

                end = elf_bytes.find(b'\x00', name_offset, name_offset + 512)
                if end == -1:
                    end = name_offset + 512

                func_name = elf_bytes[name_offset:end].decode('utf-8', errors='replace')

                if func_name:
                    func_names[func_pc] = func_name
                
                
                # _func: pcfile at offset 20, cuOffset at offset 32
                pcfile_off = int.from_bytes(elf_bytes[func_struct_file + 20:func_struct_file + 24], 'little', signed=True)
                cuOffset = int.from_bytes(elf_bytes[func_struct_file + 32:func_struct_file + 36], 'little')
                if pcfile_off <= 0:
                    continue

                filename = self._resolve_filename_from_elf(
                    elf_bytes, pctab_file, filetab_file, cutab_file,
                    pcfile_off, cuOffset, func_pc
                )
                if filename and filename != "<unknown>":
                    filenames[func_pc] = filename
                    
               
        # =====================================================
        # Go 1.16-1.17: pcHeader with uintptr offsets
        # =====================================================
        elif is_go_116_117:
            # Go 1.16-1.17 pcHeader layout:
            # magic(4) + pad(2) + minLC(1) + ptrSize(1) = 8 bytes
            # nfunc(uintptr) + nfiles(uintptr) = 16 bytes on 64-bit
            # funcnameOffset(uintptr) + cuOffset(uintptr) + filetabOffset(uintptr) + 
            # pctabOffset(uintptr) + pclnOffset(uintptr) = 40 bytes on 64-bit
            
            if ptrSize == 8:
                nfunc = int.from_bytes(header[8:16], 'little')
                nfiles = int.from_bytes(header[16:24], 'little')
                # CRITICAL: These are uintptr (8 bytes on 64-bit), NOT uint32!
                funcname_offset = int.from_bytes(header[24:32], 'little')
                cu_offset = int.from_bytes(header[32:40], 'little')
                filetab_offset = int.from_bytes(header[40:48], 'little')
                pctab_offset = int.from_bytes(header[48:56], 'little')
                pcln_offset = int.from_bytes(header[56:64], 'little')
            else:
                nfunc = int.from_bytes(header[8:12], 'little')
                nfiles = int.from_bytes(header[12:16], 'little')
                funcname_offset = int.from_bytes(header[16:20], 'little')
                cu_offset = int.from_bytes(header[20:24], 'little')
                filetab_offset = int.from_bytes(header[24:28], 'little')
                pctab_offset = int.from_bytes(header[28:32], 'little')
                pcln_offset = int.from_bytes(header[32:36], 'little')

            # Calculate file positions - offsets are relative to pcHeader start
            funcnametab_file = pos + funcname_offset
            pctab_file = pos + pctab_offset
            filetab_file = pos + filetab_offset
            cutab_file = pos + cu_offset
            ftab_file = pos + pcln_offset
            print(f"    funcnameOffset: {hex(funcname_offset)}")
            print(f"    pclnOffset: {hex(pcln_offset)}")
            print(f"    ftab_file: {hex(ftab_file)}")
          
            
            # Go 1.16-1.17: ftab entry is [func_pc uintptr, funcoff uintptr]
            functab_entry_size = 2 * ptrSize
            for i in range(nfunc):
                entry_offset = ftab_file + (i * functab_entry_size)

                if entry_offset + functab_entry_size > len(elf_bytes):
                    break

                # Read ftab entry
                if ptrSize == 8:
                    func_pc = int.from_bytes(elf_bytes[entry_offset:entry_offset + 8], 'little')
                    funcoff = int.from_bytes(elf_bytes[entry_offset + 8:entry_offset + 16], 'little')
                else:
                    func_pc = int.from_bytes(elf_bytes[entry_offset:entry_offset + 4], 'little')
                    funcoff = int.from_bytes(elf_bytes[entry_offset + 4:entry_offset + 8], 'little')

                if func_pc == 0:
                    continue

                # _func struct is at pos + funcoff
                func_struct_file = pos + funcoff

                if func_struct_file + ptrSize + 4 > len(elf_bytes):
                    continue

                # Go 1.16-1.17 _func layout:
                # 64-bit: entry(8) then nameoff(int32) at offset 8
                # 32-bit: entry(4) then nameoff(int32) at offset 4
                if ptrSize == 8:
                    nameoff = int.from_bytes(elf_bytes[func_struct_file + 8:func_struct_file + 12], 'little', signed=True)
                else:
                    nameoff = int.from_bytes(elf_bytes[func_struct_file + 4:func_struct_file + 8], 'little', signed=True)

                if nameoff < 0:
                    continue

                # Name is at funcnametab + nameoff
                name_offset = funcnametab_file + nameoff
                if name_offset >= len(elf_bytes) or name_offset < 0:
                    continue

                end = elf_bytes.find(b'\x00', name_offset, name_offset + 512)
                if end == -1:
                    end = name_offset + 512

                func_name = elf_bytes[name_offset:end].decode('utf-8', errors='replace')

                if func_name and not func_name.startswith('\x00'):
                    func_names[func_pc] = func_name
               
                # Go 1.16-1.17 _func layout (64-bit):
                # entry(8) + nameoff(4) + args(4) + deferreturn(4) + pcsp(4) + pcfile(4) + pcln(4) + npcdata(4) + cuOffset(4)
                if ptrSize == 8:
                    pcfile_off = int.from_bytes(elf_bytes[func_struct_file + 24:func_struct_file + 28], 'little', signed=True)
                    cuOffset = int.from_bytes(elf_bytes[func_struct_file + 36:func_struct_file + 40], 'little')
                else:
                    pcfile_off = int.from_bytes(elf_bytes[func_struct_file + 16:func_struct_file + 20], 'little', signed=True)
                    cuOffset = int.from_bytes(elf_bytes[func_struct_file + 28:func_struct_file + 32], 'little')

                if pcfile_off <= 0:
                    continue

                filename = self._resolve_filename_from_elf(
                    elf_bytes, pctab_file, filetab_file, cutab_file,
                    pcfile_off, cuOffset, func_pc
                )
                if filename and filename != "<unknown>":
                    filenames[func_pc] = filename
        # =====================================================
        # Go 1.2-1.15: Older layout - no separate funcnametab
        # =====================================================
        elif is_go_115:
            # In Go 1.2-1.15, there's no pcHeader with offsets
            # Layout: magic(4) + pad(2) + minLC(1) + ptrSize(1) + nfunc(ptrSize)
            # ftab starts right after
            if ptrSize == 8:
                nfunc = int.from_bytes(header[8:16], 'little')
                ftab_start = pos + 16
            else:
                nfunc = int.from_bytes(header[8:12], 'little')
                ftab_start = pos + 12

            print(f"    nfunc (uintptr): {nfunc}")
            print(f"    ftab starts at file offset: {hex(ftab_start)}")

            if nfunc > 100000:
                print("[!] nfunc too large, skipping")
                continue

            # Go 1.2-1.15: ftab entry is [func_pc uintptr, funcoff uintptr]
            functab_entry_size = 2 * ptrSize

            for i in range(nfunc):
                entry_offset = ftab_start + (i * functab_entry_size)

                if entry_offset + functab_entry_size > len(elf_bytes):
                    break

                if ptrSize == 8:
                    func_pc = int.from_bytes(elf_bytes[entry_offset:entry_offset + 8], 'little')
                    funcoff = int.from_bytes(elf_bytes[entry_offset + 8:entry_offset + 16], 'little')
                else:
                    func_pc = int.from_bytes(elf_bytes[entry_offset:entry_offset + 4], 'little')
                    funcoff = int.from_bytes(elf_bytes[entry_offset + 4:entry_offset + 8], 'little')

                if func_pc == 0:
                    continue

                # _func struct is at pclntab + funcoff
                func_struct_file = pos + funcoff

                if func_struct_file + ptrSize + 4 > len(elf_bytes):
                    continue

                # Go 1.15: _func layout same as 1.16-1.17
                # entry(ptrSize) + nameoff(4)
                if ptrSize == 8:
                    nameoff = int.from_bytes(elf_bytes[func_struct_file + 8:func_struct_file + 12], 'little', signed=True)
                else:
                    nameoff = int.from_bytes(elf_bytes[func_struct_file + 4:func_struct_file + 8], 'little', signed=True)

                if nameoff <= 0:
                    continue

                # In Go 1.2-1.15, names are stored directly in pclntab
                # Name is at pclntab + nameoff
                name_offset = pos + nameoff

                if name_offset >= len(elf_bytes):
                    continue

                end = elf_bytes.find(b'\x00', name_offset, name_offset + 512)
                if end == -1:
                    end = name_offset + 512

                func_name = elf_bytes[name_offset:end].decode('utf-8', errors='replace')

                if func_name:
                    func_names[func_pc] = func_name
                
                # Go 1.15 _func: pcfile at offset 24 (64-bit), no cuOffset
                if ptrSize == 8:
                    pcfile_off = int.from_bytes(elf_bytes[func_struct_file + 24:func_struct_file + 28], 'little', signed=True)
                else:
                    pcfile_off = int.from_bytes(elf_bytes[func_struct_file + 16:func_struct_file + 20], 'little', signed=True)

                if pcfile_off <= 0:
                    continue

                filename = self._resolve_filename_from_elf_go115(
                    elf_bytes, pos, pcfile_off, func_pc
                )
                if filename and filename != "<unknown>":
                    filenames[func_pc] = filename
        print(f"[+] Extracted {len(func_names)} function names and {len(filenames)} filenames from cached ELF")

        break  # Found valid pclntab, stop searching

      return func_names,filenames
    
    
    
    def _resolve_filename_from_elf(self, elf_bytes: bytes, pctab_file: int, filetab_file: int, 
                                cutab_file: int, pcfile_off: int, cuOffset: int, func_pc: int) -> str:
      """Resolve filename for Go 1.16+ from cached ELF."""
      try:
        # Read pcfile data
        pcfile_addr = pctab_file + pcfile_off
        if pcfile_addr + 256 > len(elf_bytes):
            return "<unknown>"

        pcfile_data = elf_bytes[pcfile_addr:pcfile_addr + 256]
        if all(b == 0 for b in pcfile_data[:8]):
            return "<unknown>"

        # Decode file_index
        file_index = self._pcvalue_bytes(pcfile_data, func_pc, func_pc)
        if file_index is None or file_index < 0:
            return "<unknown>"

        # cutab[cuOffset + file_index] -> filetab offset
        cutab_idx = cuOffset + file_index
        cutab_entry = cutab_file + (cutab_idx * 4)
        if cutab_entry + 4 > len(elf_bytes):
            return "<unknown>"

        fileoff = int.from_bytes(elf_bytes[cutab_entry:cutab_entry + 4], 'little')
        if fileoff == 0xFFFFFFFF:
            return "<unknown>"

        # Read filename from filetab
        name_addr = filetab_file + fileoff
        if name_addr >= len(elf_bytes):
            return "<unknown>"

        end = elf_bytes.find(b'\x00', name_addr, name_addr + 512)
        if end == -1:
            end = name_addr + 512

        return elf_bytes[name_addr:end].decode('utf-8', errors='replace')

      except Exception:
        return "<unknown>"


    def _resolve_filename_from_elf_go115(self, elf_bytes: bytes, pclntab_pos: int, 
                                      pcfile_off: int, func_pc: int) -> str:
      """Resolve filename for Go 1.2-1.15 from cached ELF."""
      try:
        # Read pcfile data
        pcfile_addr = pclntab_pos + pcfile_off
        if pcfile_addr + 256 > len(elf_bytes):
            return "<unknown>"

        pcfile_data = elf_bytes[pcfile_addr:pcfile_addr + 256]
        if all(b == 0 for b in pcfile_data[:8]):
            return "<unknown>"

        # Decode file_index
        file_index = self._pcvalue_bytes(pcfile_data, func_pc, func_pc)
        if file_index is None or file_index < 0:
            return "<unknown>"

        # Go 1.15: filetab is array of uint32 offsets into pclntab
        # Find filetab - it's after ftab in pclntab
        # For simplicity, use file_index as direct offset lookup
        # filetab[file_index] gives offset into pclntab for filename
        
        # This requires knowing filetab location - simplified approach:
        # In Go 1.15, filetab offset is stored after ftab
        # For now, return unknown - Go 1.15 needs different handling
        return "<unknown>"

      except Exception:
        return "<unknown>"


    
    #======================================================================
    #                           Get the cached files
    #======================================================================
    def _get_binary_path_from_task(self, task) -> Optional[str]:
      """Get the executable path by searching VMA mappings."""
      try:
        # Get first executable VMA - that's the binary
        for vma in task.mm.get_mmap_iter():
            # Check if executable and file-backed
            if not ((vma.vm_flags & 0x4) and vma.vm_file):  # VM_EXEC
                continue
            
            vm_file = vma.vm_file
            if not hasattr(vm_file, 'f_path'):
                continue
            
            dentry = vm_file.f_path.dentry
            if not dentry:
                continue
            
            # Try existing helper first
            if hasattr(dentry, 'get_full_path'):
                
                try:
                    return dentry.get_full_path()
                except Exception:
                    pass  # Fall through to manual
            
            # Fallback: Manual dentry walk
            path_parts = []
            current = dentry
            for _ in range(50):
                if current.d_name.name:
                    name = current.d_name.name_as_str()
                    if name and name != '/':
                        path_parts.append(name)
                parent = current.d_parent
                if parent.vol.offset == current.vol.offset:
                    break
                current = parent
            
            path_parts.reverse()
            return '/' + '/'.join(path_parts)
        
        return None
        
      except Exception as e:
        vollog.debug(f"Error: {e}")
        return None
    
    def _find_inode_by_path(self, binary_path: str):
      """Find inode for a given file path using linux.pagecache.Files plugin."""
      print(f"[*] Searching for cached file: {binary_path}")
    
      inodes_iter = Files.get_inodes(
        context=self.context,
        vmlinux_module_name=self.config["kernel"],
      )
    
      for inode_in in inodes_iter:
        if inode_in.path == binary_path:
            print(f"[+] Found inode at {hex(inode_in.inode.vol.offset)}")
            return inode_in.inode
    
      print(f"[!] File not found in page cache")
      return None
    
    def _extract_elf_from_pagecache(self, inode) -> bytes:
      """
      Extract ELF bytes from Linux page cache using InodePages.

      Uses the Volatility pagecache plugin to reconstruct the on-disk ELF
      file from cached pages. Returns raw ELF bytes or empty bytes on failure.
      """
      try:
        vmlinux = self.context.modules[self.config["kernel"]]
        vmlinux_layer = self.context.layers[vmlinux.layer_name]
        
        print(f"[*] Extracting ELF from page cache...")
        buffer = BytesIO()
        
        # Reuse InodePages method
        InodePages.write_inode_content_to_stream(
            self.context,
            vmlinux_layer.name,
            inode,
            buffer
        )
        
        elf_bytes = buffer.getvalue()
        print(f"[+] Extracted {len(elf_bytes)} bytes from page cache")
        
        return elf_bytes
        
      except Exception as e:
        print(f"[!] Error extracting ELF: {e}")
        return b""
    
   
   
    def build_data_map_type_methods(self, value_addr: int, param_type_ptr: int, types_dict: Dict, 
        itabs_dict: Dict, _func_functions:Dict, depth: int = 0, max_depth: int = 5):
      """
      Recursive type-aware memory reader: given an address and its Go type,
      reads the value from memory and returns it as a structured Python object.
    
      This is the core interpreter that turns raw bytes into typed values using
      the binary's own type system. It handles all 26 Go type kinds: pointers
      are dereferenced and followed recursively, structs are parsed field by
      field using the structType layout, strings read (ptr, len) headers and
      fetch the backing bytes, slices iterate over elements, maps walk bucket
      chains (old hmap) or Swiss Table groups (Go 1.24+), and interfaces are
      resolved via itab/type pointer lookup.
    
      Critical side effect: every address visited is recorded in
      self.data_to_type_map with its resolved type name, size, and value.
      This cache is the bridge between type-method analysis (where types are
      known) and heuristic analysis (where they are not). When a later pass
      encounters a pointer to 0xc0000a2000 without type context, the cache
      provides the full breakdown: "this is an http.Server struct with fields
      Addr='0.0.0.0:8080', Handler=0xc0000b4000, ..."
    
      Args:
        value_addr:     Memory address where the value lives
        param_type_ptr: Address of the Go _type descriptor in the types section
        types_dict:     All parsed types {type_addr: type_info}
        itabs_dict:     All parsed itabs {itab_addr: itab_info}
        _func_functions: Function lookup for resolving func pointers
        depth:          Current recursion depth (prevents infinite loops)
        max_depth:      Maximum recursion depth (default 5)
    
      Returns:
        Interpreted value — type depends on the Go kind:
        - Primitives: int, float, bool, complex
        - Strings: str
        - Pointers: recursively resolved value of the pointee
        - Structs: dict {field_name: field_value}
        - Slices: dict {slice_ptr, len, cap, elements: [...]}
        - Maps: dict {map_ptr, count, entries: [{key, value}, ...]}
        - Interfaces: dict {interface, concrete_type, value}
        - Functions: dict {func_ptr, func_name}
        - Unknown: string description
      """
      if depth > max_depth:
         return f"<max_depth_{depth}>" 
      is_heap = self._is_go_heap_pointer(value_addr)
      layer = self.context.layers[self.layer_name]
      if param_type_ptr == 0 or param_type_ptr not in types_dict:
         return "<unknown_type>"
    
      ptr_type_info = types_dict[param_type_ptr]
      ptr_type_kind = ptr_type_info.get('kind')
      
      # Start with the type we were given
      elem_type_info = ptr_type_info
      elem_type_kind = ptr_type_kind
      elem_type_kind_str = ptr_type_info.get('kind_str', '')
      elem_type_size = ptr_type_info.get('size', 0)
      elem_type_name = ptr_type_info.get('name', '<unknown>')
      elem_type_ptr = ptr_type_info.get('elem_type_ptr', 0)
      if ptr_type_kind == 22:  # ONLY for kind 22 (pointer)
         if elem_type_ptr != 0 and elem_type_ptr in types_dict:
            elem_type_info = types_dict[elem_type_ptr]
            elem_type_kind = elem_type_info.get('kind') 
            elem_type_name = elem_type_info.get('name', '<unknown>') 
            elem_type_size = elem_type_info.get('size', 0) 
            elem_type_kind_str = elem_type_info.get('kind_str', '')
           # print(f" -> Dereferencing pointer to {elem_type_name} (kind={elem_type_kind})")  
            ptr_data = layer.read(value_addr, 8, pad=True)
            ptr_value = int.from_bytes(ptr_data, 'little')
            #print(f" ->  Pointer value: {hex(ptr_value)}")
          
            
            if ptr_value != 0:
               value =  self.build_data_map_type_methods(
               value_addr=ptr_value,
               param_type_ptr=elem_type_ptr,  
               types_dict=types_dict,
               itabs_dict=itabs_dict,
               _func_functions= _func_functions,
               depth=depth + 1,
               max_depth=max_depth
               )
               self.data_to_type_map[ptr_value] = {
                'type_ptr': elem_type_ptr,
                'type_name': elem_type_info.get('name', '<unknown>'),
                'size': 8,
                'value': value,
                'location': 'heap'
                
               }
               return value
            else:
               return {'ptr': '0x0', 'type': elem_type_name, 'value': None}  
         else:
           return "<unknown_elem_type>"
      
      else:  
        # Integers
        if elem_type_kind == 1:  # bool
             bool_data = layer.read(value_addr, 1, pad=True)
             bool_val = bool(bool_data[0])
             # if is_heap:
             self.data_to_type_map[value_addr] = {'type_ptr': param_type_ptr, 'type_name': elem_type_info.get('name', 'bool'),
                'size': 1, 'value': bool_val,'location': 'heap'}
             return   bool_val
       
       
        elif elem_type_kind in [2, 3, 4, 5, 6]: 
            if elem_type_size in [1, 2, 4, 8]:
                int_data = layer.read(value_addr, elem_type_size, pad=True)
                int_val = int.from_bytes(int_data, 'little', signed=True)
                #if is_heap:
                self.data_to_type_map[value_addr] = { 'type_ptr': param_type_ptr, 'type_name': elem_type_info.get('name', 'int'),
                'size': elem_type_size, 'value': int_val, 'location': 'heap' }
                return int_val 
        
        elif elem_type_kind in [7, 8, 9, 10, 11, 12]:  # Signed integers
             if elem_type_size in [1, 2, 4, 8]:
                int_data = layer.read(value_addr, elem_type_size, pad=True)
                int_val = int.from_bytes(int_data, 'little', signed=False)
                #if is_heap:
                self.data_to_type_map[value_addr] = {'type_ptr': param_type_ptr, 'type_name': elem_type_info.get('name', 'int'),
                'size': elem_type_size, 'value': int_val,'location': 'heap' }   
                return int_val
        
        elif elem_type_kind in [13, 14, 15, 16]: 
            import struct as pystruct
            if elem_type_kind == 13:  # float32
                float_data = layer.read(value_addr, 4, pad=True)
                float_val = pystruct.unpack('<f', float_data)[0]
                #if is_heap:
                self.data_to_type_map[value_addr] = { 'type_ptr': param_type_ptr, 'type_name': 'float32', 'size': 4,
                'value': float_val,'location': 'heap' }
                return  float_val
            
            elif elem_type_kind == 14:  # float64
                float_data = layer.read(value_addr, 8, pad=True)
                float_val = pystruct.unpack('<d', float_data)[0]
                #if is_heap:
                self.data_to_type_map[value_addr] = {'type_ptr': param_type_ptr, 'type_name': 'float64','size': 8,
                'value': float_val, 'location': 'heap'}
                return  float_val
            
            elif elem_type_kind == 15:  # complex64 (2x float32)
                complex_data = layer.read(value_addr, 8, pad=True)
                real = pystruct.unpack('<f', complex_data[0:4])[0]
                imag = pystruct.unpack('<f', complex_data[4:8])[0]
                complex_val = complex(real, imag)
                #if is_heap:
                self.data_to_type_map[value_addr] = {'type_ptr': param_type_ptr, 'type_name': 'complex64', 'size': 8,
                'value': complex_val, 'location': 'heap'}
                return complex_val
            
            elif elem_type_kind == 16:  # complex128 (2x float64)
                complex_data = layer.read(value_addr, 16, pad=True)
                real = pystruct.unpack('<d', complex_data[0:8])[0]
                imag = pystruct.unpack('<d', complex_data[8:16])[0]
                complex_val = complex(real, imag)
                #if is_heap:
                self.data_to_type_map[value_addr] = {'type_ptr': param_type_ptr,  'type_name': 'complex128', 'size': 16,
                'value': complex_val, 'location': 'heap'}
                return complex_val
       
        elif elem_type_kind == 17:
            array_length = elem_type_info.get('length', 0)
            elem_type_ptr_array = elem_type_info.get('elem_type_ptr', 0)
    
            if elem_type_ptr_array == 0 or elem_type_ptr_array not in types_dict:
              return f"<array[{array_length}]_unknown_elem_type>"
    
            elem_info_array = types_dict[elem_type_ptr_array]
            elem_size_array = elem_info_array.get('size', 0)
            elem_name_array = elem_info_array.get('name', '<unknown>')
    
            # Read all array elements
            array_elements = []
            for i in range(array_length):
              elem_addr = value_addr + (i * elem_size_array)
              try:
                elem_val = self.build_data_map_type_methods(
                  value_addr=elem_addr,
                  param_type_ptr=elem_type_ptr_array,
                  types_dict=types_dict,
                  itabs_dict=itabs_dict,
                  _func_functions=_func_functions,
                  depth=depth + 1,
                  max_depth=max_depth
                )
                #if is_heap:
                self.data_to_type_map[elem_addr] = {  # ← Key is elem_addr, NOT elem_val
                'type_ptr': elem_type_ptr_array,  # ← Element type
                'type_name': elem_name_array,     # ← Element type name
                'size': elem_size_array,          # ← Element size
                'value': elem_val,                # ← Parsed value
                'location': 'heap'
                }
                array_elements.append(elem_val)
              except Exception as e:
                 break
    
              
            #if is_heap:
            self.data_to_type_map[value_addr] = {
            'type_ptr': param_type_ptr,                    # ← Array type (not element type!)
            'type_name': f'[{array_length}]{elem_name_array}',  # ← Full array type name
            'size': elem_size_array * array_length,        # ← Total array size
            'value': array_elements,                       # ← All elements
            'location': 'heap'
            }
            return array_elements
       
       
        elif elem_type_kind == 18:
            if elem_type_size == 8:
               chan_data = layer.read(value_addr, 8, pad=True)
               chan_ptr = int.from_bytes(chan_data, 'little')
               if chan_ptr == 0:
                   return {'chan': '0x0'}
               # ONLY map the hchan structure (on heap)
               # NOT the value_addr (the channel variable on stack)
               self.data_to_type_map[chan_ptr] = {
               'type_ptr': param_type_ptr,
               'type_name': elem_type_info.get('name', 'chan'),
               'size': 8,  # Size of hchan structure (varies, but pointer is 8)
               'value': hex(chan_ptr),
               'location': 'heap'
                }
          
               return {'chan': hex(chan_ptr)}
            else:
               return f'<invalid_chan_size_{elem_type_size}>'
        
        # Function _func_functions
        elif elem_type_kind == 19: 
             if elem_type_size == 8:
                func_data = layer.read(value_addr, 8, pad=True)
                func_ptr = int.from_bytes(func_data, 'little')
                if func_ptr == 0:
                   return {'func_ptr': '0x0', 'func_name': 'nil'} 
                text_start = self.moduledata["text"]
                text_end = self.moduledata["etext"]
                actual_pc = func_ptr
                is_closure = False
                func_name = "<unknown_func>"
                if not (text_start <= func_ptr < text_end):
                   
                     is_closure = True
                     try:
                       # Read first 8 bytes to get actual function PC
                       closure_data = layer.read(func_ptr, 8, pad=True)
                       actual_pc = int.from_bytes(closure_data, 'little')
                     
                
                       # Validate it's in text section
                       if not (text_start <= actual_pc < text_end):
                       
                          actual_pc = func_ptr  # Revert
                          is_closure = False
                     except Exception as e:
                         actual_pc = func_ptr
                         is_closure = False
                
                # Look up function name
                if hasattr(self, '_current_func_lookup') and self._current_func_lookup:
                   # Try exact match
                   if actual_pc in self._current_func_lookup:
                      func_info = self._current_func_lookup[actual_pc]
                      func_name = func_info.get('name')
                      if not func_name or func_name == '':
                         func_name = f"<func@{hex(actual_pc)}>"
                    
                   else:
                      # Try finding which function contains this PC
                      for pc, func_info in self._current_func_lookup.items():
                          func_start = func_info['pc']
                          func_end = func_start + func_info.get('size', 0)
                          if func_start <= actual_pc < func_end:
                             func_name = func_info.get('name')
                             if not func_name or func_name == '':
                                func_name = f""
                             offset = actual_pc - func_start
                            
                             break
        
                # ONLY map if it's a closure (on heap)
                # Regular function pointers (in text section) are NOT heap objects
                if is_closure and func_ptr != 0:
                   self.data_to_type_map[func_ptr] = {
                   'type_ptr': param_type_ptr,
                   'type_name': f'function',
                   'size': 8,
                   'func_ptr': func_ptr,
                   'value': f"func_name@{hex(actual_pc)}",
                   'location': 'heap'
                   } 
                result = {'func_ptr': hex(func_ptr), 'func_name': f"func_name@{hex(actual_pc)}"}
                return   result

        # interface
        elif elem_type_kind == 20: 
            interface_struct = layer.read(value_addr, 16, pad=True)
            type_val = int.from_bytes(interface_struct[0:8], 'little')
            data_val = int.from_bytes(interface_struct[8:16], 'little')
            
            # Check if it's an itab (non-empty interface)
            if type_val in itabs_dict:
               itab_info = itabs_dict[type_val]
               interface_name = itab_info.get('interface_name', '<unknown>')
               concrete_type = itab_info.get('concrete_type_name', '<unknown>')
               method_count = itab_info.get('method_count', 0)
               type_ptr = itab_info.get('type_ptr') 
               actual_value = None
               if data_val != 0 and type_ptr and  type_ptr in types_dict:
                  try: 
                   type_info = types_dict[type_ptr]
                   concrete_kind = type_info.get('kind')
                   concrete_size = type_info.get('size', 0)
                   is_direct = ( concrete_kind in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]and concrete_size <= 8)
                   if is_direct:
                      if concrete_kind == 1:  # bool
                        actual_value = bool(data_val & 0xFF)
                      elif concrete_kind in [2, 3, 4, 5, 6]:  # Signed int
                        mask = (1 << (concrete_size * 8)) - 1
                        value = data_val & mask
                        sign_bit = 1 << ((concrete_size * 8) - 1)
                        if value & sign_bit:
                            actual_value = value - (1 << (concrete_size * 8))
                        else:
                            actual_value = value
                      elif concrete_kind in [7, 8, 9, 10, 11, 12]:  # Unsigned int
                        mask = (1 << (concrete_size * 8)) - 1
                        actual_value = data_val & mask
                      elif concrete_kind == 13:  # float32
                        import struct as pystruct
                        bytes_val = (data_val & 0xFFFFFFFF).to_bytes(4, 'little')
                        actual_value = pystruct.unpack('<f', bytes_val)[0]
                      elif concrete_kind == 14:  # float64
                        import struct as pystruct
                        bytes_val = data_val.to_bytes(8, 'little')
                        actual_value = pystruct.unpack('<d', bytes_val)[0]
                    
                      
                   
                   else:
                      actual_value = self.build_data_map_type_methods(
                        value_addr=data_val,
                        param_type_ptr=type_ptr,
                        types_dict=types_dict,
                        itabs_dict=itabs_dict,
                        _func_functions=_func_functions,
                        depth=depth + 1,
                        max_depth=max_depth
                      )
                     
                  
                  except:
                     print(f"    → [Cannot read interface data]")
                  
                  return {'interface': interface_name, 'concrete_type': concrete_type, 'itab': hex(type_val), 'data': hex(data_val),  'method_count': method_count,
                 'value': actual_value}
             

            # Check if it's a type pointer (empty interface any)
            elif type_val in types_dict:
                  type_info = types_dict[type_val]
                  type_name = type_info.get('name', '<unknown>')
                  kind_str = type_info.get('kind_str', '')
                  actual_value = None
                  if data_val != 0:
                     try:
                        concrete_kind = type_info.get('kind')
                        concrete_size = type_info.get('size', 0)
                        is_direct = (concrete_kind in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]and concrete_size <= 8)
                        if is_direct:
                           print(f"    → Direct storage (inline value)")
                    
                           if concrete_kind == 1:  # bool
                              actual_value = bool(data_val & 0xFF)
                           elif concrete_kind in [2, 3, 4, 5, 6]:  # Signed int
                                mask = (1 << (concrete_size * 8)) - 1
                                value = data_val & mask
                                sign_bit = 1 << ((concrete_size * 8) - 1)
                                if value & sign_bit:
                                   actual_value = value - (1 << (concrete_size * 8))
                                else:
                                   actual_value = value
                           elif concrete_kind in [7, 8, 9, 10, 11, 12]:  # Unsigned int
                                mask = (1 << (concrete_size * 8)) - 1
                                actual_value = data_val & mask
                           elif concrete_kind == 13:  # float32
                                import struct as pystruct
                                bytes_val = (data_val & 0xFFFFFFFF).to_bytes(4, 'little')
                                actual_value = pystruct.unpack('<f', bytes_val)[0]
                           elif concrete_kind == 14:  # float64
                                import struct as pystruct
                                bytes_val = data_val.to_bytes(8, 'little')
                                actual_value = pystruct.unpack('<d', bytes_val)[0]
                        
                        
                        else:
                          
                          actual_value = self.build_data_map_type_methods(
                           value_addr=data_val,
                           param_type_ptr=type_val,  
                           types_dict=types_dict,
                           itabs_dict=itabs_dict,
                           _func_functions=_func_functions,
                           depth=depth + 1,
                           max_depth=max_depth
                           )
                      
                     except :
                          pass  
                  return {'interface': 'any','concrete_type': type_name,'type': hex(type_val),'data': hex(data_val),'value': actual_value} 
        
        
        # Map
        elif elem_type_kind == 21:  # map
            #print("from Map")
            if elem_type_size == 8:
                map_data = layer.read(value_addr, 8, pad=True)
                map_ptr = int.from_bytes(map_data, 'little')
                if map_ptr != 0:
                   key_type_ptr = elem_type_info.get('key_type_ptr', 0)
                   elem_type_ptr_map = elem_type_info.get('elem_type_ptr', 0)
                   if map_ptr != 0 and key_type_ptr and elem_type_ptr_map:
                     try:
                       map_contents = self._parse_hmap_contents( map_ptr, key_type_ptr, elem_type_ptr_map,
                       types_dict, itabs_dict, _func_functions,depth,max_depth)
                       entries = map_contents.get('entries', [])
                       self.data_to_type_map[map_ptr] = {'type_ptr': param_type_ptr, 'type_name': elem_type_info.get('name', 'map'),
                       'size': elem_type_size, 'value': entries,'location': 'heap'} 
                       return {
                       'map_ptr': hex(map_ptr),
                       'count': map_contents.get('count', 0),
                       'entries': map_contents.get('entries', [])
                        }
                   
                     except Exception as e:
                       pass
                   
            return {
            'map_ptr': hex(map_ptr) if map_ptr else '0x0',
            'count': 0,
            'entries': []
            }
        
     
        # Slice
        elif elem_type_kind == 23: 
         try:
             slice_struct = layer.read(value_addr, 24, pad=True)
             ptr_val = int.from_bytes(slice_struct[0:8], 'little')
             len_val = int.from_bytes(slice_struct[8:16], 'little')
             cap_val = int.from_bytes(slice_struct[16:24], 'little')
            
             if ptr_val == 0:
                return {'slice_ptr': '0x0', 'len': 0, 'cap': 0, 'elements': []} 
        
             if len_val == 0:
                return {'slice_ptr': hex(ptr_val), 'len': 0, 'cap': cap_val, 'elements': []} 
        
             # Sanity check
             if len_val > 0x100000:  # > 1MB
                return {'slice_ptr': hex(ptr_val), 'len': len_val, 'cap': cap_val, 'error': 'suspicious_length'} 
        
             # Get element type
             elem_type_ptr_slice = elem_type_info.get('elem_type_ptr', 0)
             if elem_type_ptr_slice == 0 or elem_type_ptr_slice not in types_dict:
                return {'slice_ptr': hex(ptr_val), 'len': len_val, 'cap': cap_val, 'error': 'unknown_elem_type'} 
        
             elem_type_info_slice = types_dict[elem_type_ptr_slice]
             elem_size = elem_type_info_slice.get('size', 0)
             elem_name = elem_type_info_slice.get('name', '<unknown>')
             # Read slice elements
             elements = []
             max_elements = min(len_val, 100)  # Limit to first 100 elements
        
             for i in range(max_elements):
                elem_addr = ptr_val + (i * elem_size)
                try:
                    elem_val = self.build_data_map_type_methods(
                       value_addr=elem_addr,
                       param_type_ptr=elem_type_ptr_slice,
                       types_dict=types_dict,
                       itabs_dict=itabs_dict,
                       _func_functions=_func_functions,
                       depth=depth + 1,
                       max_depth=max_depth
                    )
                    self.data_to_type_map[elem_addr] = {
                    'type_ptr': elem_type_ptr_slice,  
                    'type_name': elem_name, 
                    'size': elem_size, 
                    'value': elem_val,
                    'location': 'heap'
                     }
                    elements.append(elem_val)
                except Exception as e:
                   break
             
             self.data_to_type_map[ptr_val] = {
             'type_ptr': param_type_ptr,
             'type_name': f"[]{elem_name}",  
             'size': len_val * elem_size,  
             'value': elements,  
             'location': 'heap'
             }
             
             return {
              'slice_ptr': hex(ptr_val),
              'len': len_val,
              'cap': cap_val,
              'elem_type': elem_name,
              'elements': elements
             }
        
         except Exception as e:
            return { 'slice_ptr': '0x0', 'len': 0, 'cap': 0, 'error': str(e) }
          
      
        # String
        elif elem_type_kind == 24:
            try:
                string_struct = layer.read(value_addr, 16, pad=True)
                str_ptr = int.from_bytes(string_struct[0:8], 'little')
                str_len = int.from_bytes(string_struct[8:16], 'little')
                string_val=""
                if str_ptr != 0 and 0 < str_len < 10000:
                    string_data = layer.read(str_ptr, str_len, pad=True)
                    string_val = string_data.decode('utf-8', errors='replace')
                    
                
                    self.data_to_type_map[str_ptr] = {
                    'type_ptr': param_type_ptr,
                    'type_name': 'string',
                    'size': 16,
                    'value':string_val,
                    'location': 'heap'
                    }
                    return string_val

            except:
               string_val = "<unreadable_string>"
            
            return string_val 
        
        
        # Struct
        elif elem_type_kind == 25:
            struct_result = {}
            struct_data = layer.read(value_addr, elem_type_size, pad=True)
            fields = elem_type_info.get('fields', [])
            is_heap = self._is_go_heap_pointer(value_addr)
            if fields:
                for i, field in enumerate(fields):
                    field_info_name = field.get('name', '') 
                    if field_info_name and field_info_name != '<unnamed>':
                       field_name = field_info_name
                    else:
                       field_name = f'field_{i}_depth_{depth}'
                    
                    field_offset = field.get('offset', 0)
                    field_type_ptr = field.get('type_ptr', 0)
                    if field_offset >= len(struct_data):
                        struct_result[field_name] = "<out_of_bounds>"
                        continue
                    if field_type_ptr == 0 or field_type_ptr not in types_dict:
                        struct_result[field_name] = "<unknown_type>"
                        continue
                    
                    # Calculate the actual memory address of this field
                   
                    field_addr = value_addr + field_offset
                    field_type_info = types_dict.get(field_type_ptr, {})
                    field_size = field_type_info.get('size', 0)  
                    try:
                        field_value = self.build_data_map_type_methods(
                        value_addr=field_addr,
                        param_type_ptr=field_type_ptr,
                        types_dict=types_dict,
                        itabs_dict=itabs_dict,
                        _func_functions= _func_functions,
                        depth=depth + 1,
                        max_depth=max_depth
                        )
                        if is_heap:
                           self.data_to_type_map[field_addr] = {
                           'type_ptr': field_type_ptr,
                           'type_name': field_type_info.get('name', '<unknown>'),
                           'size': field_size,
                           'value':field_value,
                           'location': 'heap'
                            }
                        struct_result[field_name] = field_value
                    except Exception as e:
                       continue  
                if is_heap:
                   self.data_to_type_map[value_addr] = {
                   'type_ptr': param_type_ptr,  
                   'type_name': elem_type_info.get('name', 'struct'),
                   'size': elem_type_size, 
                   'value': struct_result, 
                   'location': 'heap'
                    }
                
            return  struct_result
           
        # unsafe.Pointer
        elif elem_type_kind == 26:  # unsafe.Pointer
             unsafe_data = layer.read(value_addr, 8, pad=True)
             unsafe_ptr = int.from_bytes(unsafe_data, 'little')
             if unsafe_ptr == 0:
                return {'unsafe_ptr': '0x0'}
             
             return {
                'unsafe_ptr': hex(unsafe_ptr),
                'raw_data_preview': peek_data[:64].hex()
                }
             
             
            
        
        else:
          self.data_to_type_map[value_addr] = {
          'type_ptr': param_type_ptr,
          'type_name': f'unknown_kind_{elem_type_kind}',
          'size': elem_type_size,
          'value': None,
          'location': 'heap'
          }
          return f"<unhandled_kind_{elem_type_kind}>"  

    
    
    
    
     
    def _is_go_heap_pointer(self, ptr):
      """Check if pointer looks like a Go heap address."""
      if ptr == 0:
        return False
    
      # Go heap pointers on 64-bit Linux typically look like:
      # 0x00_00_00_c0_XX_XX_XX_XX
      #           ^^
      #     0xc0 is at byte position 4 (counting from LSB)
    
      # Check if it's in reasonable userspace range
      if not (0x1000 < ptr < 0x7fffffffffff):
        return False
    
      # Check for 0xc0 byte pattern (common in Go heap)
      ptr_bytes = ptr.to_bytes(8, 'little')
    
      # Check if byte 4 or 5 is 0xc0 (typical Go heap pattern)
      if ptr_bytes[4] == 0xc0 or ptr_bytes[5] == 0xc0:
        return True
    
      # Even without 0xc0, if it's in userspace range, accept it
      # (Go heap could use different ranges on different systems)
      return True
    
    
    
    def _parse_hmap_contents(self,  map_ptr: int,   key_type_ptr: int,  elem_type_ptr: int,  types_dict: Dict, itabs_dict: Dict,
     _func_functions: Dict,depth:int,max_depth:int) -> Dict:
        major, minor, patch = self.go_version_tuple
        is_go_124_plus = (major == 1 and minor >= 24)
        layer = self.context.layers[self.layer_name]
        raw_data = layer.read(map_ptr, 128, pad=True)
        if is_go_124_plus:
           return self._parse_map_go124(map_ptr, key_type_ptr, elem_type_ptr,types_dict, itabs_dict, _func_functions,depth,max_depth )
        else:
          return self._parse_map_old(map_ptr, key_type_ptr, elem_type_ptr, types_dict, itabs_dict, _func_functions,depth,max_depth)

    
    
    def _parse_map_go124(self, map_ptr: int, key_type_ptr: int, elem_type_ptr: int, types_dict: Dict, itabs_dict: Dict, _func_functions: Dict,depth:int,max_depth:int
     ) -> Dict:
      
      try:
        layer = self.context.layers[self.layer_name]
        ptrSize = 8
        
        #print(f"\n[MAP DEBUG] Parsing Go 1.24 maps.Map @ {hex(map_ptr)}")
        
        # Read Map structure
        MAP_STRUCT_SIZE = 40
        map_data = layer.read(map_ptr, MAP_STRUCT_SIZE, pad=True)
        
        if len(map_data) < MAP_STRUCT_SIZE:
            return {'count': 0, 'entries': [], 'error': 'short_read'}
        
        # Parse fields
        used = int.from_bytes(map_data[0:8], 'little')
        seed = int.from_bytes(map_data[8:16], 'little')
        dirPtr = int.from_bytes(map_data[16:24], 'little')       
        dirLen = int.from_bytes(map_data[24:32], 'little', signed=True)  
        globalDepth = map_data[32] if len(map_data) > 32 else 0
        globalShift = map_data[33] if len(map_data) > 33 else 0
        
        
        #print(f"[MAP DEBUG] used={used}, dirPtr={hex(dirPtr)}, dirLen={dirLen}")
       # print(f"[MAP DEBUG] globalDepth={globalDepth}, globalShift={globalShift}, seed={hex(seed)}")
        
        
        if used == 0:
            return {'count': 0, 'entries': []}
        
        if dirLen == 0 or dirLen == 1:
            # Small map: dirPtr is a direct pointer to a single group
            #print(f"[MAP DEBUG] Small map - single group @ {hex(dirPtr)}")
            entries = self._parse_single_group_go124(
                dirPtr, used,
                key_type_ptr, elem_type_ptr,
                types_dict, itabs_dict, _func_functions, layer,depth,max_depth
            )
        else:
            # Large map: dirPtr points to directory
           # print(f"[MAP DEBUG] Large map - directory with {dirLen} entries")
            entries = self._parse_map_directory_go124(
                dirPtr, dirLen, used,
                key_type_ptr, elem_type_ptr,
                types_dict, itabs_dict, _func_functions, layer,depth, max_depth
            )
        
        return {
            'count': used,
            'entries': entries,
        }
       
      except Exception as e:
        print(f"[MAP DEBUG] Exception: {e}")
        return {'error': str(e)}

    
    
    def _parse_single_group_go124(self, group_ptr: int,max_entries: int,key_type_ptr: int, elem_type_ptr: int, types_dict: Dict, itabs_dict: Dict, 
    _func_functions: Dict,layer,depth:int,max_depth:int) -> List[Dict]:
      """Parse a single group (for small maps with dirLen=0 or 1)."""
     
      #print(f"[MAP DEBUG] Parsing single group @ {hex(group_ptr)}")
    
      SLOTS_PER_GROUP = 8
      CTRL_EMPTY = 0x80
      CTRL_DELETED = 0xFE
      if key_type_ptr == 0 or key_type_ptr not in types_dict:
        print(f"[MAP DEBUG] Invalid key_type_ptr: {hex(key_type_ptr) if key_type_ptr else 'NULL'}")
        return []
    
      if elem_type_ptr == 0 or elem_type_ptr not in types_dict:
        print(f"[MAP DEBUG] Invalid elem_type_ptr: {hex(elem_type_ptr) if elem_type_ptr else 'NULL'}")
        return []
      # Get type sizes
      key_type = types_dict.get(key_type_ptr, {})
      elem_type = types_dict.get(elem_type_ptr, {})
      key_size = key_type.get('size', 8)
      elem_size = elem_type.get('size', 8)
    
    
      # Group structure: [ctrl:8][keys:key_size*8][values:elem_size*8]
      ctrl_size = SLOTS_PER_GROUP
      keys_size = SLOTS_PER_GROUP * key_size
      values_size = SLOTS_PER_GROUP * elem_size
      group_size = ctrl_size + keys_size + values_size
    
   
    
      try:
        group_data = layer.read(group_ptr, group_size, pad=True)
        
        if len(group_data) < group_size:
            print(f"[WARNING] Short read: got {len(group_data)}, need {group_size}")
            return []
        
        # Parse control bytes
        ctrl_bytes = group_data[0:ctrl_size]
       # print(f"[MAP DEBUG] Control bytes: {ctrl_bytes.hex()}")
        
        entries = []
        
        # Parse each slot
        for slot_idx in range(SLOTS_PER_GROUP):
            ctrl = ctrl_bytes[slot_idx]
            
            # Skip empty/deleted slots
            if ctrl == CTRL_EMPTY or ctrl == CTRL_DELETED:
                continue
 
            
            # Calculate offsets
            key_offset = ctrl_size + (slot_idx * key_size)
            value_offset = ctrl_size + keys_size + (slot_idx * elem_size)
            
            key_addr = group_ptr + key_offset
            value_addr = group_ptr + value_offset

            # Read key
            key_value =  self.build_data_map_type_methods(
            value_addr=key_addr,
            param_type_ptr=key_type_ptr,
            types_dict=types_dict,
            itabs_dict=itabs_dict,
            _func_functions=_func_functions,
            depth=depth + 1,  
            max_depth=max_depth
            )
            self.data_to_type_map[key_addr] = {
            'type_ptr': key_type_ptr,
            'type_name': key_type.get('name', '<unknown>'),
            'size': key_size,
            'value': key_value,
            'location': 'heap'
            }
            # Read value
            elem_value = self.build_data_map_type_methods(
            value_addr=value_addr,
            param_type_ptr=elem_type_ptr,
            types_dict=types_dict,
            itabs_dict=itabs_dict,
            _func_functions=_func_functions,
            depth=depth + 1, 
            max_depth=max_depth
            )
            self.data_to_type_map[value_addr] = {
                'type_ptr': elem_type_ptr,
                'type_name': elem_type.get('name', '<unknown>'),
                'size': elem_size,
                'value': elem_value,
                'location': 'heap'
            }
            
            
            entries.append({
            'key': key_value,
            'value': elem_value,
            'key_addr': key_addr,   
            'value_addr': value_addr  
            })
            if len(entries) >= max_entries:
                break
        
        return entries
        
      except Exception as e:
        import traceback
        traceback.print_exc()
        return []
    
    
    
    def _parse_map_directory_go124(self, dirPtr: int, dirLen: int,used: int,key_type_ptr: int,elem_type_ptr: int, types_dict: Dict,
    itabs_dict: Dict,_func_functions: Dict,layer,depth:int,max_depth:int) -> List[Dict]:
     
      """Parse directory (array of group pointers) for large maps."""
      ptrSize = 8
    
      try:
        # Read directory (array of pointers)
        dir_data = layer.read(dirPtr, dirLen * ptrSize, pad=True)
        
        #print(f"[MAP DEBUG] Directory has {dirLen} entries")
        
        all_entries = []
        
        # Iterate through all directory entries
        for i in range(dirLen):
            group_ptr = int.from_bytes(dir_data[i*ptrSize:(i+1)*ptrSize], 'little')
            
            if group_ptr == 0:
                continue
           
            # Parse this group
            entries = self._parse_single_group_go124(
                group_ptr, used - len(all_entries),
                key_type_ptr, elem_type_ptr,
                types_dict, itabs_dict, _func_functions, layer,depth,max_depth
            )
            
            all_entries.extend(entries)
            
            if len(all_entries) >= used:
                break
        
        return all_entries[:used]
        
      except Exception as e:
        return []

    
    
    
    def _parse_map_old( self,map_ptr: int, key_type_ptr: int, elem_type_ptr: int, types_dict: Dict, itabs_dict: Dict, _func_functions: Dict, depth:int,
     max_depth:int) -> Dict:
      try:
        layer = self.context.layers[self.layer_name]
        ptrSize = 8
        
        hmap_data = layer.read(map_ptr, 48, pad=True)
        
        count = int.from_bytes(hmap_data[0:8], 'little')
        B = hmap_data[9]
        buckets_ptr = int.from_bytes(hmap_data[16:24], 'little')
        
        if count == 0 or buckets_ptr == 0:
            return {'count': 0, 'entries': []}
        
        # Parse buckets
        entries = self._parse_hmap_buckets_old(
            buckets_ptr, B, count,
            key_type_ptr, elem_type_ptr,
            types_dict, itabs_dict, _func_functions, layer,depth,max_depth
        )
        
        return {
            'count': count,
            'entries': entries
        }
        
      except Exception as e:
        return {'error': str(e)}


    def _parse_hmap_buckets_old( self, buckets_ptr: int, B: int, count: int, key_type_ptr: int, elem_type_ptr: int, types_dict: Dict,
     itabs_dict: Dict, _func_functions: Dict, layer, depth:int, max_depth:int) -> List[Dict]:
      """Parse old hmap buckets."""
      num_buckets = 1 << B
      
      key_type = types_dict.get(key_type_ptr, {})
      elem_type = types_dict.get(elem_type_ptr, {})
      key_size = key_type.get('size', 8)
      elem_size = elem_type.get('size', 8)
    
      bucket_size = 8 + (8 * key_size) + (8 * elem_size) + 8
    
      entries = []
    
      try:
        for bucket_idx in range(min(num_buckets, 100)):
            bucket_addr = buckets_ptr + (bucket_idx * bucket_size)
            bucket_data = layer.read(bucket_addr, bucket_size, pad=True)
            
            # Tophash
            tophash = bucket_data[0:8]
            
            keys_offset = 8
            values_offset = 8 + (8 * key_size)
            
            for slot in range(8):
                if tophash[slot] == 0 or tophash[slot] == 1:
                    continue
                
                key_addr = bucket_addr + keys_offset + (slot * key_size)
                value_addr = bucket_addr + values_offset + (slot * elem_size)
                
                key_val =  self.build_data_map_type_methods(
                value_addr=key_addr,
                param_type_ptr=key_type_ptr,
                types_dict=types_dict,
                itabs_dict=itabs_dict,
                _func_functions=_func_functions,
                depth=depth + 1,  
                max_depth=max_depth
                )
                self.data_to_type_map[key_addr] = {
                    'type_ptr': key_type_ptr,
                    'type_name': key_type.get('name', '<unknown>'),
                    'size': key_size,
                    'value': key_val,
                    'location': 'heap'
                }
                elem_val = self.build_data_map_type_methods(
                value_addr=value_addr,
                param_type_ptr=elem_type_ptr,
                types_dict=types_dict,
                itabs_dict=itabs_dict,
                _func_functions=_func_functions,
                depth=depth + 1, 
                max_depth=max_depth
                )
                self.data_to_type_map[value_addr] = {
                    'type_ptr': elem_type_ptr,
                    'type_name': elem_type.get('name', '<unknown>'),
                    'size': elem_size,
                    'value': elem_val,
                    'location': 'heap'
                }
                entries.append({'key': key_val, 'value': elem_val})
        
        return entries[:count]
        
      except Exception as e:
        print(f"[MAP DEBUG] Bucket parse error: {e}")
        return entries

    
    
    def _cache_type_method_arguments(self, allgs: Dict, ptrSize: int, array_data: bytes, 
                              types_dict: Dict, itabs_dict: Dict, _func_functions: Dict, 
                              type_methods: Dict, func_lookup: Dict, cached_func_names: Dict):
      """
      PHASE 1: Pre-scan all goroutine stacks to extract type method arguments
      before the main stack_trace display pass.
    
      This runs BEFORE stack_trace for a critical reason: type methods have full
      type information (receiver type, parameter types, field layouts) from the
      binary's own type system. By processing them first, build_data_map_type_methods
      populates self.data_to_type_map as a side effect — every pointer it follows,
      every struct it recursively parses, every string it dereferences gets cached
      with its resolved type and value.
    
      When stack_trace later processes non-type-method functions (via arginfo
      heuristics or argsmap slot scanning), those paths check self.data_to_type_map
      to resolve pointer targets. If a non-type-method function received a pointer
      to a struct that was also passed to a type method, the cache hit gives us a
      full typed breakdown instead of a heuristic guess like "pointer to unknown".
    
      Example:
        Phase 1: (*http.Server).Serve receives *http.Server at 0xc0000a2000
                 → recursively parses all fields → caches Addr="0.0.0.0:8080",
                   Handler=0xc0000b4000, TLSConfig=nil, etc.
        Phase 2: runtime.goexit's stack has 0xc0000a2000 as a raw pointer
                 → cache hit → instantly resolved as *http.Server with all fields
                 instead of "pointer to unknown heap object"
    
      Populates:
        self.type_method_arguments: {func_pc: {frame_key: {arg_idx: {...}}}}
        self.data_to_type_map: {heap_addr: {type_name, value, size, ...}}  (side effect)
      """
      type_methods_scanned = 0
      args_type_methods_scanned = 0
      print(f"\n[*] Building argument type map from {allgs['len']} goroutines...")

      for i in range(allgs["len"]):
          if ptrSize == 8:
             g_ptr = int.from_bytes(array_data[i*8:(i+1)*8], 'little')
          else:
             g_ptr = int.from_bytes(array_data[i*4:(i+1)*4], 'little')

          if g_ptr == 0:
             continue

          g_info = self._parse_goroutine(self.layer_name, g_ptr, ptrSize)
          
          if not g_info:
             continue
          goid = g_info['goid'] 
          stack_lo= g_info['stack_lo']
          stack_hi= g_info['stack_hi']
          if g_info["status"] == 6:  # dead
             continue
          frames = self._unwind_goroutine_stack(g_info, func_lookup)
          if frames:

           
            for frame in frames:
              func_info = frame.get('func_info')
              func_pc = func_info.get('pc')
              func_name = func_info.get('name', '<unknown>')
              depth = frame.get('depth')
              frame_key = f"g{goid}_f{depth}"
              
              if func_name:
                  func_name = func_name
              elif func_pc in cached_func_names:
                  func_name = cached_func_names[func_pc]
              else:
                  func_name = f"<unknown@{hex(func_pc)}>"
            
             
              arg_base= frame.get('arg_base')
              if func_pc in type_methods:
                 type_methods_scanned+= 1
                 method = type_methods[func_pc]
                 param_types = method.get('param_types', {})
                 inCount = method.get('inCount', 0)
                 if func_pc not in self.type_method_arguments:
                    self.type_method_arguments[func_pc] = {}
                 self.type_method_arguments[func_pc][frame_key] = {}
                 current_offset = 0     
                 for arg_idx in range(inCount):
                     if arg_idx not in param_types:
                        continue
                     param_info = param_types[arg_idx]
                     param_type_ptr = param_info.get('type_ptr', 0)
                     param_size = param_info.get('param_size', 8)
                     param_name = param_info.get('param_name', f'arg{arg_idx}')
                     param_type = param_info.get('param_type', '')        
                     value_addr = arg_base + current_offset  
                     if param_type_ptr == 0 or param_type_ptr not in types_dict:
                        current_offset += param_size
                        continue          
                      
                     try:
                        param_value = self.build_data_map_type_methods( value_addr=value_addr, param_type_ptr=param_type_ptr,
                        types_dict=types_dict, itabs_dict=itabs_dict, _func_functions=_func_functions, depth=0, max_depth=5)
                        self.type_method_arguments[func_pc][frame_key][arg_idx]= {
                        'param_name': param_info.get('param_name', 'unknown'),
                        'param_address': value_addr,
                        'param_type': param_info.get('param_type', ''),
                        'param_size': param_info.get('param_size', 0),
                        'param_value': param_value,
                        'param_type_ptr': param_type_ptr,}    
                        args_type_methods_scanned += 1
                     except Exception as e:
                         continue
                     current_offset += param_size
              
      print(f"\n[+] Scanned {type_methods_scanned} methods, {args_type_methods_scanned} arguments")
      print(f"[+] Length of type_method_arguments: {len(self.type_method_arguments)}")
      print(f"[+] Length of data_to_type_map: {len(self.data_to_type_map)}")
 

    
    def _lookup_func_name_from_external(self, filename: str, line_number: int, 
                                     return_full_info: bool = False) -> Optional:
      """
      Look up function name from external database by finding which function
      contains the given line number.
    
      Args:
        filename: Source filename
        line_number: Current line number (from pcln table)
        
      Returns:
        Function name if found, None otherwise
      """
      if not hasattr(self, '_external_func_db'):
         self._external_func_db = self._load_external_func_db(self.go_version_str)
    
      if not self._external_func_db:
         return None
    
      files = self._external_func_db.get('files', {})
      normalized = self._normalize_filename(filename)
    
      if normalized not in files:
         return None
    
      funcs = files[normalized]
      containing_func = None
      best_entry_line = -1
    
      for func in funcs:
          entry_line = func['entry_line']
          if entry_line <= line_number and entry_line > best_entry_line:
             best_entry_line = entry_line
             containing_func = func
    
      if containing_func is None:
         return None
    
      if not return_full_info:
         return containing_func.get('func_name')  # ← existing behavior, unchanged
    
      return {
        'func_name': containing_func.get('func_name'),
        'entry_line': containing_func.get('entry_line'),
        'num_params': containing_func.get('num_params', 0),
        'num_returns': containing_func.get('num_returns', 0),
        'params': containing_func.get('params', []),
        'returns': containing_func.get('returns', []),
      }
  
    
   
    def _normalize_filename(self, filename: str) -> str:
      """Normalize filename to match JSON keys (e.g., runtime/proc.go)."""
    
      # Look for common Go source patterns and extract the relative path
      # Pattern: /any/path/go/src/runtime/... -> runtime/...
      # Pattern: /any/path/go/src/net/http/... -> net/http/...
    
      import re
    
      # Match: anything/src/package/file.go
      # Capture everything after /src/
      match = re.search(r'/src/((?:runtime|internal|[a-z][a-z0-9_]*(?:/[a-z][a-z0-9_]*)*)/[^/]+\.go)$', filename)
      if match:
        return match.group(1)
    
      # Fallback: try to find /src/ and take everything after it
      if '/src/' in filename:
        return filename.split('/src/', 1)[1]
    
      # Last resort: return as-is
      return filename
    
    

    def stack_trace(self, allgs,pclntab,_func_functions, func_lookup,type_methods,itabs_dict,types_dict, cached_func_names, cached_filenames, heap_addresses):
        """
        PHASE 2: Walk every live goroutine's stack and extract argument values
        from each frame using the best available type information.
    
        For each goroutine in runtime.allgs (skipping dead ones), this method:
        1. Parses the goroutine struct (goid, status, wait reason, stack bounds)
        2. Unwinds the stack via PCSP-guided frame walking
        3. For each frame, resolves the function name (pclntab → page cache → external DB)
        4. Dispatches argument extraction through a 5-tier priority chain:
    
        Tier 1 — Type methods (func_pc in self.type_method_arguments):
            Arguments were pre-extracted in Phase 1 (_cache_type_method_arguments)
            with full type information from the binary's type system. Retrieved
            directly from cache with named, typed, recursively-resolved values.
    
        Tier 2 — Runtime/stdlib/internal (classify_go_filepath match):
             Parameter names and types come from the external function DB
             (go_func_lines JSON, built from Go source by go_func_signature.py).
             Values are read from the stack via _extract_stdlib_function_arguments
             which dispatches by type string (string, slice, interface, pointer, etc).
    
        Tier 3 — Third-party (classify_go_filepath → 'third_party'):
            Parameter info from third_party_analyzer module. Converted to
            sig-compatible format and reuses the stdlib extraction path.
    
        Tier 4 — Go 1.17+ with ArgInfo (arginfo_data available):
            ArgInfo bytecode gives argument offset/size layout. External DB
            (go_func_lines JSON) provides parameter names and types when
            available. Values extracted via _get_non_type_argument_info using
            pointer bitmap heuristics + data_to_type_map cache lookups.
    
        Tier 5 — Pre-1.17 with ArgsPointerMaps only:
            No ArgInfo, no type names. Raw slot-by-slot scanning using the
            pointer bitmap to distinguish pointers from scalars. Composite
            types (string, slice, interface) detected by structural patterns
            (ptr+len, ptr+len+cap, itab+data). Poorest type fidelity.
    
        Each tier falls through to the next when its prerequisite is missing.
        Extracted arguments are stored in self.non_type_method_arguments
        (or read from self.type_method_arguments for tier 1) for downstream use.
        """
    
        layer = self.context.layers[self.layer_name]
        ptrSize = pclntab["ptrSize"]
        array_data = layer.read(allgs["ptr"], allgs["len"] * ptrSize, pad=True)
        major, minor, patch = self.go_version_tuple
        is_go_117_plus = (major == 1 and minor >= 17)

        for i in range(allgs["len"]):
          if ptrSize == 8:
             g_ptr = int.from_bytes(array_data[i*8:(i+1)*8], 'little')
          else:
             g_ptr = int.from_bytes(array_data[i*4:(i+1)*4], 'little')

          if g_ptr == 0:
             continue
          
          g_info = self._parse_goroutine(self.layer_name, g_ptr, ptrSize)
          if not g_info:
             continue
          print(f"\n{'='*80}")
          print(f"Goroutine {g_info['goid']}")
          print(f"{'='*80}")
          print(f"status: {g_info['status']}")
          print(f"status_name {g_info['status_name']}")
          stack_lo= g_info['stack_lo']
          stack_hi= g_info['stack_hi']
          print(f"stack_lo {hex(stack_lo)}")
          print(f"stack_hi {hex(stack_hi)}")
          print(f"sched_sp {g_info['sched_sp']}")
         
          print(f"sched_pc {hex(g_info['sched_pc'])}")
          print(f"sched_bp {g_info['sched_bp']}")
          print(f"startpc {hex(g_info['startpc'])}")
          print(f"gopc {hex(g_info['gopc'])}")
          print(f"waitreason_enum {g_info['waitreason_enum']}")
          print(f"waitreason {g_info['waitreason']}")
          print(f"waitsince {g_info['waitsince']}")
          print(f"lockedm {hex(g_info['lockedm'])}")
        
          # Skip dead goroutines
          if g_info["status"] == 6:  # dead
             print("  [DEAD - no stack trace]")
             continue
          # Unwind stack!
          frames = self._unwind_goroutine_stack(g_info, func_lookup)
          if frames:
             print(f"\n{'='*80}")
             print(f"\n  Stack Trace ({len(frames)} frames):")
             print(f"{'='*80}")
 
             for frame in frames:
               arg_base = frame.get('arg_base')
               func_info = frame.get('func_info')
               func_name = func_info.get('name', '')
               func_pc = func_info.get('pc')
               startLine = func_info.get('startLine', 0)
               args = func_info.get('args')
               goid = g_info['goid']
               depth = frame.get('depth')
               frame_key = f"g{goid}_f{depth}"
               arginfo_data=func_info.get('arginfo_data')
               argsmap_data = func_info.get('argsmap_data')
               if argsmap_data:
                  Pointer_offsets=argsmap_data['pointer_slots']
               
               arg_base= frame.get('arg_base')
               layer = self.context.layers[self.layer_name]
               Pointer_offsets=[]
               current_pc = frame.get('pc', func_pc)

               filename, line_num = self._get_file_line_for_pc(func_info, current_pc)
               if filename == "<unknown>" and func_pc in cached_filenames:
                   filename = cached_filenames[func_pc]
   
               # Resolve function name
               if func_name:
                  func_name = func_name
               
               elif func_pc in cached_func_names:
                  func_name = cached_func_names[func_pc]
               
               else:
                  external_name = self._lookup_func_name_from_external(filename, line_num)
                  if external_name:
                     func_name = external_name
                   
                  else:
                    func_name = f"<unknown@{hex(func_pc)}>"
            
               print(f"\n  [{depth}] {func_name} @ {hex(func_pc)} in the file : {filename} at {line_num} with start line number is {startLine}")
            
               # Skip if no args or not Go 1.15-1.16
               if not args or args <= 0:
                  print(f" This fucntion has no arguments")
                  

               else:
               
                 # Check if this is a type method
                 if func_pc in self.type_method_arguments:
                    print("This function is a type method")
                    frame_args = self.type_method_arguments[func_pc][frame_key]
                    for arg_idx in sorted(frame_args.keys()):
                        arg_info = frame_args[arg_idx]
                        print(f"\n  Arg {arg_idx}, param_name: {arg_info['param_name']}", 
                        f"param_type: {arg_info['param_type']}, param_size: {arg_info['param_size']},"
                        f" param_value:  {arg_info['param_value']}")
                   
  
                 else:
                     external_params = None
                     ext_info = self._lookup_func_name_from_external(filename, line_num, return_full_info=True)
                     if ext_info and ext_info['num_params'] > 0:
                        external_params = ext_info['params']
                     
                     if classify_go_filepath(filename).get('category') in ["runtime_core", "runtime_internal", "stdlib_internal", "stdlib_public"]:
                        print("This is a itnernal/runtime/stdlib/assmebly")
                      
                        stdlib_args = self._extract_stdlib_function_arguments( func_name=func_name,external_params=external_params,arg_base=arg_base,
                        argsmap_data=argsmap_data, types_dict=types_dict,itabs_dict=itabs_dict,_func_functions=_func_functions, 
                         stack_lo=stack_lo, stack_hi=stack_hi,heap_addresses=heap_addresses)
                      
                        if func_pc not in self.non_type_method_arguments:
                           self.non_type_method_arguments[func_pc] = {}
                        self.non_type_method_arguments[func_pc][frame_key] = stdlib_args
                        # Print extracted arguments
                        for arg_idx, arg_info in sorted(stdlib_args.items()):
                          print(f"\n  Arg {arg_idx}: {arg_info['param_name']}  Value: {arg_info['param_value']}")
                          if 'error' in arg_info:
                             print(f"      Error: {arg_info['error']}")
                      
                     elif classify_go_filepath(filename).get('category') == 'third_party':
                        print("This is a third-party function")
                        actual_func_name = self._extract_third_party_func_name(func_name)
                        third_party_info = self._lookup_third_party_function(filename, actual_func_name)
                        
                        if third_party_info:
                            tp_args = self._extract_third_party_arguments(
                                func_name=func_name,
                                third_party_info=third_party_info,
                                arg_base=arg_base,
                                argsmap_data=argsmap_data,
                                types_dict=types_dict,
                                itabs_dict=itabs_dict,
                                _func_functions=_func_functions,
                                stack_lo=stack_lo,
                                stack_hi=stack_hi,
                                heap_addresses=heap_addresses
                            )
                            
                            if func_pc not in self.non_type_method_arguments:
                                self.non_type_method_arguments[func_pc] = {}
                            self.non_type_method_arguments[func_pc][frame_key] = tp_args
                            
                            for arg_idx, arg_info in sorted(tp_args.items()):
                                print(f"\n  Arg {arg_idx}: {arg_info['param_name']}  Value: {arg_info['param_value']}")
                                if 'error' in arg_info:
                                    print(f"      Error: {arg_info['error']}")
                        else:
                            print(f"  [!] No third-party info found for: {actual_func_name}")
                            print(f"      File: {filename}")
                            # Fall through — will be handled by arginfo/argsmap below
                     
                     elif is_go_117_plus: 
                       print("This is a non-type method function (with version >= 1.17 so with arginfo)")
                       
                       if args and arginfo_data:
                             external_params = None   
                             arginfo_args = arginfo_data.get('args', [])
                             if filename and line_num:
                                ext_info = self._lookup_func_name_from_external(filename, line_num, return_full_info=True)
                                if ext_info and ext_info['num_params'] > 0:
                                   external_params = ext_info['params']
                            
                             if func_pc not in self.non_type_method_arguments:
                                self.non_type_method_arguments[func_pc] = {}
                            
                             self.non_type_method_arguments[func_pc][frame_key] = {} 
                                
                            
                             for arginfo_idx, arg in enumerate(arginfo_args):
                                 
                                 if external_params and arginfo_idx < len(external_params):
                                    ext_param = external_params[arginfo_idx]
                                    param_name = ext_param.get('name', f'arg{arginfo_idx}')
                                    param_type_from_db  = ext_param.get('type', '')
                                 else:
                                    param_name = f'arg{arginfo_idx}'
                                    param_type_from_db  = ''
                                 
                                 if isinstance(arg, dict):
                                    offset = arg['offset']
                                 else:
                                    offset = arg[0]['offset']
            
                                 value_addr = arg_base + offset
       
                                 param_info= self._get_non_type_argument_info( arg,  Pointer_offsets, arg_base, itabs_dict, 
                                 types_dict,_func_functions, stack_lo,stack_hi,heap_addresses) 
                                 if param_info is None:
                                    print(f" Arg {param_name}: <extraction failed>")
                                 
                                 else:  
                                    display_type = param_type_from_db if param_type_from_db else param_info.get('type_name', '')
                                    print(f"  Arg {param_name} ({display_type}): {param_info['value']}")
                                 
                                    self.non_type_method_arguments[func_pc][frame_key][arginfo_idx] = {
                                   'param_name': param_name,
                                   'param_address': value_addr,
                                   'param_type': display_type,
                                   'param_type_heuristic': param_info.get('type_name', ''), 
                                   'param_size': param_info.get('size', 0),
                                   'param_value':  param_info.get('value','unknown' ),
                                   'param_type_ptr': param_info.get('type_ptr', 'unknown'),
                                   }
                             
                     else:     
                        print("This is a non-method function (with version < 1.17 so no arginfo)")
    
                        if not argsmap_data:
                           print(f"      (no argsmap_data available)")
                           continue
            
                        total_arg_bytes = argsmap_data.get('total_arg_bytes', 0)
                        num_slots = argsmap_data.get('num_slots', 0)
                        pointer_slots = set(argsmap_data.get('pointer_slots', []))
            
                        if total_arg_bytes <= 0:
                           print(f"      (no argument bytes)")
                           continue
            
                        print(f"      Argument area: {total_arg_bytes} bytes, {num_slots} slots")
                        print(f"      Pointer slots: {sorted(pointer_slots)}")
            
                        # Read argument data
                        try:
                          arg_data = layer.read(arg_base, total_arg_bytes, pad=True)
                        except Exception as e:
                          print(f"      (failed to read argument data: {e})")
                          continue
            
                        if len(arg_data) < total_arg_bytes:
                           print(f"      (incomplete argument data: got {len(arg_data)}/{total_arg_bytes})")
                           continue
            
                        # Parse each slot
                        offset = 0
                        arg_index = 0
                        max_iterations = num_slots + 10  # Safety limit
                        iteration = 0
            
                        while offset < total_arg_bytes and iteration < max_iterations:
                           iteration += 1
                           # Check if we have enough data for this slot
                           if offset + ptrSize > len(arg_data):
                              break
                
                           is_pointer = offset in pointer_slots
                           slot_value = int.from_bytes(arg_data[offset:offset+ptrSize], 'little')
                
                           print(f"\n      [Slot {arg_index}] offset={offset}, value={hex(slot_value)}, is_ptr={is_pointer}")
                
                           # Handle zero values
                           if slot_value == 0:
                              if is_pointer:
                                 print(f"        -> NIL pointer")
                              else:
                                 print(f"        -> ZERO (bool=false, int=0, or nil)")
                              offset += ptrSize
                              arg_index += 1
                              continue
                
                           # Non-pointer slot: primitive type
                           if not is_pointer:
                              inferred = self._infer_primitive_type(arg_data[offset:offset+ptrSize])
                              print(f"        -> PRIMITIVE [{inferred['confidence']}]: {inferred['type']} = {inferred['value']}")
                              offset += ptrSize
                              arg_index += 1
                              continue
                
                           # Pointer slot: check for composite types
                           # Peek at next slots
                           next_offset = offset + ptrSize
                           next2_offset = offset + ptrSize * 2
                
                           next_value = 0
                           next_is_pointer = False
                           next2_value = 0
                           next2_is_pointer = False
                
                           if next_offset < total_arg_bytes and next_offset + ptrSize <= len(arg_data):
                              next_is_pointer = next_offset in pointer_slots
                              next_value = int.from_bytes(arg_data[next_offset:next_offset+ptrSize], 'little')
                
                           if next2_offset < total_arg_bytes and next2_offset + ptrSize <= len(arg_data):
                              next2_is_pointer = next2_offset in pointer_slots
                              next2_value = int.from_bytes(arg_data[next2_offset:next2_offset+ptrSize], 'little')
                
                           # Check 1: INTERFACE - [PTR to itab/type, PTR to data]
                           if next_offset < total_arg_bytes and next_is_pointer:
                              if slot_value in itabs_dict or slot_value in types_dict:
                                 type_name = "<unknown>"
                                 if slot_value in itabs_dict:
                                    type_name = itabs_dict[slot_value].get('concrete_type_name', '<itab>')
                                 elif slot_value in types_dict:
                                    type_name = types_dict[slot_value].get('name', '<type>')
                        
                                 print(f"        -> INTERFACE:")
                                 print(f"           type/itab: {hex(slot_value)} ({type_name})")
                                 print(f"           data:      {hex(next_value)}")
                                 offset += ptrSize * 2
                                 arg_index += 1
                                 continue
                
                           # Check 2: SLICE - [PTR, len (non-ptr), cap (non-ptr)]
                           if next2_offset < total_arg_bytes:
                              if not next_is_pointer and not next2_is_pointer:
                                 slice_len = next_value
                                 slice_cap = next2_value
                                 # Validate slice: len <= cap, reasonable sizes
                                 if slice_cap > 0 and slice_len <= slice_cap and slice_cap < 0x100000:
                                    print(f"        -> SLICE:")
                                    print(f"           ptr: {hex(slot_value)}")
                                    print(f"           len: {slice_len}")
                                    print(f"           cap: {slice_cap}")
                                    offset += ptrSize * 3
                                    arg_index += 1
                                    continue
                
                           # Check 3: STRING - [PTR, len (non-ptr)]
                           if next_offset < total_arg_bytes:
                              if not next_is_pointer and 0 < next_value < 0x100000:
                                 str_len = next_value
                                 # Try to read and validate as string
                                 try:
                                   read_len = min(str_len, 200)
                                   str_data = layer.read(slot_value, read_len, pad=True)
                                   # Check if it looks like valid UTF-8
                                   str_value = str_data[:str_len].decode('utf-8', errors='strict')
                                   # If we get here, it's likely a string
                                   display_str = str_value[:50] + ('...' if len(str_value) > 50 else '')
                                   print(f"        -> STRING:")
                                   print(f"           ptr: {hex(slot_value)}")
                                   print(f"           len: {str_len}")
                                   print(f"           value: \"{display_str}\"")
                                   offset += ptrSize * 2
                                   arg_index += 1
                                   continue
                                 except (UnicodeDecodeError, Exception):
                                   # Not a valid string, fall through to raw pointer
                                   pass
                
                           # Default: Raw pointer
                           print(f"        -> POINTER: {hex(slot_value)}")
                           analysis = self._analyze_pointer_target(slot_value, layer, itabs_dict, types_dict, _func_functions,heap_addresses , stack_lo, stack_hi)
                           if analysis:
                              print(f"           ptr: {hex(slot_value)}")
                              print(f"           type_name: {analysis.get('type_name', 'unknown')}")
                              print(f"           value: {analysis.get('value', '<unknown>')}")
                           else:
                              print(f"           ptr: {hex(slot_value)}")
                              print(f"           type_name: unknown (analysis returned None)")
                           offset += ptrSize
                           arg_index += 1
            
                        if iteration >= max_iterations:
                            print(f"      [WARNING: Hit iteration limit, possible infinite loop avoided]")
                     print("----------------------------")
     
          else:
             print("  [No frames unwound]")

    
    
    
    def _extract_stdlib_function_arguments(self, func_name: str, external_params: Dict, arg_base: int, 
                                    argsmap_data: Optional[Dict], types_dict: Dict,
                                    itabs_dict: Dict, _func_functions: Dict,
                                    stack_lo: int, stack_hi: int, heap_addresses: Dict) -> Dict[int, Dict]:
      """
      Extract arguments for runtime/stdlib functions using external parameter DB.

      Iterates external_params (from go_func_lines JSON), reads each value
      from arg_base + current_offset using _extract_value_by_type_string.
      Pointer bitmap from argsmap_data is passed through for pointer detection.
      Advances by ptrSize (8) per parameter regardless of actual type size
      to match Go's stack slot alignment.
      """
      if not external_params:
        return {}
      layer = self.context.layers[self.layer_name]
      ptrSize = self.pclntab["ptrSize"]
    

      pointer_slots = set()  # Use set for O(1) lookup
      if argsmap_data:
        pointer_slots = set(argsmap_data.get('pointer_slots', []))
      
      arguments = {}
      current_offset = 0
    
      for arg_idx, param in enumerate(external_params):
        param_type = param.get('type', 'unknown')
        param_size = param.get('size', 8)
        param_name = param.get('name', f'arg{arg_idx}')
        if param_type.startswith('*'):
          # All pointers are pointer-sized, regardless of what they point to
          actual_size = ptrSize 
        # Correct sizes for known small types
        elif param_type in ('waitReason', 'traceBlockReason', 'uint8', 'byte', 'bool'):
            actual_size = 1
        elif param_type in ('uint16', 'int16'):
            actual_size = 2
        elif param_type in ('uint32', 'int32', 'float32'):
            actual_size = 4
        else:
            actual_size = param_size
        
        value_addr = arg_base + current_offset
     
         
        # Validate address
        if value_addr < stack_lo or value_addr + actual_size > stack_hi:
            arguments[arg_idx] = {
                'param_name': param_name,
                'param_type': param_type,
                'param_size': actual_size,
                'param_address': value_addr,
                'param_value': '<out_of_stack_bounds>',
                'error': 'address_out_of_bounds'
            }
            current_offset += ptrSize  # Always advance by 8
            continue
        
        try:
            # ============================================================
            # Extract value - now with correct pointer detection
            # ============================================================
            value = self._extract_value_by_type_string(
                value_addr, param_type, actual_size,
                pointer_slots, current_offset,  
                types_dict, itabs_dict, _func_functions,
                stack_lo, stack_hi, heap_addresses
            )
            
            arguments[arg_idx] = {
                'param_name': param_name,
                'param_type': param_type,
                'param_size': actual_size,
                'param_address': value_addr,
                'param_value': value,
            }
            
        except Exception as e:
            arguments[arg_idx] = {
                'param_name': param_name,
                'param_type': param_type,
                'param_size': actual_size,
                'param_address': value_addr,
                'param_value': '<extraction_error>',
                'error': str(e)
            }
        
        # Always advance by 8 bytes (register size)
        current_offset += ptrSize
    
      return arguments

    

    def _extract_value_by_type_string(self, value_addr: int, type_str: str, type_size: int,
                                   pointer_slots: List[int], current_offset: int,
                                   types_dict: Dict, itabs_dict: Dict, _func_functions: Dict,
                                   stack_lo: int, stack_hi: int,heap_addresses:Dict) -> any:
      """
      Read a value from memory given its Go type name as a string.

      Dispatches by type_str to type-specific readers: bool, intN, uintN,
      floatN, complexN, string, unsafe.Pointer, error, interface{}/any,
      *T (pointers), []T (slices), map[K]V, chan T, func(...), [N]T (arrays),
      package.Type (struct lookup), and runtime-specific types (*g, *m, *p,
      waitReason). Uses data_to_type_map cache and _analyze_pointer_target
      for pointer/interface resolution.
      """
      import struct as pystruct
    
      layer = self.context.layers[self.layer_name]
      ptrSize = self.pclntab["ptrSize"]
    
      # Normalize type string
      type_str = type_str.strip()
    
      # Check if this offset is a pointer (from argsmap)
      is_pointer_slot = current_offset in pointer_slots
    
      # =========================================================================
      # BOOLEAN
      # =========================================================================
      if type_str == 'bool':
        data = layer.read(value_addr, 1, pad=True)
        return bool(data[0])
    
      # =========================================================================
      # INTEGERS (signed)
      # =========================================================================
      if type_str == 'int8':
        data = layer.read(value_addr, 1, pad=True)
        return int.from_bytes(data, 'little', signed=True)
    
      if type_str == 'int16':
        data = layer.read(value_addr, 2, pad=True)
        return int.from_bytes(data, 'little', signed=True)
    
      if type_str in ('int32', 'rune'):
        data = layer.read(value_addr, 4, pad=True)
        return int.from_bytes(data, 'little', signed=True)
    
      if type_str == 'int64':
        data = layer.read(value_addr, 8, pad=True)
        return int.from_bytes(data, 'little', signed=True)
    
      if type_str == 'int':
        data = layer.read(value_addr, ptrSize, pad=True)
        return int.from_bytes(data, 'little', signed=True)
    
      # =========================================================================
      # INTEGERS (unsigned)
      # =========================================================================
      if type_str in ('uint8', 'byte'):
        data = layer.read(value_addr, 1, pad=True)
        return data[0]
    
      if type_str == 'uint16':
        data = layer.read(value_addr, 2, pad=True)
        return int.from_bytes(data, 'little', signed=False)
    
      if type_str == 'uint32':
        data = layer.read(value_addr, 4, pad=True)
        return int.from_bytes(data, 'little', signed=False)
    
      if type_str == 'uint64':
        data = layer.read(value_addr, 8, pad=True)
        return int.from_bytes(data, 'little', signed=False)
    
      if type_str in ('uint', 'uintptr'):
        data = layer.read(value_addr, ptrSize, pad=True)
        return int.from_bytes(data, 'little', signed=False)
    
      # =========================================================================
      # FLOATING POINT
      # =========================================================================
      if type_str == 'float32':
        data = layer.read(value_addr, 4, pad=True)
        return pystruct.unpack('<f', data)[0]
    
      if type_str == 'float64':
        data = layer.read(value_addr, 8, pad=True)
        return pystruct.unpack('<d', data)[0]
    
      # =========================================================================
      # COMPLEX
      # =========================================================================
      if type_str == 'complex64':
        data = layer.read(value_addr, 8, pad=True)
        real = pystruct.unpack('<f', data[0:4])[0]
        imag = pystruct.unpack('<f', data[4:8])[0]
        return complex(real, imag)
    
      if type_str == 'complex128':
        data = layer.read(value_addr, 16, pad=True)
        real = pystruct.unpack('<d', data[0:8])[0]
        imag = pystruct.unpack('<d', data[8:16])[0]
        return complex(real, imag)
    
      # =========================================================================
      # STRING
      # =========================================================================
      if type_str == 'string':
        string_struct = layer.read(value_addr, 16, pad=True)
        str_ptr = int.from_bytes(string_struct[0:8], 'little')
        str_len = int.from_bytes(string_struct[8:16], 'little')
        
        if str_ptr == 0:
            return ""
        
        if str_len <= 0 or str_len > 10000:
            return f"<invalid_string_len:{str_len}>"
        
        # Check cache first
        if str_ptr in self.data_to_type_map:
            cached = self.data_to_type_map[str_ptr]
            return cached.get('value', f"<cached@{hex(str_ptr)}>")
        
        try:
            string_data = layer.read(str_ptr, str_len, pad=True)
            string_val = string_data.decode('utf-8', errors='replace')
            
           
            return string_val
        except:
            return f"<unreadable_string@{hex(str_ptr)}>"
    
      # =========================================================================
      # UNSAFE.POINTER - Use _analyze_pointer_target for deep analysis
      # =========================================================================
      if type_str == 'unsafe.Pointer':
        data = layer.read(value_addr, ptrSize, pad=True)
        ptr_val = int.from_bytes(data, 'little')
        
        if ptr_val == 0:
            return {'unsafe_ptr': '0x0', 'value': None}
        
        # Check cache first
        if ptr_val in self.data_to_type_map:
            cached = self.data_to_type_map[ptr_val]
            return {
                'unsafe_ptr': hex(ptr_val),
                'type_name': cached.get('type_name', 'unknown'),
                'value': cached.get('value', '<cached>')
            }
        
        # Use _analyze_pointer_target for deep analysis
        try:
            analysis = self._analyze_pointer_target(ptr_val, layer, itabs_dict, types_dict, _func_functions,heap_addresses, stack_lo, stack_hi)
            return {
                'unsafe_ptr': hex(ptr_val),
                'type_name': analysis.get('type_name', 'unknown'),
                'value': analysis.get('value', '<unknown>')
            }
        except Exception as e:
            return {'unsafe_ptr': hex(ptr_val), 'error': str(e)}
    
      # =========================================================================
      # ERROR (interface type) - Use existing interface analysis
      # =========================================================================
      if type_str == 'error':
        return self._extract_interface_value(value_addr, types_dict, itabs_dict, _func_functions)
    
      # =========================================================================
      # INTERFACE{} / ANY - Use existing interface analysis
      # =========================================================================
      if type_str in ('interface{}', 'any'):
        return self._extract_interface_value(value_addr, types_dict, itabs_dict, _func_functions)
    
      # =========================================================================
      # POINTER TYPES (*T) - Use _analyze_pointer_target for deep analysis
      # =========================================================================
      if type_str.startswith('*'):
        data = layer.read(value_addr, ptrSize, pad=True)
        ptr_val = int.from_bytes(data, 'little')
        
        if ptr_val == 0:
            return {'ptr': '0x0', 'type': type_str, 'value': None}
        
        pointed_type = type_str[1:]  # Remove leading *
        
        # Check cache first
        if ptr_val in self.data_to_type_map:
            cached = self.data_to_type_map[ptr_val]
            return {
                'ptr': hex(ptr_val),
                'type': type_str,
                'cached_type': cached.get('type_name', 'unknown'),
                'value': cached.get('value', '<cached>')
            }
        
        # For known runtime types, use specialized analysis
        if pointed_type in ('g', 'runtime.g'):
            return self._extract_g_pointer(ptr_val)
        elif pointed_type in ('m', 'runtime.m'):
            return {'ptr': hex(ptr_val), 'type': '*m'}
        elif pointed_type in ('p', 'runtime.p'):
            return self._extract_p_pointer(ptr_val)
        elif pointed_type in ('sudog', 'runtime.sudog'):
            return {'ptr': hex(ptr_val), 'type': '*sudog'}
        elif pointed_type in ('hchan', 'runtime.hchan'):
            return {'ptr': hex(ptr_val), 'type': '*hchan'}
        
        # Use _analyze_pointer_target for general pointer analysis
        try:
            analysis = self._analyze_pointer_target(ptr_val, layer, itabs_dict, types_dict, _func_functions,heap_addresses, stack_lo, stack_hi)
            return {
                'ptr': hex(ptr_val),
                'type': type_str,
                'target_type': analysis.get('type_name', 'unknown'),
                'value': analysis.get('value', '<unknown>')
            }
        except Exception as e:
            return {'ptr': hex(ptr_val), 'type': type_str, 'error': str(e)}
    
      # =========================================================================
      # SLICE TYPES ([]T) - Enhanced with cache lookup
      # =========================================================================
      if type_str.startswith('[]'):
        slice_struct = layer.read(value_addr, 24, pad=True)
        ptr_val = int.from_bytes(slice_struct[0:8], 'little')
        len_val = int.from_bytes(slice_struct[8:16], 'little')
        cap_val = int.from_bytes(slice_struct[16:24], 'little')
        
        elem_type = type_str[2:]  # Remove leading []
        
        if ptr_val == 0:
            return {'slice_ptr': '0x0', 'len': 0, 'cap': 0, 'elem_type': elem_type}
        
        # Check cache first
        if ptr_val in self.data_to_type_map:
            cached = self.data_to_type_map[ptr_val]
            return {
                'slice_ptr': hex(ptr_val),
                'len': len_val,
                'cap': cap_val,
                'elem_type': elem_type,
                'cached_type': cached.get('type_name', 'unknown'),
                'value': cached.get('value', '<cached>')
            }
        
        result = {
            'slice_ptr': hex(ptr_val),
            'len': len_val,
            'cap': cap_val,
            'elem_type': elem_type,
        }
        
        # Try to read first few elements
        if 0 < len_val <= 100:
            elem_size = self._get_type_size(elem_type)
            elements = []
            max_elements = min(len_val, 10)
            
            for i in range(max_elements):
                elem_addr = ptr_val + (i * elem_size)
                try:
                    elem_val = self._extract_value_by_type_string(
                        elem_addr, elem_type, elem_size,
                        [], 0, types_dict, itabs_dict, _func_functions,
                        0, 0xFFFFFFFFFFFFFFFF,heap_addresses
                    )
                    elements.append(elem_val)
                except:
                    elements.append('<unreadable>')
                    break
            
            result['elements'] = elements
            if len_val > max_elements:
                result['truncated'] = True
        
        return result
    
      # =========================================================================
      # MAP TYPES (map[K]V) - Use _analyze_pointer_target
      # =========================================================================
      if type_str.startswith('map['):
        data = layer.read(value_addr, ptrSize, pad=True)
        map_ptr = int.from_bytes(data, 'little')
        
        if map_ptr == 0:
            return {'map_ptr': '0x0', 'count': 0, 'entries': []}
        
        # Check cache first
        if map_ptr in self.data_to_type_map:
            cached = self.data_to_type_map[map_ptr]
            return {
                'map_ptr': hex(map_ptr),
                'type': type_str,
                'cached_type': cached.get('type_name', 'unknown'),
                'value': cached.get('value', '<cached>')
            }
        
        # Use _analyze_pointer_target which handles map detection
        try:
            analysis = self._analyze_pointer_target(map_ptr, layer, itabs_dict, types_dict, _func_functions,heap_addresses, stack_lo, stack_hi)
            return {
                'map_ptr': hex(map_ptr),
                'type': type_str,
                'detected_type': analysis.get('type_name', 'unknown'),
                'value': analysis.get('value', '<unknown>')
            }
        except Exception as e:
            return {'map_ptr': hex(map_ptr), 'type': type_str, 'error': str(e)}
    
      # =========================================================================
      # CHANNEL TYPES (chan T)
      # =========================================================================
      if type_str.startswith('chan '):
        data = layer.read(value_addr, ptrSize, pad=True)
        chan_ptr = int.from_bytes(data, 'little')
        
        if chan_ptr == 0:
            return {'chan_ptr': '0x0', 'type': type_str}
        
        # Check cache
        if chan_ptr in self.data_to_type_map:
            cached = self.data_to_type_map[chan_ptr]
            return {
                'chan_ptr': hex(chan_ptr),
                'type': type_str,
                'value': cached.get('value', '<cached>')
            }
        
        return {'chan_ptr': hex(chan_ptr), 'type': type_str}
    
      # =========================================================================
      # FUNCTION TYPES (func(...)) - Use cached names
      # =========================================================================
      if type_str.startswith('func(') or type_str == 'func(...)':
        data = layer.read(value_addr, ptrSize, pad=True)
        func_ptr = int.from_bytes(data, 'little')
    
        if func_ptr == 0:
          return {'func_ptr': '0x0', 'func_name': 'nil'}
    
        text_start = self.moduledata.get("text", 0)
        text_end = self.moduledata.get("etext", 0)
    
        actual_pc = func_ptr
        is_closure = False
    
        # Check if it's directly a code pointer
        if text_start <= func_ptr < text_end:
          # Direct function pointer - good!
          actual_pc = func_ptr
          is_closure = False
        else:
          # Maybe a closure - try to dereference
          is_closure = True
          try:
            closure_data = layer.read(func_ptr, ptrSize, pad=True)
            potential_pc = int.from_bytes(closure_data, 'little')
            
            # CRITICAL: Validate the dereferenced value is actually code
            if text_start <= potential_pc < text_end:
                actual_pc = potential_pc
            else:
                # Not a valid closure or unknown structure
                # Don't try to look up function name
                return {
                    'func_ptr': hex(func_ptr),
                    'actual_pc': None,
                    'func_name': f'<closure@{hex(func_ptr)}>',
                    'is_closure': True,
                    'note': 'could_not_resolve_pc'
                }
          except:
            return {
                'func_ptr': hex(func_ptr),
                'func_name': f'<unreadable@{hex(func_ptr)}>',
                'is_closure': True
            }
    
        # NOW actual_pc is guaranteed to be in text section
        # Safe to look up function name
        func_name = None
    
        if hasattr(self, '_cached_func_names') and self._cached_func_names:
          func_name = self._cached_func_names.get(actual_pc)
    
        if not func_name and hasattr(self, '_current_func_lookup') and self._current_func_lookup:
          func_info = self._find_function_by_pc(actual_pc, self._current_func_lookup)
          if func_info:
            name = func_info.get('name', '')
            if name and name.isprintable():
                func_name = name
    
        if not func_name:
          func_name = f"func@{hex(actual_pc)}"
    
        return {
        'func_ptr': hex(func_ptr),
        'actual_pc': hex(actual_pc),
        'func_name': func_name,
        'is_closure': is_closure
        }
      # =========================================================================
      # RUNTIME-SPECIFIC TYPES
      # =========================================================================
    
      # waitReason is uint8 enum in Go runtime
      if type_str == 'waitReason':
        data = layer.read(value_addr, 1, pad=True)
        enum_val = data[0]
        reason_str = self._map_waitreason_enum(enum_val)
        return {'enum': enum_val, 'reason': reason_str}
    
      # g (goroutine pointer)
      if type_str in ('*g', '*runtime.g'):
        return self._extract_g_pointer_from_addr(value_addr)
    
      # m (machine/thread pointer)
      if type_str in ('*m', '*runtime.m'):
        data = layer.read(value_addr, ptrSize, pad=True)
        m_ptr = int.from_bytes(data, 'little')
        return {'m_ptr': hex(m_ptr) if m_ptr else '0x0'}
    
      # p (processor pointer)
      if type_str in ('*p', '*runtime.p'):
        return self._extract_p_pointer_from_addr(value_addr)
    
      # sudog (channel wait structure)
      if type_str in ('*sudog', '*runtime.sudog'):
        data = layer.read(value_addr, ptrSize, pad=True)
        sudog_ptr = int.from_bytes(data, 'little')
        return {'sudog_ptr': hex(sudog_ptr) if sudog_ptr else '0x0'}
    
      # hchan (channel structure)
      if type_str in ('*hchan', '*runtime.hchan'):
        data = layer.read(value_addr, ptrSize, pad=True)
        hchan_ptr = int.from_bytes(data, 'little')
        return {'hchan_ptr': hex(hchan_ptr) if hchan_ptr else '0x0'}
    
      # =========================================================================
      # ARRAY TYPES ([N]T)
      # =========================================================================
      array_match = re.match(r'\[(\d+)\](.+)', type_str)
      if array_match:
        array_len = int(array_match.group(1))
        elem_type = array_match.group(2)
        elem_size = self._get_type_size(elem_type)
        
        elements = []
        max_elements = min(array_len, 10)
        
        for i in range(max_elements):
            elem_addr = value_addr + (i * elem_size)
            try:
                elem_val = self._extract_value_by_type_string(
                    elem_addr, elem_type, elem_size,
                    [], 0, types_dict, itabs_dict, _func_functions,
                    0, 0xFFFFFFFFFFFFFFFF,heap_addresses
                )
                elements.append(elem_val)
            except:
                elements.append('<unreadable>')
                break
        
        result = {
            'type': type_str,
            'length': array_len,
            'elements': elements
        }
        
        if array_len > max_elements:
            result['truncated'] = True
        
        return result
    
      # =========================================================================
      # STRUCT TYPES (package.TypeName) - Try to find in types_dict
      # =========================================================================
      if '.' in type_str and not type_str.startswith('*'):
        # Try to find type by name in types_dict
        for type_addr, type_info in types_dict.items():
            if type_info and type_info.get('name') == type_str:
                try:
                    return self.build_data_map_type_methods(
                        value_addr=value_addr,
                        param_type_ptr=type_addr,
                        types_dict=types_dict,
                        itabs_dict=itabs_dict,
                        _func_functions=_func_functions,
                        depth=0,
                        max_depth=3
                    )
                except:
                    pass
        
        # Fallback: read raw bytes
        data = layer.read(value_addr, type_size, pad=True)
        return {
            'type': type_str,
            'size': type_size,
            'raw_hex': data.hex() if len(data) <= 64 else data[:64].hex() + '...'
        }
    
      # =========================================================================
      # FALLBACK: Unknown type - try heuristic analysis if pointer-like
      # =========================================================================
      data = layer.read(value_addr, type_size, pad=True)
    
      # If it's 8 bytes and looks like a pointer, try to analyze it
      if type_size == 8:
        uint64_val = int.from_bytes(data, 'little')
        
        if self._is_go_heap_pointer(uint64_val):
            # Check cache first
            if uint64_val in self.data_to_type_map:
                cached = self.data_to_type_map[uint64_val]
                return {
                    'type': type_str,
                    'likely_pointer': hex(uint64_val),
                    'cached_type': cached.get('type_name', 'unknown'),
                    'value': cached.get('value', '<cached>')
                }
            
            # Try deep analysis
            try:
                analysis = self._analyze_pointer_target(uint64_val, layer, itabs_dict, types_dict, _func_functions,heap_addresses, stack_lo, stack_hi)
                return {
                    'type': type_str,
                    'likely_pointer': hex(uint64_val),
                    'detected_type': analysis.get('type_name', 'unknown'),
                    'value': analysis.get('value', '<unknown>')
                }
            except:
                pass
    
      return {
        'type': type_str,
        'size': type_size,
        'raw_hex': data.hex() if len(data) <= 64 else data[:64].hex() + '...'
      }


    def _extract_interface_value(self, value_addr: int, types_dict: Dict, 
                                       itabs_dict: Dict, _func_functions: Dict) -> Dict:
      """Extract an interface value with enhanced analysis using existing code."""
      layer = self.context.layers[self.layer_name]
      ptrSize = self.pclntab["ptrSize"]
    
      interface_struct = layer.read(value_addr, 16, pad=True)
      type_val = int.from_bytes(interface_struct[0:8], 'little')
      data_val = int.from_bytes(interface_struct[8:16], 'little')
    
      if type_val == 0 and data_val == 0:
        return {'interface': 'nil', 'value': None}
    
      # Check if data is in cache
      if data_val != 0 and data_val in self.data_to_type_map:
        cached = self.data_to_type_map[data_val]
        return {
            'interface': 'cached',
            'type_name': cached.get('type_name', 'unknown'),
            'data_ptr': hex(data_val),
            'value': cached.get('value', '<cached>')
        }
    
      # Check if it's an itab (non-empty interface)
      if type_val in itabs_dict:
        itab_info = itabs_dict[type_val]
        concrete_type_ptr = itab_info.get('type_ptr')
        interface_name = itab_info.get('interface_name', '<unknown>')
        concrete_type = itab_info.get('concrete_type_name', '<unknown>')
        
        actual_value = None
        if data_val != 0 and concrete_type_ptr and concrete_type_ptr in types_dict:
            try:
                actual_value = self.build_data_map_type_methods(
                    value_addr=data_val,
                    param_type_ptr=concrete_type_ptr,
                    types_dict=types_dict,
                    itabs_dict=itabs_dict,
                    _func_functions=_func_functions,
                    depth=0,
                    max_depth=3
                )
                
              
            except Exception as e:
                actual_value = f"<read_error: {e}>"
        
        return {
            'interface': interface_name,
            'concrete_type': concrete_type,
            'itab': hex(type_val),
            'data': hex(data_val),
            'value': actual_value
        }
    
      # Check if it's a type pointer (empty interface / any)
      if type_val in types_dict:
        type_info = types_dict[type_val]
        type_name = type_info.get('name', '<unknown>')
        
        actual_value = None
        if data_val != 0:
            try:
                actual_value = self.build_data_map_type_methods(
                    value_addr=data_val,
                    param_type_ptr=type_val,
                    types_dict=types_dict,
                    itabs_dict=itabs_dict,
                    _func_functions=_func_functions,
                    depth=0,
                    max_depth=3
                )
                
                # Cache it
               
            except Exception as e:
                actual_value = f"<read_error: {e}>"
        
        return {
            'interface': 'any',
            'concrete_type': type_name,
            'type': hex(type_val),
            'data': hex(data_val),
            'value': actual_value
        }
    
      return {
        'interface': '<unknown>',
        'type_ptr': hex(type_val),
        'data_ptr': hex(data_val),
      }


    def _extract_g_pointer_from_addr(self, value_addr: int) -> Dict:
      """Extract goroutine pointer and parse basic info."""
      layer = self.context.layers[self.layer_name]
      ptrSize = self.pclntab["ptrSize"]
    
      data = layer.read(value_addr, ptrSize, pad=True)
      g_ptr = int.from_bytes(data, 'little')
    
      if g_ptr == 0:
        return {'g_ptr': '0x0'}
    
      # Try to parse goroutine info
      g_info = self._parse_goroutine(self.layer_name, g_ptr, ptrSize)
      if g_info:
        return {
            'g_ptr': hex(g_ptr),
            'goid': g_info.get('goid'),
            'status': g_info.get('status_name'),
            'stack_lo': hex(g_info.get('stack_lo', 0)),
            'stack_hi': hex(g_info.get('stack_hi', 0))
        }
    
      return {'g_ptr': hex(g_ptr)}


    def _extract_g_pointer(self, g_ptr: int) -> Dict:
      """Extract goroutine info from pointer value."""
      if g_ptr == 0:
        return {'g_ptr': '0x0'}
    
      ptrSize = self.pclntab["ptrSize"]
      g_info = self._parse_goroutine(self.layer_name, g_ptr, ptrSize)
      
      if g_info:
        return {
            'g_ptr': hex(g_ptr),
            'goid': g_info.get('goid'),
            'status': g_info.get('status_name'),
            'stack_lo': hex(g_info.get('stack_lo', 0)),
            'stack_hi': hex(g_info.get('stack_hi', 0))
        }
    
      return {'g_ptr': hex(g_ptr)}


    def _extract_p_pointer_from_addr(self, value_addr: int) -> Dict:
      """Extract P (processor) pointer and parse basic info."""
      layer = self.context.layers[self.layer_name]
      ptrSize = self.pclntab["ptrSize"]
    
      data = layer.read(value_addr, ptrSize, pad=True)
      p_ptr = int.from_bytes(data, 'little')
    
      if p_ptr == 0:
        return {'p_ptr': '0x0'}
    
      # Try to read P's id field (first field after status)
      try:
        p_data = layer.read(p_ptr, 16, pad=True)
        p_id = int.from_bytes(p_data[0:4], 'little')
        p_status = int.from_bytes(p_data[4:8], 'little')
        
        return {
            'p_ptr': hex(p_ptr),
            'id': p_id,
            'status': p_status
        }
      except:
          return {'p_ptr': hex(p_ptr)}


    def _extract_p_pointer(self, p_ptr: int) -> Dict:
      """Extract P info from pointer value."""
      if p_ptr == 0:
        return {'p_ptr': '0x0'}
    
      layer = self.context.layers[self.layer_name]
    
      try:
        p_data = layer.read(p_ptr, 16, pad=True)
        p_id = int.from_bytes(p_data[0:4], 'little')
        p_status = int.from_bytes(p_data[4:8], 'little')
        
        return {
            'p_ptr': hex(p_ptr),
            'id': p_id,
            'status': p_status
        }
      except:
        return {'p_ptr': hex(p_ptr)}



    def _get_type_size(self, type_str: str) -> int:
      """Get the size in bytes for a type string."""
      type_str = type_str.strip()
    
      # Remove pointer/slice markers
      base_type = type_str.lstrip('*')
    
      # Basic types
      size_map = {
        'bool': 1,
        'byte': 1,
        'int8': 1,
        'uint8': 1,
        'int16': 2,
        'uint16': 2,
        'int32': 4,
        'uint32': 4,
        'float32': 4,
        'rune': 4,
        'int64': 8,
        'uint64': 8,
        'float64': 8,
        'int': 8,
        'uint': 8,
        'uintptr': 8,
        'complex64': 8,
        'complex128': 16,
        'string': 16,  # pointer + length
        'interface{}': 16,
        'any': 16,
        'error': 16,
        'waitReason': 1,  # uint8 enum
      }
    
      if base_type in size_map:
        return size_map[base_type]
    
      # Pointers are always 8 bytes on 64-bit
      if type_str.startswith('*'):
        return 8
    
      # Slices are 24 bytes (ptr + len + cap)
      if type_str.startswith('[]'):
        return 24
    
      # Maps and channels are pointers
      if type_str.startswith('map[') or type_str.startswith('chan '):
        return 8
    
      # Functions are pointers
      if type_str.startswith('func('):
        return 8
    
      # Default to pointer size
      return 8
    
    
    
    def _infer_primitive_type(self, value_bytes: bytes) -> Dict:
      """
      Infer the most likely primitive type from an 8-byte slot value.
      Returns dict with 'type', 'value', and 'confidence'.
      """
      import struct as pystruct
    
      if len(value_bytes) < 8:
        value_bytes = value_bytes.ljust(8, b'\x00')
    
      uint64_val = int.from_bytes(value_bytes, 'little')
      int64_val = int.from_bytes(value_bytes, 'little', signed=True)
    
      # Check upper bytes for sign extension patterns
      upper_7 = value_bytes[1:8]
      upper_6 = value_bytes[2:8]
      upper_4 = value_bytes[4:8]
    
      all_zeros_7 = all(b == 0 for b in upper_7)
      all_ones_7 = all(b == 0xFF for b in upper_7)
      all_zeros_6 = all(b == 0 for b in upper_6)
      all_ones_6 = all(b == 0xFF for b in upper_6)
      all_zeros_4 = all(b == 0 for b in upper_4)
      all_ones_4 = all(b == 0xFF for b in upper_4)
    
      byte0 = value_bytes[0]
    
      # Priority 1: bool (exactly 0 or 1)
      if uint64_val == 0 or uint64_val == 1:
        return {'type': 'bool', 'value': bool(uint64_val), 'confidence': 'high'}
    
      # Priority 2-3: int8/uint8 (upper 7 bytes are 0x00 or 0xFF for signed)
      if all_zeros_7:
        # Could be uint8
        if 0 <= byte0 <= 255:
            return {'type': 'uint8', 'value': byte0, 'confidence': 'medium'}
    
      if all_ones_7 and (byte0 & 0x80):  # Sign bit set
        # Likely int8 with sign extension
        int8_val = byte0 - 256 if byte0 > 127 else byte0
        return {'type': 'int8', 'value': int8_val, 'confidence': 'medium'}
    
      # Priority 4-5: int16/uint16
      uint16_val = int.from_bytes(value_bytes[0:2], 'little')
      int16_val = int.from_bytes(value_bytes[0:2], 'little', signed=True)
    
      if all_zeros_6:
        return {'type': 'uint16', 'value': uint16_val, 'confidence': 'medium'}
    
      if all_ones_6 and (value_bytes[1] & 0x80):  # Sign bit of uint16
        return {'type': 'int16', 'value': int16_val, 'confidence': 'medium'}
    
      # Priority 6-7: int32/uint32
      uint32_val = int.from_bytes(value_bytes[0:4], 'little')
      int32_val = int.from_bytes(value_bytes[0:4], 'little', signed=True)
    
      if all_zeros_4:
        # Could be uint32 or float32
        # Check if it looks like a reasonable float32
        try:
            float32_val = pystruct.unpack('<f', value_bytes[0:4])[0]
            # Check for valid, reasonable float (not NaN, not Inf, reasonable range)
            if not (float32_val != float32_val):  # Not NaN
                if abs(float32_val) < 1e10 and abs(float32_val) > 1e-10:
                    # Has fractional part? More likely float
                    if float32_val != int(float32_val) and abs(float32_val) < 1e6:
                        return {'type': 'float32', 'value': float32_val, 'confidence': 'low'}
        except:
            pass
        
        return {'type': 'uint32', 'value': uint32_val, 'confidence': 'medium'}
    
      if all_ones_4 and (value_bytes[3] & 0x80):  # Sign bit of uint32
        return {'type': 'int32', 'value': int32_val, 'confidence': 'medium'}
    
      # Priority 8-9: float64 check
      try:
        float64_val = pystruct.unpack('<d', value_bytes)[0]
        # Check for valid, reasonable float64
        if not (float64_val != float64_val) and abs(float64_val) != float('inf'):
            if 1e-100 < abs(float64_val) < 1e100:
                # Has fractional part and reasonable magnitude
                if float64_val != int(float64_val) and abs(float64_val) < 1e10:
                    return {'type': 'float64', 'value': float64_val, 'confidence': 'low'}
      except:
        pass
    
      # Priority 10: Default to int64/uint64
      if int64_val < 0:
        return {'type': 'int64', 'value': int64_val, 'confidence': 'low'}
      else:
        return {'type': 'uint64', 'value': uint64_val, 'confidence': 'low'}
    
    
    
    
    #############################################
    def _get_third_party_analyzer(self):
      """Lazy initialize the third-party analyzer."""
      if not hasattr(self, '_third_party_analyzer_instance') or self._third_party_analyzer_instance is None:
        try:
            from volatility3.plugins.linux.third_party_analyzer import get_analyzer
            self._third_party_analyzer_instance = get_analyzer()
        except ImportError:
            print("[WARN] third_party_analyzer module not found")
            self._third_party_analyzer_instance = None
      return self._third_party_analyzer_instance


    def _lookup_third_party_function(self, filepath: str, func_name: str):
      """Look up a third-party function's parameter info."""
      analyzer = self._get_third_party_analyzer()
      if analyzer is None:
        return None
      try:
        return analyzer.get_function_info(filepath, func_name)
      except Exception as e:
        print(f"[!] Error looking up third-party function: {e}")
        return None


    def _extract_third_party_func_name(self, full_name: str) -> str:
      """
      Extract the actual function name from a fully qualified Go name.
    
      Examples:
        "github.com/gorilla/mux.(*Router).ServeHTTP" → "ServeHTTP"
        "github.com/BishopFox/sliver/client/command.RegisterCommands" → "RegisterCommands"
        "golang.org/x/crypto/ssh.(*connection).clientHandshake" → "clientHandshake"
      """
      if '/' in full_name:
        last_slash_idx = full_name.rfind('/')
        after_slash = full_name[last_slash_idx + 1:]
        parts = []
        current = ""
        paren_depth = 0
        for char in after_slash:
            if char == '(':
                paren_depth += 1
                current += char
            elif char == ')':
                paren_depth -= 1
                current += char
            elif char == '.' and paren_depth == 0:
                if current:
                    parts.append(current)
                current = ""
            else:
                current += char
        if current:
            parts.append(current)
        if parts:
            return parts[-1]
      return full_name


    def _extract_third_party_arguments(self, func_name: str, third_party_info: Dict, 
                                    arg_base: int, argsmap_data: Optional[Dict],
                                    types_dict: Dict, itabs_dict: Dict, 
                                    _func_functions: Dict, stack_lo: int, 
                                    stack_hi: int, heap_addresses: Dict) -> Dict[int, Dict]:
      """
      Extract arguments for a third-party function using its parameter info.
    
      Converts third_party_analyzer format to sig-compatible format
      and reuses _extract_stdlib_function_arguments.
      """
      params = third_party_info.get('full_params', third_party_info.get('params', []))
    
      if not params:
        return {}
    
      # Build sig-compatible dict that _extract_stdlib_function_arguments expects
      sig_compatible = {
        'params': []
      }
    
      for param in params:
        sig_compatible['params'].append({
            'name': param.get('name', ''),
            'type': param.get('type', ''),
            'size': param.get('size', 8),
        })
    
      return self._extract_stdlib_function_arguments(
        func_name=func_name,
        external_params=sig_compatible,
        arg_base=arg_base,
        argsmap_data=argsmap_data,
        types_dict=types_dict,
        itabs_dict=itabs_dict,
        _func_functions=_func_functions,
        stack_lo=stack_lo,
        stack_hi=stack_hi,
        heap_addresses=heap_addresses
      )
    
    #############################################
    def _get_non_type_argument_info(self, arg,  Pointer_offsets: List[int], arg_base: int, itabs_dict: Dict[int, Dict], 
      types_dict: Dict[int, Dict], _func_functions: Dict, stack_lo: int, stack_hi:int,heap_addresses:Dict) -> str:
       
      """
      Extract argument value using heuristics when no type info is available.

      Handles two cases:
         Simple (arg is dict): reads offset+size from stack, classifies by
          size (1→bool/uint8, 2→uint16, 4→uint32/float32, 8→pointer or
          int64/float64) using pointer bitmap and data_to_type_map cache.
       Aggregate (arg is list): detects composite patterns —
          2×8 bytes → string (ptr+len) or interface (itab+data),
          3×8 bytes → slice (ptr+len+cap),
          N×same → fixed-size array.

      Returns dict with: data_ptr, type_ptr, type_name, size, value, location.
      """
      layer = self.context.layers[self.layer_name] 
      
      # ================================================================
      # CASE 1: Simple argument (single field)
      # ================================================================
      # Simple argument (single field)
      if isinstance(arg, dict):
          offset = arg['offset']
          size = arg['size']
          is_pointer = offset in Pointer_offsets
          addr = arg_base + offset
          
          if size == 1:
             value_data = layer.read(addr, 1, pad=True)
             byte_val = value_data[0]
    
             # Interpretation 1: unsigned
             uint8_val = byte_val
    
             # Interpretation 2: signed (two's complement)
             if byte_val > 127:
                int8_val = byte_val - 256  # Convert to signed
             else:
                int8_val = byte_val
    
             # Interpretation 3: boolean
             bool_val = bool(byte_val)
    
             # Heuristic: Guess most likely type
             likely_type = 'uint8'
             likely_value = uint8_val
    
             # If it's 0 or 1, probably a bool
             if byte_val in [0, 1]:
                likely_type = 'bool'
                likely_value = bool_val
    
             # If it's negative when interpreted as int8, probably int8
             elif byte_val > 127:
                  likely_type = 'int8'
                  likely_value = int8_val
    
             # Otherwise, probably uint8
             else:
                 likely_type = 'uint8'
                 likely_value = uint8_val
             
             return {'data_ptr': addr, 'type_ptr': None, 'type_name': f'bool/int8/uint8 → {likely_type}','size': 1,'value': likely_value,'raw': {'bool': bool_val,'uint8': uint8_val, 'int8': int8_val}, 'location':'stack'}
        
          elif size == 2:
             # int16/uint16
             value_data = layer.read(addr, 2, pad=True)
             uint16_val = int.from_bytes(value_data, 'little')
             int16_val = int.from_bytes(value_data, 'little', signed=True)
    
             # Heuristic: Guess most likely type
             likely_type = 'uint16'
             likely_value = uint16_val
    
             # If negative when interpreted as signed, probably int16
             if int16_val < 0:
                likely_type = 'int16'
                likely_value = int16_val
             # Otherwise uint16
             else:
               likely_type = 'uint16'
               likely_value = uint16_val
               
             return {'data_ptr': addr, 'type_ptr': None, 'type_name': f'int16/uint16 → {likely_type}','size': 2,'value': likely_value,'raw': {'uint16': uint16_val,'int16': int16_val}, 'location':'stack'}
        
          elif size == 4:
            # int32/uint32/float32
            value_data = layer.read(addr, 4, pad=True)
            uint32_val = int.from_bytes(value_data, 'little')
            int32_val = int.from_bytes(value_data, 'little', signed=True)
    
            import struct as pystruct
            float32_val = pystruct.unpack('<f', value_data)[0]
    
            # Heuristic: Guess most likely type
            likely_type = 'uint32'
            likely_value = uint32_val
    
            # Small integers are probably integers, not floats
            if uint32_val < 1000:
               likely_type = 'uint32'
               likely_value = uint32_val
    
            # Negative values
            elif int32_val < 0:
                 likely_type = 'int32'
                 likely_value = int32_val
    
            # Valid-looking floats (not NaN, not Inf, reasonable range)
            elif not (float32_val != float32_val or  abs(float32_val) == float('inf') or  abs(float32_val) > 1e30):
                 # Only if it has a decimal part and is not tiny noise
                 if abs(float32_val) > 1e-30 and abs(float32_val) < 1e6 and float32_val != int(float32_val):
                    likely_type = 'float32'
                    likely_value = float32_val
   
            return {'data_ptr': addr, 'type_ptr': None, 'type_name': f'int32/uint32/float32 → {likely_type}','size': 4,'value': likely_value,'raw':
            {'uint32': uint32_val, 'int32': int32_val, 'float32': float32_val}, 'location':'stack'}
         
         
          elif size == 8:
              if is_pointer:
                 if addr < stack_lo or addr + 8 > stack_hi:
                    return {'data_ptr': addr, 'type_ptr': None, 'type_name': 'pointer_invalid', 'size': 8, 'value': 'addr_outside_stack', 'location':'stack'}
                
                 ptr_data = layer.read(addr, 8, pad=True)
                 ptr_value = int.from_bytes(ptr_data, 'little')
                 #print(f"----------------> POINTER (ptr_value):{ptr_value}")
                 if ptr_value == 0:
                    return {'data_ptr': addr, 'type_ptr': None, 'type_name': 'nil_pointer', 'size': 8, 'value': '0x0', 'location':'stack'}
                 
                # print(f"[Non-Type Methods] this arg is a pointer")
                 # ================================================================
                 # Priority 1: Check cache (fastest - O(1) lookup)
                 # ================================================================
                 if ptr_value in self.data_to_type_map:
                    known_type = self.data_to_type_map[ptr_value]
                    type_ptr = known_type.get('type_ptr', 0)
                    type_name = known_type.get('type_name', '<unknown>')
                    size = known_type.get('size', '<unknown>')
                    value = known_type.get('value', '<unknown>')
                    location = known_type.get('location', '<unknown>')
                 
                    return {'data_ptr': ptr_value, 'type_ptr': type_ptr, 'type_name': type_name, 'size': size, 'value': value, 'location': location}
                    
                 # ================================================================
                 # Priority 2: Not in cache - try to identify what it points to
                 # ================================================================
                 
                 else:
                    return self._analyze_pointer_target(ptr_value, layer, itabs_dict, types_dict, _func_functions,heap_addresses, stack_lo, stack_hi) 
              else:
                  # Not a pointer - direct int64/uint64/float64
                  value_data = layer.read(addr, 8, pad=True)
                  uint64_val = int.from_bytes(value_data, 'little')
                  int64_val = int.from_bytes(value_data, 'little', signed=True)
                  import struct as pystruct
                  float64_val = pystruct.unpack('<d', value_data)[0]
                  if uint64_val in self.data_to_type_map:
                      known_type = self.data_to_type_map[uint64_val]
                      type_ptr = known_type.get('type_ptr', 0)
                      type_name = known_type.get('type_name', '<unknown>')
                      size = known_type.get('size', '<unknown>')
                      value = known_type.get('value', '<unknown>')
                      location = known_type.get('location', '<unknown>')
                   
                      return { 'data_ptr': uint64_val, 'type_ptr': type_ptr,  'type_name': type_name, 'size': size,  'value': value, 'location': location  }
                  
                 
                  likely_type = 'uint64'
                  likely_value = uint64_val
                
                  if uint64_val < 1000:
                     likely_type = 'uint64'
                     likely_value = uint64_val
    
                  # Negative small numbers
                  elif -1000000 < int64_val < 0:
                       likely_type = 'int64'
                       likely_value = int64_val
    
                  # Valid-looking floats (but not tiny noise)
                  elif not (float64_val != float64_val or 
                       abs(float64_val) == float('inf') or 
                       abs(float64_val) > 1e100):
                       if abs(float64_val) > 1e-300 and abs(float64_val) < 1e6 and float64_val != int(float64_val):
                          likely_type = 'float64'
                          likely_value = float64_val
                       
                       elif 0x100000 < uint64_val < 0x7fffffffffff and (uint64_val % 8 == 0):
                            likely_type = 'uintptr'
                            likely_value = uint64_val
                 
                  return {'data_ptr': addr, 'type_ptr': None, 'type_name': f'int64/uint64/float64 → {likely_type}','size': 8,'value': likely_value,'raw':
                  {'uint64': uint64_val,'int64': int64_val, 'float64': float64_val}, 'location':'stack'}
         
         
      
      # ================================================================
      # CASE 2: Aggregate argument (multiple fields)
      # ================================================================
      # Aggregate argument (multiple fields)
      elif isinstance(arg, list):
          
          num_fields = len(arg)
          if num_fields == 0:
               return {'data_ptr':None, 'type_ptr': None, 'type_name': 'aggregated', 'size': 0,'value': 'No fields', 'location': 'heap'}
          # Get field sizes
          field_sizes = [f['size'] for f in arg]
          field_offsets = [f['offset'] for f in arg]
          total_size = sum(field_sizes)
         
          # Check which fields are pointers
          pointer_fields = [i for i, f in enumerate(arg) if f['offset'] in Pointer_offsets]
          print(pointer_fields)
          # Pattern B: 2 fields, 16 bytes total
          
          # ========================================
          # Pattern: 2 fields × 8 bytes = 16 bytes
          # ========================================
          if num_fields == 2 and field_sizes == [8, 8]:
             field0_is_ptr = 0 in pointer_fields
             field1_is_ptr = 1 in pointer_fields
             field0_addr = arg_base + arg[0]['offset']
             field1_addr = arg_base + arg[1]['offset']
             if field0_is_ptr and not field1_is_ptr:
                 str_ptr_data = layer.read(field0_addr, 8, pad=True)
                 str_ptr = int.from_bytes(str_ptr_data, 'little')
                 len_data = layer.read(field1_addr, 8, pad=True)
                 str_len = int.from_bytes(len_data, 'little')
                 if str_ptr in self.data_to_type_map:
                   
                    known_type = self.data_to_type_map[str_ptr]
                    type_ptr = known_type.get('type_ptr')
                    type_name = known_type.get('type_name', 'unknown')
                    size = known_type.get('size', 'unknown')
                    value = known_type.get('value', 'unknown')
                    location = known_type.get('location', '<unknown>')
                    
                    return {'data_ptr':str_ptr, 'type_ptr': type_ptr, 'type_name': type_name, 'size': size, 'value': value, 'location': location}
                 
                 elif str_ptr != 0 and 0 < str_len < 1000000:
                    try:
                        str_bytes = layer.read(str_ptr, str_len, pad=True)
                        str_value = str_bytes.decode('utf-8', errors='ignore')
                        
                        return {'data_ptr': str_ptr,'type_ptr': None, 'type_name': '*string',  'size': 16, 'value': str_value, 'location': 'heap'}
                  
                    except:
                       return {'data_ptr':str_ptr,'type_ptr': None,  'type_name': 'string', 'size': 16, 'value': 'error', 'location': 'heap'}
                 else:
                       return {'data_ptr':str_ptr, 'type_ptr': None, 'type_name': 'string', 'size': 16, 'value': '', 'location': 'heap'}
            
              # [PTR, PTR] = Interface
             elif field0_is_ptr and field1_is_ptr:
                type_ptr_data = layer.read(field0_addr, 8, pad=True)
                type_ptr = int.from_bytes(type_ptr_data, 'little')
                data_ptr_data = layer.read(field1_addr, 8, pad=True)
                data_ptr = int.from_bytes(data_ptr_data, 'little')
                if type_ptr == 0:
                   return {'data_ptr':data_ptr,'type_ptr': None,  'type_name': 'interface_nil', 'size': 16, 'value': None, 'location': 'heap'}
                
                if data_ptr in self.data_to_type_map:
                   known_type = self.data_to_type_map[data_ptr]
                   type_ptr = known_type.get('type_ptr')
                   type_name = known_type.get('type_name', '<unknown>')
                   size = known_type.get('size', '<unknown>')
                   value = known_type.get('value', '<unknown>')
                   location = known_type.get('location', '<unknown>')
                   
                # Check if it's an itab (iface)
                if type_ptr in itabs_dict:
                   itab_info = itabs_dict[type_ptr]
                   concrete_type_ptr = itab_info.get('type_ptr')
                   actual_value = None
                   if data_ptr != 0 and concrete_type_ptr and concrete_type_ptr in types_dict:
                       try:
                         type_info = types_dict[concrete_type_ptr]
                         type_name = type_info.get('name', '<unknown>')
                         type_size = type_info.get('size', '<unknown>')
                        
                         actual_value = self.build_data_map_type_methods (value_addr=data_ptr,param_type_ptr=concrete_type_ptr,types_dict=types_dict,
                         itabs_dict=itabs_dict, _func_functions=_func_functions,depth=0, max_depth=3)
                         
                      
                                 
                         return {'data_ptr': data_ptr,'type_ptr': concrete_type_ptr, 'type_name': type_name, 'size': type_size, 'value': actual_value, 
                               'location': 'heap'}

                       except Exception as e:
                         actual_value = f"<read_error: {e}>"
                    
                 
               
                # Check if it's a type pointer (eface)
                if type_ptr in types_dict:
                   type_info = types_dict[type_ptr]
                   type_name = type_info.get('name', '<unknown>')
                   type_size = type_info.get('size', '<unknown>')
                   actual_value = None
                   if data_ptr != 0:
                        try:
                          actual_value = self.build_data_map_type_methods( value_addr=data_ptr, param_type_ptr=type_ptr,
                          types_dict=types_dict, itabs_dict=itabs_dict, _func_functions=_func_functions,depth=0, max_depth=3)
                          
                        
                          return {'data_ptr': data_ptr,'type_ptr': type_ptr, 'type_name': type_name, 'size': type_size, 'value': actual_value, 'location': 'heap'}
                        except Exception as e:
                          actual_value = f"<read_error: {e}>"
   
             
             # [NON-PTR, PTR] = Interface (itab/type is NOT marked as pointer, data IS)
             elif not field0_is_ptr and field1_is_ptr:
                  type_ptr_data = layer.read(field0_addr, 8, pad=True)
                  type_ptr = int.from_bytes(type_ptr_data, 'little')
                  data_ptr_data = layer.read(field1_addr, 8, pad=True)
                  data_ptr = int.from_bytes(data_ptr_data, 'little')
                  if type_ptr == 0:
                     return {'data_ptr':data_ptr,'type_ptr': None,  'type_name': 'interface_nil', 'size': 16, 'value': None, 'location': 'heap'}
                 
                  if data_ptr in self.data_to_type_map:
                     known_type = self.data_to_type_map[data_ptr]
                     type_ptr = known_type.get('type_ptr')
                     type_name = known_type.get('type_name', '<unknown>')
                     size = known_type.get('size', '<unknown>')
                     value = known_type.get('value', '<unknown>')
                     location = known_type.get('location', '<unknown>')
                     
                     return {'data_ptr':data_ptr, 'type_ptr': type_ptr, 'type_name': type_name, 'size': size, 'value': value, 'location': location}
                     

                  if type_ptr in itabs_dict:
                     itab_info = itabs_dict[type_ptr]
                     concrete_type_ptr = itab_info.get('type_ptr')
                     actual_value = None
                     if data_ptr != 0 and concrete_type_ptr and concrete_type_ptr in types_dict:
                       try:
                         type_info = types_dict[concrete_type_ptr]
                         type_name = type_info.get('name', '<unknown>')
                         type_size = type_info.get('size', '<unknown>')
                         
                         actual_value = self.build_data_map_type_methods(value_addr=data_ptr,param_type_ptr=concrete_type_ptr,types_dict=types_dict,
                          itabs_dict=itabs_dict,_func_functions=_func_functions,depth=0, max_depth=3)
                         
                        
                         return {'data_ptr': data_ptr,'type_ptr': concrete_type_ptr, 'type_name': type_name, 'size': type_size, 'value': actual_value, 'location': 'heap'}
                       
                       except Exception as e:
                         actual_value = f"<read_error: {e}>"
                  
                  
                  if type_ptr in types_dict:
                     type_info = types_dict[type_ptr]
                     type_name = type_info.get('name', '<unknown>')
                     type_size = type_info.get('size', '<unknown>') 
                     kind_str = type_info.get('kind_str', 'unknown')
                     actual_value = None
                     if data_ptr != 0:
                        try:
                          actual_value = self.build_data_map_type_methods( value_addr=data_ptr, param_type_ptr=type_ptr,
                          types_dict=types_dict, itabs_dict=itabs_dict, _func_functions=_func_functions,depth=0, max_depth=3)
                          
                         
                          return {'data_ptr': data_ptr,'type_ptr': type_ptr,  'type_name': type_name, 'size': type_size, 'value': actual_value, 'location': 'heap'}
                        except Exception as e:
                          actual_value = f"<read_error: {e}>"
                     

             else:
                return {'data_ptr': None, 'type_ptr':None , 'type_name': 'complex128_or_struct', 'size': 16, 'value': None, 'location': 'heap'}
        
         
          # Pattern C: 3 fields, 24 bytes total (slice)
          if num_fields == 3 and field_sizes == [8, 8, 8]:
            field0_is_ptr = 0 in pointer_fields
            if field0_is_ptr:
                # Slice: [ptr, len, cap]
                field0_addr = arg_base + arg[0]['offset']
                field1_addr = arg_base + arg[1]['offset']
                field2_addr = arg_base + arg[2]['offset']
                ptr_data = layer.read(field0_addr, 8, pad=True)
                slice_ptr = int.from_bytes(ptr_data, 'little')
                
                len_data = layer.read(field1_addr, 8, pad=True)
                slice_len = int.from_bytes(len_data, 'little')
                
                cap_data = layer.read(field2_addr, 8, pad=True)
                slice_cap = int.from_bytes(cap_data, 'little')
                
             
                if slice_ptr in self.data_to_type_map:
                   known_type = self.data_to_type_map[slice_ptr]
                   type_ptr = known_type.get('type_ptr')
                   type_name = known_type.get('type_name', '<unknown>')
                   size = known_type.get('size', '<unknown>')
                   value = known_type.get('value', '<unknown>')
                   location = known_type.get('location', '<unknown>')
                   
                 
                   return {'data_ptr': slice_ptr, 'type_ptr':type_ptr,'type_name': type_name, 'size': size, 'value': value, 'location': 'heap'}

                else:
                   #print(f"    ✗ Slice array NOT in map - cannot parse elements")
                   return {'data_ptr': slice_ptr, 'type_ptr':None, 'type_name': 'slice', 'size': 24,  'value': '<unknown - not in map>', 'location': 'heap'}

            
            else:
                return {'data_ptr': None, 'type_ptr':None, 'type_name': 'struct_3x8', 'size': 24, 'value': None, 'location': 'stack'}
        

         
          if num_fields >= 2 and len(set(field_sizes)) == 1:
              elem_size = field_sizes[0]
              array_len = num_fields
              base_offset = field_offsets[0]
              expected_offsets = [base_offset + (i * elem_size) for i in range(array_len)]
              if field_offsets == expected_offsets:
                 elements = []
                 for i in range(array_len):
                    try:
                      if elem_size <= 8:
                         elem_arg = {'offset': arg[i]['offset'], 'size': elem_size }
                      else:
                         elem_base_offset  = arg[i]['offset']
                         num_fields_in_elem  = elem_size // 8
                         elem_arg = [{'offset': elem_base_offset + (j * 8), 'size': 8}  for j in range(num_fields_in_elem)]
                     
                      elem_info = self._get_non_type_argument_info(arg=elem_arg,Pointer_offsets=Pointer_offsets,
                      arg_base=arg_base, itabs_dict=itabs_dict, types_dict=types_dict, _func_functions=_func_functions,
                      stack_lo=stack_lo, stack_hi=stack_hi)
                     
                      
                      if 'data_ptr' in elem_info and elem_info['data_ptr'] is not None:
                          data_ptr = elem_info['data_ptr']
                          
                          print(f"      ✓ Added element {i} data_ptr {hex(data_ptr)} to map")
                      elem_value = elem_info.get('value', '<unknown>')
                      elements.append(elem_value)
                      
                      print(f"      Element {i}: {elem_info.get('type_name')} = {elem_info.get('value')}")
        
                    except Exception as e:
                           print(f"    → Error reading element {i}: {e}")
                           elements.append(f"<error: {e}>")
                
                 # No data_ptr for the array itself (it's on stack)       
                 return {'data_ptr': None, 'type_ptr':None, 'type_name': f'array[{array_len}]', 'size': elem_size * array_len,'value': elements, 
                 'location': 'stack'}  
        
          return {'data_ptr': None,'type_ptr':None, 'type_name': 'unknown_aggregate', 'size': total_size,'value': None, 'location': ''}

    
    

    
    
    
    
     
    def _get_data_location(self, ptr: int) -> str:
      """
      Classify which memory region a pointer belongs to.
    
      Returns:
        'rodata', 'data', 'types', 'heap', 'stack', 'text', 'invalid', or 'unknown'
      """
      if ptr == 0:
        return "invalid"
    
      try:
        # Text section (machine code) - reject strings from here
        text_start = self.moduledata.get('text', 0)
        text_end = self.moduledata.get('etext', 0)
        if text_start <= ptr < text_end:
            return "text"
        
        # RODATA
        rodata_start = self.moduledata.get('rodata', 0)
        rodata_end = self.moduledata.get('erodata', 0)
        if rodata_start <= ptr < rodata_end:
            return "rodata"
        
        # Types section (extends beyond rodata)
        types_end = self.moduledata.get('etypes', 0)
        if rodata_end <= ptr < types_end:
            return "types"
        
        # DATA section
        data_start = self.moduledata.get('data_start', 0)
        data_end = self.moduledata.get('edata', 0)
        if data_start <= ptr < data_end:
            return "data"
        
        # BSS section
        bss_start = self.moduledata.get('bss', 0)
        bss_end = self.moduledata.get('ebss', 0)
        if bss_start <= ptr < bss_end:
            return "bss"
        
        # noptrbss section
        noptrbss_start = self.moduledata.get('noptrbss', 0)
        noptrbss_end = self.moduledata.get('enoptrbss', 0)
        if noptrbss_start <= ptr < noptrbss_end:
            return "noptrbss"

        
        # Go heap (0xc0... range)
        if self._is_go_heap_pointer(ptr):
            return "heap"
        
        # Stack (high memory)
        if 0x7ff000000000 <= ptr <= 0x7fffffffffff:
            return "stack"
        
        return "unknown"
    
      except (KeyError, TypeError):
        return "unknown"
    
    def _analyze_pointer_target(self, ptr_value, layer, itabs_dict, types_dict, _func_functions,heap_addresses, stack_lo, stack_hi):
      """
      Analyze what a pointer target contains using pattern matching.

      Priority order:
        1. data_to_type_map cache hit (O(1), best fidelity)
        2. Stack data analysis (if ptr is within goroutine stack bounds)
        3. Heap address lookup (pre-loaded from heap scanner JSON)
        4. Header pattern matching: reads first 48 bytes and checks for
         interface (itab/type ptr), string (ptr+len), slice (ptr+len+cap),
         map (Go 1.24 Swiss table or old hmap bucket structure)
        5. Falls back to {type_name: 'pointer', value: 'unknown_structure'}

      Returns dict with: data_ptr, type_ptr, type_name, size, value, location.
      """
      if ptr_value == 0:
        return {
            'data_ptr': 0,
            'type_ptr': None,
            'type_name': 'nil',
            'size': 8,
            'value': None,
            'location': 'nil'
        }
    
      # Small values (< 0x1000 / 4KB) are NOT valid pointers
      # They are integers, flags, enums, or error codes
      if ptr_value < 0x1000:
        return {
            'data_ptr': ptr_value,
            'type_ptr': None,
            'type_name': 'small_integer',
            'size': 8,
            'value': ptr_value,
            'location': 'not_a_pointer'
        }
    
      try:
          
          
         data_location = self._get_data_location(ptr_value)
         if ptr_value in self.data_to_type_map:
            known_type = self.data_to_type_map[ptr_value]
            type_ptr = known_type.get('type_ptr', 0)
            type_name = known_type.get('type_name', '<unknown>')
            size = known_type.get('size', '<unknown>')
            actual_value = known_type.get('value', '<unknown>')
            location = known_type.get('location', '<unknown>')
            print(f"    ✓ target pointer  found in data_to_type_map!")
            print(f"    → Data type: {type_name}")
            print(f"    → Data value: {actual_value}")
            return {'data_ptr': ptr_value, 'type_ptr': type_ptr, 'type_name': type_name, 
            'size': size, 'value': actual_value, 'location': location} 
         elif stack_lo and stack_hi and stack_lo <= ptr_value < stack_hi:
             return self._analyze_stack_data( ptr_value, layer, itabs_dict, types_dict, _func_functions, heap_addresses, stack_lo, stack_hi)
         
         elif data_location =="heap":
            print(f"ptr_value: {hex(ptr_value)}  in data_location: {data_location}")
            if ptr_value in heap_addresses:
              heap_info=heap_addresses[ptr_value]
              data_addr=heap_info['data_addr']
              data_type=heap_info['type']
              data_value=heap_info['value']
              data_size=heap_info['length']
              data_location=heap_info['data_location']
              #print(f"yesssssss--------------> {data_value}")
              return {'data_ptr': data_addr, 'type_ptr': ptr_value,'type_name': data_type, 'size': data_size, 'value': data_value, 'location': data_location}
                              
       
         elif data_location in ("text", "invalid", "bss", "unknown", "noptrbss"):
                 return { 'data_ptr': ptr_value,'type_ptr': None,'type_name': f'invalid_{data_location}','size': 8, 'value': f'<{data_location}@{hex(ptr_value)}>',
                  'location': data_location}
         
         else:
          header = layer.read(ptr_value, 48, pad=True)
          if len(header) < 16:
             return {'data_ptr': ptr_value, 'type_ptr': None, 'type_name': 'pointer','size': 8, 'value': 'target_unreadable', 'location': ''}
          field0 = int.from_bytes(header[0:8], 'little')
          field1 = int.from_bytes(header[8:16], 'little')
          field2 = int.from_bytes(header[16:24], 'little') if len(header) >= 24 else 0

          # ============================================================
          # Pattern 1: Interface (itab or type)
          # ============================================================
                   
          if field0 in itabs_dict or field0 in types_dict:
             if field0 in itabs_dict: 
                         print(f"  → Detected: *Interface (itab)")
                         itab_info = itabs_dict[field0]
                         interface_name = itab_info.get('interface_name', '<unknown>')
                         concrete_type = itab_info.get('concrete_type_name', '<unknown>')
                         concrete_type_ptr = itab_info.get('type_ptr')
                         actual_value = None
                         if field1 != 0:
                            if field1 in self.data_to_type_map:
                               known_type = self.data_to_type_map[field1]
                               type_ptr = known_type.get('type_ptr', 0)
                               type_name = known_type.get('type_name', '<unknown>')
                               size = known_type.get('size', '<unknown>')
                               actual_value = known_type.get('value', '<unknown>')
                               location = known_type.get('location', '<unknown>')
                               
                               return {'data_ptr': field1, 'type_ptr': type_ptr,'type_name': type_name, 'size': size, 'value': actual_value, 'location': location}
                               
                            elif concrete_type_ptr and concrete_type_ptr in types_dict:
                               try:
                                 type_info = types_dict[concrete_type_ptr]
                                 type_name = type_info.get('name', '<unknown>')
                                 type_size = type_info.get('size', '<unknown>')
                                 actual_value = self.build_data_map_type_methods (value_addr=field1,param_type_ptr=concrete_type_ptr,types_dict=types_dict,
                                 itabs_dict=itabs_dict, _func_functions=_func_functions,depth=0, max_depth=3)
                                
                                
                                 
                                 return {'data_ptr': field1,'type_ptr': concrete_type_ptr, 'type_name': type_name, 'size': type_size, 'value': actual_value, 
                               'location': 'heap'}
                          
                               except Exception as e:
                                 actual_value = f"<read_error: {e}>"
                               
                   
             if field0 in types_dict:
                         type_info = types_dict[field0]
                         type_name = type_info.get('name', '<unknown>')
                         type_size = type_info.get('size', '<unknown>')
                         actual_value = None
                         if field1  != 0:
                            if field1 in self.data_to_type_map:
                               known_type = self.data_to_type_map[field1]
                               type_ptr = known_type.get('type_ptr', 0)
                               type_name = known_type.get('type_name', '<unknown>')
                               size = known_type.get('size', '<unknown>')
                               actual_value = known_type.get('value', '<unknown>')
                               location = known_type.get('location', '<unknown>')
                              
                               return {'data_ptr': field1, 'type_ptr': type_ptr,'type_name': type_name, 'size': size, 'value': actual_value, 'location': location}
                        
                            else:
                              try: 
                                actual_value = self.build_data_map_type_methods( value_addr=field1, param_type_ptr=field0,
                                types_dict=types_dict, itabs_dict=itabs_dict, _func_functions=_func_functions,depth=0, max_depth=5)
                               
                                return {'data_ptr': field1, 'type_ptr': field0, 'type_name': type_name, 'size': type_size, 'value': actual_value, 'location': 'heap'}
                              except Exception as e:
                                actual_value = f"<read_error: {e}>"
                     

          # ============================================================
          # Pattern 2: String (ptr + len)
          # ============================================================
          if field0 > 0x1000 and 0 < field1 < 10000:
                         if field0 in self.data_to_type_map:
                            known_type = self.data_to_type_map[field0]
                            type_ptr = known_type.get('type_ptr', 0)
                            type_name = known_type.get('type_name', '<unknown>')
                            str_value = known_type.get('value', '<unknown>')
                            size = known_type.get('size', '<unknown>')
                            location = known_type.get('location', '<unknown>')
                           
                            return {'data_ptr': field0, 'type_ptr': type_ptr,'type_name': type_name, 'size': size, 'value': str_value, 'location': location}
                         else:
                           try:
                              str_data = layer.read(field0, min(field1, 100), pad=True)
                              str_value = str_data.decode('utf-8', errors='replace')
                              
                              return {'data_ptr': field0,'type_ptr': None, 'type_name': '*string',  'size': 16, 'value': str_value, 'location': 'heap'}
                         
                           except Exception as e:
                              return {'data_ptr': field0, 'type_ptr': None, 'type_name': '*string','size': 16, 'value': f'<read_error: {e}>', 'location': 'heap'}
                      
          # ============================================================
          # Pattern 3: Slice (ptr + len + cap)
          # ============================================================ 
          if field0 > 0x1000 and 0 < field1 <= field2 < 0x100000:
                         print(f"  → Detected: *Slice")
                         elements = []
                         elem_type_name = "unknown"
                         if field0 in self.data_to_type_map:
                            known_type = self.data_to_type_map[field0]
                            type_ptr = known_type.get('type_ptr')
                            type_name = known_type.get('type_name', 'unknown')
                            size = known_type.get('size', 'unknown')
                            actual_value = known_type.get('value', 'unknown')
                            location = known_type.get('location', '<unknown>')
                           
                            return {'data_ptr': field0, 'type_ptr': type_ptr,'type_name': type_name,  'size': size, 'value': actual_value}
                         else:
                          
                            return {'data_ptr': field0, 'type_ptr': None, 'type_name': '*slice', 'size': 24,'value': '<unknown - not in map>', 'location': 'heap'}
                
          # ============================================================
          # Pattern 4: Map (Go 1.24+ or old hmap)
          # ============================================================
          major, minor, patch = self.go_version_tuple
          is_go_118_plus = (major == 1 and minor >= 18) 
          if ptr_value in self.data_to_type_map:
                         known_type = self.data_to_type_map[ptr_value]
                         type_ptr = known_type.get('type_ptr')
                         type_name = known_type.get('type_name', 'unknown')
                         size = known_type.get('size', 'unknown')
                         actual_value = known_type.get('value', 'unknown')
                         location = known_type.get('location', '<unknown>')
                         
                         return {'data_ptr':ptr_value,'type_ptr': type_ptr, 'type_name': type_name, 'size': size, 'value': actual_value, 'location': location}

                      
          if is_go_118_plus and len(header) >= 48:
                         used = int.from_bytes(header[0:8], 'little')
                         seed = int.from_bytes(header[8:16], 'little')
                         dirPtr = int.from_bytes(header[16:24], 'little')
                         dirLen = int.from_bytes(header[24:32], 'little', signed=True)
                         globalDepth = header[32] if len(header) > 32 else 0
                         globalShift = header[33] if len(header) > 33 else 0
                         is_go_heap = self._is_go_heap_pointer(dirPtr)
                         is_all_zeros = (used == 0 and seed == 0 and dirPtr == 0 and 
                         dirLen == 0 and globalDepth == 0 and globalShift == 0)
                         
                         is_valid_map = ( not is_all_zeros and   1 <= used < 1000  and
                          -1 <= dirLen < 128  and  0 <= globalDepth <= 16 and 0 <= globalShift <= 64 and  (dirPtr == 0 or (dirPtr > 0x1000 and is_go_heap))
                          and (dirLen == 0 or dirLen == 1 or dirLen > 1) )
                         if used > 0 and seed == 0:
                             is_valid_map = False
                         if dirLen > 1:
                             expected_dirLen = 1 << globalDepth
                             if dirLen != expected_dirLen:
                                print(f"dirLen mismatch: got {dirLen}, expected {expected_dirLen} (2^{globalDepth})")
                                is_valid_map = False
                          
                         if is_valid_map: 
                             try:
                                entries =   self._extract_go124_entries_no_type(ptr_value, dirPtr,dirLen,used,  layer)
                                entries_with_data = []
                                for entry in entries:
                                    key_addr = entry['key_addr']
                                    value_addr = entry['value_addr']
                                    key_size_guess=entry['key_size_guess']
                                    value_size_guess= entry['value_size_guess']
                                    
                                    if key_size_guess ==16:
                                       key_type_guess="string"
                                    elif key_size_guess ==8:
                                       key_type_guess="int"
                                   
                                   
                                    if value_size_guess ==16:
                                       value_type_guess="string"
                                    elif value_size_guess ==8:
                                       value_type_guess="int/uint64/pointer"
                                    elif value_size_guess ==4:
                                       value_type_guess="int32/uint32"
                                       
                                    elif value_size_guess ==1:
                                       value_type_guess="bool/byte"  
                           
                                    if key_addr in self.data_to_type_map:
                                       known_type = self.data_to_type_map[key_addr]
                                       type_ptr = known_type.get('type_ptr')
                                       type_name = known_type.get('type_name', 'unknown')
                                       size = known_type.get('size', 'unknown')
                                       key_value = known_type.get('value', 'unknown')
                                       location = known_type.get('location', '<unknown>')
                                     
                                    else:
                                       key_value = None
                                    
                                   
                                    if value_addr in self.data_to_type_map:
                                       known_type = self.data_to_type_map[value_addr]
                                       type_ptr = known_type.get('type_ptr')
                                       type_name = known_type.get('type_name', 'unknown')
                                       size = known_type.get('size', 'unknown')
                                       value_value = known_type.get('value', 'unknown')
                                       location = known_type.get('location', '<unknown>')
                                      
                                    else:
                                       value_value = None
                                    
                                   
                                    if key_value is None or value_value is None:
                                       entry_with_data = self._try_read_map_entry_data(entry, layer)
                                       if key_value is None:
                                          key_value = entry_with_data.get('key_value', f"@{hex(entry['key_addr'])}")
                                         
                                       if value_value is None:
                                          value_value = entry_with_data.get('value_value', f"@{hex(entry['value_addr'])}")
                                          
                                    
                                    entries_with_data.append({'key': key_value, 'value': value_value})
                                    #print(f"      {key_value} → {value_value}")
                                
                              
                                return {'data_ptr': ptr_value, 'type_ptr': None, 'type_name': '*map','size': 48, 'value': entries_with_data,'location': 'heap'}
                             except Exception as e:
                                     print(f"    → Cannot extract entries: {e}")
                        
                       
          elif len(header) >= 24:
                            count = int.from_bytes(header[0:8], 'little')
                            flags = header[8]
                            B = header[9]
                            buckets_ptr = int.from_bytes(header[16:24], 'little')
                            is_go_heap = self._is_go_heap_pointer(buckets_ptr)
                            if (0 <= count < 100000  and  0 <= B <= 15 and flags < 16   and buckets_ptr > 0x1000 and is_go_heap):
                                expected_buckets = 1 << B
                                if expected_buckets > 10000:  # Sanity check
                                   print(f" Too many buckets: 2^{B} = {expected_buckets}")
                                else:
                                 
                                 try:
                                   entries = self._extract_old_hmap_entries_no_type(ptr_value, buckets_ptr, count, B, layer)
                                   entries_with_data = []
                                   for entry in entries:
                                     key_addr = entry['key_addr']
                                     value_addr = entry['value_addr']
                                     key_size_guess=entry['key_size_guess']
                                     value_size_guess= entry['value_size_guess']
                                    
                                     if key_size_guess ==16:
                                        key_type_guess="string"
                                     elif key_size_guess ==8:
                                        key_type_guess="int"
                                   
                                   
                                     if value_size_guess ==16:
                                        value_type_guess="string"
                                     elif value_size_guess ==8:
                                        value_type_guess="int/uint64/pointer"
                                     elif value_size_guess ==4:
                                        value_type_guess="int32/uint32"
                                       
                                     elif value_size_guess ==1:
                                        value_type_guess="bool/byte"  
                           
                                     if key_addr in self.data_to_type_map:
                                        known_type = self.data_to_type_map[key_addr]
                                        type_ptr = known_type.get('type_ptr')
                                        type_name = known_type.get('type_name', 'unknown')
                                        size = known_type.get('size', 'unknown')
                                        key_value = known_type.get('value', 'unknown')
                                        location = known_type.get('location', '<unknown>')
                                       
                                     else:
                                        key_value = None
                                    
                                   
                                     if value_addr in self.data_to_type_map:
                                        known_type = self.data_to_type_map[value_addr]
                                        type_ptr = known_type.get('type_ptr')
                                        type_name = known_type.get('type_name', 'unknown')
                                        size = known_type.get('size', 'unknown')
                                        value_value = known_type.get('value', 'unknown')
                                        location = known_type.get('location', '<unknown>')
                                       
                                     else:
                                        value_value = None
                                    
                                   
                                     if key_value is None or value_value is None:
                                        entry_with_data = self._try_read_map_entry_data(entry, layer)
                                        if key_value is None:
                                          key_value = entry_with_data.get('key_value', f"@{hex(entry['key_addr'])}")
                                         
                                        if value_value is None:
                                          value_value = entry_with_data.get('value_value', f"@{hex(entry['value_addr'])}")
                                         
                                    
                                     entries_with_data.append({'key': key_value, 'value': value_value})
                                     print(f"      {key_value} → {value_value}")
                                     
                                     
                                 
                                   return {'data_ptr': ptr_value, 'type_ptr': None, 'type_name': '*map','size': 48, 'value': entries_with_data,'location': 'heap'}
                                
                    
                                 except Exception as e:
                                    print(f"    → Error extracting map: {e}")
                     
                            else:
                                  vollog.debug(f"Not a valid old hmap at {hex(ptr_value)}")
          return {'data_ptr':ptr_value,'type_ptr': None,  'type_name': 'pointer', 'size': 8,'value': 'unknown_structure', 'location': 'heap'}
      
      except Exception as e:
             print(f"  → Error analyzing pointer target: {e}")
             import traceback
             traceback.print_exc()
             return {'data_ptr':ptr_value, 'type_ptr': None,  'type_name': 'pointer', 'size': 8,'value': str(e), 'location': 'heap'}
              
    
    
    
    
    
    
    
    
    def _analyze_stack_data(self, stack_addr: int, layer, itabs_dict: Dict, types_dict: Dict,
                        _func_functions: Dict, heap_addresses: Dict,
                        stack_lo: int, stack_hi: int) -> Dict:
  
      if stack_addr == 0:
        return {
            'data_ptr': 0,
            'type_ptr': None,
            'type_name': 'nil',
            'size': 8,
            'value': None,
            'location': 'nil'
        }
    
      # Validate it's on stack
      if not (stack_lo <= stack_addr < stack_hi):
        return {
            'data_ptr': stack_addr,
            'type_ptr': None,
            'type_name': 'not_on_stack',
            'size': 8,
            'value': f'<invalid@{hex(stack_addr)}>',
            'location': 'unknown'
        }
    
      remaining_stack = stack_hi - stack_addr
      if remaining_stack < 8:
        return {
            'data_ptr': stack_addr,
            'type_ptr': None,
            'type_name': 'stack_edge',
            'size': remaining_stack,
            'value': '<near_stack_top>',
            'location': 'stack'
        }
    
      try:
        # Read up to 24 bytes to detect headers
        read_size = min(24, remaining_stack)
        data = layer.read(stack_addr, read_size, pad=True)
        
        if len(data) < 8:
            return {
                'data_ptr': stack_addr,
                'type_ptr': None,
                'type_name': 'unreadable',
                'size': 8,
                'value': '<unreadable>',
                'location': 'stack'
            }
        
        field0 = int.from_bytes(data[0:8], 'little')
        field1 = int.from_bytes(data[8:16], 'little') if len(data) >= 16 else 0
        field2 = int.from_bytes(data[16:24], 'little') if len(data) >= 24 else 0
        
        # ============================================================
        # Check if field0 is a POINTER (to heap or elsewhere)
        # ============================================================
        if self._is_go_heap_pointer(field0) or (stack_lo <= field0 < stack_hi):
            # It's a pointer - analyze target
            target_result = self._analyze_pointer_target(
                field0, layer, itabs_dict, types_dict,
                _func_functions, heap_addresses, stack_lo, stack_hi
            )
            return {
                'data_ptr': stack_addr,
                'type_ptr': target_result.get('type_ptr'),
                'type_name': f"*{target_result.get('type_name', 'unknown')}",
                'size': 8,
                'value': target_result.get('value'),
                'location': 'stack',
                'points_to': target_result.get('location')
            }
        
        # ============================================================
        # Pattern: String header (ptr in rodata/types + len)
        # ============================================================
        if len(data) >= 16 and field0 > 0x1000 and 0 < field1 < 100000:
            str_location = self._get_data_location(field0)
            if str_location in ('rodata', 'types', 'data'):
                try:
                    str_bytes = layer.read(field0, min(field1, 200), pad=True)
                    str_value = str_bytes[:field1].decode('utf-8', errors='replace')
                    return {
                        'data_ptr': stack_addr,
                        'type_ptr': None,
                        'type_name': 'string',
                        'size': 16,
                        'value': str_value,
                        'location': 'stack'
                    }
                except:
                    pass
        
        # ============================================================
        # Pattern: Slice header (ptr + len + cap)
        # ============================================================
        if len(data) >= 24 and field0 > 0x1000 and 0 < field1 <= field2 < 0x100000:
            # Check backing array in cache
            if field0 in self.data_to_type_map:
                known = self.data_to_type_map[field0]
                return {
                    'data_ptr': stack_addr,
                    'type_ptr': known.get('type_ptr'),
                    'type_name': known.get('type_name', 'slice'),
                    'size': 24,
                    'value': {'ptr': hex(field0), 'len': field1, 'cap': field2, 'elements': known.get('value')},
                    'location': 'stack'
                }
            return {
                'data_ptr': stack_addr,
                'type_ptr': None,
                'type_name': 'slice',
                'size': 24,
                'value': {'ptr': hex(field0), 'len': field1, 'cap': field2},
                'location': 'stack'
            }
        
        # ============================================================
        # Pattern: Interface header (itab/type + data ptr)
        # ============================================================
        if len(data) >= 16:
            if field0 in itabs_dict:
                itab_info = itabs_dict[field0]
                concrete_type_ptr = itab_info.get('type_ptr')
                actual_value = None
                if field1 != 0:
                    if field1 in self.data_to_type_map:
                        actual_value = self.data_to_type_map[field1].get('value')
                    elif self._is_go_heap_pointer(field1):
                        # Data is on heap - analyze it
                        data_result = self._analyze_pointer_target(
                            field1, layer, itabs_dict, types_dict,
                            _func_functions, heap_addresses, stack_lo, stack_hi
                        )
                        actual_value = data_result.get('value')
                
                return {
                    'data_ptr': stack_addr,
                    'type_ptr': concrete_type_ptr,
                    'type_name': f"interface({itab_info.get('interface_name', '?')})",
                    'size': 16,
                    'value': {'concrete_type': itab_info.get('concrete_type_name'), 'data': actual_value},
                    'location': 'stack'
                }
            
            elif field0 in types_dict:
                # Empty interface (any)
                type_info = types_dict[field0]
                actual_value = None
                if field1 != 0:
                    if field1 in self.data_to_type_map:
                        actual_value = self.data_to_type_map[field1].get('value')
                    elif self._is_go_heap_pointer(field1):
                        data_result = self._analyze_pointer_target(
                            field1, layer, itabs_dict, types_dict,
                            _func_functions, heap_addresses, stack_lo, stack_hi
                        )
                        actual_value = data_result.get('value')
                
                return {
                    'data_ptr': stack_addr,
                    'type_ptr': field0,
                    'type_name': f"any({type_info.get('name', '?')})",
                    'size': 16,
                    'value': actual_value,
                    'location': 'stack'
                }
        
        # ============================================================
        # Fallback: Primitive value
        # ============================================================
        inferred = self._infer_primitive_type(data[0:8])
        return {
            'data_ptr': stack_addr,
            'type_ptr': None,
            'type_name': inferred['type'],
            'size': 8,
            'value': inferred['value'],
            'location': 'stack',
            'confidence': inferred['confidence']
        }
        
      except Exception as e:
        return {
            'data_ptr': stack_addr,
            'type_ptr': None,
            'type_name': 'error',
            'size': 8,
            'value': f'<error: {e}>',
            'location': 'stack'
        }
    
    
    
    
    
    
    
    
    
    def _extract_go124_entries_no_type(self, map_addr: int, dirPtr: int, dirLen: int, used: int, layer) -> List[Dict]:
     
      if dirPtr == 0 or used == 0:
        return []
     
      if dirLen < 0 or dirLen > 10000:  # Max 10k directory entries
        print(f"[MAP EXTRACT] ERROR: dirLen={dirLen} is invalid! Skipping map.")
        return []
      print(f"\n[MAP EXTRACT] Go 1.24 map @ {hex(map_addr)}")
      print(f"[MAP EXTRACT]   used={used}, dirLen={dirLen}, dirPtr={hex(dirPtr)}")
    
      # Constants from Go 1.24 Swiss Table
      SLOTS_PER_GROUP = 8
      CTRL_EMPTY = 0x80
      CTRL_DELETED = 0xFE
    
      entries = []
    
      try:
        if dirLen == 0  or dirLen == 1:
            # Small map: dirPtr points directly to a single group
            print(f"[MAP EXTRACT] Small map - single group @ {hex(dirPtr)}")
            group_entries = self._parse_go124_group_no_type(
                dirPtr, used, layer
            )
            entries.extend(group_entries)
        else:
            # Large map: dirPtr points to directory of group pointers
            max_dir_entries = min(dirLen, 1000)  # Cap at 1000
            bytes_to_read = max_dir_entries * 8
            print(f"[MAP EXTRACT] Large map - directory with {dirLen} entries")
            
            # Read directory (array of pointers to groups)
            dir_data = layer.read(dirPtr, dirLen * 8, pad=True)
            
            for dir_idx in range(dirLen):
                group_ptr = int.from_bytes(
                    dir_data[dir_idx*8:(dir_idx+1)*8], 'little'
                )
                
                if group_ptr == 0:
                    continue
                
                print(f"[MAP EXTRACT]   Directory[{dir_idx}] → group @ {hex(group_ptr)}")
                
                group_entries = self._parse_go124_group_no_type(
                    group_ptr, used - len(entries), layer
                )
                entries.extend(group_entries)
                
                if len(entries) >= used:
                    break
        
        print(f"[MAP EXTRACT] Extracted {len(entries)}/{used} entries")
        return entries[:used]  # Return exactly 'used' entries
        
      except Exception as e:
        print(f"[MAP EXTRACT] Error: {e}")
        import traceback
        traceback.print_exc()
        return entries


    
    def _guess_key_value_sizes_from_group(
      self,
      group_addr: int,
      occupied_slots: list,
      layer
      ) -> tuple:
      """
      Smart heuristic to guess key/value sizes by trying multiple combinations.
      """
    
      print(f"\n[GUESS] Trying multiple size combinations...")
    
      # Common Go map type combinations
      candidates = [
        (16, 8, "map[string]int/uint64/pointer"),
        (8, 8, "map[int]int/uint64/pointer"),
        (16, 16, "map[string]string/interface"),
        (8, 16, "map[int]string/interface"),
        (16, 4, "map[string]int32/uint32"),
        (8, 4, "map[int64]int32"),
        (16, 1, "map[string]bool/byte"),
        (8, 1, "map[int]bool/byte"),
      ]
    
      best_score = 0.0
      best_sizes = (16, 8)  # Default fallback
    
      for key_size, value_size, description in candidates:
        score = self._score_size_combination(
            group_addr, occupied_slots, key_size, value_size, layer
        )
        
        print(f"[GUESS]   {description:40s} → score: {score:.2f}")
        
        if score > best_score:
            best_score = score
            best_sizes = (key_size, value_size)
    
      print(f"[GUESS] ✓ Best: {best_sizes[0]}-byte keys, {best_sizes[1]}-byte values (score: {best_score:.2f})")
    
      return best_sizes


    def _score_size_combination(
    self,
    group_addr: int,
    occupied_slots: list,
    key_size: int,
    value_size: int,
    layer
    ) -> float:
      """
      Score a key/value size combination by checking if data looks valid.
      Returns 0.0 (bad) to 1.0+ (perfect, with bonuses).
      """
    
      SLOTS_PER_GROUP = 8
      ctrl_size = 8
      keys_start = ctrl_size
      values_start = keys_start + (SLOTS_PER_GROUP * key_size)
      group_size = ctrl_size + (SLOTS_PER_GROUP * key_size) + (SLOTS_PER_GROUP * value_size)
    
      try:
        # Read entire group
        group_data = layer.read(group_addr, group_size, pad=True)
        
        if len(group_data) < group_size:
            return 0.0
        
        valid_keys = 0
        valid_values = 0
        string_bonus = 0.0  # ← NEW: Bonus for detecting actual strings
        
        for slot in occupied_slots:
            key_offset = keys_start + (slot * key_size)
            value_offset = values_start + (slot * value_size)
            
            key_data = group_data[key_offset:key_offset + key_size]
            value_data = group_data[value_offset:value_offset + value_size]
            
            # Check if key looks valid
            key_valid, key_is_string = self._data_looks_valid_for_size(key_data, key_size, layer)
            if key_valid:
                valid_keys += 1
                if key_is_string:
                    string_bonus += 0.1  # Bonus for actual string detected!
            
            # Check if value looks valid
            value_valid, value_is_string = self._data_looks_valid_for_size(value_data, value_size, layer)
            if value_valid:
                valid_values += 1
                if value_is_string:
                    string_bonus += 0.1
            
            if value_valid and value_size == 8 and not value_is_string:
                try:
                    value_int = int.from_bytes(value_data, 'little')
                    if 0 <= value_int < 10000:  # Values like 100, 200, 300
                        string_bonus += 0.05  # Small extra bonus
                except:
                    pass
        
        # Calculate base score
        if len(occupied_slots) == 0:
            return 0.0
        
        key_ratio = valid_keys / len(occupied_slots)
        value_ratio = valid_values / len(occupied_slots)
        
        base_score = (key_ratio * 0.5) + (value_ratio * 0.5)
        
        # Add string bonus - this pushes string types above integer types
        final_score = base_score + string_bonus
        
        return final_score
        
      except Exception as e:
        return 0.0


    def _data_looks_valid_for_size(self, data: bytes, size: int, layer) -> tuple:
      """
      Check if data looks valid for a given size.
    
      Returns: (is_valid: bool, is_string: bool)
      """
    
      if len(data) < size:
        return (False, False)
    
      if size == 1:
        return (True, False)
    
      elif size == 4:
        value = int.from_bytes(data[:4], 'little')
        return (value < 1000000000, False)
    
      elif size == 8:
        value = int.from_bytes(data[:8], 'little')
        
        # Check for reasonable integer
        if value < 0x10000000000:  # 2^40
            return (True, False)
        
        # Or valid pointer
        if self._is_go_heap_pointer(value):
            return (True, False)
        
        return (False, False)
    
      elif size == 16:
        field0 = int.from_bytes(data[0:8], 'little')
        field1 = int.from_bytes(data[8:16], 'little')
        
        # ============================================================
        # PRIORITY 1: Try to detect as STRING
        # ============================================================
        if field0 > 0x1000 and 0 < field1 < 100000:
            try:
                if not self._is_go_heap_pointer(field0):
                    # Not a valid pointer, can't be a string
                    pass
                else:
                    # Try to read the string data
                    str_data = layer.read(field0, min(field1, 30), pad=True)
                    
                    if len(str_data) > 0:
                        # Check if it's printable text
                        printable = sum(1 for b in str_data if (32 <= b <= 126) or b in (9, 10, 13))
                        ratio = printable / len(str_data)
                        
                        if ratio >= 0.6:  # 60% printable = likely a string
                            return (True, True)  
            except:
                pass
        
        # ============================================================
        # PRIORITY 2: Check as interface
        # ============================================================
        if field0 > 0x1000 and (field1 == 0 or field1 > 0x1000):
            if self._is_go_heap_pointer(field0):
                if field1 == 0 or self._is_go_heap_pointer(field1):
                    return (True, False)  # Valid but not a string
        
        return (False, False)
    
      else:
        # Unknown size
        non_zero = sum(1 for b in data if b != 0)
        is_valid = non_zero >= len(data) // 2
        return (is_valid, False)
    
    
    
    
    
    
    def _parse_go124_group_no_type(self, group_addr: int, max_entries: int, layer) -> List[Dict]:
      """
      Parse a Go 1.24 Swiss Table group WITHOUT type information.
      
      Strategy: Use SMART HEURISTICS to guess key/value sizes
      """
    
      SLOTS_PER_GROUP = 8
      CTRL_EMPTY = 0x80
      CTRL_DELETED = 0xFE
    
      # Read control bytes first
      ctrl_data = layer.read(group_addr, 8, pad=True)
    
      if len(ctrl_data) < 8:
        return []
    
      print(f"\n[GROUP] @ {hex(group_addr)}")
      print(f"[GROUP] Control bytes: {ctrl_data.hex()}")
    
      entries = []
      occupied_slots = []
    
      # Find occupied slots
      for slot in range(SLOTS_PER_GROUP):
        ctrl = ctrl_data[slot]
        if ctrl != CTRL_EMPTY and ctrl != CTRL_DELETED and ctrl != 0x00: 
            occupied_slots.append(slot)
            print(f"[GROUP]   Slot {slot}: occupied (ctrl={hex(ctrl)})")
    
      if not occupied_slots:
        return []
    
      # ============================================================
      # Try multiple size combinations
      # ============================================================
      key_size, value_size = self._guess_key_value_sizes_from_group(
        group_addr, occupied_slots, layer
      )
    
      print(f"[GROUP] Determined key_size={key_size}, value_size={value_size}")
    
      # Calculate offsets
      ctrl_size = 8
      keys_start = ctrl_size
      values_start = keys_start + (SLOTS_PER_GROUP * key_size)
    
      for slot in occupied_slots:
        key_addr = group_addr + keys_start + (slot * key_size)
        value_addr = group_addr + values_start + (slot * value_size)
        
        print(f"[GROUP]   Slot {slot}: key @ {hex(key_addr)}, value @ {hex(value_addr)}")
        
        entries.append({
            'slot': slot,
            'key_addr': key_addr,
            'value_addr': value_addr,
            'key_size_guess': key_size,
            'value_size_guess': value_size
        })
        
        if len(entries) >= max_entries:
            break
    
      return entries


    def _extract_old_hmap_entries_no_type(self, map_addr: int, buckets_ptr:int, count:int,B:int, layer) -> List[Dict]:
      """
      Extract entries from old hmap (Go 1.22 and earlier) WITHOUT type information.
    
      Similar strategy to Go 1.24, but using old bucket structure.
      """
      if buckets_ptr == 0 or count == 0:
        return []
    
      print(f"\n[MAP EXTRACT] Old hmap @ {hex(map_addr)}")
      print(f"[MAP EXTRACT]   count={count}, B={B}, buckets={hex(buckets_ptr)}")
    
      # Old hmap uses 2^B buckets, each with 8 slots
      num_buckets = 1 << B
      SLOTS_PER_BUCKET = 8
      sample_occupied_slots = []
      sample_bucket_addr = buckets_ptr
    
      try:
          # Read first bucket's tophash to find occupied slots
          tophash_data = layer.read(sample_bucket_addr, 8, pad=True)
          for slot in range(8):
              top = tophash_data[slot]
              if top != 0 and top != 1:  # Not empty/deleted
                  sample_occupied_slots.append(slot)
      except:
          pass
      
      if sample_occupied_slots:
        key_size, value_size = self._guess_key_value_sizes_from_old_bucket(
            buckets_ptr, sample_occupied_slots, layer
        )
      else:
        # Default fallback
        key_size = 16
        value_size = 8
    
      print(f"[MAP EXTRACT] Determined key_size={key_size}, value_size={value_size}")

      # Bucket structure: [tophash:8][keys:key_size*8][values:value_size*8][overflow:8]
      bucket_size = 8 + (SLOTS_PER_BUCKET * key_size) + (SLOTS_PER_BUCKET * value_size) + 8
    
      entries = []
    
      try:
        for bucket_idx in range(min(num_buckets, 100)):  # Limit to first 100 buckets
            bucket_addr = buckets_ptr + (bucket_idx * bucket_size)
            bucket_data = layer.read(bucket_addr, bucket_size, pad=True)
            
            if len(bucket_data) < bucket_size:
                break
            
            # Tophash bytes
            tophash = bucket_data[0:8]
            
            keys_start = 8
            values_start = 8 + (SLOTS_PER_BUCKET * key_size)
            
            for slot in range(SLOTS_PER_BUCKET):
                top = tophash[slot]
                
                # Empty/deleted markers
                if top == 0 or top == 1:
                    continue
                
                key_addr = bucket_addr + keys_start + (slot * key_size)
                value_addr = bucket_addr + values_start + (slot * value_size)
                
                entries.append({
                    'bucket': bucket_idx,
                    'slot': slot,
                    'key_addr': key_addr,
                    'value_addr': value_addr,
                    'key_size_guess': key_size,
                    'value_size_guess': value_size
                })
                
                if len(entries) >= count:
                    break
            
            if len(entries) >= count:
                break
        
        print(f"[MAP EXTRACT] Extracted {len(entries)}/{count} entries")
        return entries[:count]
        
      except Exception as e:
        print(f"[MAP EXTRACT] Error: {e}")
        import traceback
        traceback.print_exc()
        return entries 

    
    def _guess_key_value_sizes_from_old_bucket(
      self,
      bucket_addr: int,
      occupied_slots: list,
      layer
      ) -> tuple:
      """
      Guess key/value sizes for old hmap by trying combinations.
      Similar to _guess_key_value_sizes_from_group but for old bucket structure.
      """
    
      print(f"\n[GUESS OLD HMAP] Trying size combinations...")
    
      # Common Go map type combinations
      candidates = [
        (16, 8, "map[string]int/uint64/pointer"),
        (8, 8, "map[int]int/uint64/pointer"),
        (16, 16, "map[string]string/interface"),
        (8, 16, "map[int]string/interface"),
        (16, 4, "map[string]int32/uint32"),
        (8, 4, "map[int64]int32"),
        (16, 1, "map[string]bool/byte"),
        (8, 1, "map[int]bool/byte"),
      ]
    
      best_score = 0.0
      best_sizes = (16, 8)  # Default fallback
    
      for key_size, value_size, description in candidates:
        score = self._score_old_bucket_size_combination(
            bucket_addr, occupied_slots, key_size, value_size, layer
        )
        
        print(f"[GUESS OLD HMAP]   {description:40s} → score: {score:.2f}")
        
        if score > best_score:
            best_score = score
            best_sizes = (key_size, value_size)
    
      print(f"[GUESS OLD HMAP] ✓ Best: {best_sizes[0]}-byte keys, {best_sizes[1]}-byte values (score: {best_score:.2f})")
    
      return best_sizes

    def _score_old_bucket_size_combination(
      self,
      bucket_addr: int,
      occupied_slots: list,
      key_size: int,
      value_size: int,
      layer
      ) -> float:
      """
      Score a key/value size combination for old hmap bucket.
      Returns 0.0 (bad) to 1.0+ (perfect, with bonuses).
      """
    
      SLOTS_PER_BUCKET = 8
      tophash_size = 8
      keys_start = tophash_size
      values_start = keys_start + (SLOTS_PER_BUCKET * key_size)
      overflow_ptr_offset = values_start + (SLOTS_PER_BUCKET * value_size)
      bucket_size = overflow_ptr_offset + 8
    
      try:
        # Read entire bucket
        bucket_data = layer.read(bucket_addr, bucket_size, pad=True)
        
        if len(bucket_data) < bucket_size:
            return 0.0
        
        valid_keys = 0
        valid_values = 0
        string_bonus = 0.0
        
        for slot in occupied_slots:
            key_offset = keys_start + (slot * key_size)
            value_offset = values_start + (slot * value_size)
            
            key_data = bucket_data[key_offset:key_offset + key_size]
            value_data = bucket_data[value_offset:value_offset + value_size]
            
            # Check if key looks valid
            key_valid, key_is_string = self._data_looks_valid_for_size(key_data, key_size, layer)
            if key_valid:
                valid_keys += 1
                if key_is_string:
                    string_bonus += 0.1
            
            # Check if value looks valid
            value_valid, value_is_string = self._data_looks_valid_for_size(value_data, value_size, layer)
            if value_valid:
                valid_values += 1
                if value_is_string:
                    string_bonus += 0.1
        
        # Calculate base score
        if len(occupied_slots) == 0:
            return 0.0
        
        key_ratio = valid_keys / len(occupied_slots)
        value_ratio = valid_values / len(occupied_slots)
        
        base_score = (key_ratio * 0.5) + (value_ratio * 0.5)
        
        # Add string bonus
        final_score = base_score + string_bonus
        
        return final_score
        
      except Exception as e:
        return 0.0
    
    def _try_read_map_entry_data(self, entry: Dict, layer) -> Dict:
      """
      Try to interpret key/value data from addresses.
    
      Without type info, we use heuristics:
      - 8 bytes → try as int64/uint64
      - 16 bytes → try as string header (ptr + len)
      """
    
      key_addr = entry['key_addr']
      value_addr = entry['value_addr']
      key_size = entry.get('key_size_guess', 8)
      value_size = entry.get('value_size_guess', 8)
    
      result = {**entry}
    
      # Try to read key
      try:
        key_data = layer.read(key_addr, key_size, pad=True)
        
        if key_size == 8:
            # Try as int64
            key_val = int.from_bytes(key_data, 'little')
            result['key_value'] = key_val
        elif key_size == 16:
            # Try as string (ptr + len)
            str_ptr = int.from_bytes(key_data[0:8], 'little')
            str_len = int.from_bytes(key_data[8:16], 'little')
            
            if 0 < str_len < 1000 and str_ptr > 0x1000:
                str_data = layer.read(str_ptr, min(str_len, 100), pad=True)
                try:
                    key_str = str_data.decode('utf-8', errors='replace')
                    result['key_value'] = f'"{key_str}"'
                except:
                    result['key_value'] = f'<string @ {hex(str_ptr)}, len={str_len}>'
      except:
        pass
    
      # Try to read value
      try:
        value_data = layer.read(value_addr, value_size, pad=True)
        
        if value_size == 8:
            value_val = int.from_bytes(value_data, 'little')
            result['value_value'] = value_val
        elif value_size == 16:
            # String
            str_ptr = int.from_bytes(value_data[0:8], 'little')
            str_len = int.from_bytes(value_data[8:16], 'little')
            
            if 0 < str_len < 1000 and str_ptr > 0x1000:
                str_data = layer.read(str_ptr, min(str_len, 100), pad=True)
                try:
                    value_str = str_data.decode('utf-8', errors='replace')
                    result['value_value'] = f'"{value_str}"'
                except:
                    result['value_value'] = f'<string @ {hex(str_ptr)}, len={str_len}>'
      except:
        pass
    
      return result
    
    
    def _resolve_filename(self, file_index: int) -> str:
  
      try:
        if file_index < 0:
            return "<negative_idx>"
        
        layer = self.context.layers[self.layer_name]
        major, minor, _ = self.go_version_tuple
        
        # Go 1.16+ all use cutab -> filetab structure
        is_go_116_plus = (major == 1 and minor >= 16) or major > 1
        
        if is_go_116_plus:
            # Go 1.16+: Use cutab to get offset into filetab
            cutab_ptr = self.moduledata.get('cutab', {}).get('ptr', 0)
            cutab_len = self.moduledata.get('cutab', {}).get('len', 0)
            filetab_ptr = self.moduledata.get('filetab', {}).get('ptr', 0)
            filetab_len = self.moduledata.get('filetab', {}).get('len', 0)
           
            if cutab_ptr == 0 or filetab_ptr == 0:
                return "<no_cutab_or_filetab>"
            
            if file_index >= cutab_len:
                return f"<cutab_oob:{file_index}/{cutab_len}>"
            
            # Read offset from cutab (uint32)
            cutab_entry_addr = cutab_ptr + (file_index * 4)
            offset_data = layer.read(cutab_entry_addr, 4, pad=True)
            filetab_offset = int.from_bytes(offset_data, 'little')
           
            if filetab_offset >= filetab_len:
                return f"<filetab_oob:{filetab_offset}/{filetab_len}>"
            
            # Read filename from filetab
            name_addr = filetab_ptr + filetab_offset
           
            filename = self._read_cstring(name_addr, 512)
           
            return filename if filename else "<empty>"
        
        else:
            # Go 1.2-1.15: filetab contains uint32 offsets into pclntab
            pclntable_ptr = self.moduledata['pclntable']['ptr']
            filetab_ptr = self.moduledata.get('filetab', {}).get('ptr', 0)
            filetab_len = self.moduledata.get('filetab', {}).get('len', 0)
            
            if filetab_ptr == 0:
                return "<no_filetab>"
            
            if file_index >= filetab_len:
                return f"<idx_oob:{file_index}/{filetab_len}>"
            
            # Read offset from filetab
            offset_addr = filetab_ptr + (file_index * 4)
            offset_data = layer.read(offset_addr, 4, pad=True)
            name_offset = int.from_bytes(offset_data, 'little')
            
            # Offset is relative to pclntab
            name_addr = pclntable_ptr + name_offset
            return self._read_cstring(name_addr, 512)
            
      except Exception as e:
        import traceback
        traceback.print_exc()
        return f"<error:{e}>"
    
    
    def _get_file_line_for_pc(self, func_info: Dict, target_pc: int) -> Tuple[str, int]:
      try:
        entry_pc = func_info.get('pc', 0)
        pcfile_offset = func_info.get('pcfile', 0)
        pcln_offset = func_info.get('pcln', 0)
        startLine = func_info.get('startLine', 0)
        cuOffset = func_info.get('cuOffset', 0)  
        
        layer = self.context.layers[self.layer_name]
        pctab_base = self.moduledata["pctab"]["ptr"]
        
        major, minor, _ = self.go_version_tuple
        is_go_116_plus = (major == 1 and minor >= 16) or major > 1
        
        # Get file index from pcfile table
        file_index = None
        if pcfile_offset > 0:
            pcfile_addr = pctab_base + pcfile_offset
            pcfile_data = layer.read(pcfile_addr, 1024, pad=True)
            file_index = self._pcvalue(pcfile_data, target_pc, entry_pc,
                                       f"{func_info.get('name', '')} [pcfile]")
        
        # Get line delta from pcln table
        line_delta = None
        if pcln_offset > 0:
            pcln_addr = pctab_base + pcln_offset
            pcln_data = layer.read(pcln_addr, 1024, pad=True)
            line_delta = self._pcvalue(pcln_data, target_pc, entry_pc,
                                       f"{func_info.get('name', '')} [pcln]")
        
        # Resolve filename - THIS IS THE KEY FIX
        filename = "<unknown>"
        if file_index is not None and file_index >= 0:
            if is_go_116_plus:
                # Go 1.16+: file_index is relative to the CU's file table
                # We need to add cuOffset to get the actual cutab index
                filename = self._resolve_filename_go116(file_index, cuOffset)
            else:
                # Go 1.2-1.15: file_index is a direct index
                filename = self._resolve_filename(file_index)
        
        # Calculate line number
        line_number = 0
        if line_delta is not None:
            line_number = line_delta
        
        
      
        return (filename, line_number)
        
      except Exception as e:
        import traceback
        traceback.print_exc()
        return ("<error>", 0)


    def _resolve_filename_go116(self, file_index: int, cuOffset: int) -> str:
   
      try:
        if file_index < 0:
            return "<negative_idx>"
        
        layer = self.context.layers[self.layer_name]
        
        cutab_ptr = self.moduledata.get('cutab', {}).get('ptr', 0)
        cutab_len = self.moduledata.get('cutab', {}).get('len', 0)
        filetab_ptr = self.moduledata.get('filetab', {}).get('ptr', 0)
        filetab_len = self.moduledata.get('filetab', {}).get('len', 0)
        
        if cutab_ptr == 0 or filetab_ptr == 0:
            return "<no_cutab_or_filetab>"
        
        # The actual cutab index is cuOffset + file_index
        # cuOffset is the base index for this function's CU
        # file_index is the local file number within the CU
        actual_cutab_index = cuOffset + file_index
        
        if actual_cutab_index < 0 or actual_cutab_index >= cutab_len:
            return f"<cutab_oob:{actual_cutab_index}/{cutab_len}>"
        
        # Read offset from cutab (uint32)
        cutab_entry_addr = cutab_ptr + (actual_cutab_index * 4)
        offset_data = layer.read(cutab_entry_addr, 4, pad=True)
        filetab_offset = int.from_bytes(offset_data, 'little')
        
        if filetab_offset >= filetab_len:
            return f"<filetab_oob:{filetab_offset}/{filetab_len}>"
        
        # Read filename from filetab
        name_addr = filetab_ptr + filetab_offset
        filename = self._read_cstring(name_addr, 512)
        
        return filename if filename else "<empty>"
        
      except Exception as e:
        import traceback
        traceback.print_exc()
        return f"<error:{e}>"
    
    
    # =========================================================================
    # Main Generator - 
    # =========================================================================
    def _generator(self) -> Generator[Tuple[int, Tuple], None, None]:
     try: 
      """Main plugin generator."""
      kernel = self.context.modules[self.config["kernel"]]
      # Create ELF type definitions
      elf_table_name = intermed.IntermediateSymbolTable.create(self.context, self.config_path, "linux",  "elf",class_types=elf.class_types,)
      # Get target processes
      filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
      tasks = pslist.PsList.list_tasks( self.context, self.config["kernel"],filter_func=filter_func,)
      for task in tasks:
        pid = int(task.pid)
        comm = objects.utility.array_to_string(task.comm)

        # ================================
        # Get process memory layer
        try:
            self.layer_name = task.add_process_layer()
        except:
            print(f"[!] Cannot add process layer for PID {pid}")
            continue
        # Find ELF base
        try:
             vma_iter = task.mm.get_vma_iter()
        except:
            print(f"[!] Cannot iterate VMAs for PID {pid}")
            continue

        elf_base = None
        for vma in vma_iter:
            base = vma.vm_start
            try:
                layer = self.context.layers[self.layer_name]
                magic = layer.read(base, 4, pad=True)
                if magic == b"\x7fELF":
                    elf_base = base
                    break
            except:
                continue

        if not elf_base:
            print(f"[!] No ELF found for PID {pid}")
            continue

        
        
        print(f"[+] Found ELF at {hex(elf_base)}")
        # Parse ELF
        header_info = self._parse_elf_header(elf_table_name, elf_base)
        if not header_info.get("valid"):
            print(f"[!] Invalid ELF header")
            continue
       
       
        
     
       
        segments = self._parse_program_headers(elf_table_name, header_info)
        self.go_version_str = self._extract_go_version(segments)
        self.go_version_tuple = self._parse_go_version(self.go_version_str)
        # ==============================
        print(f"-"*100)
        print(f"[+] Get the cached ELF FIle")
        binary_path = self._get_binary_path_from_task(task)
        cached_func_names = {}
        cached_filenames = {}  
        if binary_path:
           cached_inode = self._find_inode_by_path(binary_path)
           if cached_inode:
              print(f"[+] File is cached in memory")
              # Extract ELF bytes
              elf_bytes = self._extract_elf_from_pagecache(cached_inode)
              if elf_bytes and len(elf_bytes) >= 64:
                  print(f"[+] Valid ELF extracted")
                  cached_sections = self._parse_cached_elf_sections(elf_bytes)
                  cached_func_names,cached_filenames = self._build_funcname_cache_from_elf(elf_bytes, elf_base, cached_sections)
              else:
                  cached_func_names = {}
                  cached_filenames = {}    
           else:
               print(f"[!] File not in page cache")
               elf_bytes = None
        else:
           elf_bytes = None
        
        print(f"[+] Got {len(cached_func_names)} cached function names")
        print(f"-"*100)
        # Find pclntab
        pclntab = self._find_pclntab(segments)
        if not pclntab:
            print(f"[!] pclntab not found - not a Go binary?")
            continue

        self.pclntab = pclntab 
        # Infer Go version from pclntab if RODATA scan failed (Garble'd binary)
        if self.go_version_str == "unknown" or self.go_version_tuple == (0, 0, 0):
            pclntab_version = pclntab.get('version', '')
            print(f"[*] pclntab version hint: {pclntab_version}")
            if any(v in pclntab_version for v in ['1.20', '1.21', '1.22', '1.23', '1.24', '1.25']):
                self.go_version_tuple = (1, 20, 0)
                self.go_version_str = "go1.20.0 (inferred from pclntab)"
            elif any(v in pclntab_version for v in ['1.18', '1.19']):
                self.go_version_tuple = (1, 18, 0)
                self.go_version_str = "go1.18.0 (inferred)"
            elif any(v in pclntab_version for v in ['1.16', '1.17']):
                self.go_version_tuple = (1, 16, 0)
                self.go_version_str = "go1.16.0 (inferred)"
            else:
                self.go_version_tuple = (1, 20, 0)
                self.go_version_str = "go1.20.0 (default)"
            print(f"[*] Inferred Go version: {self.go_version_str}")
            
             
        # Find moduledata
        moduledata = self._find_moduledata(segments, pclntab["address"], pclntab["ptrSize"], self.go_version_str)
        if not moduledata:
            print(f"[!] moduledata not found")
            continue
        
        # Set instance variables for type parsing
        self.moduledata = moduledata
        self.types_start = moduledata['types']
        print(f"typelinks: ptr={hex(moduledata['typelinks']['ptr'])}, len={moduledata['typelinks']['len']}")
        print(f"types section: {hex(moduledata['types'])}-{hex(moduledata['etypes'])}")
        print("\n" + "=" * 170)
        print(f"GO RUNTIME INFORMATION")
        print("=" * 170)
        print(f"PID: {pid}")
        print(f"COMM: {comm}")
        print(f"[*] Go version detected: {self.go_version_str}")
        print(f"Functions: {pclntab['nfunc']}")
        print("=" * 170)
        
        # Extract all types and interface tables (itabs).
        types_dict = self._extract_types_by_scanning(pclntab["ptrSize"])
        itabs_dict = self._extract_itabs(pclntab["ptrSize"])
        heap_addresses=self._load_heap_addresses()
        
        # Get the signatures of the type methods
        type_methods={}
        for type_addr,type_info in sorted(types_dict.items()):
            if type_info is None or type_info.get('_parsing'):
                continue
            name  = type_info['name']
            kind = type_info['kind']
            kind_str= type_info['kind_str']
            has_uncommon =type_info['has_uncommon']

            if has_uncommon:
               uncommon_methods  = type_info.get('methods', []) 
               if uncommon_methods : 
                  for method in uncommon_methods :
                      method_name = method.get('name', '<unnamed>')
                      method_pkg = method.get('pkgpath', '<unnamed>')
                      method_ifn_pc = method.get('ifn_pc')
                      method_tfn_pc = method.get('tfn_pc')
                      method_pc = method.get('pc')
                      method_class = method.get('class', 'None')
                      method_signature = method.get('signature')
                      if method_signature: 
                         functype_addr= method_signature.get('functype_addr', 0)
                         inCount = method_signature.get('inCount', 0)
                         outCount = method_signature.get('outCount', 0)
                         param_types = method_signature.get('param_types', [])
                         return_types = method_signature.get('return_types', [])
                         processed_param_types ={}
                         processed_return_types ={}
                         receiver_type_info = types_dict.get(type_addr)
                         if receiver_type_info:
                            ptrToThis_offset = receiver_type_info.get('ptrToThis', 0)
                            if ptrToThis_offset > 0:  # Positive offset
                               ptr_type_addr = self.types_start + ptrToThis_offset
                            else:
                               # ptrToThis not available, use the type_addr itself
                               # The receiver IS the pointer type (e.g., *xgb.Conn is already a pointer)
                               ptr_type_addr = type_addr
                         else:
                               ptr_type_addr = type_addr 
                        
                         if receiver_type_info:
                            processed_param_types[0] = {'param_name': f'*{name}' if not name.startswith('*') else name,   'param_type': 'pointer', 
                            'param_size': 8, 'type_ptr': ptr_type_addr}
    
                         for param in param_types:
                              param_idx = param.get('index', 0)
                              param_type_ptr = param.get('type_ptr', 0)
                              if param_type_ptr and param_type_ptr in types_dict:
                                 param_info = types_dict[param_type_ptr]
                                 param_kind = param_info.get('kind_str', None)
                                      
                                
                                 # If it's a pointer, get what it points to
                                 if param_kind == 'pointer':
                                    param_name = param_info.get('name', None)  # e.g., "*uint32"
                                    param_type = 'pointer'
                                    param_size = 8  # Pointers are always 8 bytes on 64-bit
                                 else:
                                    # Not a pointer, use directly
                                    param_name = param_info.get('name', None)
                                    param_type = param_kind
                                    param_size = param_info.get('size', 0)
                                 processed_param_types[param_idx+1] = { 'param_name': param_name,'param_type': param_type,
                                 'param_size': param_size,'type_ptr': param_type_ptr }
                         
                         for ret  in return_types:
                              ret_idx = ret .get('index', 0)
                              ret_type_ptr = ret.get('type_ptr', 0)
                              if ret_type_ptr and ret_type_ptr in types_dict:
                                 ret_info= types_dict[ret_type_ptr]
                                 ret_name = ret_info.get('name', None)
                                 ret_type = ret_info.get('kind_str', None)
                                 ret_size= ret_info.get('size', 0)
                                 #print(f"          -> Return {ret_idx}, ret_name: {ret_name}, ret_type: {ret_type}, ret_size: {ret_size}")
                                 processed_return_types[ret_idx] = {'ret_name': ret_name, 'ret_type': ret_type, 'ret_size': ret_size}  

                         actual_inCount = len(processed_param_types)
                         if method_ifn_pc:
                            type_methods[method_ifn_pc] = {'name': method_name,'pkg': method_pkg, 'inCount': actual_inCount, 
                            'outCount': outCount, 'param_types': processed_param_types, 'return_types': processed_return_types}
                         elif method_tfn_pc:     
                            type_methods[method_tfn_pc]= {'name': method_name,'pkg': method_pkg, 'inCount': actual_inCount, 
                            'outCount': outCount, 'param_types': processed_param_types, 'return_types': processed_return_types}
        
        
        print(f"Total Interface Tables: {len(itabs_dict)}")
        print(f"Total Type Methods: {len(type_methods)}")
        
        for itab_addr, itab_info in sorted(itabs_dict.items()):
          interface_name = itab_info['interface_name']
          concrete_type = itab_info['concrete_type_name']
          method_count = itab_info['method_count']
          hash_val = itab_info['hash']
          inter_ptr = itab_info['inter_ptr']
          type_ptr = itab_info['type_ptr']
        
          if type_ptr in types_dict: 
             type_info = types_dict[type_ptr]
             if type_info is None or type_info.get('_parsing'):
                continue
             name  = type_info['name']
             kind = type_info['kind']
             kind_str= type_info['kind_str']
          
             
        type_counts = {}
        for type_info in types_dict.values():
            kind_str = type_info['kind_str']
            type_counts[kind_str] = type_counts.get(kind_str, 0) + 1
        print(f"Total Types: {len(types_dict)}")
        
          
      
        _func_functions = list(self._extract_functions(self.layer_name, pclntab, moduledata))
        print(f"Total Functions: {len(_func_functions)}")
        func_lookup = {}
        for func_info in _func_functions:
            func_lookup[func_info["pc"]] = func_info
            func_pc = func_info.get('pc', 0)
            func_name = func_info.get('name', '<unknown>')
            argsmap_data= func_info.get('argsmap_data')
            arginfo_data= func_info.get('arginfo_data')
          
        
        print(f"\n[+] Built function lookup with {len(func_lookup)} functions")
       
        # Get the goroutines. 
        allgs = self._find_allgs_via_scan(self.layer_name, segments, pclntab["ptrSize"])
        if not allgs:
           print("ERROR: runtime.allgs not found")
           continue
      
     
        print(f"Found runtime.allgs at {hex(allgs['address'])}, {allgs['len']} goroutines") 
        
        print(f"\n{'='*80}")
        print("GOROUTINES WITH STACK TRACES")
        print(f"{'='*80}")
        if allgs:     
           layer = self.context.layers[self.layer_name]
           ptrSize = pclntab["ptrSize"]
           array_data = layer.read(allgs["ptr"], allgs["len"] * ptrSize, pad=True)
           
           #PHASE 1: Pre-scan all goroutine stacks to extract type method arguments before the main stack_trace display pass.
           self._cache_type_method_arguments(allgs,ptrSize, array_data,  types_dict,itabs_dict, _func_functions, type_methods,func_lookup,cached_func_names)
          
           #PHASE 2: Walk every live goroutine's stack and extract argument values from each frame using the best available type information.
           self.stack_trace(allgs,pclntab,_func_functions, func_lookup,type_methods,itabs_dict,types_dict, cached_func_names,cached_filenames, heap_addresses)
           
      

      
     except Exception as e:
        print(f"\n[FATAL ERROR] Plugin crashed: {e}")
        import traceback
        traceback.print_exc()
     return
     yield


  
    
    
    def run(self) -> renderers.TreeGrid:
        return renderers.TreeGrid(
            [("Result", str)],
            self._generator(),
        )


