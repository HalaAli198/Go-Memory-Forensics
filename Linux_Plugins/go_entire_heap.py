"""
go_entire_heap: type-driven recovery of all Go runtime heap objects from process memory.

This Volatility 3 plugin reconstructs typed heap objects from the memory
image of a running Go (golang) process on Linux.  Rather than scanning
flat bytes for printable sequences, it walks the Go runtime's own type
metadata and heap allocator structures, recovering booleans, integers,
floats, strings, slices, arrays, structs, maps, and interfaces with
their concrete values and memory locations.

Per target process the plugin:

  1. Locates the in-memory ELF image and parses its section table.
  2. Detects the Go toolchain version from the rodata section.
  3. Finds pclntab (via pcHeader magic, with a structural fallback for
     Garble-obfuscated binaries) and moduledata (via a pointer back to
     pclntab), exposing the text, rodata, data, bss, and types sections.
  4. Parses all reachable type metadata by scanning the types section
     (structs, slices, arrays, maps, interfaces, functions, pointers)
     and extracts interface tables (itabs) via moduledata.itablink.
  5. Locates mheap_ through its allspans slice, enumerates in-use spans,
     and recovers allocated objects from each span via the allocBits
     bitmap.
  6. Performs a type-driven recursive walk over heap objects, matching
     allocation sizes to candidate types and extracting values for all
     Go kinds, including nested strings inside structs, map key/value
     pairs (hmap buckets for Go <1.24, Swiss Tables for Go 1.24+), and
     interface concrete values.
  7. Outputs all recovered objects with heap address, data address, type,
     value, and memory region classification to a per-PID JSON file.

Usage:

    python3 vol.py -f <image> linux.go_entire_heap.Go_Entire_Heap --pid <PID>
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
import re
import json
import os
import pandas as pd


vollog = logging.getLogger(__name__)



class Go_Entire_Heap(interfaces.plugins.PluginInterface):
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
    
    MSPAN_OFFSETS = {
        'next': 0x00,               # *mspan
        'prev': 0x08,               # *mspan
        'list': 0x10,               # *mSpanList
        'startAddr': 0x18,          # uintptr - START ADDRESS
        'npages': 0x20,             # uintptr - NUMBER OF PAGES
        'manualFreeList': 0x28,     # gclinkptr
        'freeindex': 0x30,          # uint16
        'nelems': 0x32,             # uint16 - NUMBER OF ELEMENTS
        'freeIndexForScan': 0x34,   # uint16
        'scanIdx': 0x36,            # uint16
        'allocCache': 0x38,         # uint64
        'allocBits': 0x40,          # *gcBits - ALLOCATION BITMAP
        'gcmarkBits': 0x48,         # *gcBits
        'pinnerBits': 0x50,         # *gcBits
        'sweepgen': 0x58,           # uint32
        'divMul': 0x5C,             # uint32
        'allocCount': 0x60,         # uint16
        'spanclass': 0x62,          # uint8 (spanClass)
        'state': 0x63,              # uint8 (mSpanStateBox)
        'needzero': 0x64,           # uint8
        'isUserArenaChunk': 0x65,   # bool
        'allocCountBeforeCache': 0x66, # uint16
        'elemsize': 0x68,           # uintptr - ELEMENT SIZE
        'limit': 0x70,              # uintptr
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
    MSPAN_PROFILES = {
        'go1.18-1.20': {
            'name': 'Go 1.18-1.20', 'startAddr': 0x18, 'npages': 0x20,
            'nelems_offset': 0x38, 'nelems_size': 8, 'allocBits': 0x48,
            'sweepgen': 0x58, 'allocCount': 0x60, 'spanclass': 0x62,
            'state': 0x63, 'elemsize': 0x68,
        },
        'go1.21-1.23': {
            'name': 'Go 1.21-1.23', 'startAddr': 0x18, 'npages': 0x20,
            'nelems_offset': 0x38, 'nelems_size': 8, 'allocBits': 0x48,
            'sweepgen': 0x60, 'allocCount': 0x68, 'spanclass': 0x6A,
            'state': 0x6B, 'elemsize': 0x70,
        },
        'go1.24+': {
            'name': 'Go 1.24+', 'startAddr': 0x18, 'npages': 0x20,
            'nelems_offset': 0x32, 'nelems_size': 2, 'allocBits': 0x40,
            'sweepgen': 0x58, 'allocCount': 0x60, 'spanclass': 0x62,
            'state': 0x63, 'elemsize': 0x68,
        },
    }
    # mheap offsets - approximate, varies by Go version
    # These are estimated based on field sizes in the source
    MHEAP_OFFSETS_GO_120 = {
        'lock': 0x00,               # mutex (16 bytes)
        'pages': 0x10,              # pageAlloc (~144 bytes)
        'sweepgen': 0x90,           # uint32 (after pages)
        'allspans': 0xa8,           # []*mspan - SLICE (24 bytes)
        # Note: Exact offset needs empirical verification
    }
    
    MHEAP_OFFSETS_GO_118 = {
        'allspans': 0xa0,           # Slightly different layout
    }
    
    MHEAP_OFFSETS_GO_116 = {
        'allspans': 0x98,           # Older layout
    }
    
    MHEAP_OFFSETS_GO_123 = {
    'lock': 0x00,
    'pages': 0x10,
    'sweepgen': None,  # Will scan for it
    'allspans': None,  # Will scan for it
    }

    MHEAP_OFFSETS_GO_120 = {
    'allspans': 0xe8,  # Approximate
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
        self.go_version_str = "unknown"     
        self.go_version_tuple = (0, 0, 0)
        self.heap_spans: List[Dict] = []
        self.objects_found = {}
        self.mspan_profile: Optional[str] = None
    # =========================================================================
    # Helper Methods
    # =========================================================================

    def _decode_e_type(self, e_type: int) -> str:
        """Decode ELF type."""
        types = {
            self.ET_NONE: "ET_NONE",
            self.ET_REL: "ET_REL",
            self.ET_EXEC: "ET_EXEC",
            self.ET_DYN: "ET_DYN",
            self.ET_CORE: "ET_CORE",
        }
        return types.get(e_type, f"Unknown({e_type})")

    
    
    
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
        """Parse all program headers (segments)."""
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
    # Go Runtime Structure Discovery (pclntab + moduledata)
    # =========================================================================

    def _find_pclntab(self, segments: List[Dict]) -> Optional[Dict]:
        """Find Go pclntab - tries magic bytes first, then structural detection for Garble'd binaries."""
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

        """Find moduledata by scanning RW segment for pointer to pclntab."""
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

                    result = self._validate_moduledata(candidate_addr, pclntab_addr, ptrSize, go_version,segments)
                    if result:
                        return result

                    pos += ptrSize

                current += chunk_size - ptrSize

            except:
                current += chunk_size

        return None
    
    
    def _validate_moduledata(self, address: int, pclntab_addr: int, ptrSize: int, go_version: str, segments: List[Dict]) -> Optional[Dict]:
      """Validate a potential moduledata structure."""
      """
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
        is_go_116_117= (major == 1 and minor >= 16 and minor <18) 
        is_go_115_116= (major == 1 and minor >= 15 and minor <16) 
        is_go_118_plus = (major == 1 and minor >= 18) 
        is_go_120_plus= (major == 1 and minor >= 20)
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
                'pctab': slices['pctab'],
                'pclntable': slices['pclntable'],
                'ftab': slices['ftab'],
                'minpc': minpc,
                'maxpc': maxpc,
                'text': text,
                'etext': etext,
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
       
        # moduledata has no erodata field so we derive it from segments
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
        print(f"\n ========== SLICE POINTER ANALYSIS ==========")
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
        print("Types and RODATA overlapping is NORMAL:In Go binaries, the types section is embedded within the RODATA segment. This is by design.")
        print(f"  rodata: {hex(rodata)}")
        print(f"  erodata: {hex(erodata)}")  
        print("-------------------")
        print(f"  data: {hex(data_start )}")
        print(f"  edata: {hex(edata)}")
        print("-------------------")
        print(f"  gofunc: {hex(gofunc)}")

        # In Go 1.16-1.17, slice pointers are OFFSETS, not addresses
        if not is_go_118_plus:
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
            'pctab': slices['pctab'],
            'pclntable': slices['pclntable'],
            'ftab': slices['ftab'],
            'minpc': minpc,
            'maxpc': maxpc,
            'text': text,
            'etext': etext,
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
    
    
    def _extract_itabs(self, ptrSize: int) -> Dict[int, Dict]:
      """Extract all itabs via moduledata.itablink."""
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
        
        if not (types_start <= type_ptr < etypes):
            print(f"type_ptr not in [types_start,etypes]")
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
    
    
    
    def _extract_types_via_typelinks(self, ptrSize: int) -> Dict[int, Dict]:
        typelinks_ptr = self.moduledata['typelinks']['ptr']
        typelinks_len = self.moduledata['typelinks']['len']
        layer = self.context.layers[self.layer_name]
        typelinks_data = layer.read(typelinks_ptr, typelinks_len * 4, pad=True)
        for i in range(typelinks_len):
            offset = int.from_bytes(typelinks_data[i*4:(i+1)*4], 'little', signed=True)
            type_addr = self.types_start + offset
            self._parse_single_type(type_addr, ptrSize)  # Stores in self.types_cache\
        return self.types_cache.copy()

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
        pkgpath = ""
        if pkgpath_offset != 0 and pkgpath_offset != -1:
           pkgpath = self._resolve_name(pkgpath_offset)
            
        if mcount == 0:
            return []
            
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
                        except Exception:
                            pass
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
    
    
    
    
    
    # =========================================================================
    # Find the globa Variable (mheap)
    # =========================================================================
     
    def _find_mheap_global(self, sections: List[Dict]) -> Optional[Dict]:
      """
      Find mheap_ by scanning for the allspans slice directly.
    
      The allspans field is a slice: {ptr, len, cap} where:
      - ptr points to an array of *mspan pointers
      - Each mspan pointer points to a valid mspan structure
      """
      layer = self.context.layers[self.layer_name]
    
      # Determine scan regions (data + bss)
      scan_regions = []
    
      if self.moduledata:
        if self.moduledata.get('data_start') and self.moduledata.get('edata'):
            scan_regions.append(('data', self.moduledata['data_start'], self.moduledata['edata']))
        if self.moduledata.get('bss') and self.moduledata.get('ebss'):
            scan_regions.append(('bss', self.moduledata['bss'], self.moduledata['ebss']))
    
      # Fallback to sections
      if not scan_regions:
        for sect in sections:
            if sect["name"] in [".data", ".bss"] or sect["p_flags_str"] == "RW-":
                scan_regions.append((sect["name"], sect["runtime_vaddr"], sect["runtime_end"]))
    
      print(f"\n[*] Searching for allspans slice in {len(scan_regions)} regions...")
    
      for region_name, start, end in scan_regions:
        print(f"[*] Scanning {region_name}: {hex(start)}-{hex(end)}")
        result = self._scan_for_allspans_slice(start, end, layer)
        if result:
            return result
    
      return None

   
    
    def _scan_for_allspans_slice(self, start: int, end: int, layer) -> Optional[Dict]:
      """
      Scan for a valid allspans slice pattern.
      """
      chunk_size = 0x10000
      current = start
      candidates_found = 0
    
      print(f"Scanning range: {hex(start)} - {hex(end)}")
    
      while current < end:
        try:
            read_size = min(chunk_size, end - current)
            data = layer.read(current, read_size, pad=True)
            
            for offset in range(0, len(data) - 24, 8):
                slice_ptr = int.from_bytes(data[offset:offset+8], 'little')
                slice_len = int.from_bytes(data[offset+8:offset+16], 'little')
                slice_cap = int.from_bytes(data[offset+16:offset+24], 'little')
                
                # Quick validation
                if slice_ptr == 0 or slice_ptr < 0x1000:
                    continue
                if slice_len == 0 or slice_cap == 0:
                    continue
                if slice_len > slice_cap:
                    continue
                if slice_cap > 50000:
                    continue
                if slice_len > 10000:
                    continue
                if slice_ptr % 8 != 0:
                    continue
                
                candidate_addr = current + offset
                
                if self._validate_allspans_array(slice_ptr, slice_len, layer):
                    candidates_found += 1
                    # Only return if we have STRONG validation
                    if self._strong_validate_allspans(slice_ptr, slice_len, layer):
                        print(f"[+] CONFIRMED valid allspans at {hex(candidate_addr)}")
                        return {
                            'address': candidate_addr,
                            'allspans_offset': 0,
                            'allspans_ptr': slice_ptr,
                            'allspans_len': slice_len,
                            'allspans_cap': slice_cap,
                        }
            
            current += chunk_size - 24
            
        except Exception as e:
            print(f"Exception at {hex(current)}: {e}")
            current += chunk_size
    
      print(f"Total candidates found: {candidates_found}")
      return None


    def _debug_dump_span_pointers(self, array_ptr: int, count: int, layer):
      """Debug: dump the first N span pointers from the array."""
      try:
        print(f"Reading {count} span pointers from {hex(array_ptr)}:")
        array_data = layer.read(array_ptr, count * 8, pad=True)
        
        for i in range(count):
            span_ptr = int.from_bytes(array_data[i*8:(i+1)*8], 'little')
            print(f"    [{i}] span_ptr = {hex(span_ptr)}")
            
            if span_ptr != 0 and span_ptr > 0x1000:
                # Try to read mspan header
                try:
                    mspan_data = layer.read(span_ptr, 0x30, pad=True)
                    print(f"        mspan bytes: {mspan_data.hex()}")
                    
                    # Parse key fields
                    startAddr = int.from_bytes(mspan_data[0x18:0x20], 'little')
                    npages = int.from_bytes(mspan_data[0x20:0x28], 'little')
                    print(f"        startAddr={hex(startAddr)}, npages={npages}")
                except Exception as e:
                    print(f"        Cannot read mspan: {e}")
      except Exception as e:
        print(f"Error dumping span pointers: {e}")


    
    
    def _strong_validate_allspans(self, array_ptr: int, array_len: int, layer) -> bool:
      """
      Strong validation: actually read and parse span pointers.
      Require multiple valid mspan structures.
      """
      try:
        # The span pointers should be in the HEAP range (0xc0... on 64-bit)
        # OR in the data section for the mspan structs themselves
        
        check_count = min(array_len, 20)
        array_data = layer.read(array_ptr, check_count * 8, pad=True)
        
        valid_spans = 0
        heap_range_spans = 0
        
        for i in range(check_count):
            span_ptr = int.from_bytes(array_data[i*8:(i+1)*8], 'little')
            
            if span_ptr == 0:
                continue
            
            if span_ptr < 0x1000 or span_ptr % 8 != 0:
                continue
            
            # Check if span_ptr is in reasonable range
            # mspan structures are allocated from the heap or special arena
            
            try:
                mspan_data = layer.read(span_ptr, 0x80, pad=True)
                
                # Validate mspan fields
                startAddr = int.from_bytes(mspan_data[0x18:0x20], 'little')
                npages = int.from_bytes(mspan_data[0x20:0x28], 'little')
                
                # startAddr should be page-aligned (8KB = 0x2000)
                if startAddr % 0x2000 != 0:
                    continue
                
                # startAddr should be in Go heap range
                if 0xc000000000 <= startAddr < 0xd000000000:
                    heap_range_spans += 1
                
                # npages should be reasonable
                if npages == 0 or npages > 10000:
                    continue
                
                # Additional: check that startAddr + npages*8192 doesn't overflow
                span_size = npages * 8192
                if span_size > 0x10000000:  # 256MB max per span
                    continue
                
                valid_spans += 1
                
            except:
                continue

        # Require at least 3 valid spans with startAddr in heap range
        return valid_spans >= 3 and heap_range_spans >= 2
        
      except Exception as e:
        print(f"  [DEBUG] Validation error: {e}")
        return False
    
    def _validate_allspans_array(self, array_ptr: int, array_len: int, layer) -> bool:
      """
      Validate that array_ptr points to an array of valid mspan pointers.
    
      We check multiple entries to ensure this is really allspans.
      """
      try:
        # Read first N span pointers (check up to 10)
        check_count = min(array_len, 10)
        array_data = layer.read(array_ptr, check_count * 8, pad=True)
        
        valid_spans = 0
        null_spans = 0
        
        for i in range(check_count):
            span_ptr = int.from_bytes(array_data[i*8:(i+1)*8], 'little')
            
            if span_ptr == 0:
                null_spans += 1
                continue
            
            # Basic pointer validation
            if span_ptr < 0x1000:
                return False
            if span_ptr % 8 != 0:
                return False
            
            # Validate mspan structure
            if self._quick_validate_mspan(span_ptr, layer):
                valid_spans += 1
        
        # Require at least 3 valid spans (or all if less than 3)
        min_required = min(3, check_count - null_spans)
        return valid_spans >= min_required
        
      except Exception:
        return False


    
    def _quick_validate_mspan(self, span_ptr: int, layer) -> bool:
      """Quick validation - tries all profiles."""
      try:
        data = layer.read(span_ptr, 0x80, pad=True)
        
        for profile in self.MSPAN_PROFILES.values():
            if self._validate_span_with_profile(data, profile):
                return True
        
        return False
        
      except:
        return False
        
        
    def _scan_for_mheap(self, start: int, end: int, layer) -> Optional[Dict]:
      """Helper to scan a memory region for mheap_."""
      chunk_size = 0x10000
      current = start
    
      while current < end:
        try:
            data = layer.read(current, min(chunk_size, end - current), pad=True)
            
            for offset in range(0, len(data) - 0x200, 8):
                candidate = current + offset
                mheap_info = self._validate_and_parse_mheap(candidate)
                if mheap_info:
                    return mheap_info
            
            current += chunk_size - 8
        except:
            current += chunk_size
    
      return None
    
    
    
    
    
    
    def _validate_and_parse_mheap(self, addr: int) -> Optional[Dict]:
      """
      Validate if address points to mheap and return parsed info.
      Scans multiple possible allspans offsets for Go 1.23.
      https://go.dev/src/runtime/mheap.go
      """
      try:
        allspans_offset = 0x120
        
        try:
            # Read slice: ptr, len, cap
            allspans_ptr = self._read_pointer(addr + allspans_offset)
            allspans_len = self._read_pointer(addr + allspans_offset + 8)
            allspans_cap = self._read_pointer(addr + allspans_offset + 16)
            
            # Validation checks
            if allspans_len == 0 or allspans_len > allspans_cap:
                return None
            
            if allspans_cap > 100000 or allspans_cap < 2:
                return None
            
            if allspans_ptr < 0x10000:
                return None
            
            # Validate multiple spans
            valid_spans_count = 0
            
            for i in range(allspans_len):
                try:
                    span_ptr_addr = allspans_ptr + (i * 8)
                    span_ptr = self._read_pointer(span_ptr_addr)
                    
                    if span_ptr == 0:
                        continue
                    
                    if span_ptr < 0x10000 or span_ptr > 0x7fffffffffff:
                        continue
                    
                    is_valid = self._parse_mspan_for_validation(span_ptr)
                    if is_valid:
                        valid_spans_count += 1
                        if valid_spans_count >= 10:
                            break
                
                except:
                    continue
            
            # Need at least 10 valid spans
            if valid_spans_count < 10:
                return None
            
            # SUCCESS - only print the final result
            print(f"[+] Found valid mheap_ at {hex(addr)}")
            print(f"    allspans offset: {hex(allspans_offset)}")
            print(f"    allspans ptr: {hex(allspans_ptr)}")
            print(f"    allspans len: {allspans_len}, cap: {allspans_cap}")
            print(f"    Validated: {valid_spans_count} spans")
            
            return {
                'address': addr,
                'allspans_offset': allspans_offset,
                'allspans_ptr': allspans_ptr,
                'allspans_len': allspans_len,
                'allspans_cap': allspans_cap,
            }
        
        except:
            return None
    
      except:
        return None

    # =========================================================================
    # Parse the Heap Spans
    # =========================================================================
    def _parse_mspan_for_validation(self, span_addr: int) -> bool:
      """
      Quick validation during mheap scan.
      Uses Go 1.20+ offsets only (works for both versions during scan).
      Returns True if looks like a valid span, False otherwise.
      """
      try:
        startAddr = self._read_pointer(span_addr + 0x18)
        npages = self._read_pointer(span_addr + 0x20)
        state = self._read_uint8(span_addr + 0x63)
        
        # Quick checks only
        if state not in [0, 1, 2]:
            return False
        if startAddr == 0 or npages == 0 or npages > 10000:
            return False
        
       
        
        return True
      except:
        return False


   
    def _parse_mspan(self, span_addr: int, stats: Optional[Dict] = None) -> Optional[Dict]:
      """Parse a single mspan structure using detected profile."""
      if not self.mspan_profile:
        if stats: stats['invalid'] += 1
        return None
      profile = self.MSPAN_PROFILES[self.mspan_profile]
      try:
        layer = self.context.layers[self.layer_name]
        data = layer.read(span_addr, 0x80, pad=True)
        startAddr = int.from_bytes(data[0x18:0x20], 'little')
        npages = int.from_bytes(data[0x20:0x28], 'little')
        nelems_offset = profile['nelems_offset']
        nelems_size = profile['nelems_size']
        if nelems_size == 2:
            nelems = int.from_bytes(data[nelems_offset:nelems_offset+2], 'little')
        else:
            nelems = int.from_bytes(data[nelems_offset:nelems_offset+8], 'little')
        allocBits_ptr = int.from_bytes(data[profile['allocBits']:profile['allocBits']+8], 'little')
        allocCount = int.from_bytes(data[profile['allocCount']:profile['allocCount']+2], 'little')
        spanclass = data[profile['spanclass']]
        state = data[profile['state']]
        elemsize = int.from_bytes(data[profile['elemsize']:profile['elemsize']+8], 'little')
        if state == 0:
            if stats: stats['dead'] += 1
            return None
        if state == 2:
            if stats: stats['manual'] += 1
            return None
        if state != 1:
            if stats: stats['invalid'] += 1
            return None
        if startAddr == 0 or elemsize == 0:
            if stats: stats['invalid'] += 1
            return None
        if elemsize > 0x20000000:
            if stats: stats['invalid'] += 1
            return None
        if npages == 0 or npages > 10000:
            if stats: stats['invalid'] += 1
            return None
        if nelems == 0 and elemsize > 0:
            nelems = (npages * 8192) // elemsize
        if nelems > 100000:
            if stats: stats['invalid'] += 1
            return None
        return {
            'span_addr': span_addr, 'startAddr': startAddr, 'npages': npages,
            'nelems': nelems, 'elemsize': elemsize, 'allocBits_ptr': allocBits_ptr,
            'spanclass': spanclass, 'state': state, 'allocCount': allocCount,
        }
      except Exception as e:
        if stats: stats['invalid'] += 1
        return None
    

    # =========================================================================
    # Enumerate the Heap Spans
    # =========================================================================
    def _enumerate_spans(self, mheap_info: Dict) -> List[Dict]:
      """Enumerate all mspan structures from mheap."""
      layer = self.context.layers[self.layer_name]
      allspans_ptr = mheap_info['allspans_ptr']
      allspans_len = mheap_info['allspans_len']
      self.mspan_profile = self._detect_mspan_profile(allspans_ptr, allspans_len)
      if not self.mspan_profile:
        print("[!] Could not detect mspan profile, trying go1.24+ as default")
        self.mspan_profile = 'go1.24+'
     
      print(f"\n[+] Using mspan profile: {self.mspan_profile}")
      if self.go_version_str == "unknown":
         if self.mspan_profile == 'go1.24+':
            self.go_version_tuple = (1, 24, 0)
            self.go_version_str = "go1.24.0 (detected from mspan)"
         elif self.mspan_profile == 'go1.21-1.23':
            self.go_version_tuple = (1, 21, 0)
            self.go_version_str = "go1.21.0 (detected from mspan)"
         elif self.mspan_profile == 'go1.18-1.20':
            self.go_version_tuple = (1, 18, 0)
            self.go_version_str = "go1.18.0 (detected from mspan)"
         print(f"[+] Updated go_version_tuple to {self.go_version_tuple} based on mspan profile")
      else:
         print(f"[*] Keeping detected version {self.go_version_str}, not overriding from mspan profile")
      
      spans = []
      stats = {'total': allspans_len, 'null_ptr': 0, 'dead': 0, 'in_use': 0,
               'manual': 0, 'parse_error': 0, 'invalid': 0}
      print(f"\n[*] Enumerating {allspans_len} spans...")
      for i in range(allspans_len):
        span_ptr_addr = allspans_ptr + (i * 8)
        try:
            span_ptr = self._read_pointer(span_ptr_addr)
            if span_ptr == 0:
                stats['null_ptr'] += 1
                continue
            span_info = self._parse_mspan(span_ptr, stats)
            if span_info:
                spans.append(span_info)
                stats['in_use'] += 1
        except:
            stats['parse_error'] += 1
            continue
        if (i + 1) % 100 == 0:
            print(f"    Progress: {i+1}/{allspans_len} ({stats['in_use']} in-use)")
      print(f"\n[*] Span Statistics:")
      for k in ['total', 'null_ptr', 'in_use', 'dead', 'manual', 'parse_error', 'invalid']:
          label = {'total':'Total spans', 'null_ptr':'Null pointers', 'in_use':'In-use (state=1)',
                   'dead':'Dead (state=0)', 'manual':'Manual (state=2)',
                   'parse_error':'Parse errors', 'invalid':'Invalid'}[k]
          print(f"    {label+':':<22} {stats[k]}")
      return spans

    def _validate_span_with_profile(self, span_data: bytes, profile: Dict) -> bool:
      """Validate span data against a specific profile."""
      try:
        # Read common fields (always same offset)
        startAddr = int.from_bytes(span_data[0x18:0x20], 'little')
        npages = int.from_bytes(span_data[0x20:0x28], 'little')
        
        # Basic validation
        if startAddr == 0 or npages == 0:
            return False
        if startAddr % 0x2000 != 0:  # Page alignment
            return False
        if not (0xc000000000 <= startAddr < 0xd000000000):
            return False
        if npages > 10000:
            return False
        
        # Read profile-specific fields
        state_offset = profile['state']
        elemsize_offset = profile['elemsize']
        nelems_offset = profile['nelems_offset']
        nelems_size = profile['nelems_size']
        
        # Validate we have enough data
        max_offset = max(state_offset + 1, elemsize_offset + 8, nelems_offset + nelems_size)
        if len(span_data) < max_offset:
            return False
        
        state = span_data[state_offset]
        
        if state not in (0, 1, 2):
            return False
        
        elemsize = int.from_bytes(
            span_data[elemsize_offset:elemsize_offset+8], 'little'
        )
        
        if elemsize == 0 or elemsize > 0x8000000:  # 128MB max
            return False
        
        # Read nelems based on profile
        if nelems_size == 2:
            nelems = int.from_bytes(
                span_data[nelems_offset:nelems_offset+2], 'little'
            )
        else:
            nelems = int.from_bytes(
                span_data[nelems_offset:nelems_offset+8], 'little'
            )
        
        # Cross-validate: nelems should roughly equal (npages * 8192) / elemsize
        if elemsize > 0:
            expected_nelems = (npages * 8192) // elemsize
            
            # Go 1.24+ may have nelems == 0 (calculated on-the-fly)
            if nelems == 0:
                if nelems_size != 2:
                    return False
            elif nelems > expected_nelems * 2:
                return False
            elif nelems > 100000:
                return False
        
        return True
        
      except Exception:
        return False

    def _detect_mspan_profile(self, allspans_ptr: int, allspans_len: int) -> Optional[str]:
      """
      Auto-detect the correct mspan profile by trying each one on sample spans.
      Returns the profile key that produces the most valid parses.
      """
      layer = self.context.layers[self.layer_name]
    
      # Sample up to 20 spans for detection
      sample_count = min(allspans_len, 20)
    
      profile_scores = {key: 0 for key in self.MSPAN_PROFILES.keys()}
    
      # Read span pointers
      array_data = layer.read(allspans_ptr, sample_count * 8, pad=True)
    
      for i in range(sample_count):
        span_ptr = int.from_bytes(array_data[i*8:(i+1)*8], 'little')
        
        if span_ptr == 0 or span_ptr < 0x1000:
            continue
        
        try:
            span_data = layer.read(span_ptr, 0x80, pad=True)
        except:
            continue
        
        # Debug: Print first span's raw data
        if i == 0:
            print(f"\n First span @ {hex(span_ptr)}")
            print(f"Raw bytes [0x58:0x70]: {span_data[0x58:0x70].hex()}")
            print(f"Raw bytes [0x60:0x78]: {span_data[0x60:0x78].hex()}")
            print(f"Raw bytes [0x68:0x80]: {span_data[0x68:0x80].hex()}")
            
            for profile_key, profile in self.MSPAN_PROFILES.items():
                state = span_data[profile['state']]
                elemsize = int.from_bytes(span_data[profile['elemsize']:profile['elemsize']+8], 'little')
                
                if profile['nelems_size'] == 2:
                    nelems = int.from_bytes(span_data[profile['nelems_offset']:profile['nelems_offset']+2], 'little')
                else:
                    nelems = int.from_bytes(span_data[profile['nelems_offset']:profile['nelems_offset']+8], 'little')
                
                print(f"{profile_key}: state@0x{profile['state']:02x}={state}, "
                      f"elemsize@0x{profile['elemsize']:02x}={elemsize}, "
                      f"nelems@0x{profile['nelems_offset']:02x}={nelems}")
        
        # Test each profile
        for profile_key, profile in self.MSPAN_PROFILES.items():
            if self._validate_span_with_profile(span_data, profile):
                profile_scores[profile_key] += 1
    
      # Find best profile
      best_profile = max(profile_scores, key=profile_scores.get)
      best_score = profile_scores[best_profile]
    
      print(f"\n[*] Profile detection scores:")
      for key, score in profile_scores.items():
        marker = " <-- SELECTED" if key == best_profile else ""
        print(f"    {key}: {score}/{sample_count}{marker}")
    
      if best_score < 3:
        print(f"[!] Warning: Low confidence in profile detection (score={best_score})")
        return None
    
      return best_profile
      
    def _display_span_summary(self, spans: List[Dict]) -> None:
        """Display summary of spans grouped by element size."""
        print(f"\n{'='*80}")
        print(f"HEAP ANALYSIS")
        print(f"{'='*80}\n")
        
        # Group by element size
        size_groups = {}
        total_memory = 0
        
        for span in spans:
            elemsize = span['elemsize']
            nelems = span['nelems']
            memory = elemsize * nelems
            total_memory += memory
            
            if elemsize not in size_groups:
                size_groups[elemsize] = {
                    'count': 0,
                    'total_elems': 0,
                    'total_memory': 0
                }
            
            size_groups[elemsize]['count'] += 1
            size_groups[elemsize]['total_elems'] += nelems
            size_groups[elemsize]['total_memory'] += memory
        
        # Display grouped results
       # print(f"{'Element Size':<15} {'Spans':<10} {'Elements':<15} {'Memory':<15}")
       # print("-" * 60)
        
        for elemsize in sorted(size_groups.keys()):
            group = size_groups[elemsize]
            memory_mb = group['total_memory'] / (1024 * 1024)
            #print(f"{elemsize:<15} {group['count']:<10} {group['total_elems']:<15} {memory_mb:.2f} MB")
        
       # print("-" * 60)
        print(f"Total spans: {len(spans)}")
        print(f"Total heap memory: {total_memory / (1024 * 1024):.2f} MB")
        print()
    
   
    
   
    # =========================================================================
    # Extract  Objects from all the Spans
    # =========================================================================
      
    def _extract_all_objects(self, spans: List[Dict], max_spans: Optional[int] = None) -> List[Dict]:
      """
      Extract objects from all spans.
    
      Args:
        spans: List of parsed span structures
        max_spans: Optional limit on number of spans to process (for testing)
    
      Returns:
        List of all extracted objects
      """
      all_objects = []
    
      # Optionally limit number of spans (useful for initial testing)
      spans_to_process = spans[:max_spans] if max_spans else spans 
      for i, span in enumerate(spans_to_process):
        heap_objects = self._extract_objects_from_span(span)
        all_objects.extend(heap_objects)
      
    
      return all_objects
    
      
    # =========================================================================
    # Extract Span Objects 
    # =========================================================================
   
    def _extract_objects_from_span(self, span_info: Dict) -> List[Dict]:
      """Extract all allocated objects from a span using allocBits bitmap."""
      layer = self.context.layers[self.layer_name]
      heap_objects = []
    
      startAddr = span_info['startAddr']
      nelems = span_info['nelems']
      elemsize = span_info['elemsize']
      allocBits_ptr = span_info['allocBits_ptr']
      span_addr = span_info['span_addr']
      allocCount = span_info['allocCount']
      if allocBits_ptr == 0 or nelems == 0 or elemsize == 0:
        return heap_objects
    
      try:
        # Read allocation bitmap
        bitmap_size = (nelems + 7) // 8
        bitmap = layer.read(allocBits_ptr, bitmap_size, pad=True)
        # Count set bits in bitmap
        set_bits = sum(bin(b).count('1') for b in bitmap)
        
        # If bitmap is all zeros but allocCount > 0, use allocCount
        if set_bits == 0 and allocCount > 0:
            # Assume first allocCount objects are allocated
            for i in range(min(allocCount, nelems)):
                obj_addr = startAddr + (i * elemsize)
                
                try:
                    _ = layer.read(obj_addr, min(8, elemsize), pad=True)
                    heap_objects.append({
                        'address': obj_addr,
                        'size': elemsize,
                        'index': i,
                        'span_addr': span_addr,
                    })
                except:
                    pass
            
            return heap_objects
        
        # Normal path: use bitmap
        for i in range(nelems):
            byte_idx = i // 8
            bit_idx = i % 8
            
            if byte_idx < len(bitmap):
                is_allocated = (bitmap[byte_idx] >> bit_idx) & 1
                
                if is_allocated:
                    obj_addr = startAddr + (i * elemsize)
                    
                    try:
                        _ = layer.read(obj_addr, min(8, elemsize), pad=True)
                        heap_objects.append({
                            'address': obj_addr,
                            'size': elemsize,
                            'index': i,
                            'span_addr': span_addr,
                        })
                    except:
                        pass
        
        return heap_objects
    
      except Exception as e:
        vollog.debug(f"Error extracting objects from span {hex(span_addr)}: {e}")
        return []
    
    
    
    # =========================================================================
    # Display Span Objects Statistics
    # =========================================================================
    
    def _display_object_summary(self, heap_objects: List[Dict]) -> None:
      """Display summary of extracted objects."""
      print(f"\n{'='*80}")
      print(f"HEAP OBJECT SUMMARY")
      print(f"{'='*80}\n")
    
      if not heap_objects:
        print("[!] No heap_objects found")
        return
    
      # Group by size
      size_groups = {}
    
      for obj in heap_objects:
        size = obj['size']
        if size not in size_groups:
            size_groups[size] = {
                'count': 0,
                'total_memory': 0,
                'sample_addresses': [],
            }
        
        size_groups[size]['count'] += 1
        size_groups[size]['total_memory'] += size
        
        # Keep first 3 sample addresses
        if len(size_groups[size]['sample_addresses']) < 3:
            size_groups[size]['sample_addresses'].append(obj['address'])
    
      # Display results
      for size in sorted(size_groups.keys()):
        group = size_groups[size]
        memory_kb = group['total_memory'] / 1024
        
        # Format sample addresses
        samples = ", ".join(hex(addr) for addr in group['sample_addresses'][:3])
      total_memory = sum(obj['size'] for obj in heap_objects)
      print(f"Total heap_objects: {len(heap_objects)}")
      print(f"Total memory: {total_memory / 1024:.2f} KB ({total_memory / (1024*1024):.2f} MB)")
      print()
   
   
    def heap_objects_extraction(self, heap_objects: List, types_dict: Dict, itabs_dict: Dict) -> List[Dict]:
      """
      Extract strings from heap objects using recursive type-driven approach.
    
      Handles:
      - Direct strings (string)
      - Pointers to strings (*string)
      - Slices of strings ([]string)
      - Arrays of strings ([N]string)
      - Structs containing strings
      - Pointers to structs (*SomeStruct)
      - Slices of structs ([]SomeStruct)
      - Maps with string keys/values
      - Nested combinations of all above
      """
      layer = self.context.layers[self.layer_name]
     
      
      visited_addrs = set()     # Avoid infinite recursion (cycles)
    
      # Configuration
      MAX_RECURSION_DEPTH = 1
      MAX_SLICE_LENGTH = 10000
      MAX_ARRAY_LENGTH = 1000
      MAX_STRING_LENGTH = 100000
    
      # =================================================================
      # Step 1: Pre-compute which types can contain strings
      # =================================================================
      types_with_primitive = self._find_types_containing_primitive(types_dict)
      print(f"[*] Found {len(types_with_primitive)} types that can contain strings")
    
      # =================================================================
      # Step 2: Build map types dictionary for map extraction
      # =================================================================
      map_types = self._build_map_types_dict(types_dict)
      print(f"[*] Found {len(map_types)} map types")
    
      # =================================================================
      # Step 3: Build size-to-types mapping for heap object identification
      # =================================================================
      size_to_types = {}  # {size: [type_info, ...]}
      for addr, info in types_dict.items():
        type_size = info.get('size', 0)
        if type_size > 0:
            if type_size not in size_to_types:
                size_to_types[type_size] = []
            size_to_types[type_size].append(info)
    
      print(f"[*] Mapped {len(size_to_types)} unique sizes to string-containing types")
    
      # =================================================================
      # Helper: Recursive string extraction
      # =================================================================
      def extract_objects_recursive(address: int, type_info: Dict, depth: int = 0, context: str = "root") -> None:
        """
        Recursively extract strings from an address based on type information.
        """
       
        nonlocal  visited_addrs
        layer = self.context.layers[self.layer_name]
        # Depth check
        if depth > MAX_RECURSION_DEPTH:
            return
        
        # Cycle detection
        cache_key = (address, type_info.get('address', id(type_info)))
        if cache_key in visited_addrs:
            return
        visited_addrs.add(cache_key)
        
        # Validate address
        if address == 0 or address < 0x1000:
            return
        
        kind = type_info.get('kind', 0)
        size = type_info.get('size', 0)
        kind_str = type_info.get('kind_str', 0)
        # =============================================================
        # KIND 1: Bool
        # =============================================================
        if kind == 1:
           bool_data = layer.read(address, 1, pad=True)
           bool_val = bool(bool_data[0]) 
           self.objects_found[address]= { 'struct_addr': address,'data_addr': address,'type': kind_str, 'length': size,'value': bool_val, 'context':bool_val, 'struct_location': 'heap',
                'data_location': 'heap', 'depth': depth }
           return bool_val
        
        # =============================================================
        #  Signed integers
        # =============================================================
        elif kind in  [2, 3, 4, 5, 6]:
           if size in [1, 2, 4, 8]:
                int_data = layer.read(address, size, pad=True)
                int_val = int.from_bytes(int_data, 'little', signed=True)
                self.objects_found[address]={
                'struct_addr': address,'data_addr': address,'type': kind_str, 'length': size,'value': int_val, 'context':int_val, 'struct_location': 'heap',
                'data_location': 'heap', 'depth': depth }
                return int_val 
         
        # =============================================================
        # # Unsigned integers
        # =============================================================
        elif kind in [7, 8, 9, 10, 11, 12]: 
           if size in [1, 2, 4, 8]:
              int_data = layer.read(address, size, pad=True)
              int_val= int.from_bytes(int_data, 'little', signed=False)
              self.objects_found[address]={
                'struct_addr': address,'data_addr': address, 'type': kind_str,'length': size,'value': int_val, 'context':int_val, 'struct_location': 'heap',
                'data_location': 'heap', 'depth': depth }
              return int_val
        
        # =============================================================
        #  Float
        # =============================================================
        elif kind in [13, 14, 15, 16]:
            import struct as pystruct
            if kind == 13:  # float32
               float_data = layer.read(address, 4, pad=True)
               float_val = pystruct.unpack('<f', float_data)[0]
               self.objects_found[address]={
                'struct_addr': address,'data_addr': address, 'type': kind_str, 'length': size,'value': float_val, 'context':float_val, 'struct_location': 'heap',
                'data_location': 'heap', 'depth': depth }
               return  float_val
            
            elif kind == 14:  # float64
                float_data = layer.read(address, 8, pad=True)
                float_val = pystruct.unpack('<d', float_data)[0]
                self.objects_found[address]={
                'struct_addr': address,'data_addr': address,'type': kind_str, 'length': size,'value': float_val, 'context':float_val, 'struct_location': 'heap',
                'data_location': 'heap', 'depth': depth }
                return  float_val
            
            elif kind == 15:  # complex64 (2x float32)
                complex_data = layer.read(address, 8, pad=True)
                real = pystruct.unpack('<f', complex_data[0:4])[0]
                imag = pystruct.unpack('<f', complex_data[4:8])[0]
                complex_val = complex(real, imag)
                self.objects_found[address]={
                'struct_addr': address,'data_addr': address,'type': kind_str, 'length': size,'value': complex_val, 'context':complex_val, 'struct_location': 'heap',
                'data_location': 'heap', 'depth': depth }
                return complex_val
            
            elif kind == 16:  # complex128 (2x float64)
                complex_data = layer.read(address, 16, pad=True)
                real = pystruct.unpack('<d', complex_data[0:8])[0]
                imag = pystruct.unpack('<d', complex_data[8:16])[0]
                complex_val = complex(real, imag)
                self.objects_found[address]={
                'struct_addr': address,'data_addr': address,'type': kind_str, 'length': size,'value': complex_val, 'context':complex_val, 'struct_location': 'heap',
                'data_location': 'heap', 'depth': depth }
               
                return complex_val
        
            
        # =============================================================
        # KIND 24: String
        # =============================================================
        elif kind == 24:
            string_value= extract_string_at_address(address, context, depth, kind_str)
            return string_value
        
        # =============================================================
        # KIND 22: Pointer
        # =============================================================
        elif kind == 22:
            try:
                ptr = self._read_pointer(address)
                if ptr == 0 or ptr < 0x1000:
                    return
                
                # Validate pointer is in valid memory region
                if not self._is_valid_data_pointer(ptr):
                    return
               
                # Get element type
                elem_type_ptr = type_info.get('elem_type_ptr', 0)
                if elem_type_ptr and elem_type_ptr in types_dict:
                    elem_type = types_dict[elem_type_ptr]
                    value= extract_objects_recursive(ptr, elem_type, depth + 1, f"{context}->ptr")
                    if value is not None:
                         self.objects_found[address]={'struct_addr': address,'data_addr': address, 'type': kind_str, 'length': 8 ,'value': value, 'context':'Poiinter',
                        'struct_location': 'heap(pointer)','data_location': 'heap', 'depth': depth}
                         return value
                 
            except:
                pass
            return None
        
        # =============================================================
        # KIND 23: Slice
        # =============================================================
        elif kind == 23:
            elements=[]
            try:
                # Read slice header: {data_ptr, len, cap}
                header = layer.read(address, 24, pad=True)
                data_ptr = int.from_bytes(header[0:8], 'little')
                slice_len = int.from_bytes(header[8:16], 'little')
                slice_cap = int.from_bytes(header[16:24], 'little')
                
                # Validate
                if data_ptr == 0 or slice_len == 0:
                    return
                if slice_len > slice_cap or slice_cap > MAX_SLICE_LENGTH:
                    return
                if not self._is_valid_data_pointer(data_ptr):
                    return
                
                # Get element type
                elem_type_ptr = type_info.get('elem_type_ptr', 0)
                if not elem_type_ptr or elem_type_ptr not in types_dict:
                    return
                
                elem_type = types_dict[elem_type_ptr]
                elem_size = elem_type.get('size', 0)
                
                if elem_size == 0:
                    return
              
                total_element_size=0
                # Iterate through slice elements
                for i in range(min(slice_len, MAX_SLICE_LENGTH)):
                    elem_addr = data_ptr + (i * elem_size)
                    element_value= extract_objects_recursive(elem_addr, elem_type, depth + 1, f"{context}[{i}]")
                    elements.append(element_value)
                    total_element_size+=elem_size    
               
                if slice_len > 0:
                   self.objects_found[address]={'struct_addr': address,'data_addr': data_ptr, 'type': kind_str, 'length': total_element_size ,'value': elements,
                   'context':'Slice', 'struct_location': 'heap(slice)','data_location': 'heap', 'depth': depth}
            except:
                pass
            return elements if elements else None
        
        # =============================================================
        # KIND 17: Array
        # =============================================================
        elif kind == 17:
            elements=[]
            try:
                array_length = type_info.get('length', 0)
                if array_length == 0 or array_length > MAX_ARRAY_LENGTH:
                    return
                
                # Get element type
                elem_type_ptr = type_info.get('elem_type_ptr', 0)
                if not elem_type_ptr or elem_type_ptr not in types_dict:
                    return
                
                elem_type = types_dict[elem_type_ptr]
                elem_size = elem_type.get('size', 0)
                
                if elem_size == 0:
                    return
               
                total_element_size=0
                # Iterate through array elements
                for i in range(array_length):
                    elem_addr = address + (i * elem_size)
                    element_value= extract_objects_recursive(elem_addr, elem_type, depth + 1, f"{context}[{i}]")
                    if element_value is not None:
                       elements.append(element_value)
                       total_element_size+=elem_size   
                if elements and any(e is not None for e in elements):
                   self.objects_found[address]={'struct_addr': address,'data_addr': address,'type': kind_str, 'length': total_element_size ,'value': elements,
                   'context':'Struct', 'struct_location': 'heap(array)','data_location': 'heap', 'depth': depth}
            except:
                pass
            return elements if elements else None
        
        # =============================================================
        # KIND 25: Struct
        # =============================================================
        elif kind == 25:
            try:
                fields = type_info.get('fields', [])
                struct_size = type_info.get('size', 0)
                field_values=[]
                total_fields_size = 0
                for field in fields:
                    field_offset = field.get('offset', 0)
                    field_type_ptr = field.get('type_ptr', 0)
                    field_name = field.get('name', '<unknown>')
                    
                    if field_offset >= struct_size:
                        continue
                    
                    if not field_type_ptr or field_type_ptr not in types_dict:
                        continue
                    
                    # Check if field type can contain strings
                   
                    field_type = types_dict[field_type_ptr]
                    field_addr = address + field_offset
                    field_size = field_type.get('size', 0)
                    field_value= extract_objects_recursive(field_addr, field_type, depth + 1,  f"{context}.{field_name}" )
                    if field_value  is not None: 
                       field_values.append(field_value)
                       total_fields_size += field_size 
                if field_values:
                   self.objects_found[address]={'struct_addr': address,'data_addr': address,'type': kind_str, 'length': total_fields_size ,'value': field_values,
                   'context':'Struct', 'struct_location': 'heap(struct)','data_location': 'heap', 'depth': depth}
            
            except:
                pass
            return field_values if field_values else None
        
        # =============================================================
        # KIND 21: Map
        # =============================================================
        elif kind == 21:
            try:
                value= extract_primitives_from_map_at_address(address, type_info, depth, context)
                map_ptr = self._read_pointer(address)  
                if value: 
                   self.objects_found[address]={'struct_addr': address,'data_addr': address, 'type': kind_str, 'length': 8 ,'value': value, 'context':'Map', 'struct_location': 'heap(map)',
                   'data_location': 'heap', 'depth': depth}
                   
                   self.objects_found[map_ptr]={'struct_addr': address,'data_addr': address, 'type': kind_str, 'length': 8 ,'value': value, 'context':'Map', 'struct_location': 'heap(map)',
                   'data_location': 'heap', 'depth': depth}


            except:
                pass
            return value
        
        # =============================================================
        # KIND 20: Interface
        # =============================================================
        elif kind == 20:
         try:
           # Interface: {itab_ptr/type_ptr, data_ptr/direct_value}
           header = layer.read(address, 16, pad=True)
           itab_or_type_ptr = int.from_bytes(header[0:8], 'little')
           data_val = int.from_bytes(header[8:16], 'little')
        
           if itab_or_type_ptr == 0:
            return None
        
           concrete_type = None
           concrete_type_ptr = None
           interface_name = '<unknown>'
           concrete_type_name = '<unknown>'
        
           # Check if it's an itab (non-empty interface like io.Reader)
           if itab_or_type_ptr in itabs_dict:
             itab_info = itabs_dict[itab_or_type_ptr]
             interface_name = itab_info.get('interface_name', '<unknown>')
             concrete_type_name = itab_info.get('concrete_type_name', '<unknown>')
             concrete_type_ptr = itab_info.get('type_ptr', 0)
            
             if concrete_type_ptr and concrete_type_ptr in types_dict:
                concrete_type = types_dict[concrete_type_ptr]
        
           # Check if it's a type pointer (empty interface `any`/`interface{}`)
           elif itab_or_type_ptr in types_dict:
            interface_name = 'any'
            concrete_type = types_dict[itab_or_type_ptr]
            concrete_type_ptr = itab_or_type_ptr
            concrete_type_name = concrete_type.get('name', '<unknown>')
        
           else:
            # Unknown - neither itab nor type
            return None
        
           if concrete_type is None:
            return None
        
           # Determine if value is stored directly or as a pointer
           concrete_kind = concrete_type.get('kind', 0)
           concrete_size = concrete_type.get('size', 0)
        
           # Direct storage: small primitives (≤8 bytes) are stored inline
           is_direct = (
            concrete_kind in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14] 
            and concrete_size <= 8
           )
        
           actual_value = None
        
           if data_val == 0:
              # Nil data
              actual_value = None
        
           elif is_direct:
             # Value is stored DIRECTLY in data_val (not as a pointer)
             import struct as pystruct
            
             if concrete_kind == 1:  # bool
                actual_value = bool(data_val & 0xFF)
            
             elif concrete_kind in [2, 3, 4, 5, 6]:  # Signed integers
                mask = (1 << (concrete_size * 8)) - 1
                value = data_val & mask
                sign_bit = 1 << ((concrete_size * 8) - 1)
                if value & sign_bit:
                    actual_value = value - (1 << (concrete_size * 8))
                else:
                    actual_value = value
            
             elif concrete_kind in [7, 8, 9, 10, 11, 12]:  # Unsigned integers
                mask = (1 << (concrete_size * 8)) - 1
                actual_value = data_val & mask
            
             elif concrete_kind == 13:  # float32
                bytes_val = (data_val & 0xFFFFFFFF).to_bytes(4, 'little')
                actual_value = pystruct.unpack('<f', bytes_val)[0]
            
             elif concrete_kind == 14:  # float64
                bytes_val = data_val.to_bytes(8, 'little')
                actual_value = pystruct.unpack('<d', bytes_val)[0]
        
           else:
             # Value is stored as a POINTER - data_val is an address
             if self._is_valid_data_pointer(data_val):
                actual_value = extract_objects_recursive(
                    data_val, 
                    concrete_type, 
                    depth + 1, 
                    f"{context}.(iface:{concrete_type_name})"
                )
        
           # Store the interface
           if actual_value is not None:
              self.objects_found[address] = {
                'struct_addr': address,
                'data_addr': data_val if not is_direct else address,
                'type': kind_str,
                'length': 16,
                'value': actual_value,
                'context': f'Interface<{interface_name}->{concrete_type_name}>',
                'struct_location': 'heap(interface)',
                'data_location': 'direct' if is_direct else 'heap',
                'depth': depth
              }
              return actual_value
        
         except Exception as e:
            pass
         return None
      # =================================================================
      # Helper: Extract string at a specific address
      # =================================================================
      def extract_string_at_address(address: int, context: str, depth: int, kind_str:str)  -> Optional[str]:
        """Extract a Go string from a 16-byte header at the given address."""
       
        
        try:
            header = layer.read(address, 16, pad=True)
            data_ptr = int.from_bytes(header[0:8], 'little')
            str_len = int.from_bytes(header[8:16], 'little')
            
            # Validate
            if data_ptr == 0 or str_len <= 0:
                return
            if str_len > MAX_STRING_LENGTH:
                return
            
            if data_ptr in types_dict or data_ptr in itabs_dict:
                return
            
            # Check data location
            data_location = self._get_string_data_location(data_ptr)
            if data_location in ("text", "invalid"):
                return
            
            # Read and validate string content
            string_data = layer.read(data_ptr, str_len, pad=True)
            string_val = string_data.decode('utf-8', errors='replace').rstrip('\x00')
         
            if not self._is_valid_string_content(string_val, min_length=2):
                return None
           
            # Success - add to results
            self.objects_found[address] ={
                'struct_addr': address,
                'data_addr': data_ptr,
                'type': kind_str,
                'length': str_len,
                'value': string_val,
                'context': context,
                'struct_location': 'heap(string)',
                'data_location': data_location,
                'depth': depth
            }
            
        
            return string_val
            
        except:
            return None
    
      # =================================================================
      # Helper: Extract strings from a map at a specific address
      # =================================================================
      def extract_primitives_from_map_at_address(
        address: int, 
        type_info: Dict, 
        depth: int, 
        context: str
      ) -> None:
        """Extract strings from a map whose pointer is at the given address."""
       
        
        try:
            # Read map pointer (maps are always pointers to hmap)
            map_ptr = self._read_pointer(address)
            if map_ptr == 0 or not self._is_go_heap_pointer(map_ptr):
                return
            
            # Read hmap header
            header = layer.read(map_ptr, 48, pad=True)
            if len(header) < 48:
                return
            
            # Get key/value type info
            key_type_ptr = type_info.get('key_type_ptr', 0)
            elem_type_ptr = type_info.get('elem_type_ptr', 0)
            
            key_type = types_dict.get(key_type_ptr, {})
            elem_type = types_dict.get(elem_type_ptr, {})
            
            key_size = key_type.get('size', 0)
            value_size = elem_type.get('size', 0)
            
            if key_size == 0 or value_size == 0:
                return
            
            key_can_have_primitive = key_type_ptr in types_with_primitive
            value_can_have_primitive = elem_type_ptr in types_with_primitive
            
            if not key_can_have_primitive and not value_can_have_primitive:
                return
            
            # Determine Go version and parse accordingly
            major, minor, _ = self.go_version_tuple
            is_go_124_plus = (major == 1 and minor >= 24)
            
            if is_go_124_plus:
                entries = extract_go124_map_entries(header, map_ptr, key_size, value_size)
            else:
                entries = extract_old_map_entries(header, key_size, value_size)
            map_contents = {}
            # Process entries
            for entry in entries:
              
                key_val = extract_objects_recursive(entry['key_addr'], key_type,depth + 1,f"[key]")
                
                
                value_val = extract_objects_recursive(entry['value_addr'], elem_type,depth + 1, f"[value]" )
                     
                if key_val is not None:
                   # For hashable keys (strings, ints, bools)
                   try:
                      if isinstance(key_val, list):
                        key_val = tuple(key_val)  # Make hashable
                      map_contents[key_val] = value_val
                   except TypeError:
                      # Key not hashable, store as tuple
                      pass
            
                '''# Also store individual addresses
                if key_val is not None:
                   self.objects_found[entry['key_addr']] = key_val
                if value_val is not None:
                   self.objects_found[entry['value_addr']] = value_val
                 '''
       
        
            return map_contents if map_contents else None      
                   
                   
                   
                   
                   
        except:
            pass
    
      # =================================================================
      # Helper: Extract Go 1.24+ Swiss Table map entries
      # =================================================================
      def extract_go124_map_entries(header: bytes, map_ptr: int, key_size: int, value_size: int) -> List[Dict]:
        """Extract entries from Go 1.24+ Swiss Table map."""
        entries = []
        
        try:
            used = int.from_bytes(header[0:8], 'little')
            seed = int.from_bytes(header[8:16], 'little')
            dirPtr = int.from_bytes(header[16:24], 'little')
            dirLen = int.from_bytes(header[24:32], 'little', signed=True)
            
            # Validate
            if used == 0 or dirPtr == 0:
                return []
            if used > 10000 or dirLen > 1000:
                return []
            if seed == 0 and used > 0:
                return []
            
            entries = self._extract_go124_entries_no_type(map_ptr, dirPtr, dirLen, used, key_size, value_size, layer)
        except:
            pass
        
        return entries
    
      # =================================================================
      # Helper: Extract old hmap entries (Go < 1.24)
      # =================================================================
      def extract_old_map_entries(header: bytes, key_size: int, value_size: int) -> List[Dict]:
        """Extract entries from old-style hmap."""
        entries = []
        
        try:
            count = int.from_bytes(header[0:8], 'little')
            flags = header[8]
            B = header[9]
            hash0 = int.from_bytes(header[12:16], 'little')
            buckets_ptr = int.from_bytes(header[16:24], 'little')
            
            # Validate
            if count == 0 or buckets_ptr == 0:
                return []
            if count > 10000000 or B > 20:
                return []
            if flags > 15:
                return []
            if hash0 == 0 and count > 0:
                return []
            if not self._is_go_heap_pointer(buckets_ptr):
                # Also check data section
                data_start = self.moduledata.get('data_start', 0)
                ebss = self.moduledata.get('ebss', 0)
                if not (data_start <= buckets_ptr < ebss):
                    return []
            
            entries = self._extract_old_hmap_entries(
                buckets_ptr, count, B, key_size, value_size, layer
            )
        except:
            pass
        
        return entries
    
      # =================================================================
      # Main Processing Loop
      # =================================================================
      print(f"\n[*] Starting recursive string extraction...")
      print(f"[*] Processing {len(heap_objects)} heap objects")
    
      # Statistics
      stats = {
        'objects_processed': 0,
        'objects_with_strings': 0,
        'strings_by_kind': {},
        'strings_by_depth': {},
      }
    
      # Group heap objects by size for efficient matching
      objects_by_size = {}
      for obj in heap_objects:
        size = obj['size']
        if size not in objects_by_size:
            objects_by_size[size] = []
        objects_by_size[size].append(obj)
      
     
      # Process each size that has matching types
      for size in sorted(size_to_types.keys()):
        if size > 256:
           break
        type_list = size_to_types[size]
        
        if size not in objects_by_size:
            continue
        
        objects = objects_by_size[size]
       
        for obj in objects:
            obj_addr = obj['address']
            stats['objects_processed'] += 1
            if obj_addr in self.objects_found:
               continue
            objects_before = len(self.objects_found)
            
            # Try each type that matches this size
            for type_info in type_list:
                # Clear visited for each new root object
                visited_addrs.clear()
                
                extract_objects_recursive( obj_addr,  type_info, depth=0, context=type_info.get('name', '<unnamed>'))
                if obj_addr in self.objects_found:
                   break
                #if len(self.objects_found) > objects_before:
                   # break
    
      # =================================================================
      # Also scan for standalone strings (16-byte objects)
      # =================================================================
      print(f"\n[*] Scanning standalone 16-byte string headers...")
    
      if 16 in objects_by_size:
        for obj in objects_by_size[16]:
            obj_addr = obj['address']
            
            try:
                header = layer.read(obj_addr, 16, pad=True)
                data_ptr = int.from_bytes(header[0:8], 'little')
                str_len = int.from_bytes(header[8:16], 'little')
                
                # Quick validation
                if data_ptr == 0 or str_len <= 0 or str_len > MAX_STRING_LENGTH:
                    continue
              
                if data_ptr in types_dict or data_ptr in itabs_dict:
                    continue
                
                data_location = self._get_string_data_location(data_ptr)
                if data_location in ("text", "invalid"):
                    continue
                
                string_data = layer.read(data_ptr, str_len, pad=True)
                string_val = string_data.decode('utf-8', errors='replace').rstrip('\x00')
                
                if not self._is_valid_string_content(string_val, min_length=2):
                    continue
                
                self.objects_found[obj_addr] = {
                    'struct_addr': obj_addr,
                    'data_addr': data_ptr,
                    'type': 'string',
                    'length': str_len,
                    'value': string_val,
                    'context': 'standalone_string',
                    'struct_location': 'heap',
                    'data_location': data_location,
                    'depth': 0}
              
                
            except:
                continue
    
     
      # =================================================================
      # ALso scan for direct slice (16-byte objects)
      # =================================================================
      
      print(f"\n[*] Scanning for direct slice headers (24-byte objects)...")
      slices_found = 0
      strings_from_slices = 0
      if 24 in objects_by_size:
           for obj in objects_by_size[24]:
               obj_addr = obj['address']
               try:
                 header = layer.read(obj_addr, 24, pad=True)
               except:
                 continue
        
               # Parse slice header
               data_ptr = int.from_bytes(header[0:8], 'little')
               slice_len = int.from_bytes(header[8:16], 'little')
               slice_cap = int.from_bytes(header[16:24], 'little')
        
               # Validate slice header
               if data_ptr == 0:
                  continue
               if slice_len == 0 or slice_len > slice_cap:
                  continue
               if slice_cap > 10000:  # Sanity check
                  continue
               if slice_len > 1000:  # Reasonable limit for string slices
                  continue
      
               # Skip if data_ptr looks like a type or itab
               if data_ptr in types_dict or data_ptr in itabs_dict:
                  continue
      
               # Calculate backing array size
               backing_array_size = slice_len * 16  # Each string header is 16 bytes
               # Read backing array
               try:
                  backing_data = layer.read(data_ptr, backing_array_size, pad=True)
               except:
                  continue
        
               # Parse string headers from backing array
               valid_strings = 0
               slice_strings = []
               for i in range(slice_len):
                   offset = i * 16
                   str_ptr = int.from_bytes(backing_data[offset:offset+8], 'little')
                   str_len = int.from_bytes(backing_data[offset+8:offset+16], 'little')
            
                   # Validate string header
                   if str_ptr == 0 or str_len <= 0 or str_len > 10000:
                      continue
                   if str_ptr in types_dict or str_ptr in itabs_dict:
                      continue
                
        
                   # Determine string data location
                   data_location = self._get_string_data_location(str_ptr)
                   if data_location == "text":  # Skip machine code
                      continue
           
                   if data_location == "invalid":
                      continue
                   try:
                      string_data = layer.read(str_ptr, str_len, pad=True)
                      string_val = string_data.decode('utf-8', errors='replace').rstrip('\x00')
                
                      if not self._is_valid_string_content(string_val, min_length=2):
                         continue

                
                      valid_strings += 1
                      slice_strings.append({
                      'struct_addr': data_ptr + offset,  # Address of string header in backing array
                      'data_addr': str_ptr,
                      'type': 'slice',
                      'length': str_len,
                      'value': string_val,
                      'context': 'direct_slice',
                      'struct_location': 'heap',
                      'data_location': data_location
                       })
                
                   except:
                     continue
        
        
               if valid_strings >= 1:
                  slices_found += 1
                  for s in slice_strings:
                         self.objects_found[s['struct_addr']] = s
                         strings_from_slices += 1
      # =================================================================
      # Scan for map pointers (8-byte objects and 48-byte hmaps)
      # =================================================================
      print(f"\n[*] Scanning for map pointers...")
    
      maps_found = 0
      strings_from_maps_direct = 0
      MAP_HEADER_SIZE = 48
      # Collect potential hmap addresses
      potential_hmaps = set()
    
      # Direct 48-byte hmap allocations
      if 48 in objects_by_size:
        for obj in objects_by_size[48]:
            potential_hmaps.add(obj['address'])
    
      # 8-byte pointers to hmaps
      if 8 in objects_by_size:
        for obj in objects_by_size[8]:
            obj_addr = obj['address']  
            try:
                ptr_data = layer.read(obj_addr, 8, pad=True)
                map_header_ptr = int.from_bytes(ptr_data[0:8], 'little')
            except:
                continue
            
            # Step 2: Validate pointer
            if map_header_ptr == 0:
                continue
            if not self._is_go_heap_pointer(map_header_ptr):
                continue
            if map_header_ptr in types_dict or map_header_ptr in itabs_dict:
                continue
            potential_hmaps.add(map_header_ptr)

      print(f"    Found {len(potential_hmaps)} potential hmap addresses")
      
      # Process each potential hmap
      major, minor, _ = self.go_version_tuple
      is_go_124_plus = (major == 1 and minor >= 24)
      is_go_1_15 = (major == 1 and minor >= 15 and minor < 24)
     
      for map_header_ptr in potential_hmaps:       
            # Step 3: Read potential map header
            try:
                header = layer.read(map_header_ptr, MAP_HEADER_SIZE, pad=True)
            except:
                continue
       
            if len(header) < MAP_HEADER_SIZE:
               continue
           
            if is_go_124_plus:
                # ==========================================================
                # Go 1.24+ Swiss Table map
                # ==========================================================
                used = int.from_bytes(header[0:8], 'little')
                seed = int.from_bytes(header[8:16], 'little')
                dirPtr = int.from_bytes(header[16:24], 'little')
                dirLen = int.from_bytes(header[24:32], 'little', signed=True)
                globalDepth = header[32] if len(header) > 32 else 0
                globalShift = header[33] if len(header) > 33 else 0
                
                # Validate
                is_dir_heap = dirPtr == 0 or self._is_go_heap_pointer(dirPtr)
                is_all_zeros = (used == 0 and seed == 0 and dirPtr == 0 and 
                                dirLen == 0 and globalDepth == 0 and globalShift == 0)
                
                is_valid_map = (
                    not is_all_zeros and
                    1 <= used < 1000 and
                    -1 <= dirLen < 128 and
                    0 <= globalDepth <= 16 and
                    0 <= globalShift <= 64 and
                    (dirPtr == 0 or dirPtr > 0x1000) and
                    is_dir_heap
                )
                
                if used > 0 and seed == 0:
                    is_valid_map = False
                
                if dirLen > 1:
                    expected_dirLen = 1 << globalDepth
                    if dirLen != expected_dirLen:
                        is_valid_map = False
                
                if not is_valid_map:
                    continue
                
                maps_found += 1
                matched = False
                for type_addr, type_info in map_types.items():
                    key_size = type_info['key_size']
                    value_size = type_info['value_size']

                    key_type_ptr = type_info.get('key_type_ptr', 0)
                    elem_type_ptr = type_info.get('elem_type_ptr', 0)
                    key_type = types_dict.get(key_type_ptr, {})
                    elem_type = types_dict.get(elem_type_ptr, {})
                   
                    key_can_have_primitive = key_type_ptr in types_with_primitive
                    value_can_have_primitive= elem_type_ptr in types_with_primitive
                    entries = self._extract_go124_entries_no_type(map_header_ptr, dirPtr, dirLen, used, key_size, value_size, layer)
                    if len(entries) == used:
                        # Found matching type!  
                        matched = True
                        
                        
                        map_contents = {}  
                        # Extract strings from keys
                        # if type_info['key_is_string']:
                        for entry in entries:
                               key_val = None
                               value_val = None  
                        
                               key_val = extract_objects_recursive(entry['key_addr'],   key_type, 0, f"[key]")   
                           
                               value_val = extract_objects_recursive( entry['value_addr'],  elem_type, 0, f"[value]" )
                               if key_val is not None: 
                                  try:
                                    if isinstance(key_val, list):
                                        key_val = tuple(key_val)  # Make hashable
                                        map_contents[key_val] = value_val
                                  except TypeError:
                                        # Key not hashable, store as tuple
                                        pass
                               
                        if map_contents:
                           self.objects_found[map_header_ptr] = {'struct_addr': map_header_ptr,
                          'data_addr': map_header_ptr,'type': 'map', 'length': len(map_contents),
                          'value': map_contents,'context': 'Map', 'struct_location': 'heap(map)','data_location': 'heap(map)','depth': 0}    
                       
                    
                    
                   
            
            elif is_go_1_15:
                # ==========================================================
                # Old hmap (Go < 1.24)
                # ==========================================================
                
                count = int.from_bytes(header[0:8], 'little')
                flags = header[8]
                B = header[9]
                noverflow = int.from_bytes(header[10:12], 'little')
                hash0 = int.from_bytes(header[12:16], 'little')
                buckets_ptr = int.from_bytes(header[16:24], 'little')
                oldbuckets_ptr = int.from_bytes(header[24:32], 'little')
                nevacuate = int.from_bytes(header[32:40], 'little')
                extra_ptr = int.from_bytes(header[40:48], 'little')
                is_buckets_heap = buckets_ptr == 0 or self._is_go_heap_pointer(buckets_ptr)
                
                # Check count is reasonable
                if count < 0 or count > 10000000:
                   continue
    
                # Empty maps are valid but not interesting for string extraction
                if count == 0:
                   continue
    
                # B should be small (2^B = number of buckets)
                if B > 20:  # 2^20 = 1M buckets max
                   continue
    
                # flags should be small (only lower 4 bits used)
                if flags > 15:
                   continue
    
                # hash0 should be non-zero for non-empty maps
                if hash0 == 0 and count > 0:
                   continue
    
                # buckets_ptr validation - CRITICAL
                if buckets_ptr == 0:
                   continue
                if buckets_ptr == 0xffffffffffffffff:
                   continue
                if buckets_ptr < 0x10000:
                   continue
    
                # buckets must be in Go heap or data sections
                buckets_in_heap = 0xc000000000 <= buckets_ptr < 0xd000000000
                buckets_in_data = (self.moduledata.get('data_start', 0) <= buckets_ptr < self.moduledata.get('ebss', 0))
    
                if not (buckets_in_heap or buckets_in_data):
                   continue
    
                if oldbuckets_ptr != 0:
                   if oldbuckets_ptr == 0xffffffffffffffff:
                      continue
                  
                   oldbuckets_valid = (0xc000000000 <= oldbuckets_ptr < 0xd000000000 or
                          self.moduledata.get('data_start', 0) <= oldbuckets_ptr < 
                          self.moduledata.get('ebss', 0))
                   if not oldbuckets_valid:
                      continue
                
                maps_found += 1
                matched = False
                for type_addr, type_info in map_types.items():
                     key_size = type_info['key_size']
                     value_size = type_info['value_size']
                     
                     key_type_ptr = type_info.get('key_type_ptr', 0)
                     elem_type_ptr = type_info.get('elem_type_ptr', 0)
                     key_type = types_dict.get(key_type_ptr, {})
                     elem_type = types_dict.get(elem_type_ptr, {})
                     
                     key_can_have_primitive = key_type_ptr in types_with_primitive
                     value_can_have_primitive= elem_type_ptr in types_with_primitive
                     entries = self._extract_old_hmap_entries(buckets_ptr, count, B, key_size, value_size, layer)
                     map_contents={}
                     for entry in entries:
                            key_val = None
                            value_val = None   
                          
                            key_val = extract_objects_recursive(entry['key_addr'],    key_type,0, f"[key]")   
                          
                            value_val = extract_objects_recursive( entry['value_addr'], elem_type, 0, f"[value]" )
                            if key_val is not None: 
                                  try:
                                    if isinstance(key_val, list):
                                        key_val = tuple(key_val)  # Make hashable
                                        map_contents[key_val] = value_val
                                  except TypeError:
                                        # Key not hashable, store as tuple
                                        pass
                          
                     if map_contents:
                        self.objects_found[map_header_ptr] = { 'struct_addr': map_header_ptr,'data_addr': map_header_ptr, 'type': 'map',
                        'length': len(map_contents),
                        'value': map_contents,'context': 'Map','struct_location': 'heap(map)', 'data_location': 'heap','depth': 0 }  

                    

      print(f"\n[+] Phase 5: Found {maps_found} maps with {strings_from_maps_direct} strings")
    
      # =================================================================
      # Print Statistics
      # =================================================================
      print(f"\n{'='*80}")
      print(f"RECURSIVE STRING EXTRACTION SUMMARY")
      print(f"{'='*80}")
      print(f"Objects processed: {stats['objects_processed']}")
      print(f"Objects with strings: {stats['objects_with_strings']}")
      print(f"Maps found: {maps_found}")
      print(f"Strings from maps: {strings_from_maps_direct}")
      print(f"Total strings found: {len(self.objects_found)}")
      print(f"{'='*80}\n")
    
      return self.objects_found

    
    def _find_types_containing_primitive(self, types_dict: Dict) -> Set[int]:
      can_contain_primitive = {}  # {type_addr: bool}
      computing = set()  # For cycle detection
    
      def check_type(type_addr: int) -> bool:
        """Check if a type can contain strings (recursive with memoization)."""
        if type_addr in can_contain_primitive:
            return can_contain_primitive[type_addr]
        
        if type_addr in computing:
            # Cycle detected - assume False to break cycle
            return False
        
        if type_addr not in types_dict:
            return False
        
        computing.add(type_addr)
        
        type_info = types_dict[type_addr]
        kind = type_info.get('kind', 0)
        result = False
        
        # String type
        if kind in (1,2,3,4,5,6,7,8,9,10,11,12,13,14,24):
            result = True
        
        # Pointer - check element type
        elif kind == 22:
            elem_ptr = type_info.get('elem_type_ptr', 0)
            if elem_ptr:
                result = check_type(elem_ptr)
        
        # Slice - check element type
        elif kind == 23:
            elem_ptr = type_info.get('elem_type_ptr', 0)
            if elem_ptr:
                result = check_type(elem_ptr)
        
        # Array - check element type
        elif kind == 17:
            elem_ptr = type_info.get('elem_type_ptr', 0)
            if elem_ptr:
                result = check_type(elem_ptr)
        
        # Struct - check all fields
        elif kind == 25:
            fields = type_info.get('fields', [])
            for field in fields:
                field_type_ptr = field.get('type_ptr', 0)
                if field_type_ptr and check_type(field_type_ptr):
                    result = True
                    break
        
        # Map - check key and value types
        elif kind == 21:
            key_ptr = type_info.get('key_type_ptr', 0)
            elem_ptr = type_info.get('elem_type_ptr', 0)
            if key_ptr and check_type(key_ptr):
                result = True
            elif elem_ptr and check_type(elem_ptr):
                result = True
        
        # Interface - can hold anything, assume True
        elif kind == 20:
            result = True
        
        computing.discard(type_addr)
        can_contain_primitive[type_addr] = result
        return result
    
      # Check all types
      for type_addr in types_dict:
        check_type(type_addr)
    
      # Return set of types that can contain strings
      return {addr for addr, can in can_contain_primitive.items() if can}

    
    
    def _build_map_types_dict(self, types_dict: Dict) -> Dict:
      """
      Build dictionary of map types with their key/value information.
      """
      map_types = {}
    
      for addr, info in types_dict.items():
        if info.get('kind') != 21:  # Not a map
            continue
        
        key_ptr = info.get('key_type_ptr', 0)
        elem_ptr = info.get('elem_type_ptr', 0)
        
        key_size = 0
        value_size = 0
        key_kind = 0
        value_kind = 0
        
        if key_ptr and key_ptr in types_dict:
            key_info = types_dict[key_ptr]
            key_size = key_info.get('size', 0)
            key_kind = key_info.get('kind', 0)
        
        if elem_ptr and elem_ptr in types_dict:
            value_info = types_dict[elem_ptr]
            value_size = value_info.get('size', 0)
            value_kind = value_info.get('kind', 0)
        
        if key_size > 0 and value_size > 0:
            map_types[addr] = {
                'key_size': key_size,
                'value_size': value_size,
                'key_kind': key_kind,
                'value_kind': value_kind,
                'key_is_string': key_kind == 24,
                'value_is_string': value_kind == 24,
                'key_type_ptr': key_ptr,
                'elem_type_ptr': elem_ptr,
                'bucket_size': 8 + (8 * key_size) + (8 * value_size) + 8,
            }
    
      return map_types
      
      
    def _is_valid_string_content(self, string_val: str, min_length: int = 2) -> bool:
      """
      Validate string content is actually readable text.
    
      Args:
        string_val: Decoded string
        min_length: Minimum length (default 2)
    
      Returns:
        True if valid readable string, False otherwise
      """
      # Length check
      if len(string_val) < min_length:
        return False
    
      stripped = string_val.strip()
      if len(stripped) < min_length:
        return False
    
      # Printability check - require 85%+ printable
      printable_count = sum(c.isprintable() or c in '\n\r\t' for c in string_val)
      if len(string_val) > 0:
        printable_ratio = printable_count / len(string_val)
        if printable_ratio < 0.85:
            return False
    
      # Reject replacement characters (�) - indicates bad UTF-8
      if '\ufffd' in string_val:
        return False
    
      # Reject control characters (except \n \r \t)
      for c in string_val:
        if ord(c) < 32 and c not in '\n\r\t':
            return False
        if ord(c) == 127:  # DEL character
            return False
    
      return True
    
    
    def _is_valid_data_pointer(self, ptr: int) -> bool:
      """
      Check if a pointer points to valid data memory (heap, data, rodata, bss).
      """
      if ptr == 0 or ptr < 0x1000:
        return False
    
      # Go heap range
      if self._is_go_heap_pointer(ptr):
        return True
    
      # Data section
      data_start = self.moduledata.get('data_start', 0)
      edata = self.moduledata.get('edata', 0)
      if data_start <= ptr < edata:
        return True
    
      # BSS section
      bss = self.moduledata.get('bss', 0)
      ebss = self.moduledata.get('ebss', 0)
      if bss <= ptr < ebss:
        return True
    
      # Rodata section
      rodata = self.moduledata.get('rodata', 0)
      erodata = self.moduledata.get('erodata', 0)
      if rodata <= ptr < erodata:
        return True
    
      return False

    
    
    def _get_string_data_location(self, ptr: int) -> str:
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
        
        # Go heap (0xc0... range)
        if self._is_go_heap_pointer(ptr):
            return "heap"
        
        # Stack (high memory)
        if 0x7ff000000000 <= ptr <= 0x7fffffffffff:
            return "stack"
        
        return "unknown"
    
      except (KeyError, TypeError):
        return "unknown"
    
    
    
    
    
    
    
    
    
    def _is_go_heap_pointer(self, ptr):
      """
      Check if pointer is in actual allocated heap spans.
      Most accurate method.
      """
      if ptr == 0:
        return False
    
      # First check: Standard Go heap range (fast check)
      if not (0xc000000000 <= ptr < 0xc100000000):
        return False
    
      # Second check: Is it in an actual allocated span? (accurate check)
      if hasattr(self, 'heap_spans') and self.heap_spans:
        for span in self.heap_spans:
            start = span['startAddr']
            # Go uses 8KB pages
            end = start + (span['npages'] * 8192)
            if start <= ptr < end:
                return True
    
      # Fallback: If we haven't enumerated spans yet, accept 0xc0 range
      return True
    
    
     
   
    
    
    
    
    def _extract_go124_entries_no_type(self, map_addr: int, dirPtr: int, dirLen: int, used: int,  key_size: int, value_size: int, layer) -> List[Dict]:
     
      if dirPtr == 0 or used == 0:
        return []
     
      if dirLen < 0 or dirLen > 10000:  # Max 10k directory entries
        return []
    
      # Constants from Go 1.24 Swiss Table
      SLOTS_PER_GROUP = 8
      CTRL_EMPTY = 0x80
      CTRL_DELETED = 0xFE
    
      entries = []
    
      try:
        if dirLen == 0  or dirLen == 1:
            group_entries = self._parse_go124_group_no_type( dirPtr, key_size, value_size, used, layer)
            entries.extend(group_entries)
        else:
            # Large map: dirPtr points to directory of group pointers
            max_dir_entries = min(dirLen, 1000)  # Cap at 1000
            bytes_to_read = max_dir_entries * 8
            # Read directory (array of pointers to groups)
            dir_data = layer.read(dirPtr, dirLen * 8, pad=True)
            
            for dir_idx in range(dirLen):
                group_ptr = int.from_bytes(
                    dir_data[dir_idx*8:(dir_idx+1)*8], 'little'
                )
                
                if group_ptr == 0:
                    continue

                
                group_entries = self._parse_go124_group_no_type(group_ptr,  key_size, value_size, used - len(entries), layer)
                entries.extend(group_entries)
                
                if len(entries) >= used:
                    break
        
        return entries[:used]  # Return exactly 'used' entries
        
      except Exception as e:
        print(f"[MAP EXTRACT] Error: {e}")
        import traceback
        traceback.print_exc()
        return entries



    def _parse_go124_group_no_type(self, group_addr: int,  key_size: int, value_size: int, max_entries: int, layer) -> List[Dict]:
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
    
    
      entries = []
      occupied_slots = []
    
      # Find occupied slots
      for slot in range(SLOTS_PER_GROUP):
        ctrl = ctrl_data[slot]
        if ctrl != CTRL_EMPTY and ctrl != CTRL_DELETED and ctrl != 0x00: 
            occupied_slots.append(slot)
    
      if not occupied_slots:
        return []
    
    
      # Calculate offsets
      ctrl_size = 8
      keys_start = ctrl_size
      values_start = keys_start + (SLOTS_PER_GROUP * key_size)
    
      for slot in occupied_slots:
        key_addr = group_addr + keys_start + (slot * key_size)
        value_addr = group_addr + values_start + (slot * value_size)
        
        #print(f"[GROUP]   Slot {slot}: key @ {hex(key_addr)}, value @ {hex(value_addr)}")
        
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


    def _extract_old_hmap_entries(self, buckets_ptr: int, count: int, B: int,
                          key_size: int, value_size: int, layer) -> List[Dict]:
      """Extract map entries using known key/value sizes."""
      SLOTS = 8
      MIN_TOPHASH = 5
    
      keys_offset = 8
      values_offset = 8 + (SLOTS * key_size)
      bucket_size = 8 + (SLOTS * key_size) + (SLOTS * value_size) + 8
    
      num_buckets = 1 << B
      entries = []
    
      for bucket_idx in range(num_buckets):
        bucket_addr = buckets_ptr + (bucket_idx * bucket_size)
        
        try:
            tophash = layer.read(bucket_addr, 8, pad=True)
        except:
            continue
        
        for slot in range(SLOTS):
            if tophash[slot] < MIN_TOPHASH:
                continue
            
            entries.append({
                'key_addr': bucket_addr + keys_offset + (slot * key_size),
                'value_addr': bucket_addr + values_offset + (slot * value_size),
            })
            
            if len(entries) >= count:
                return entries
    
      return entries



    
   
    
   
    
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
       
        types_dict = self._extract_types_by_scanning(pclntab["ptrSize"])
        #types_dict = self._extract_types_via_typelinks(pclntab["ptrSize"])
        print(f"length of types_dict: {len(types_dict)}")
        # Count by kind
        kind_counts = {}
        for addr, info in types_dict.items():
            #print(f"  {hex(addr)}: size={info.get('size')}, name='{info.get('name')}'")

            kind = info.get('kind', 0)
            kind_str = info.get('kind_str', 'unknown')
            key = f"{kind} ({kind_str})"
            kind_counts[key] = kind_counts.get(key, 0) + 1
        
        itabs_dict = self._extract_itabs(pclntab["ptrSize"])
        print(f"length of itabs_dict: {len(itabs_dict)}")
        print(f"\n{'='*80}")
        print(f"HEAP ANALYSIS")
       
        # ===================
        #  Extract HEAP strings
        # ===================
        mheap_info = self._find_mheap_global(segments)
        if mheap_info:
           print(f"[*] mheap_ address: {hex(mheap_info['address'])}")
           # Step 2: Enumerate spans
           spans = self._enumerate_spans(mheap_info)
    
           if spans:
              # Step 3: Display summary
              self._display_span_summary(spans)
        
              # Store for later use
              self.heap_spans = spans
              # Extract heap_objects from all spans
              heap_objects = self._extract_all_objects(spans)
                
              if heap_objects:
                    # Display object summary
                    self._display_object_summary(heap_objects)
                    
                    # Optionally: Display detailed list of first 20 heap_objects
                
                    all_objects = self.heap_objects_extraction(heap_objects,types_dict,itabs_dict)
                    print(f"\n{'='*100}")
                    print(f"STRING STRUCTURES (HEAP) ---> DATA BYTES IN (DATA/RODATA/TEXT/TYPES)")
                    print(f"{'='*100}")
                    print(f"{'Struct Addr':<20} {'Data Addr':<20} {'Length':<10} {'Value':<60} {'Struct Location':<20} {' Data Location':<20}") 
                    print("-" * 100)
                    structured = {}
                   
                    for obj, obj_info  in all_objects.items():
                        try:
                          # Check if obj_info is a properly formatted dict
                          if not isinstance(obj_info, dict):
                             # Handle raw values (like map_contents which is a dict of key:value pairs)
                             print(f"{hex(obj):<20} {hex(obj):<20} {'?':<10} {str(obj_info)[:60]:<60}{'map_data':<20} {'heap':<20}")
                             continue
            
                          if 'value' not in obj_info or 'struct_addr' not in obj_info:
                            # Handle entries without standard format
                            print(f"{hex(obj):<20} {hex(obj):<20} {'?':<10} {str(obj_info)[:60]:<60}{'unknown':<20} {'unknown':<20}")
                            continue
            
                          value = obj_info['value']
                          value = f"{str(value)[:60]}"
                          struct_addr = obj_info['struct_addr']
                          data_addr = obj_info['data_addr']
                          data_type = obj_info['type'] 
                          length = obj_info['length']
                          struct_loc = obj_info['struct_location']
                          data_loc = obj_info['data_location']
                          structured[hex(struct_addr)] = {"data_addr": hex(data_addr), "type":data_type, "length": length, "value": value,
                          "struct_location": struct_loc,"data_location": data_loc, }
                          
        
                          print(f"{hex(struct_addr):<20} {hex(data_addr):<20} {length:<10} {value:<60}{struct_loc:<20} {data_loc:<20}")
        
                        except Exception as e:
                          print(f"[ERROR] Failed to print {hex(obj)}: {e}")
                    
                    out_path = f"heap_strings_pid_{pid}.json"
                    with open(out_path, "w", encoding="utf-8") as f:
                         json.dump(structured, f, indent=2, ensure_ascii=False)
                    print(f"\nTotal HEAP strings found: {len(all_objects)}")
                    print(f"{'='*80}\n")
              
              else:
                    print(f"[!] No heap_objects extracted from spans")
           
           
           else:
              print(f"[!] No valid spans found")
        else:
           print(f"[!] Could not find mheap_ global variable")

        print(f"{'='*80}\n")
        
       
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


