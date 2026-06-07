"""
go_functions.py — Volatility 3 Plugin for Go Function Analysis and
                  Argument Recovery from Memory Dumps
                  
Extracts all functions from a Go process's memory, classifies them by origin
(application/runtime/stdlib/third-party), and performs ABI-aware backward
disassembly on application functions to recover concrete argument values at
each CALL site.

Design Rationale — Application-First Analysis:
    This plugin deliberately focuses disassembly and argument recovery on
    APPLICATION-category functions, because:

    1. Malware behavior lives in application code. Threat actors write custom
       main/client/agent packages; they call into runtime/stdlib/third-party
       libraries but rarely modify them. 

    2. Runtime/stdlib functions are stable and well-documented. Their signatures
       are known from source (Go toolchain) and stored in pre-built JSON
       databases, so disassembly adds no information — only cost.

    3. Scope control. A Go binary contains 3,000–50,000+ functions. Disassembling
       all of them is unnecessary; the 20–200 application functions contain the
       forensic evidence.

Pipeline:
    1. Locate PE in process VMAs.
    2. Detect Go version from RODATA string or pclntab magic heuristic.
    3. Find pclntab via magic bytes; fall back to structural scan for Garble.
    4. Find moduledata by scanning RW segment for pclntab pointer; parse
       version-specific layout.
    5. Extract all functions from ftab with PCDATA/FUNCDATA (ArgInfo,
       ArgsPointerMaps, InlTree, StackObjects).
    6. Resolve source files via pcfile→cutab→filetab; supplement from
       page-cache PE for stripped binaries.
    7. Reconstruct type system (26 kinds), method sets, and interface tables.
    8. Classify functions by source path (application/runtime/stdlib/3rd-party).
    9. For each application function: disassemble, find CALL targets, walk
       instructions backward to recover register (Go 1.17+) or stack
       (Go ≤1.16) argument values, print IDA-style annotated output.
       
Supported Go Versions:
    - Go 1.2–1.15  (stack-based ABI, legacy pclntab)
    - Go 1.16–1.17 (stack-based ABI, pcHeader with uintptr offsets)
    - Go 1.18–1.24 (register-based ABI, pcHeader with uint32 offsets)
    - Go 1.25+     (register-based ABI, same layout as 1.18+)

Architecture:
    x86-64 Windows (Intel64). 32-bit support is partial.

Dependencies:
    - Capstone disassembly engine (capstone-engine)
    - External: go_file_classifier, third_party_analyzer modules
    - "file_func_params_extractor/go_func_lines_v1255.json":  the path depdens of the analyzed Go version

Usage:
    python3 vol.py -f <image> windows.go_functions.Go_Functions --pid <PID>
    
References:
    - Go runtime source: https://go.dev/src/runtime/symtab.go
    - Go ABI specification: https://go.dev/src/internal/abi/
    - Go register ABI (1.17+): https://go.dev/src/cmd/compile/abi-internal.md
"""

import logging

from typing import List, Tuple, Generator, Optional, Dict, Set
from volatility3.framework import interfaces, exceptions, constants, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows.extensions import pe
from volatility3.framework import objects
from volatility3.plugins.windows import pslist
from volatility3.plugins.windows import dumpfiles  # Extract cached file content from Windows kernel page cach
from io import BytesIO
from volatility3.plugins.windows.third_party_analyzer import get_analyzer
from volatility3.plugins.windows.go_file_classifier  import classify_go_filepath
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_REG, X86_OP_MEM
import pefile 
        
import re
import json
import os
import pandas as pd


vollog = logging.getLogger(__name__)


class Go_Functions(interfaces.plugins.PluginInterface):
    _required_framework_version = (2, 0, 0)
    _version = (2, 0, 0)


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
                description="Windows kernel",
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
    # Helper Methods
    # =========================================================================
    

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
    
     # =========================================================================
    # PE Parsing
    # =========================================================================

    def _parse_pe_header(self, base_addr: int) -> Optional[Dict]:
      """Parse PE header and extract metadata."""
      result = {"valid": False, "base_addr": base_addr}
    
      try:
        layer = self.context.layers[self.layer_name]
        
        # Check DOS header
        dos_header = layer.read(base_addr, 64, pad=True)
        if dos_header[:2] != b"MZ":
            return result
        
        # Get PE header offset
        e_lfanew = int.from_bytes(dos_header[60:64], 'little')
        
        # Check PE signature
        pe_sig = layer.read(base_addr + e_lfanew, 4, pad=True)
        if pe_sig != b"PE\x00\x00":
            return result
        
        # Read COFF header
        coff_offset = base_addr + e_lfanew + 4
        coff_data = layer.read(coff_offset, 20, pad=True)
        
        machine = int.from_bytes(coff_data[0:2], 'little')
        num_sections = int.from_bytes(coff_data[2:4], 'little')
        opt_header_size = int.from_bytes(coff_data[16:18], 'little')
        
        # Read Optional Header
        opt_offset = coff_offset + 20
        opt_data = layer.read(opt_offset, opt_header_size, pad=True)
        
        magic = int.from_bytes(opt_data[0:2], 'little')
        is_64bit = (magic == 0x20b)  # PE32+ = 64-bit
        
        if is_64bit:
            image_base = int.from_bytes(opt_data[24:32], 'little')
            entry_point = int.from_bytes(opt_data[16:20], 'little')
        else:
            image_base = int.from_bytes(opt_data[28:32], 'little')
            entry_point = int.from_bytes(opt_data[16:20], 'little')
        
        result.update({
            "valid": True,
            "is_64bit": is_64bit,
            "num_sections": num_sections,
            "image_base": image_base,
            "entry_point": entry_point,
            "section_table_offset": opt_offset + opt_header_size,
        })
        
      except Exception as e:
        vollog.debug(f"Error parsing PE header: {e}")
    
      return result
    
    def _parse_pe_sections(self, pe_info: Dict) -> List[Dict]:
    
      sections = []
    
      if not pe_info.get("valid"):
        return sections
    
      base_addr = pe_info["base_addr"]
      num_sections = pe_info["num_sections"]
      section_offset = pe_info["section_table_offset"]
    
      layer = self.context.layers[self.layer_name]
    
      # Each section header is 40 bytes
      for i in range(num_sections):
        try:
            sect_addr = section_offset + (i * 40)
            sect_data = layer.read(sect_addr, 40, pad=True)
            
            # Parse section header
            name = sect_data[0:8].rstrip(b'\x00').decode('ascii', errors='ignore')
            virtual_size = int.from_bytes(sect_data[8:12], 'little')
            virtual_addr = int.from_bytes(sect_data[12:16], 'little')
            raw_size = int.from_bytes(sect_data[16:20], 'little')
            characteristics = int.from_bytes(sect_data[36:40], 'little')
            
            # Calculate runtime address
            runtime_vaddr = base_addr + virtual_addr
            
            # Decode permissions from characteristics
            is_readable = (characteristics & 0x40000000) != 0
            is_writable = (characteristics & 0x80000000) != 0
            is_executable = (characteristics & 0x20000000) != 0
            
            flags_str = ""
            flags_str += "R" if is_readable else "-"
            flags_str += "W" if is_writable else "-"
            flags_str += "X" if is_executable else "-"
            
            section = {
                "index": i,
                "name": name,
                "runtime_vaddr": runtime_vaddr,
                "runtime_end": runtime_vaddr + virtual_size,
                "virtual_size": virtual_size,
                "raw_size": raw_size,
                "characteristics": characteristics,
                "p_flags_str": flags_str,  # Keep same key for compatibility
            }
            
            sections.append(section)
            
        except Exception as e:
            vollog.debug(f"Error parsing section {i}: {e}")
            break
    
      return sections

    # =========================================================================
    # Go Runtime Structure Discovery
    # =========================================================================

    def _find_pclntab(self, sections: List[Dict]) -> Optional[Dict]:
        """Find Go pclntab - tries magic bytes first, then structural detection for Garble'd binaries."""
        result = self._find_pclntab_by_magic(sections)
        if result:
            return result

        print("[*] Standard magic bytes not found, trying structural detection")
        result = self._find_pclntab_structural(sections)
        if result:
            print(f"[+] Found pclntab via structural detection")
            return result

        return None

    def _find_pclntab_by_magic(self, sections: List[Dict]) -> Optional[Dict]:
        """Original magic-byte based pclntab detection."""
        rodata_section = None
        for sect in sections:
            if sect["name"] in [".rdata", ".rodata"] or sect["p_flags_str"] == "R--":
                rodata_section = sect
                break

        if not rodata_section:
            for sect in sections:
                if "R" in sect["p_flags_str"]:
                    rodata_section = sect
                    break

        if not rodata_section:
            return None

        start = rodata_section["runtime_vaddr"]
        end = rodata_section["runtime_end"]

        print(f"\n[*] Scanning for pclntab (magic bytes) in {rodata_section['name']}: {hex(start)}-{hex(end)}")

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

    def _find_pclntab_structural(self, sections: List[Dict]) -> Optional[Dict]:
        """
        Find pclntab using structural validation - works with Garble'd binaries.
        Scans .rdata/.rodata for pcHeader structures without relying on magic bytes.
        """
        rodata_section = None
        for sect in sections:
            if sect["name"] in [".rdata", ".rodata"] or sect["p_flags_str"] == "R--":
                rodata_section = sect
                break

        if not rodata_section:
            for sect in sections:
                if "R" in sect["p_flags_str"]:
                    rodata_section = sect
                    break

        if not rodata_section:
            return None

        start = rodata_section["runtime_vaddr"]
        end = rodata_section["runtime_end"]

        print(f"\n[*] Scanning for pclntab (structural) in {rodata_section['name']}: {hex(start)}-{hex(end)}")

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
        """Validate a potential pcHeader using structural checks (no magic byte dependency)."""
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

    
    def _extract_go_version(self, sections: List[Dict]) -> str:
      """
      Extract exact Go version string from binary.
      Works with stripped binaries - searches RODATA for "go1.X.Y" pattern.
      """
      try:
        layer = self.context.layers[self.layer_name]
        
        # Search in RODATA segment only
        for sect  in sections:
                is_rdata = sect["name"] in [".rdata", ".rodata"]
                is_readonly = sect["p_flags_str"] == "R--"
                if not (is_rdata or is_readonly):
                   continue 
                start = sect["runtime_vaddr"]
                end = sect["runtime_end"]
                
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
   
   
     
    def _find_moduledata(self, sections: List[Dict], pclntab_addr: int, ptrSize: int, go_version: str) -> Optional[Dict]:

        """Find moduledata by scanning RW segment for pointer to pclntab."""
        major, minor, _ = self.go_version_tuple
        is_go_116_plus = (major == 1 and minor >= 16) or major > 1
       
        rw_section  = None
        for sect in sections:
            if sect["name"] in [".data", ".bss"] or sect["p_flags_str"] == "RW-":
               rw_section = sect
               break
    
        if not rw_section:
           return None

        start = rw_section["runtime_vaddr"]
        end = rw_section["runtime_end"]


       
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
                        result = self._validate_moduledata(candidate_addr, pclntab_addr, ptrSize, go_version, sections)
                    else:
                        result = self._validate_moduledata_go115(candidate_addr, pclntab_addr, ptrSize, sections)
               
                    if result:
                        return result

                    pos += ptrSize

                current += chunk_size - ptrSize

            except:
                current += chunk_size

        return None
    
    
    def _validate_moduledata(self, address: int, pclntab_addr: int, ptrSize: int, go_version: str, sections: List[Dict]) -> Optional[Dict]:
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
            for sect in sections:
                if sect["p_flags_str"] == "R--" or sect["name"] in [".rdata", ".rodata"]:
                   rodata = sect["runtime_vaddr"]
                   erodata  = sect["runtime_end"]
          

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

            print(f"\n========== Go 1.16-1.17 MODULEDATA ==========")
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
        
           
        for sect in sections:
            if sect["p_flags_str"] == "R--" or sect["name"] in [".rdata", ".rodata"]:
               sect_start = sect["runtime_vaddr"]
               sect_end  = sect["runtime_end"]
               if sect_start <= rodata < sect_end:
                  erodata = sect_end
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
    

    
    def _validate_moduledata_go115(self, address: int, pclntab_addr: int, ptrSize: int, sections) -> dict:
      """
      Validate moduledata for Go 1.2-1.15.
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
        
        # Field 2: filetab []uint32 - THIS IS THE KEY FIX
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
        
        for sect in sections:
            if sect["p_flags_str"] == "R--" or sect["name"] in [".rdata", ".rodata"]:
                rodata = sect["runtime_vaddr"]
                erodata = sect["runtime_end"]
                break
        
        if rodata is None:
            rodata = types
            erodata = etypes
        
        print(f"[+] Found moduledata (Go 1.15) at {hex(address)}")
        print(f"    pclntable: ptr={hex(pclntable_ptr)}, len={pclntable_len}")
        print(f"    filetab: ptr={hex(filetab_ptr)}, len={filetab_len}")  # Debug output
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
            'filetab': {'ptr': filetab_ptr, 'len': filetab_len, 'cap': filetab_cap},  # <-- ADD THIS LINE
            'cutab': {'ptr': 0, 'len': 0, 'cap': 0},  # Go 1.15 has no cutab - set to empty
            'minpc': minpc,
            'maxpc': maxpc,
            'text': text,
            'etext': etext,
            'noptrbss': noptrbss,
            'enoptrbss': enoptrbss,
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
                vollog.debug(f"Error reading function {i}: {e}")
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
      Decode pcvalue from a pctab - matches Go runtime/symtab.go
    
     
      1. val_delta=0 means "advance by 1 quantum, don't consume pc_delta"
      2. pc_delta is scaled by pcQuantum (typically 1, but check your binary)
      3. Check target_pc < pc after advancing
      """
      if not pctab_data or len(pctab_data) == 0:
        return None
    
      # Get pcQuantum from pclntab header (typically 1 for x86-64)
      pc_quantum = self.pclntab.get("minLC", 1)
    
      try:
        pc = entry_pc
        value = -1
        idx = 0

        step = 0
        while idx < len(pctab_data) and step < 50:
            step += 1
           
            
            # Read value delta (zigzag varint)
            val_delta, consumed = self._read_varint_zigzag(pctab_data[idx:])
            if consumed == 0:
                break
        
            idx += consumed
            
            # CRITICAL: Special case for val_delta == 0
            if val_delta == 0:
                # Advance PC by exactly 1 quantum, do NOT consume another varint
                pc += pc_quantum
                
                # Check if we passed target
                if target_pc < pc:
                    return value
                continue  # Go to next iteration WITHOUT reading pc_delta
            
            # Apply value delta
            value += val_delta
           
            
            # Read PC delta (unsigned varint)
            if idx >= len(pctab_data):
                return value
            
            pc_delta, consumed = self._read_varint(pctab_data[idx:])
            if consumed == 0:
                return value
           
            idx += consumed
            
            # Advance PC by pc_delta * pc_quantum
            pc += pc_delta * pc_quantum
          
            # Check if we passed target
            if target_pc < pc:
                return value
        
     
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
      Extract PCDATA tables for a function.
    
      Returns dict: {pcdata_index: pctab_bytes}
    
      CRITICAL: PCDATA is NOT null-terminated. Length is determined by next offset.
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
                    continue
                all_offsets.append(offset)
        
        # Sort all valid offsets to find boundaries
        all_offsets_sorted = sorted(set(all_offsets))
        # Step 4: Extract each PCDATA table using offset boundaries
        for i in range(npcdata):
            offset = pcdata_offsets[i]
            
            if offset == 0:
                continue
            
            # Validate offset (should already be validated above, but double-check)
            if offset >= pctab_len:
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
                continue
            if length > 100000:  # Reasonable upper bound for a single pcdata table
                # Continue anyway, but cap it
                length = min(length, 100000)
            
            # Validate address range
            pctab_addr = pctab_base + offset
            pctab_end_addr = pctab_base + offset + length
            
            if pctab_end_addr > pctab_base + pctab_len:
                continue
            
         
            # Read the PCDATA blob
            data = layer.read(pctab_addr, length, pad=True)
            
            if len(data) < length:
                pcdata_tables[i] = data
            else:
                pcdata_tables[i] = data[:length]
            
            if length > 16:
               preview = pcdata_tables[i][:16].hex()

     
        return pcdata_tables
        
      except Exception as e:
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

   
    
  

    def _extract_types_by_scanning(self, ptrSize: int) -> Dict[int, Dict]:
      """
      Extract types by scanning the entire types section.
      This is more robust than relying on typelinks.
      Populates self.types_cache and returns a copy.
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

      uncommonType is located immediately after the kind-specific fields.
      Contains: pkgpath offset, mcount, xcount (exported count), moff.
      Each method has: name offset, type offset (funcType), ifn/tfn text offsets.
  
      Returns list of method dicts with resolved names, PCs, classifications,
      and optionally parsed function signatures.
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
    
    
    
    def _find_pe_base(self, proc) -> Optional[int]:
      """Find PE base address via VADs."""
      try:
        # Method 1: Use Peb.ImageBaseAddress (most reliable)
        try:
            peb = proc.get_peb()
            if peb:
                image_base = peb.ImageBaseAddress
                if image_base:
                    # Verify it's actually a PE
                    layer = self.context.layers[self.layer_name]
                    magic = layer.read(image_base, 2, pad=True)
                    if magic == b"MZ":
                        return image_base
        except:
            pass
        
        # Method 2: Scan VADs for executable region with MZ header
        for vad in proc.get_vad_root().traverse():
            start = vad.get_start()
            
            # Check for executable permission
            protection = vad.get_protection()
            if "EXECUTE" not in protection:
                continue
            
            try:
                layer = self.context.layers[self.layer_name]
                magic = layer.read(start, 2, pad=True)
                if magic == b"MZ":
                    return start
            except:
                continue
        
      except Exception as e:
        vollog.debug(f"Error finding PE base: {e}")
    
      return None
    
    def _extract_cached_binary(self, proc) -> Optional[bytes]:
      """Extract cached binary using dumpfiles plugin."""
      kernel = self.context.modules[self.config["kernel"]]
      primary_layer_name = kernel.layer_name
      memory_layer_name = self.context.layers[primary_layer_name].config["memory_layer"]
      memory_layer = self.context.layers[memory_layer_name]
    
      class BytesCapture:
        def __init__(self, filename):
            self.preferred_filename = filename
            self._buffer = BytesIO()
        
        def write(self, data):
            return self._buffer.write(data)
        
        def seek(self, offset):
            return self._buffer.seek(offset)
        
        def close(self):
            pass
        
        def getvalue(self):
            return self._buffer.getvalue()
    
      for vad in proc.get_vad_root().traverse():
        try:
            if vad.has_member("Subsection"):
                file_obj = vad.Subsection.ControlArea.FilePointer.dereference().cast("_FILE_OBJECT")
            elif vad.has_member("ControlArea"):
                file_obj = vad.ControlArea.FilePointer.dereference()
            else:
                continue
            
            if not file_obj.is_valid():
                continue
            
            try:
                file_name = file_obj.file_name_with_device()
                if isinstance(file_name, renderers.UnreadableValue):
                    continue
            except:
                continue
            
            if not file_name.lower().endswith('.exe'):
                continue
            
            print(f"[+] Found executable: {file_name}")
            
            # Try ImageSectionObject first (best for executables)
            try:
                section_obj = file_obj.SectionObjectPointer.ImageSectionObject
                control_area = section_obj.dereference().cast("_CONTROL_AREA")
                
                if control_area.is_valid():
                    file_handle = dumpfiles.DumpFiles.dump_file_producer(
                        file_obj,
                        control_area,
                        BytesCapture,
                        memory_layer,
                        "cached_binary.img"
                    )
                    
                    if file_handle and hasattr(file_handle, 'getvalue'):
                        pe_bytes = file_handle.getvalue()
                        if pe_bytes and len(pe_bytes) > 64 and pe_bytes[:2] == b'MZ':
                            print(f"[+] Extracted {len(pe_bytes)} bytes from ImageSectionObject")
                            return pe_bytes
            except exceptions.InvalidAddressException:
                pass
            
            # Try DataSectionObject
            try:
                section_obj = file_obj.SectionObjectPointer.DataSectionObject
                control_area = section_obj.dereference().cast("_CONTROL_AREA")
                
                if control_area.is_valid():
                    file_handle = dumpfiles.DumpFiles.dump_file_producer(
                        file_obj,
                        control_area,
                        BytesCapture,
                        memory_layer,
                        "cached_binary.dat"
                    )
                    
                    if file_handle and hasattr(file_handle, 'getvalue'):
                        pe_bytes = file_handle.getvalue()
                        if pe_bytes and len(pe_bytes) > 64 and pe_bytes[:2] == b'MZ':
                            print(f"[+] Extracted {len(pe_bytes)} bytes from DataSectionObject")
                            return pe_bytes
            except exceptions.InvalidAddressException:
                pass
                        
        except exceptions.InvalidAddressException:
            continue
    
      return None



    
   


    def _resolve_filename_from_pe(self, pe_bytes: bytes, pctab_file: int, filetab_file: int, 
                                cutab_file: int, pcfile_off: int, cuOffset: int, func_pc: int) -> str:
      """Resolve filename for Go 1.16+ from cached ELF."""
      try:
        # Read pcfile data
        pcfile_addr = pctab_file + pcfile_off
        if pcfile_addr + 256 > len(pe_bytes):
            return "<unknown>"

        pcfile_data = pe_bytes[pcfile_addr:pcfile_addr + 256]
        if all(b == 0 for b in pcfile_data[:8]):
            return "<unknown>"

        # Decode file_index
        file_index = self._pcvalue_bytes(pcfile_data, func_pc, func_pc)
        if file_index is None or file_index < 0:
            return "<unknown>"

        # cutab[cuOffset + file_index] -> filetab offset
        cutab_idx = cuOffset + file_index
        cutab_entry = cutab_file + (cutab_idx * 4)
        if cutab_entry + 4 > len(pe_bytes):
            return "<unknown>"

        fileoff = int.from_bytes(pe_bytes[cutab_entry:cutab_entry + 4], 'little')
        if fileoff == 0xFFFFFFFF:
            return "<unknown>"

        # Read filename from filetab
        name_addr = filetab_file + fileoff
        if name_addr >= len(pe_bytes):
            return "<unknown>"

        end = pe_bytes.find(b'\x00', name_addr, name_addr + 512)
        if end == -1:
            end = name_addr + 512

        return pe_bytes[name_addr:end].decode('utf-8', errors='replace')

      except Exception:
        return "<unknown>"


    def _resolve_filename_from_pe_go115(self, pe_bytes: bytes, pclntab_pos: int, 
                                      pcfile_off: int, func_pc: int) -> str:
      """Resolve filename for Go 1.2-1.15 from cached ELF."""
      try:
        # Read pcfile data
        pcfile_addr = pclntab_pos + pcfile_off
        if pcfile_addr + 256 > len(pe_bytes):
            return "<unknown>"

        pcfile_data = pe_bytes[pcfile_addr:pcfile_addr + 256]
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


    def _pcvalue_bytes(self, data: bytes, target_pc: int, entry_pc: int) -> Optional[int]:
      """Decode pcvalue from bytes."""
      if not data:
        return None

      pc = entry_pc
      value = -1
      idx = 0

      while idx < len(data):
        val_delta, consumed = self._read_varint_zigzag(data[idx:])
        if consumed == 0:
            break
        idx += consumed

        if val_delta == 0 and idx > 1:
            break

        value += val_delta

        if idx >= len(data):
            return value

        pc_delta, consumed = self._read_varint(data[idx:])
        if consumed == 0:
            return value
        idx += consumed

        pc += pc_delta

        if target_pc < pc:
            return value

      return value
    

    
    
    def _build_funcname_cache_from_pe(self, pe_bytes: bytes, pe_base: int, cached_sections: List[Dict]) -> Tuple[Dict[int, str], Dict[int, str]]:

       
      """Build {runtime_pc: func_name} and {runtime_pc: source_filename} from cached PE.

      Parses pclntab from the on-disk PE (page cache) to recover function names
      and source filenames when the in-memory binary is stripped.
      Version-aware: Go 1.18+ (uint32 offsets), 1.16-1.17 (uintptr), 1.2-1.15 (legacy).

      Returns:
        (func_names, filenames): both {runtime_pc: str}
      """
      func_names = {}
      filenames = {}
      # Find .rdata section
      rdata_section = None
      for sect in cached_sections:
        if sect['name'] in ['.rdata', '.rodata']:
            rdata_section = sect
            break
    
      if not rdata_section:
        print("[!] No .rdata section found")
        return func_names, filenames
    
      rdata_start = rdata_section['raw_offset']
      rdata_size = rdata_section['raw_size']
      rdata_va = rdata_section['virtual_address']
    
      # Search for pclntab magic
      for magic_bytes, version_info in self.GO_MAGICS.items():
        pos = pe_bytes.find(magic_bytes, rdata_start, rdata_start + rdata_size)
        if pos == -1:
            continue
        
        # Validate header
        header = pe_bytes[pos:pos + 80]
        if len(header) < 32:
            continue
        if header[4] != 0 or header[5] != 0:
            continue
        
        minLC = header[6]
        ptrSize = header[7]
        if minLC not in (1, 2, 4) or ptrSize not in (4, 8):
            continue
       
       
        major, minor, patch = self.go_version_tuple
        is_go_118_plus = (major == 1 and minor >= 18) 
        is_go_116_117= (major == 1 and minor >= 16 and minor <= 17)
        is_go_115 =(major == 1 and minor >= 15 and minor < 16)
        
  
        
        # Calculate runtime address of pclntab
        offset_in_rdata = pos - rdata_start
        pclntab_rva = rdata_va + offset_in_rdata
        pclntab_runtime = pe_base + pclntab_rva
        print(f"[+] Found pclntab in cached PE at file offset {hex(pos)}")
      
       
        print(f"    pclntab runtime: {hex(pclntab_runtime)}")
        
        # =====================================================
        # Go 1.18+: Parse pcHeader with offsets
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
            
            print(f"    textStart: {hex(text_start)}")
            print(f"    funcnameOffset: {hex(funcname_offset)}")
            print(f"    pclnOffset: {hex(pcln_offset)}")
            funcnametab_file = pos + funcname_offset
            pctab_file = pos + pctab_offset
            filetab_file = pos + filetab_offset
            cutab_file = pos + cu_offset
            
            # ftab is at pclntab + pcln_offset + 8 (skip functab header)
            ftab_file = pos + pcln_offset + 8 
            
            # pclntable (for _func structs) is at pclntab + pcln_offset
            pclntable_file = pos + pcln_offset
            
            # Parse ftab entries (8 bytes each: uint32 entryoff, uint32 funcoff)
            functab_entry_size = 8
            
            for i in range(nfunc):
                entry_offset = ftab_file + (i * functab_entry_size)
                
                if entry_offset + functab_entry_size > len(pe_bytes):
                    break
                
                entryoff = int.from_bytes(pe_bytes[entry_offset:entry_offset + 4], 'little')
                funcoff = int.from_bytes(pe_bytes[entry_offset + 4:entry_offset + 8], 'little')
                
                func_pc = text_start + entryoff
                
                # Read _func to get nameoff (at offset 4)
                func_struct_file = pclntable_file + funcoff
                if func_struct_file + 8 > len(pe_bytes):
                    continue
   
                
                nameoff = int.from_bytes(pe_bytes[func_struct_file + 4:func_struct_file + 8], 'little', signed=True)
                
                if nameoff < 0:
                    continue
                
                # Read name from funcnametab
                name_offset = funcnametab_file + nameoff
                if name_offset >= len(pe_bytes):
                    continue
                
                end = pe_bytes.find(b'\x00', name_offset, name_offset + 512)
                if end == -1:
                    end = name_offset + 512
                
                func_name = pe_bytes[name_offset:end].decode('utf-8', errors='replace')
                
                if func_name:
                    func_names[func_pc] = func_name
                
                # _func: pcfile at offset 20, cuOffset at offset 32
                pcfile_off = int.from_bytes(pe_bytes[func_struct_file + 20:func_struct_file + 24], 'little', signed=True)
                cuOffset = int.from_bytes(pe_bytes[func_struct_file + 32:func_struct_file + 36], 'little')
                
                if pcfile_off <= 0:
                    continue
                
                filename = self._resolve_filename_from_pe( pe_bytes, pctab_file, filetab_file, cutab_file, pcfile_off, cuOffset, func_pc )
                if filename and filename != "<unknown>":
                    filenames[func_pc] = filename

        # =====================================================
        # Go 1.16-1.17: Similar but no textStart in header
        # =====================================================
        elif is_go_116_117:
          # Parse header fields - offsets are uint32 regardless of ptrSize
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
    
          print(f"    nfunc: {nfunc}, nfiles: {nfiles}")
          print(f"    funcnameOffset: {hex(funcname_offset)}")
          print(f"    pclnOffset: {hex(pcln_offset)}")
    
          funcnametab_file = pos + funcname_offset
          pctab_file = pos + pctab_offset
          filetab_file = pos + filetab_offset
          cutab_file = pos + cu_offset
          ftab_file = pos + pcln_offset  # Go 1.16-1.17: NO header to skip
    
          print(f"    funcnametab_file: {hex(funcnametab_file)}")
          print(f"    ftab_file: {hex(ftab_file)}")
    
          functab_entry_size = 2 * ptrSize  # Go 1.16-1.17: [pc uintptr, funcoff uintptr]
    
          for i in range(nfunc):
              entry_offset = ftab_file + (i * functab_entry_size)
        
              if entry_offset + functab_entry_size > len(pe_bytes ):
                 break
        
              if ptrSize == 8:
                 func_pc = int.from_bytes(pe_bytes[entry_offset:entry_offset + 8], 'little')
                 funcoff = int.from_bytes(pe_bytes[entry_offset + 8:entry_offset + 16], 'little')
              else:
                 func_pc = int.from_bytes(pe_bytes[entry_offset:entry_offset + 4], 'little')
                 funcoff = int.from_bytes(pe_bytes[entry_offset + 4:entry_offset + 8], 'little')
        
              # _func struct: entry(uintptr) + nameoff(int32) at offset ptrSize
              func_struct_file = ftab_file + funcoff
              if func_struct_file + ptrSize + 4 > len(pe_bytes):
                  continue
        
              # nameoff is at offset ptrSize (after entry field)
              nameoff = int.from_bytes(pe_bytes[func_struct_file + ptrSize:func_struct_file + ptrSize + 4], 'little', signed=True)
        
              if nameoff < 0:
                 continue
        
              name_offset = funcnametab_file + nameoff
              if name_offset >= len(pe_bytes):
                 continue
        
              end = pe_bytes.find(b'\x00', name_offset, name_offset + 512)
              if end == -1:
                 end = name_offset + 512
        
              func_name = pe_bytes[name_offset:end].decode('utf-8', errors='replace')
        
              if func_name:
                 func_names[func_pc] = func_name
             
              # Go 1.16-1.17 _func layout (64-bit):
              # entry(8) + nameoff(4) + args(4) + deferreturn(4) + pcsp(4) + pcfile(4) + pcln(4) + npcdata(4) + cuOffset(4)
              if ptrSize == 8:
                    pcfile_off = int.from_bytes(pe_bytes[func_struct_file + 24:func_struct_file + 28], 'little', signed=True)
                    cuOffset = int.from_bytes(pe_bytes[func_struct_file + 36:func_struct_file + 40], 'little')
              else:
                    pcfile_off = int.from_bytes(pe_bytes[func_struct_file + 16:func_struct_file + 20], 'little', signed=True)
                    cuOffset = int.from_bytes(pe_bytes[func_struct_file + 28:func_struct_file + 32], 'little')

              if pcfile_off <= 0:
                    continue

              filename = self._resolve_filename_from_pe(
                    pe_bytes, pctab_file, filetab_file, cutab_file,
                    pcfile_off, cuOffset, func_pc
              )
              if filename and filename != "<unknown>":
                    filenames[func_pc] = filename
        # =====================================================
        # Go 1.2-1.15: Older layout, everything relative to pclntab
        # =====================================================
        elif is_go_115:
            
            # In Go 1.2-1.15, nfunc is uintptr, not int32
            if ptrSize == 8:
                nfunc = int.from_bytes(header[8:16], 'little')
                ftab_start = pos + 16  # After header: magic(4) + pad(2) + minLC(1) + ptrSize(1) + nfunc(8)
            else:
                nfunc = int.from_bytes(header[8:12], 'little')
                ftab_start = pos + 12
            
            print(f"    nfunc (uintptr): {nfunc}")
            print(f"    ftab starts at file offset: {hex(ftab_start)}")
            
            if nfunc > 100000:
                print("[!] nfunc too large, skipping")
                continue
            
            functab_entry_size = 2 * ptrSize
              
         
            
            
            for i in range(nfunc):
                entry_offset = ftab_start + (i * functab_entry_size)
                
                if entry_offset + functab_entry_size > len(pe_bytes):
                    break
                
                if ptrSize == 8:
                    func_pc = int.from_bytes(pe_bytes[entry_offset:entry_offset + 8], 'little')
                    funcoff = int.from_bytes(pe_bytes[entry_offset + 8:entry_offset + 16], 'little')
                else:
                    func_pc = int.from_bytes(pe_bytes[entry_offset:entry_offset + 4], 'little')
                    funcoff = int.from_bytes(pe_bytes[entry_offset + 4:entry_offset + 8], 'little')
                
                if func_pc == 0:
                    continue
                
                # _func struct is at pclntab + funcoff
                func_struct_file = pos + funcoff
               
                
                if func_struct_file + 16 > len(pe_bytes):
                    continue

                if ptrSize == 8:
                    nameoff = int.from_bytes(pe_bytes[func_struct_file + 8:func_struct_file + 12], 'little', signed=True)
                else:
                    nameoff = int.from_bytes(pe_bytes[func_struct_file + 4:func_struct_file + 8], 'little', signed=True)
                
                if nameoff == 0:
                   func_struct_raw = pe_bytes[func_struct_file:func_struct_file + 32]
                   
                  
                   continue
                if nameoff < 0:
               
                    continue
                
                # Name is at pclntab + nameoff
                name_offset = pos + nameoff
                
                if name_offset >= len(pe_bytes):
                 
                    continue
                
                end = pe_bytes.find(b'\x00', name_offset, name_offset + 512)
                if end == -1:
                    end = name_offset + 512
                
                func_name = pe_bytes[name_offset:end].decode('utf-8', errors='replace')
                
                if func_name:
                    func_names[func_pc] = func_name
                
                # Go 1.15 _func: pcfile at offset 24 (64-bit), no cuOffset
                if ptrSize == 8:
                    pcfile_off = int.from_bytes(pe_bytes[func_struct_file + 24:func_struct_file + 28], 'little', signed=True)
                else:
                    pcfile_off = int.from_bytes(pe_bytes[func_struct_file + 16:func_struct_file + 20], 'little', signed=True)

                if pcfile_off <= 0:
                    continue

                filename = self._resolve_filename_from_pe_go115(
                    pe_bytes, pos, pcfile_off, func_pc
                )
                if filename and filename != "<unknown>":
                    filenames[func_pc] = filename
        print(f"[+] Extracted {len(func_names)} function names and {len(filenames)} filenames from cached PE")
        break  # Found valid pclntab, stop searching
        
        
      return func_names,filenames
    
    
   
 
   
   
    
    def _lookup_func_name_from_external(self, filename: str, line_number: int, return_full_info: bool = False) -> Optional[Dict]:

  
      if not hasattr(self, '_external_func_db'):
        self._external_func_db = self._load_external_func_db(self.go_version_str)
    
      if not self._external_func_db:
        return None
    
      files = self._external_func_db.get('files', {})
      normalized = self._normalize_filename(filename)
    
      if normalized not in files:
        return None
    
      funcs = files[normalized]
    
      # Find the function that contains this line number
      # The containing function has the highest entry_line that is <= line_number
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
        return containing_func.get('func_name')
      
      
      return {
        'func_name': containing_func.get('func_name'),
        'entry_line': containing_func.get('entry_line'),
        'num_params': containing_func.get('num_params', 0),
        'num_returns': containing_func.get('num_returns', 0),
        'params': containing_func.get('params', []),
        'returns': containing_func.get('returns', []),
      }
  
    
    def _load_external_func_db(self, go_version: str) -> Dict:
      """Load pre-built function line database."""
      version_str = go_version.replace(".", "")
      db_file = f"/home/hala/file_func_params_extractor/go_func_lines_v115.json"  # Update this path
    
      if os.path.exists(db_file):
        with open(db_file, 'r') as f:
            return json.load(f)
      return {}
    
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
    
    
    
   
    
    
    def _get_file_line_for_pc(self, func_info: Dict, func_pc: int) -> Tuple[str, int]:
      try:
        
        pcfile_offset = func_info.get('pcfile', 0)
        pcln_offset = func_info.get('pcln', 0)
        startLine = func_info.get('startLine', 0)
        cuOffset = func_info.get('cuOffset', 0)  
        
        layer = self.context.layers[self.layer_name]
        pctab_base = self.moduledata["pctab"]["ptr"]
        
        major, minor, _ = self.go_version_tuple
        is_go_115 = (major == 1 and minor == 15) 
        is_go_116 = (major == 1 and minor == 16) 
        is_go_117_plus = (major == 1 and minor >= 17) 
       
        # Get file index from pcfile table
        file_index = None
        if pcfile_offset > 0:
            pcfile_addr = pctab_base + pcfile_offset
            pcfile_data = layer.read(pcfile_addr, 1024, pad=True)
            file_index = self._pcvalue(pcfile_data, func_pc, func_pc,
                                       f"{func_info.get('name', '')} [pcfile]")
        
        # Get line delta from pcln table
        line_delta = None
        if pcln_offset > 0:
            pcln_addr = pctab_base + pcln_offset
            pcln_data = layer.read(pcln_addr, 1024, pad=True)
            line_delta = self._pcvalue(pcln_data, func_pc, func_pc,
                                       f"{func_info.get('name', '')} [pcln]")
        
        # Resolve filename - THIS IS THE KEY FIX
        filename = "<unknown>"
        if file_index is not None and file_index >= 0:
            if is_go_115  or (major == 1 and minor < 16):
               filename = self._resolve_filename_go115(file_index)
            elif is_go_116:
               filename = self._resolve_filename_go116(file_index, cuOffset)
            elif is_go_117_plus:
                filename = self._resolve_filename_go117_plus(file_index, cuOffset)
            
        # Calculate line number
        line_number = 0
        if line_delta is not None:
            line_number = line_delta
        
        
      
        return (filename, line_number)
        
      except Exception as e:
        import traceback
        traceback.print_exc()
        return ("<error>", 0)


     
    def _resolve_filename_go115(self, file_index: int) -> str:
  
      try:
        if file_index < 0:
            return "<negative_idx>"
        
        layer = self.context.layers[self.layer_name]
        
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
    
    def _resolve_filename_go116(self, file_index: int, cuOffset: int) -> str:

      try:
        if file_index < 0:
            return "<negative_file_idx>"
        
        layer = self.context.layers[self.layer_name]
        
        # Get cutab and filetab from moduledata
        cutab_ptr = self.moduledata.get('cutab', {}).get('ptr', 0)
        cutab_len = self.moduledata.get('cutab', {}).get('len', 0)
        filetab_ptr = self.moduledata.get('filetab', {}).get('ptr', 0)
        filetab_len = self.moduledata.get('filetab', {}).get('len', 0)
        
        if cutab_ptr == 0 or filetab_ptr == 0:
            return "<no_cutab_or_filetab>"
        
        # Calculate the cutab index: cuOffset + file_index
        # cuOffset is the starting index in cutab for this function's CU
        # file_index (fileno) is the local file number within the CU
        cutab_index = cuOffset + file_index
        
        # Validate bounds
        if cutab_index < 0 or cutab_index >= cutab_len:
            return f"<cutab_oob:{cutab_index}/{cutab_len}>"
        
        # Read the fileoff from cutab (cutab is []uint32)
        # cutab[cutab_index] is a uint32
        cutab_entry_addr = cutab_ptr + (cutab_index * 4)  # 4 bytes per uint32
        fileoff_data = layer.read(cutab_entry_addr, 4, pad=True)
        fileoff = int.from_bytes(fileoff_data, 'little')
        
        # Check for invalid marker (^uint32(0) == 0xFFFFFFFF)
        if fileoff == 0xFFFFFFFF:
            return "<invalid_fileoff>"
        
        # Validate fileoff is within filetab bounds
        if fileoff >= filetab_len:
            return f"<filetab_oob:{fileoff}/{filetab_len}>"
        
        # Read the filename string from filetab
        # filetab is []byte containing null-terminated strings
        name_addr = filetab_ptr + fileoff
        filename = self._read_cstring(name_addr, 512)
        
        return filename if filename else "<empty>"
        
      except Exception as e:
        return f"<error:{e}>"
    
    
    def _resolve_filename_go117_plus(self, file_index: int, cuOffset: int) -> str:
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
        
        # CRITICAL: The actual cutab index is cuOffset + file_index
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
    
    
     
    def _disassemble_function( self,  layer_name: str,  func_pc: int,  func_size: int) -> List[Dict]:
      try:
        layer = self.context.layers[layer_name]
        # Read function bytes
        code_bytes = layer.read(func_pc, func_size, pad=True)
        if len(code_bytes) < func_size:
            print(f"[WARN] Only read {len(code_bytes)}/{func_size} bytes at {hex(func_pc)}")
        
        # Initialize disassembler (x86-64)
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = True  # Enable detailed instruction info
        
        instructions = []
        consecutive_int3 = 0
        found_ret = False
        for insn in md.disasm(code_bytes, func_pc):
             # Stop at padding after ret
             if found_ret and insn.mnemonic == 'int3':
                 break
    
             # Append BEFORE checking ret status
             instructions.append({"address": insn.address,"mnemonic": insn.mnemonic,"op_str": insn.op_str,  "bytes": insn.bytes.hex(),"size": insn.size, "cs_insn":insn,})
             # Track ret without resetting too early
             if insn.mnemonic in ['ret', 'retq']:
                found_ret = True
           
        
        
        return instructions
        
      except exceptions.InvalidAddressException as e:
        print(f"[ERROR] Cannot read memory at {hex(func_pc)}: {e}")
        return []
      except Exception as e:
        print(f"[ERROR] Disassembly failed: {e}")
        return []

    
    def _parse_cached_pe_sections(self, pe_bytes: bytes) -> List[Dict]:
      """Parse sections from cached PE bytes."""
      try:
        pe = pefile.PE(data=pe_bytes)
        sections = []
        
        print(f"\n[*] Cached PE Sections:")
        print(f"{'Name':<10} {'VirtAddr':<12} {'VirtSize':<12} {'RawSize':<12} {'Characteristics'}")
        print("-" * 70)
        
        for section in pe.sections:
            name = section.Name.rstrip(b'\x00').decode('utf-8', errors='replace')
            
            sect_info = {
                'name': name,
                'virtual_address': section.VirtualAddress,
                'virtual_size': section.Misc_VirtualSize,
                'raw_size': section.SizeOfRawData,
                'raw_offset': section.PointerToRawData,
                'characteristics': section.Characteristics,
            }
            sections.append(sect_info)
            
            print(f"{name:<10} {hex(section.VirtualAddress):<12} {section.Misc_VirtualSize:<12} {section.SizeOfRawData:<12} {hex(section.Characteristics)}")
        
        pe.close()
        return sections
        
      except Exception as e:
        print(f"[!] Error parsing cached PE: {e}")
        return []
    

    def _print_ida_style_call_analysis(self, caller_instructions: List[Dict], 
                                    call_index: int,
                                    callee_name: str,
                                    callee_pc: int,
                                    register_state: Dict[str, Dict],
                                    stack_state: Dict[int, Dict],
                                    recovered_args: List[Dict],
                                    func_lookup: Dict[int, Dict] = None):
      print(f"\n{'─'*80}")
      print(f"CALL: {callee_name}")
      print(f"{'─'*80}")
    
      start_idx = max(0, call_index - 30)
    
      for i in range(start_idx, call_index + 1):
        insn = caller_instructions[i]
        addr = insn['address']
        mnemonic = insn['mnemonic']
        op_str = insn['op_str']
        
        base_str = f"  {hex(addr)}: {mnemonic:<8} {op_str}"
        
        # Pass all_instructions and index so we can look ahead for length
        annotation = self._get_instruction_annotation(
            insn, register_state, stack_state, recovered_args,
            all_instructions=caller_instructions,
            insn_index=i,func_lookup=func_lookup
        )
        
        if annotation:
            padding = max(0, 55 - len(base_str))
            print(f"{base_str}{' ' * padding} ; {annotation}")
        else:
            print(base_str)
    
      # Print call summary
      call_insn = caller_instructions[call_index]
      call_summary = self._format_call_summary(callee_name, recovered_args)
      print(f"\n  {hex(call_insn['address'])}: call    {hex(callee_pc):<20} ; {call_summary}")
      print(f"{'─'*80}\n")


    def _get_instruction_annotation(self, insn: Dict, 
                                 register_state: Dict[str, Dict],
                                 stack_state: Dict[int, Dict],
                                 recovered_args: List[Dict],
                                 all_instructions: List[Dict] = None,
                                 insn_index: int = None,
                                 func_lookup: Dict[int, Dict] = None) -> Optional[str]:
      mnemonic = insn['mnemonic'].lower()
      op_str = insn['op_str'].lower()
    
      inst = insn.get('cs_insn')
      if inst is None:
        return None
     
      if mnemonic == 'call':
        # Try to resolve the target address to a function name
        if op_str.startswith('0x'):
            try:
                target_pc = int(op_str, 16)
                if func_lookup and target_pc in func_lookup:
                    func_name = func_lookup[target_pc].get('name', '')
                    if func_name:
                        # Shorten long names
                        if len(func_name) > 40:
                            parts = func_name.split('/')
                            func_name = parts[-1] if len(parts) > 1 else func_name[-40:]
                        return func_name
            except:
                pass
        return None
      # === LEA: load address, try to find length in following instructions ===
      if mnemonic == 'lea':
        target = self._get_rip_relative_target(inst)
        if target:
            # Try to find the string length in next few instructions
            str_len = None
            if all_instructions and insn_index is not None:
                for j in range(insn_index + 1, min(insn_index + 5, len(all_instructions))):
                    next_insn = all_instructions[j]
                    next_inst = next_insn.get('cs_insn')
                    if next_inst and next_insn['mnemonic'].lower() in ['mov', 'movq']:
                        # Look for: mov [rsp + 8], <length>
                        if len(next_inst.operands) >= 2:
                            from capstone.x86 import X86_OP_MEM, X86_OP_IMM
                            dst, src = next_inst.operands[0], next_inst.operands[1]
                            if dst.type == X86_OP_MEM and src.type == X86_OP_IMM:
                                base = next_inst.reg_name(dst.mem.base) if dst.mem.base else None
                                if base == 'rsp' and dst.mem.disp == 8:
                                    str_len = src.imm
                                    break
            
            # Read string with exact length
            if str_len and 0 < str_len < 1000:
                string_val = self._try_read_string_at_address(target, str_len)
                if string_val:
                   printable_count = sum(1 for c in string_val if c.isprintable())
                   if printable_count > len(string_val) * 0.5:
                      return f'"{string_val}"'
                   else:
                      return f"-> {hex(target)} (binary data)"
            
            return f"-> {hex(target)}"
        
        # Stack address
        if 'rsp' in op_str:
            import re
            match = re.search(r'\[rsp\s*[\+\-]?\s*(0x[0-9a-f]+|[0-9]+)\]', op_str)
            if match:
                return f"&stack[{match.group(1)}]"
        return None
    
      # === MOV [rsp + X], imm ===
      if mnemonic in ['mov', 'movq']:
        from capstone.x86 import X86_OP_MEM, X86_OP_IMM, X86_OP_REG
        
        if inst and len(inst.operands) >= 2:
            dst, src = inst.operands[0], inst.operands[1]
            
            if dst.type == X86_OP_MEM:
                base_reg = inst.reg_name(dst.mem.base) if dst.mem.base else None
                if base_reg == 'rsp':
                    if src.type == X86_OP_IMM:
                        val = src.imm
                        if val < 0:
                            val = val & 0xFFFFFFFFFFFFFFFF
                        return f"= {val}"
    
      # === XOR reg, reg ===
      if mnemonic == 'xor':
        parts = op_str.replace(' ', '').split(',')
        if len(parts) == 2 and parts[0] == parts[1]:
            return "= 0"
    
      return None

    def _format_call_summary(self, callee_name: str, recovered_args: List[Dict]) -> str:
      # Shorten callee name
      short_name = callee_name
      if len(callee_name) > 35:
        parts = callee_name.split('/')
        if len(parts) > 1:
            short_name = parts[-1]
        if len(short_name) > 35:
            short_name = f"...{short_name[-32:]}"
    
      # Build argument summary
      arg_strs = []
      for arg in recovered_args:
        if not arg.get('recovered', False):
            # Show WHY it wasn't recovered
            reason = arg.get('reason', arg.get('details', {}).get('reason', ''))
            if 'runtime' in str(reason).lower() or 'call_return' in str(reason).lower():
                arg_strs.append("<runtime>")
            elif 'stack' in str(reason).lower():
                arg_strs.append("<stack>")
            else:
                arg_strs.append("?")
            continue
        value = arg['value']
        ptype = arg.get('param_type', arg.get('inferred_type', ''))
        
        if isinstance(value, str):
            # Show full string (or increase limit)
            if len(value) > 50:
                arg_strs.append(f'"{value[:47]}..."')
            else:
                arg_strs.append(f'"{value}"')
        elif isinstance(value, dict):
            if 'len' in value:
                arg_strs.append(f"[]({value.get('len')})")
            else:
                arg_strs.append("{...}")
        elif isinstance(value, int):
            if value > 0x100000:
                arg_strs.append(f"0x{value:x}")
            else:
                arg_strs.append(str(value))
        else:
            arg_strs.append(str(value)[:20])
    
      return f"{short_name}({', '.join(arg_strs)})"
    
    
    
    # =========================================================================
    # Main Generator - 
    # =========================================================================
    def _generator(self) -> Generator[Tuple[int, Tuple], None, None]:
     try: 
      kernel = self.context.modules[self.config["kernel"]]
      filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
      for proc in pslist.PsList.list_processes(context=self.context, kernel_module_name=self.config["kernel"], filter_func=filter_func):
        pid = proc.UniqueProcessId
        try:
                proc_name = proc.ImageFileName.cast("string", max_length=proc.ImageFileName.vol.count, errors="replace")
        except:
                proc_name = "Unknown"
     
        # Get process memory layer
        try:
                proc_layer_name = proc.add_process_layer()
                curr_layer = self.context.layers[proc_layer_name]
                self.layer_name = curr_layer.name
        except:
                print(f"[!] Cannot add process layer for PID {pid}")
                continue
   
        pe_base = self._find_pe_base(proc)
        if not pe_base:
                print(f"[!] No PE found for PID {pid} ({proc_name})")
                continue
            
     
        pe_info = self._parse_pe_header(pe_base)
        if not pe_info.get("valid"):
              print(f"[!] Invalid PE header")
              continue
          
        print(f"[+] Valid PE header (64-bit: {pe_info['is_64bit']})")
        sections = self._parse_pe_sections(pe_info)
        if not sections:
                print(f"[!] No PE sections found for PID {pid}")
                continue  # Skip to next process
            
        print(f"[+] Found {len(sections)} PE sections")
            
        # Display sections summary
        print(f"\n[*] PE Sections:")
        for sect in sections:
              print(f"    {sect['name']:<10} {hex(sect['runtime_vaddr']):<18} "
                    f"Size: {sect['virtual_size']:<10} Flags: {sect['p_flags_str']}")
            
        self.go_version_str = self._extract_go_version(sections)
        self.go_version_tuple = self._parse_go_version(self.go_version_str)
        
        print(f"[+] Found PE at {hex(pe_base)}")
        cached_pe_bytes = self._extract_cached_binary(proc)
        cached_func_names = {}
        cached_filenames = {}
        if cached_pe_bytes:
           print(f"[+] Got cached binary: {len(cached_pe_bytes)} bytes")
           cached_sections = self._parse_cached_pe_sections(cached_pe_bytes)
           print("-" * 70)
           cached_func_names, cached_filenames = self._build_funcname_cache_from_pe(cached_pe_bytes, pe_base, cached_sections)
         
           print("-" * 70)
     
    
        else:
           cached_pe_bytes = None
        
        print(f"[+] Got {len(cached_func_names)} cached function names")
        print(f"-"*100)
        # Find pclntab
        pclntab = self._find_pclntab(sections)
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
        moduledata = self._find_moduledata(sections, pclntab["address"], pclntab["ptrSize"], self.go_version_str)
        if not moduledata:
            print(f"[!] moduledata not found")
            continue
        # Set instance variables for type parsing
        self.moduledata = moduledata
        self.types_start = moduledata['types']
        print(f" typelinks: ptr={hex(moduledata['typelinks']['ptr'])}, len={moduledata['typelinks']['len']}")
        print(f" types section: {hex(moduledata['types'])}-{hex(moduledata['etypes'])}")
        print("\n" + "=" * 170)
        print(f"GO RUNTIME INFORMATION")
        print("=" * 170)
        print(f"PID: {pid}")
        print(f"COMM: {proc_name}")
        print(f"[*] Go version detected: {self.go_version_str}")
        print(f"Functions: {pclntab['nfunc']}")
        print("=" * 170)
        types_dict = self._extract_types_by_scanning(pclntab["ptrSize"])
        itabs_dict = self._extract_itabs(pclntab["ptrSize"])
      
       
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
        print(f"{'Function PC':<30} {'Function Name':<50} {'File Path':<30} {'Category':<40}")  
        func_lookup = {}
        file_to_functions = {}
        _func_functions_new={}
        
        for func_info in _func_functions:
            func_lookup[func_info["pc"]] = func_info
            func_pc = func_info.get('pc', 0)
            filename, line_num = self._get_file_line_for_pc(func_info, func_pc)
            func_name = func_info.get('name', '<unknown>')
            func_args = func_info.get('args', 0)
            arginfo_data=func_info.get('arginfo_data')
            argsmap_data = func_info.get('argsmap_data')
            func_size = func_info.get('size', 0)
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

            classification = classify_go_filepath(filename)  
            category=classification['category'] 
            
            if line_num:
               func_info_new = { 'pc': func_pc,   'name': func_name,   'size': func_size, 'args':func_args,  'file': filename, 'line_num':line_num,  'category': category,
              'arginfo_data':arginfo_data, 'argsmap_data': argsmap_data}
           
            else:
              func_info_new = { 'pc': func_pc,   'name': func_name,   'size': func_size, 'args':func_args,  'file': filename, 'line_num':0,  'category': category,
              'arginfo_data':arginfo_data, 'argsmap_data': argsmap_data}
            
            
            if filename not in file_to_functions:
               file_to_functions[filename] = []
            file_to_functions[filename].append(func_info_new)
            print(f"{hex(func_pc):<30} {func_name:<50} {filename:<30} {category:<40} ")

            _func_functions_new[func_pc]=func_info_new
          
          
          
          
          
          
        print(f"\n[+] Built function lookup with {len(func_lookup)} functions")
        print(f"\n{'='*80}")
        print(f"FILES AND THEIR FUNCTIONS")
        print(f"{'='*80}")
        function_call_graph = {}
        file_call_graph = {} 
      
       
       
        for filename, functions in sorted(file_to_functions.items()):
            classification = classify_go_filepath(filename)
            category=classification['category']
            print(f"\n{filename} with classification: {category}  ({len(functions)} functions):")
            for func_info in sorted(functions, key=lambda x: x['pc']):
                print(f"    {hex(func_info['pc']):<18} {func_info['name']}")
       
        print(f"{'='*80}")
        for filename, functions in sorted(file_to_functions.items()):
            classification = classify_go_filepath(filename)
            category=classification['category']
            if category=="application":
               if filename not in file_call_graph:
                  file_call_graph[filename] = set()  # Use set to avoid duplicates

               for func_info in sorted(functions, key=lambda x: x['pc']):
                    func_pc = func_info.get('pc', 0)
                    func_name = func_info.get('name', 0)
                    func_size = func_info.get('size', 0)
                    func_category = func_info.get('category', 0)
                    instructions = self._disassemble_function(self.layer_name, func_pc, func_size)
                    called_pcs = self._extract_call_targets(instructions)
                    function_call_graph[func_pc] = called_pcs
                    for called_pc in called_pcs:
                        if called_pc in _func_functions_new:
                           called_file = _func_functions_new[called_pc]['file']
                        
                          
                           if called_file!=filename:
                              file_call_graph[filename].add(called_file)
                  
                    self.disassembly_analysis(func_pc, func_name, func_size, func_category, _func_functions_new,type_methods,depth=0,  max_depth=2)
              
               print(f"{'-'*80}")
     
  
        
     except Exception as e:
        print(f"\n[FATAL ERROR] Plugin crashed: {e}")
        import traceback
        traceback.print_exc()
     return
     yield


    
    def disassembly_analysis(self,func_pc,func_name, func_size, func_category,_func_functions_new,type_methods, depth, max_depth):
      """
      Disassemble an application function and analyze each CALL site.

      This is the core forensic analysis loop. For each direct CALL in the
      function's disassembly:
        1. Identifies the callee and its category (app/stdlib/method/3rd-party)
        2. Recovers argument values via ABI-aware backward analysis
        3. Prints IDA-style annotated disassembly around each CALL
        4. Optionally recurses into callee (depth-limited)
        
      """
      if depth > max_depth:
          return 
      instructions = self._disassemble_function(self.layer_name, func_pc, func_size)
      called_pcs = self._extract_call_targets(instructions)
      print("="*80)
      print(f"{func_name} @ {hex(func_pc)}, calls the following functions:")
      print("="*80)
      
      analyzed_calls = set()
      for called_pc in called_pcs:
          call_site_key = (func_pc, called_pc)
          if call_site_key in analyzed_calls:
             continue
          
          analyzed_calls.add(call_site_key)
         
          if called_pc in _func_functions_new:
             called_func_info = _func_functions_new[called_pc]
             called_name = called_func_info.get('name', '<unknown>')
             called_size = called_func_info.get('size', 0)
             called_category = called_func_info.get('category', 'unknown')
             func_args = called_func_info.get('args', 0)
            
             if func_args and func_args > 0:
                self._get_callee_parameters(func_pc, func_name, called_pc, type_methods, called_func_info, _func_functions_new, caller_instructions=instructions)
   
      print("="*80)      
    
    def _extract_call_targets(self, instructions: List[Dict]) -> List[int]:
      """Extract CALL target addresses from disassembled instructions (dict format)."""
      call_targets = []
    
      for insn in instructions:
        # insn is now a dict, not a Capstone object
        if insn['mnemonic'] == 'call':
            # Parse operand from op_str
            op_str = insn['op_str']
            
            # Direct call to address (e.g., "0x401234")
            if op_str.startswith('0x'):
                try:
                    target_pc = int(op_str, 16)
                    call_targets.append(target_pc)
                except:
                    pass
    
      return call_targets
   
    def _get_third_party_analyzer(self):
      """Lazy initialize the third-party analyzer."""
      if not hasattr(self, '_third_party_analyzer_instance') or self._third_party_analyzer_instance is None:
        try:
            from volatility3.plugins.windows.third_party_analyzer import get_analyzer
            self._third_party_analyzer_instance = get_analyzer()
        except ImportError:
            print("[WARN] third_party_analyzer module not found")
            self._third_party_analyzer_instance = None
      return self._third_party_analyzer_instance


    def _lookup_third_party_function(self, filepath: str, func_name: str):
      
      analyzer = self._get_third_party_analyzer()
      if analyzer is None:
         return None
    
      try:
        return analyzer.get_function_info(filepath, func_name)
      except Exception as e:
        print(f"[!] Error looking up third-party function: {e}")
        return None
    
    def _get_callee_parameters(self, caller_pc, caller_name, callee_pc, type_methods, called_func_info, _func_functions_new, caller_instructions=None):
        
        callee_name = called_func_info['name']
        callee_category =called_func_info['category']
        callee_file = called_func_info['file']
        arginfo_data=called_func_info.get('arginfo_data')
        argsmap_data = called_func_info.get('argsmap_data')
        
        line_num= called_func_info.get('line_num',0)
       
        if callee_file.endswith('.s'):
          print(f"The Callee {callee_name} @ {hex(callee_pc)} is an  Assembly function [SKIP]")
          return
        
        if callee_pc in type_methods:
             tag = "method"
           
        elif callee_category == "application":
             tag = "app"  
        
        elif callee_category in ["runtime_core", "runtime_internal", "stdlib_internal", "stdlib_public"]:
             tag = "stdlib"
        elif callee_category == "third_party":
             tag = "3rd-party"
        else:
             tag = callee_category
        

        register_state = {}
        stack_state = {}
        recovered_args = []
        call_index = None
        if caller_instructions:
           for idx, insn in enumerate(caller_instructions):
              if insn['mnemonic'].lower() == 'call':
                op_str = insn['op_str']
                if op_str.startswith('0x'):
                    try:
                        if int(op_str, 16) == callee_pc:
                            call_index = idx
                            break
                    except:
                        pass
        
        if callee_pc in type_methods:  
           
            type_method_info = type_methods[callee_pc]
            inCount = type_method_info['inCount']
            param_types = type_method_info['param_types']
            method_name = type_method_info.get('name', callee_name)
            method_pkg = type_method_info.get('pkg', '')
            print(f"The Callee {callee_name} @ {hex(callee_pc)} is a Type Method : {method_name},Package: {method_pkg}, Parameters: {inCount}") 
       
        
            # Analyze disassembly to recover actual argument values
            if caller_instructions:
               recovered_args = self._get_callee_parameters_from_type_method(
                 caller_pc=caller_pc,
                 caller_name=caller_name,
                 caller_instructions=caller_instructions,
                 callee_pc=callee_pc,
                 callee_name=callee_name,
                 type_method_info=type_method_info
               )
               if call_index is not None:
                register_state, stack_state = self._analyze_instructions_before_call(
                    caller_instructions, call_index, lookback=50
                )
               if recovered_args:
                  num_recovered = sum(1 for arg in recovered_args if arg['recovered'])
                  string_args = [arg for arg in recovered_args if arg['recovered'] and arg['inferred_type'] == 'string']

           
            if caller_instructions and call_index is not None:
               self._print_ida_style_call_analysis(
                caller_instructions, call_index, callee_name, callee_pc,
                register_state, stack_state, recovered_args, func_lookup=_func_functions_new
                )
            
        elif callee_category in ["runtime_core", "runtime_internal", "stdlib_internal", "stdlib_public", "autogenerated", "cgo", "unknown"]:
            print(f"The Callee {callee_name} @ {hex(callee_pc)} is a itnernal/runtime/stdlib/assmebly")
            func_parameters= self._lookup_func_name_from_external(callee_file, line_num, return_full_info=True)
            if func_parameters:
               
               if caller_instructions and func_parameters['num_params'] > 0:
                  recovered_args = self._get_callee_parameters_from_external_info(
                  caller_pc=caller_pc,
                  caller_name=caller_name,
                  caller_instructions=caller_instructions,
                  callee_pc=callee_pc,
                  callee_name=callee_name,
                  func_parameters=func_parameters
                  )
                  if call_index is not None:
                    register_state, stack_state = self._analyze_instructions_before_call(
                        caller_instructions, call_index, lookback=50
                    )

            if caller_instructions and call_index is not None and recovered_args:
              self._print_ida_style_call_analysis(
                caller_instructions, call_index, callee_name, callee_pc,
                register_state, stack_state, recovered_args, func_lookup=_func_functions_new
              )
        
        elif callee_category =="third_party":
            print(f" The Callee {callee_name} @ {hex(callee_pc)} is a Third-Party")
            actual_func_name = callee_name
            if '/' in callee_name:
                last_slash_idx = callee_name.rfind('/')
                after_slash = callee_name[last_slash_idx + 1:] 
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
                actual_func_name = parts[-1]
           
          
            func_info = self._lookup_third_party_function(callee_file, actual_func_name)

        
            if func_info:
            
                # Print receiver if it's a method
                if func_info.get('has_receiver') and func_info.get('receiver'):
                   recv = func_info['receiver']
                  
                # Print parameters
                params = func_info.get('full_params', func_info.get('params', []))
                for idx, param in enumerate(params):
                    is_recv = param.get('is_receiver', False)
                    prefix = "[recv]" if is_recv else f"[{idx}]"
                    
          
            else:
                print(f"  [!] Could not find function info for: {actual_func_name}")
                print(f"      File: {callee_file}")
       
       
        elif callee_category=="application":
            print(f" The Callee {callee_name} @ {hex(callee_pc)} is an Application") 
            if arginfo_data and caller_instructions:
               # Use static analysis!
               recovered_args = self._get_callee_parameters_static(caller_pc=caller_pc,caller_name=caller_name,caller_instructions=caller_instructions,
               callee_pc=callee_pc,callee_name=callee_name,callee_arginfo=arginfo_data)
               if recovered_args:
                  # Count how many were successfully recovered
                  num_recovered = sum(1 for arg in recovered_args if arg['recovered'])
                
            
                  # Example: Extract all string arguments
                  string_args = [arg for arg in recovered_args  if arg['recovered'] and arg['inferred_type'] == 'string']
               
               if call_index is not None:
                  register_state, stack_state = self._analyze_instructions_before_call(
                    caller_instructions, call_index, lookback=100
                  )
               if call_index is not None:
                  self._print_ida_style_call_analysis(
                    caller_instructions, call_index, callee_name, callee_pc,
                    register_state, stack_state, recovered_args, func_lookup=_func_functions_new)

            else:
                recovered_args = self._get_callee_parameters_from_argsmap( caller_pc=caller_pc, caller_name=caller_name,
                caller_instructions=caller_instructions, callee_pc=callee_pc, callee_name=callee_name, callee_argsmap=argsmap_data )
               
                if recovered_args:
                   num_recovered = sum(1 for arg in recovered_args if arg['recovered'])
                   string_args = [arg for arg in recovered_args  if arg['recovered'] and arg['inferred_type'] == 'string']
                  
                if call_index is not None and caller_instructions:
                   stack_state = self._analyze_instructions_before_call_stack_abi(
                    caller_instructions, call_index
                   )
            
                # ADD IDA-STYLE OUTPUT HERE
                if caller_instructions and call_index is not None:
                   self._print_ida_style_call_analysis(
                    caller_instructions, call_index, callee_name, callee_pc,
                    register_state, stack_state, recovered_args, func_lookup=_func_functions_new
                   )
       
    
    # =============================================================================
    # Disassembly Analysis
    # =============================================================================
    
    GO_ABI_INT_REGS = ['rax', 'rbx', 'rcx', 'rdi', 'rsi', 'r8', 'r9', 'r10', 'r11']

    # Floating-point registers (X0-X14)
    GO_ABI_FP_REGS = [f'xmm{i}' for i in range(15)]

    # =============================================================================
    # STATIC ARGUMENT RECOVERY FROM DISASSEMBLY (TYpe Methods)
    # =============================================================================
    def _get_callee_parameters_from_type_method(self, caller_pc: int, caller_name: str,
                                            caller_instructions: List[Dict],
                                            callee_pc: int, callee_name: str,
                                            type_method_info: Dict) -> List[Dict]:
      """
      Recover argument values for type methods using type method parameter info.
    
      type_method_info structure:
      {
        'name': method_name,
        'pkg': package_path,
        'inCount': number_of_params,
        'outCount': number_of_returns,
        'param_types': {
            0: {'param_name': '*TypeName', 'param_type': 'pointer', 'param_size': 8, 'type_ptr': addr},
            1: {'param_name': 'arg1', 'param_type': 'string', 'param_size': 16, 'type_ptr': addr},
            ...
        },
        'return_types': {...}
      }
      """
      if not type_method_info or not type_method_info.get('param_types'):
        return []
    
      param_types = type_method_info['param_types']
      inCount = type_method_info.get('inCount', 0)
      method_name = type_method_info.get('name', callee_name)
    
      # Convert type_method param_types format to the format expected by _map_params_to_registers
      # type_method format: {idx: {'param_name': ..., 'param_type': ..., 'param_size': ..., 'type_ptr': ...}}
      # expected format: [{'name': ..., 'type': ..., 'size': ...}, ...]
    
      params = []
      for idx in sorted(param_types.keys()):
        param_info = param_types[idx]
        params.append({
            'name': param_info.get('param_name', ''),
            'type': param_info.get('param_type', ''),
            'size': param_info.get('param_size', 8),
            'is_receiver': (idx == 0),  # First param is typically the receiver for methods
        })
    
      # Find the CALL instruction
      call_index = None
      for idx, insn in enumerate(caller_instructions):
        if insn['mnemonic'].lower() == 'call':
            op_str = insn['op_str']
            if op_str.startswith('0x'):
                try:
                    target = int(op_str, 16)
                    if target == callee_pc:
                        call_index = idx
                        break
                except:
                    pass
    
      if call_index is None:
        print(f"    [!] Could not find CALL to {method_name}")
        return []
    
      # Analyze instructions before CALL
      register_state, stack_state = self._analyze_instructions_before_call(
        caller_instructions, call_index, lookback=50
      )
    
      major, minor, _ = self.go_version_tuple
      is_go_117_plus = (major == 1 and minor >= 17)
    
      if is_go_117_plus:
        # Go 1.17+: Register-based ABI
        print(f"    Using Register-based ABI for type method")
        arg_mappings = self._map_params_to_registers(params)
        recovered_args = []
        for mapping in arg_mappings:
            recovered = self._recover_argument_from_registers(mapping, register_state, stack_state)
            recovered['param_name'] = mapping.get('param_name', '')
            recovered['param_type'] = mapping.get('param_type', '')
            recovered_args.append(recovered)
      else:
        # Go 1.16 and earlier: Stack-based ABI
        print(f"    Using Stack-based ABI for type method")
        arg_mappings = self._map_params_to_stack(params)
        recovered_args = []
        for mapping in arg_mappings:
            recovered = self._recover_argument_from_stack(mapping, register_state, stack_state)
            recovered['param_name'] = mapping.get('param_name', '')
            recovered['param_type'] = mapping.get('param_type', '')
            recovered_args.append(recovered)
     
      self._print_recovered_args(recovered_args)
      
      return recovered_args
    
    # =============================================================================
    # STATIC ARGUMENT RECOVERY FROM DISASSEMBLY (RUNTIME/STDLIB/INTERNAL)
    # =============================================================================
    
    def _get_callee_parameters_from_external_info(self, caller_pc: int, caller_name: str, 
                                            caller_instructions: List[Dict],
                                            callee_pc: int, callee_name: str, 
                                            func_parameters: Dict) -> List[Dict]:
      """
      Recover argument values for runtime/stdlib functions using external parameter info.
      """
      if not func_parameters or not func_parameters.get('params'):
        return []

      params = func_parameters['params']

      # Find the CALL instruction
      call_index = None
      for idx, insn in enumerate(caller_instructions):
        if insn['mnemonic'].lower() == 'call':
            op_str = insn['op_str']
            if op_str.startswith('0x'):
                try:
                    target = int(op_str, 16)
                    if target == callee_pc:
                        call_index = idx
                        break
                except:
                    pass

      if call_index is None:
        print(f"    [!] Could not find CALL to {callee_name}")
        return []

      #  Detect if this is a method call and prepend receiver
      is_method, receiver_info = self._detect_method_receiver(callee_name)
    
      if is_method and receiver_info:
        # Prepend receiver as first parameter
        params = [receiver_info] + list(params)
        print(f"     Detected method call, added receiver: {receiver_info}")

      # Map parameters to registers based on their types and sizes
      arg_mappings = self._map_params_to_registers(params)

      # Analyze instructions before CALL (backward walk)
      register_state, stack_state  = self._analyze_instructions_before_call(caller_instructions, call_index, lookback=50)
       
       
      major, minor, _ = self.go_version_tuple
      is_go_117_plus = (major == 1 and minor >= 17) 
      if is_go_117_plus:
        # Go 1.17+: Register-based ABI
        print(f"using Register-based ABI")
        arg_mappings = self._map_params_to_registers(params)
        recovered_args = []
        for mapping in arg_mappings:
            recovered = self._recover_argument_from_registers(mapping, register_state, stack_state)
            recovered['param_name'] = mapping.get('param_name', '')
            recovered['param_type'] = mapping.get('param_type', '')
            recovered_args.append(recovered)
      else:
        # Go 1.16 and earlier: Stack-based ABI
        print(f"using Stack-based ABI")
        arg_mappings = self._map_params_to_stack(params)
        recovered_args = []
        for mapping in arg_mappings:
            recovered = self._recover_argument_from_stack(mapping, register_state, stack_state)
            recovered['param_name'] = mapping.get('param_name', '')
            recovered['param_type'] = mapping.get('param_type', '')
            #recovered['display'] = mapping.get('display', '')
            recovered_args.append(recovered)
     
      self._print_recovered_args(recovered_args)
      
      return recovered_args


    
    
    def _detect_method_receiver(self, func_name: str) -> Tuple[bool, Optional[Dict]]:
      """
      Detect if a function is a method and extract receiver type info.
    
      Method patterns:
      - "pkg.(*Type).Method" -> pointer receiver *Type
      - "pkg.(Type).Method" -> value receiver Type
    
      Returns:
        (is_method, receiver_info_dict or None)
      """
      import re
    
      # Pattern for pointer receiver: pkg.(*Type).Method or (*Type).Method
      ptr_match = re.search(r'\.\(\*([^)]+)\)\.', func_name)
      if ptr_match:
        type_name = ptr_match.group(1)
        return (True, {
            'name': 'self',
            'type': f'*{type_name}',
            'size': 8,  # Pointer is always 8 bytes on 64-bit
            'is_receiver': True,
        })
    
      # Pattern for value receiver: pkg.(Type).Method
      val_match = re.search(r'\.\(([^*)][^)]*)\)\.', func_name)
      if val_match:
        type_name = val_match.group(1)
        # Value receiver size depends on type - estimate 8 for now
        # Could be improved by looking up type info
        return (True, {
            'name': 'self',
            'type': type_name,
            'size': 8,  # Approximation - actual size may vary
            'is_receiver': True,
        })
    
      return (False, None)
    

    
    
    def _map_params_to_registers(self, params: List[Dict]) -> List[Dict]:
      """
      Map parameters to ABI registers (Go 1.17+).
      """
      mappings = []
      reg_index = 0

      for param_idx, param in enumerate(params):
        param_name = param.get('name', '')
        param_type = param.get('type', '')
        param_size = param.get('size', 8)
        is_receiver = param.get('is_receiver', False)
        
        if reg_index >= len(self.GO_ABI_INT_REGS):
            mappings.append({
                'arg_index': param_idx,
                'param_name': param_name,
                'param_type': param_type,
                'location': 'stack',
                'registers': [],
                'inferred_type': 'stack_arg',
                'is_receiver': is_receiver,
            })
            continue
        
        inferred_type, num_regs = self._get_type_register_info(param_type, param_size)
        
        if reg_index + num_regs <= len(self.GO_ABI_INT_REGS):
            regs = self.GO_ABI_INT_REGS[reg_index:reg_index + num_regs]
            reg_index += num_regs
            location = 'registers'
        else:
            regs = []
            location = 'stack'
        
        mappings.append({
            'arg_index': param_idx,
            'param_name': param_name,
            'param_type': param_type,
            'location': location,
            'registers': regs,
            'inferred_type': inferred_type,
            'num_words': num_regs,
            'is_receiver': is_receiver,
        })

      return mappings

    
    


    def _resolve_register_value(self, register_state: Dict[str, Dict], 
                            reg_name: str, 
                            depth: int = 0,
                            visited: Optional[Set[str]] = None,
                            stack_state: Optional[Dict[int, Dict]] = None) -> Optional[Dict]:
 
      if visited is None:
        visited = set()
    
      if depth > 10:
        return None
    
      reg_name = reg_name.lower()
    
      if reg_name in visited:
        return None
    
      new_visited = visited | {reg_name}
    
      if reg_name not in register_state:
        return None
    
      assignment = register_state[reg_name]
      assign_type = assignment.get('type', '')
    
      # === ADDED: Handle 'constant' type explicitly ===
      if assign_type == 'constant':
        return {'type': 'constant', 'value': assignment['value']}
    
      # === ADDED: Handle 'rip_relative' type explicitly ===
      if assign_type == 'rip_relative':
        return {'type': 'rip_relative', 'target': assignment['target']}
    
      # === ADDED: Handle 'rip_load' type explicitly ===
      if assign_type == 'rip_load':
        return {'type': 'rip_load', 'target': assignment['target']}
    
      # Follow register copies
      if assign_type == 'register_copy':
        src_reg = assignment['src_reg'].lower()
        return self._resolve_register_value(register_state, src_reg, depth + 1, new_visited, stack_state)
    
      # Handle stack_load - look up value from stack_state
      if assign_type == 'stack_load' and stack_state is not None:
        offset = assignment.get('offset', 0)
        stack_entry = stack_state.get(offset)
        if stack_entry:
            if stack_entry.get('type') == 'resolved':
                return {'type': 'constant', 'value': stack_entry['value']}
            elif stack_entry.get('type') == 'runtime':
                return {'type': 'runtime', 'reason': stack_entry.get('reason', 'runtime')}
        # Return that it's a stack load we couldn't resolve
        return {'type': 'stack_load_unresolved', 'offset': offset}
    
      # Handle stack_address - the value IS the stack offset (relative address)
      if assign_type == 'stack_address':
        offset = assignment.get('offset', 0)
        return {'type': 'stack_address', 'offset': offset}
    
      # Unknown type - return as-is
      return assignment
    
    
   
   
   
   
   
    # =============================================================================
    # Called by Applciation Functions (ARGINFO)
    # =============================================================================

    def _get_callee_parameters_static(self, caller_pc: int, caller_name: str, caller_instructions: List[Dict],
                                   callee_pc: int, callee_name: str, callee_arginfo: Dict) -> List[Dict]:
      
   
      
      
      """
      Static analysis wrapper - recovers argument values from disassembly.
      """
      if not callee_arginfo:
        print(f"  [!] No ArgInfo available for {callee_name}")
        return []
    
      arginfo_args = callee_arginfo.get('args', [])
      total_frame_size = callee_arginfo.get('total_arg_frame_size', 0)
    
      print(f"ArgInfo: {len(arginfo_args)} arguments, {total_frame_size} bytes total")
    
      # Find the CALL to this callee in caller's instructions
      call_pc = None
      call_index = None
      for idx, insn in enumerate(caller_instructions):
        if insn['mnemonic'].lower() == 'call':
            op_str = insn['op_str']
            if op_str.startswith('0x'):
                try:
                    target = int(op_str, 16)
                    if target == callee_pc:
                        call_pc = insn['address']
                        call_index = idx
                        break
                except:
                    pass
    
      if call_pc is None:
        print(f"  [!] Could not find CALL to {callee_name} in caller instructions")
        print(f"  Total instructions in caller: {len(caller_instructions)}")
        # Show all CALLs in the function
        print(f"   All CALLs in caller:")
        for insn in caller_instructions:
            if insn['mnemonic'].lower() == 'call':
                print(f"    {hex(insn['address'])}: call {insn['op_str']}")
        return []

  
      start_debug = max(0, call_index - 20)
      for i in range(start_debug, call_index + 1):
        insn = caller_instructions[i]
        marker = " <<< CALL" if i == call_index else ""
     
      arg_mappings = self._map_arginfo_to_registers(arginfo_args)
      
      register_state, stack_state = self._analyze_instructions_before_call(caller_instructions, call_index, lookback=100)
      
      # Recover each argument
      recovered_args = []
      for mapping in arg_mappings:
        recovered = self._recover_argument_from_registers(mapping, register_state, stack_state)
        recovered_args.append(recovered)
      
      self._print_recovered_args(recovered_args)
      return recovered_args
    
    def _map_arginfo_to_registers(self, arginfo_args: List) -> List[Dict]:
      """
      Map ArgInfo argument structure to ABI registers.
    
      ArgInfo gives us:
      - Argument boundaries (offset, size)
      - Aggregate structure (lists indicate multi-field args like strings/slices)
    
      We map each 8-byte "word" to a register in ABI order.
    
      Args:
        arginfo_args: List of argument descriptors from ArgInfo
                     Each is either a dict {offset, size} or a list of dicts (aggregate)
    
      Returns:
        List of argument mappings with register assignments
      """
      mappings = []
      reg_index = 0  # Current integer register index
    
      for arg_idx, arg in enumerate(arginfo_args):
        if reg_index >= len(self.GO_ABI_INT_REGS):
            # Out of registers, remaining args go on stack
            mappings.append({
                'arg_index': arg_idx,
                'location': 'stack',
                'registers': [],
                'structure': arg,
                'inferred_type': 'stack_arg',
            })
            continue
        
        # Determine argument structure
        if isinstance(arg, dict):
            # Simple argument (single field)
            size = arg['size']
            num_words = (size + 7) // 8  # Round up to 8-byte words
            
            if reg_index + num_words <= len(self.GO_ABI_INT_REGS):
                regs = self.GO_ABI_INT_REGS[reg_index:reg_index + num_words]
                reg_index += num_words
                location = 'registers'
            else:
                regs = []
                location = 'stack'
            
            mappings.append({
                'arg_index': arg_idx,
                'location': location,
                'registers': regs,
                'structure': arg,
                'num_words': num_words,
                'inferred_type': self._infer_type_from_simple_arg(size),
            })
        
        elif isinstance(arg, list):
            # Aggregate argument (multiple fields)
            num_fields = len(arg)
            field_sizes = [f['size'] for f in arg]
            total_words = sum((s + 7) // 8 for s in field_sizes)
            
            if reg_index + total_words <= len(self.GO_ABI_INT_REGS):
                regs = self.GO_ABI_INT_REGS[reg_index:reg_index + total_words]
                reg_index += total_words
                location = 'registers'
            else:
                regs = []
                location = 'stack'
            
            # Infer type from aggregate structure
            inferred_type = self._infer_type_from_aggregate(num_fields, field_sizes)
            
            mappings.append({
                'arg_index': arg_idx,
                'location': location,
                'registers': regs,
                'structure': arg,
                'num_fields': num_fields,
                'field_sizes': field_sizes,
                'inferred_type': inferred_type,
            })
    
      return mappings




    def _infer_type_from_simple_arg(self, size: int) -> str:
      """Infer likely type from a simple (non-aggregate) argument size."""
      if size == 1:
        return 'bool/int8/uint8'
      elif size == 2:
        return 'int16/uint16'
      elif size == 4:
        return 'int32/uint32/float32'
      elif size == 8:
        return 'int64/uint64/pointer/uintptr'
      else:
        return f'unknown_{size}bytes'


    def _infer_type_from_aggregate(self, num_fields: int, field_sizes: List[int]) -> str:
      """
      Infer likely Go type from aggregate structure.
    
      Common patterns:
      - 2 fields × 8 bytes = string (ptr + len) or interface (type + data)
      - 3 fields × 8 bytes = slice (ptr + len + cap)
      """
      if num_fields == 2 and field_sizes == [8, 8]:
        return 'string_or_interface'  # Will disambiguate during analysis
      elif num_fields == 3 and field_sizes == [8, 8, 8]:
        return 'slice'
      elif all(s == field_sizes[0] for s in field_sizes):
        return f'array[{num_fields}]'
      else:
        return f'struct_{num_fields}fields'

    
    # =============================================================================
    #   # Called by Applciation Functions (ARGMAP)
    # =============================================================================

    def _get_callee_parameters_from_argsmap(self, caller_pc: int, caller_name: str,
                                    caller_instructions: List[Dict],
                                    callee_pc: int, callee_name: str,
                                    callee_argsmap: Dict) -> List[Dict]:
      """
      Recover argument values for Go < 1.17 using ArgsPointerMaps (stack-based ABI).
      Also handles closure context pointers.
      """
      print(f"\n{'='*70}")
      print(f"ARGSMAP-BASED ARGUMENT ANALYSIS (Go < 1.17)")
      print(f"{'='*70}")
      print(f"Caller: {caller_name} @ {hex(caller_pc)}")
      print(f"Callee: {callee_name} @ {hex(callee_pc)}")
      print(f"callee_argsmap: {callee_argsmap}")

      if not callee_argsmap:
        print(f"  [!] No ArgsPointerMaps available")
        return []

      total_arg_bytes = callee_argsmap.get('total_arg_bytes', 0)
      num_slots = callee_argsmap.get('num_slots', 0)
      pointer_slots = set(callee_argsmap.get('pointer_slots', []))

      # Detect closure
      is_closure = False

      print(f"\nArgsPointerMaps Info:")
      print(f"  Total argument bytes: {total_arg_bytes}")
      print(f"  Number of slots: {num_slots}")
      print(f"  Pointer slots: {sorted(pointer_slots)}")
     

      if not caller_instructions:
        print(f"  [!] No caller instructions available")
        return []

      # Find the CALL instruction
      call_index = None
      call_type = 'direct'  # 'direct' or 'indirect'

      for idx, insn in enumerate(caller_instructions):
        if insn['mnemonic'].lower() == 'call':
            op_str = insn['op_str']
            
            # Direct call: call 0x6e56c0
            if op_str.startswith('0x'):
                try:
                    target = int(op_str, 16)
                    if target == callee_pc:
                        call_index = idx
                        call_type = 'direct'
                        break
                except:
                    pass
            
            # Indirect call through register: call rax, call [rdx], etc.
            # For closures, we might see: call qword ptr [rdx]
            elif '.func' in callee_name  and ('rax' in op_str or 'rdx' in op_str or 'rcx' in op_str):
                call_index = idx
                is_closure=True
                call_type = 'indirect'

      if call_index is None:
        print(f"  [!] Could not find CALL to {callee_name}")
        return []
      print(f"  Is closure: {is_closure}")
      print(f"\nFound CALL instruction at index {call_index} (type: {call_type})")

      # Debug: Show instructions before CALL
      print(f"\n Instructions before CALL (last 15):")
      start_debug = max(0, call_index - 15)
      for i in range(start_debug, call_index + 1):
        insn = caller_instructions[i]
        marker = " <<< CALL" if i == call_index else ""
        print(f"  [{i:4d}] {hex(insn['address'])}: {insn['mnemonic']:<10} {insn['op_str']:<40}{marker}")

      # Analyze instructions - Go < 1.17 uses stack-based ABI, only need stack_state
      stack_state = self._analyze_instructions_before_call_stack_abi(caller_instructions, call_index)

      print(f"\n Stack State:")
      for offset in sorted(stack_state.keys()):
        if offset < 0x100:  # Only show argument range
            entry = stack_state[offset]
            print(f"  [rsp+{offset:3d}]: {entry}")

      recovered_args = []
  
      # === Handle Closure Context ===
      if is_closure and call_type == 'indirect':
        # For closures, RDX contains the closure context pointer
        # We need to find RDX value by scanning instructions before CALL
        rdx_value = None
        rdx_type = None
        
        for i in range(call_index - 1, max(0, call_index - 30), -1):
            insn = caller_instructions[i]
            if insn['mnemonic'].lower() == 'call':
                break  # RDX clobbered by previous call
            
            assignment = self._parse_instruction_for_assignment(insn)
            if assignment and assignment.get('dest_reg', '').lower() == 'rdx':
                rdx_type = assignment['type']
                
                if rdx_type == 'rip_relative':
                    rdx_value = assignment['target']
                elif rdx_type == 'constant':
                    rdx_value = assignment['value']
                elif rdx_type == 'rip_load':
                    rdx_value = self._read_pointer_at_address(assignment['target'])
                elif rdx_type == 'stack_load':
                    # RDX was loaded from stack - try to resolve
                    stack_offset = assignment.get('offset', 0)
                    stack_entry = stack_state.get(stack_offset)
                    if stack_entry and stack_entry.get('type') == 'resolved':
                        rdx_value = stack_entry['value']
                elif rdx_type == 'stack_address':
                    # LEA rdx, [rsp + offset] - rdx points to stack location
                    rdx_value = assignment.get('offset', 0)
                    print(f"  RDX points to stack offset: {rdx_value}")
                break
        
        closure_context = rdx_value
        
        if closure_context and isinstance(closure_context, int) and closure_context > 0x10000:
            print(f"  Closure context pointer: {hex(closure_context)}")
            
            # Try to read closure structure
            try:
                layer = self.context.layers[self.layer_name]
                
                # Read first few words of closure
                closure_data = layer.read(closure_context, 64, pad=True)
                
                print(f"  Closure data (first 64 bytes):")
                for i in range(0, min(64, len(closure_data)), 8):
                    val = int.from_bytes(closure_data[i:i+8], 'little')
                    print(f"    +{i:2d}: {hex(val)}")
                
                # First word should be function pointer
                func_ptr = int.from_bytes(closure_data[0:8], 'little')
                if func_ptr == callee_pc:
                    print(f"  ✓ Confirmed: closure[0] = function pointer")
                
                # Captured variables start at offset 8
                if total_arg_bytes > 0:
                    print(f"\n  Captured variables ({total_arg_bytes} bytes):")
                    for slot_idx in range(num_slots):
                        offset = 8 + (slot_idx * 8)  # Skip func ptr
                        if offset + 8 <= len(closure_data):
                            val = int.from_bytes(closure_data[offset:offset+8], 'little')
                            is_ptr = (slot_idx * 8) in pointer_slots
                            ptr_marker = " (PTR)" if is_ptr else ""
                            print(f"    Capture[{slot_idx}]: {hex(val)}{ptr_marker}")
                            
                            # Try to read string if it's a pointer
                            if is_ptr and val > 0x10000:
                                maybe_str = self._try_read_string_at_address(val, 64)
                                if maybe_str:
                                    print(f"      -> \"{maybe_str}\"")
                            
                            recovered_args.append({
                                'arg_index': slot_idx,
                                'inferred_type': 'pointer' if is_ptr else 'integer',
                                'recovered': True,
                                'value': val,
                                'slots': [slot_idx * 8],
                                'source': 'closure_context',
                            })
            except Exception as e:
                print(f"  [!] Error reading closure context: {e}")
        else:
            print(f"  [!] Could not determine closure context pointer")
            print(f"      rdx_value: {rdx_value}, rdx_type: {rdx_type}")

      # === Handle Regular Stack Arguments ===
      else:
        # Build slot values from stack state
        max_slots_to_check = max(num_slots * 2, 4) 
        slot_values = {}
        for slot_idx in range(max_slots_to_check):
            offset = slot_idx * 8
            is_pointer = offset in pointer_slots
            entry = stack_state.get(offset)
            
            if entry is None:
                slot_values[offset] = {
                    'value': None,
                    'is_pointer': is_pointer,
                    'resolved': False,
                    'reason': 'no_stack_entry'
                }
            elif entry.get('type') == 'resolved':
                slot_values[offset] = {
                    'value': entry['value'],
                    'is_pointer': is_pointer,
                    'resolved': True
                }
            elif entry.get('type') == 'runtime':
                slot_values[offset] = {
                    'value': None,
                    'is_pointer': is_pointer,
                    'resolved': False,
                    'reason': entry.get('reason', 'runtime')
                }
            else:
                slot_values[offset] = {
                    'value': None,
                    'is_pointer': is_pointer,
                    'resolved': False,
                    'reason': entry.get('type', 'unknown')
                }
        
        # Infer arguments
        arguments = self._infer_arguments_from_slots(slot_values, pointer_slots, max_slots_to_check, max_arg_bytes=total_arg_bytes)

        
        # Recover values
        for arg in arguments:
            recovered = self._recover_argument_from_slots(arg, slot_values)
            recovered_args.append(recovered)

      # Print results
      print(f"\nRecovered Arguments:")
      print(f"{'-'*70}")

      for arg in recovered_args:
        arg_idx = arg['arg_index']
        inferred_type = arg.get('inferred_type', 'unknown')
        recovered = arg.get('recovered', False)
        value = arg.get('value')
        source = arg.get('source', 'stack')
        
        status = "✓" if recovered else "✗"
        
        if recovered:
            if isinstance(value, int):
                # Try to read as string if it looks like a pointer
                if value > 0x400000:
                    maybe_string = self._try_read_string_at_address(value, 64)
                    if maybe_string and len(maybe_string) > 0:
                        print(f"  [{status}] Arg {arg_idx} ({inferred_type}): {hex(value)} -> \"{maybe_string}\"")
                    else:
                        print(f"  [{status}] Arg {arg_idx} ({inferred_type}): {hex(value)}")
                else:
                    print(f"  [{status}] Arg {arg_idx} ({inferred_type}): {value} ({hex(value)})")
            elif isinstance(value, dict):
                print(f"  [{status}] Arg {arg_idx} ({inferred_type}): {value}")
            elif isinstance(value, str):
                print(f"  [{status}] Arg {arg_idx} ({inferred_type}): \"{value}\"")
            else:
                print(f"  [{status}] Arg {arg_idx} ({inferred_type}): {value}")
        else:
            reason = arg.get('reason', 'unknown')
            print(f"  [{status}] Arg {arg_idx} ({inferred_type}): <not recovered> ({reason})")

      print(f"{'='*70}\n")

      return recovered_args

    
    
    def _infer_arguments_from_slots(self, slot_values: Dict, pointer_slots: Set[int], 
                             num_slots: int, max_arg_bytes: int = None) -> List[Dict]:
      """
      Infer logical arguments from raw slot data using heuristics.
    
      Args:
        slot_values: Dict of slot offset -> value info
        pointer_slots: Set of offsets that are known to be pointers
        num_slots: Number of slots we're checking
        max_arg_bytes: Maximum bytes that are actually arguments (from argsmap)
      """
      arguments = []
      consumed = set()
      arg_index = 0

      offsets = sorted(slot_values.keys())
    
      # If max_arg_bytes is provided, only consider slots within that range as primary args
      # But we still look ahead to detect string/slice patterns
      if max_arg_bytes is None:
        max_arg_bytes = num_slots * 8

      i = 0
      while i < len(offsets):
        offset = offsets[i]
        
        if offset in consumed:
            i += 1
            continue
        
        # CRITICAL: Don't start a NEW argument beyond max_arg_bytes
        # But DO allow consuming slots beyond it for string length, slice cap, etc.
        if offset >= max_arg_bytes:
            break
        
        slot = slot_values.get(offset, {})
        is_pointer = slot.get('is_pointer', offset in pointer_slots)
        value = slot.get('value')
        resolved = slot.get('resolved', False)
        
        # Check for string pattern: pointer at offset N, followed by value at N+8
        if is_pointer and (offset + 8) in slot_values:
            next_slot = slot_values.get(offset + 8, {})
            next_value = next_slot.get('value')
            next_is_pointer = next_slot.get('is_pointer', (offset + 8) in pointer_slots)
            
            # String pattern: pointer + non-pointer that looks like a length
            if not next_is_pointer and next_value is not None and 0 <= next_value < 100000:
                arguments.append({
                    'arg_index': arg_index,
                    'inferred_type': 'string',
                    'slots': [offset, offset + 8],
                    'ptr_offset': offset,
                    'len_offset': offset + 8,
                })
                consumed.add(offset)
                consumed.add(offset + 8)
                arg_index += 1
                i += 1
                # Skip to after the length slot
                while i < len(offsets) and offsets[i] <= offset + 8:
                    i += 1
                continue
            
            # Check for slice pattern: pointer + len + cap (3 consecutive slots)
            if (offset + 16) in slot_values:
                third_slot = slot_values.get(offset + 16, {})
                third_value = third_slot.get('value')
                third_is_pointer = third_slot.get('is_pointer', (offset + 16) in pointer_slots)
                
                if (not next_is_pointer and not third_is_pointer and 
                    next_value is not None and third_value is not None and
                    0 <= next_value < 100000 and 0 <= third_value < 100000):
                    arguments.append({
                        'arg_index': arg_index,
                        'inferred_type': 'slice',
                        'slots': [offset, offset + 8, offset + 16],
                        'ptr_offset': offset,
                        'len_offset': offset + 8,
                        'cap_offset': offset + 16,
                    })
                    consumed.add(offset)
                    consumed.add(offset + 8)
                    consumed.add(offset + 16)
                    arg_index += 1
                    i += 1
                    while i < len(offsets) and offsets[i] <= offset + 16:
                        i += 1
                    continue
            
            # Interface pattern: two consecutive pointers
            if next_is_pointer:
                arguments.append({
                    'arg_index': arg_index,
                    'inferred_type': 'interface',
                    'slots': [offset, offset + 8],
                    'type_offset': offset,
                    'data_offset': offset + 8,
                })
                consumed.add(offset)
                consumed.add(offset + 8)
                arg_index += 1
                i += 1
                while i < len(offsets) and offsets[i] <= offset + 8:
                    i += 1
                continue
        
        # Single slot argument
        if is_pointer:
            arguments.append({
                'arg_index': arg_index,
                'inferred_type': 'pointer',
                'slots': [offset],
            })
        else:
            arguments.append({
                'arg_index': arg_index,
                'inferred_type': 'integer',
                'slots': [offset],
            })
        
        consumed.add(offset)
        arg_index += 1
        i += 1

      return arguments
   
   
    def _recover_argument_from_slots(self, arg_info: Dict, slot_values: Dict) -> Dict:
      """
      Recover the actual value of an argument from its slots.
      """
      result = {
        'arg_index': arg_info['arg_index'],
        'inferred_type': arg_info['inferred_type'],
        'slots': arg_info['slots'],
        'recovered': False,
        'value': None,
        'reason': None,
      }
    
      inferred_type = arg_info['inferred_type']
    
      # === String ===
      if inferred_type == 'string':
        ptr_offset = arg_info['ptr_offset']
        len_offset = arg_info['len_offset']
        
        ptr_slot = slot_values.get(ptr_offset, {})
        len_slot = slot_values.get(len_offset, {})
        
        ptr_value = ptr_slot.get('value')
        len_value = len_slot.get('value')
        
        if ptr_value is not None and len_value is not None:
            if 0 < len_value < 10000 and ptr_value > 0x10000:
                string_data = self._try_read_string_at_address(ptr_value, len_value)
                if string_data:
                    result['recovered'] = True
                    result['value'] = string_data
                    return result
        
        # Partial recovery
        if ptr_value is not None or len_value is not None:
            result['value'] = {'ptr': ptr_value, 'len': len_value}
            if ptr_value is not None and len_value is None:
                # Try reading as C-string
                string_data = self._try_read_string_at_address(ptr_value, 256)
                if string_data:
                    result['recovered'] = True
                    result['value'] = string_data
                    result['reason'] = 'len_unknown_read_as_cstring'
                    return result
        
        result['reason'] = 'missing_ptr_or_len'
        return result
    
      # === Slice ===
      elif inferred_type == 'slice':
        ptr_offset = arg_info['ptr_offset']
        len_offset = arg_info['len_offset']
        cap_offset = arg_info['cap_offset']
        
        ptr_slot = slot_values.get(ptr_offset, {})
        len_slot = slot_values.get(len_offset, {})
        cap_slot = slot_values.get(cap_offset, {})
        
        ptr_value = ptr_slot.get('value')
        len_value = len_slot.get('value')
        cap_value = cap_slot.get('value')
        
        if ptr_value is not None or len_value is not None or cap_value is not None:
            result['recovered'] = True
            result['value'] = {
                'ptr': hex(ptr_value) if ptr_value else '0x0',
                'len': len_value,
                'cap': cap_value,
            }
        else:
            result['reason'] = 'no_values_resolved'
        
        return result
    
      # === Interface ===
      elif inferred_type == 'interface':
        type_offset = arg_info['type_offset']
        data_offset = arg_info['data_offset']
        
        type_slot = slot_values.get(type_offset, {})
        data_slot = slot_values.get(data_offset, {})
        
        type_value = type_slot.get('value')
        data_value = data_slot.get('value')
        
        if type_value is not None or data_value is not None:
            result['recovered'] = True
            result['value'] = {
                'type_ptr': hex(type_value) if type_value else '0x0',
                'data_ptr': hex(data_value) if data_value else '0x0',
            }
        else:
            result['reason'] = 'no_values_resolved'
        
        return result
    
      # === Pointer ===
      elif inferred_type == 'pointer':
        slot = slot_values.get(arg_info['slots'][0], {})
        value = slot.get('value')
        
        if value is not None:
            result['recovered'] = True
            result['value'] = value
        else:
            result['reason'] = slot.get('reason', 'not_resolved')
        
        return result
    
      # === Integer/Scalar ===
      elif inferred_type == 'integer':
        slot = slot_values.get(arg_info['slots'][0], {})
        value = slot.get('value')
        
        if value is not None:
            result['recovered'] = True
            result['value'] = value
        else:
            result['reason'] = slot.get('reason', 'not_resolved')
        
        return result
    
      # === Unknown ===
      else:
        result['reason'] = 'unknown_type'
        return result

    # =============================================================================
    # Matual Between ALl (INSTRUCTION ANALYSIS)
    # =============================================================================

    def _analyze_instructions_before_call_stack_abi(self, instructions: List[Dict], call_index: int, lookback: int = 100) -> Dict[int, Dict]:
      """
      Analyze instructions before CALL for stack-based ABI (Go < 1.17).
    
      IMPORTANT: For stack-based ABI, we should NOT stop at intermediate CALLs
      because stack arguments are set up earlier and persist across calls.
      We only mark registers as clobbered, not stack slots.
    
      Returns:
          stack_state: Dict mapping stack offsets to values
      """
      stack_state = {}
      register_state = {}
    
      start_index = max(0, call_index - lookback)
      found_stack_offsets = set()
    
      for i in range(call_index - 1, start_index - 1, -1):
        insn = instructions[i]
        mnemonic = insn['mnemonic'].lower()
        
        # Skip control flow
        if mnemonic in ['nop', 'ret', 'jmp', 'je', 'jne', 'jbe', 'ja', 'jl', 'jg', 'jle', 'jge']:
            continue
        
        # At intermediate CALL: mark registers as clobbered, BUT CONTINUE SCANNING
        # Stack values persist across calls in stack-based ABI!
        if mnemonic == 'call':
            for reg in ['rax', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11']:
                if reg not in register_state:  # Don't overwrite if already set
                    register_state[reg] = {'type': 'runtime', 'reason': 'call_return'}
            continue  # DON'T break - continue scanning for stack stores
        
        assignment = self._parse_instruction_for_assignment(insn)
        if assignment is None:
            continue
        
        dest = assignment['dest_reg']
        
        # === STACK STORE (what we care about for stack ABI) ===
        if dest.startswith('stack_'):
            offset = assignment['offset']
            
            # Only record first write (closest to CALL)
            if offset in found_stack_offsets:
                continue
            found_stack_offsets.add(offset)
            
            if assignment['type'] == 'stack_constant':
                stack_state[offset] = {'type': 'resolved', 'value': assignment['value']}
            
            elif assignment['type'] == 'stack_from_register':
                src_reg = assignment['src_reg'].lower()
                
                if src_reg in register_state:
                    reg_info = register_state[src_reg]
                    
                    if reg_info['type'] == 'constant':
                        stack_state[offset] = {'type': 'resolved', 'value': reg_info['value']}
                    elif reg_info['type'] == 'rip_relative':
                        stack_state[offset] = {'type': 'resolved', 'value': reg_info['target']}
                    elif reg_info['type'] == 'rip_load':
                        loaded = self._read_pointer_at_address(reg_info['target'])
                        if loaded is not None:
                            stack_state[offset] = {'type': 'resolved', 'value': loaded}
                        else:
                            stack_state[offset] = {'type': 'resolved', 'value': reg_info['target']}
                    elif reg_info['type'] == 'runtime':
                        stack_state[offset] = {'type': 'runtime', 'reason': reg_info.get('reason', 'runtime')}
                    else:
                        stack_state[offset] = {'type': 'pending', 'src_reg': src_reg}
                else:
                    stack_state[offset] = {'type': 'pending', 'src_reg': src_reg}
        
        # === REGISTER ASSIGNMENT (track for resolving stack stores) ===
        else:
            dest_lower = dest.lower()
            
            # Don't overwrite - we want the value closest to the CALL
            if dest_lower in register_state:
                continue
            
            if assignment['type'] == 'constant':
                register_state[dest_lower] = {'type': 'constant', 'value': assignment['value']}
            elif assignment['type'] == 'rip_relative':
                register_state[dest_lower] = {'type': 'rip_relative', 'target': assignment['target']}
            elif assignment['type'] == 'rip_load':
                register_state[dest_lower] = {'type': 'rip_load', 'target': assignment['target']}
            elif assignment['type'] == 'register_copy':
                src = assignment['src_reg'].lower()
                if src in register_state:
                    register_state[dest_lower] = register_state[src].copy()
                else:
                    register_state[dest_lower] = {'type': 'register_copy', 'src_reg': src}
            elif assignment['type'] == 'stack_load':
                register_state[dest_lower] = {'type': 'stack_load', 'offset': assignment['offset']}
            elif assignment['type'] == 'stack_address':
                register_state[dest_lower] = {'type': 'stack_address', 'offset': assignment['offset']}
    
      # Resolve pending entries
      for offset, entry in list(stack_state.items()):
        if entry.get('type') == 'pending':
            src_reg = entry.get('src_reg')
            if src_reg in register_state:
                reg_info = register_state[src_reg]
                if reg_info['type'] == 'constant':
                    stack_state[offset] = {'type': 'resolved', 'value': reg_info['value']}
                elif reg_info['type'] == 'rip_relative':
                    stack_state[offset] = {'type': 'resolved', 'value': reg_info['target']}
                elif reg_info['type'] == 'rip_load':
                    loaded = self._read_pointer_at_address(reg_info['target'])
                    stack_state[offset] = {'type': 'resolved', 'value': loaded if loaded else reg_info['target']}
                else:
                    stack_state[offset] = {'type': 'runtime', 'reason': f'from_{reg_info["type"]}'}
            else:
                stack_state[offset] = {'type': 'runtime', 'reason': 'unknown_register'}
    
        if entry.get('type') == 'pending' and 'src_offset' in entry:
            src_offset = entry['src_offset']
            if src_offset in stack_state:
                src_entry = stack_state[src_offset]
                if src_entry.get('type') == 'resolved':
                    stack_state[offset] = src_entry.copy()
      
      return stack_state
    
    
    
    
    
    
    def _analyze_instructions_before_call(self, instructions: List[Dict], call_index: int, 
                                       lookback: int = 100) -> Tuple[Dict[str, Dict], Dict[int, Dict]]:

  
      register_state = {}
      stack_state = {}
    
      start_index = max(0, call_index - lookback)
    
      # Track which registers/stack we've already found
      found_registers = set()
      found_stack_offsets = set()
    
      for i in range(call_index - 1, start_index - 1, -1):
        insn = instructions[i]
        mnemonic = insn['mnemonic'].lower()
        
        # Skip control flow (but not CALL)
        if mnemonic in ['nop', 'ret', 'jmp', 'je', 'jne', 'jbe', 'ja', 'jl', 'jg', 'jle', 'jge']:
            continue
        
        # === STOP AT INTERMEDIATE CALL ===
        # Everything before this CALL was setting up arguments for IT, not for our target
        if mnemonic == 'call':
            break
        
        # Parse the instruction
        assignment = self._parse_instruction_for_assignment(insn)
        if assignment is None:
            continue
        
        dest = assignment['dest_reg']
        
        # === STACK STORE ===
        if dest.startswith('stack_'):
            offset = assignment['offset']
            
            if offset in found_stack_offsets:
                continue
            
            found_stack_offsets.add(offset)
            
            if assignment['type'] == 'stack_constant':
                stack_state[offset] = {'type': 'resolved', 'value': assignment['value']}
            
            elif assignment['type'] == 'stack_from_register':
                src_reg = assignment['src_reg'].lower()
                
                if src_reg in register_state:
                    reg_info = register_state[src_reg]
                    
                    if reg_info['type'] == 'constant':
                        stack_state[offset] = {'type': 'resolved', 'value': reg_info['value']}
                    elif reg_info['type'] == 'rip_relative':
                        stack_state[offset] = {'type': 'resolved', 'value': reg_info['target']}
                    elif reg_info['type'] == 'rip_load':
                        loaded = self._read_pointer_at_address(reg_info['target'])
                        if loaded is not None:
                            stack_state[offset] = {'type': 'resolved', 'value': loaded}
                        else:
                            stack_state[offset] = {'type': 'resolved', 'value': reg_info['target']}
                    else:
                        stack_state[offset] = {'type': 'pending', 'src_reg': src_reg, 'instr_idx': i}
                else:
                    stack_state[offset] = {'type': 'pending', 'src_reg': src_reg, 'instr_idx': i}
        
        # === REGISTER ASSIGNMENT ===
        else:
            dest_lower = dest.lower()
            
            if dest_lower in found_registers:
                continue
            
            found_registers.add(dest_lower)
            
            if assignment['type'] == 'constant':
                register_state[dest_lower] = {'type': 'constant', 'value': assignment['value']}
            elif assignment['type'] == 'rip_relative':
                register_state[dest_lower] = {'type': 'rip_relative', 'target': assignment['target']}
            elif assignment['type'] == 'rip_load':
                register_state[dest_lower] = {'type': 'rip_load', 'target': assignment['target']}
            elif assignment['type'] == 'register_copy':
                src = assignment['src_reg'].lower()
                if src in register_state:
                    register_state[dest_lower] = register_state[src].copy()
                else:
                    register_state[dest_lower] = {'type': 'register_copy', 'src_reg': src}
            elif assignment['type'] == 'stack_load':
                register_state[dest_lower] = {'type': 'stack_load', 'offset': assignment['offset']}
            elif assignment['type'] == 'stack_address':
                register_state[dest_lower] = {'type': 'stack_address', 'offset': assignment['offset']}
            else:
                register_state[dest_lower] = assignment
    
      # === Resolve pending stack entries ===
      for offset, entry in list(stack_state.items()):
        if entry.get('type') == 'pending':
            src_reg = entry.get('src_reg')
            if src_reg in register_state:
                reg_info = register_state[src_reg]
                if reg_info['type'] == 'constant':
                    stack_state[offset] = {'type': 'resolved', 'value': reg_info['value']}
                elif reg_info['type'] == 'rip_relative':
                    stack_state[offset] = {'type': 'resolved', 'value': reg_info['target']}
                elif reg_info['type'] == 'rip_load':
                    loaded = self._read_pointer_at_address(reg_info['target'])
                    if loaded is not None:
                        stack_state[offset] = {'type': 'resolved', 'value': loaded}
                    else:
                        stack_state[offset] = {'type': 'resolved', 'value': reg_info['target']}
                else:
                    stack_state[offset] = {'type': 'runtime', 'reason': f'from_{reg_info["type"]}'}
            else:
                stack_state[offset] = {'type': 'runtime', 'reason': 'unknown_register'}
    
      # === Handle stack_load in registers by looking up stack_state ===
      for reg, info in list(register_state.items()):
        if info.get('type') == 'stack_load':
            offset = info.get('offset', 0)
            if offset in stack_state:
                stack_entry = stack_state[offset]
                if stack_entry.get('type') == 'resolved':
                    register_state[reg] = {'type': 'constant', 'value': stack_entry['value']}
                else:
                    register_state[reg] = {'type': 'runtime', 'reason': f'from_stack_{stack_entry.get("type", "unknown")}'}
            else:
                # Stack offset not in our captured state - it was set before
                # This could be a function parameter passed to us
                register_state[reg] = {'type': 'stack_load_unresolved', 'offset': offset}
    
      return register_state, stack_state

   
   
   
    def _parse_instruction_for_assignment(self, insn: Dict) -> Optional[Dict]:
      """
      Parse an instruction to find register or stack assignments.
      """
      mnemonic = insn["mnemonic"].lower()
      inst = insn.get("cs_insn")

      if inst is None:
        return None

      if not hasattr(inst, 'operands') or inst.operands is None or len(inst.operands) == 0:
        return None

      # ---------------- LEA ----------------
      if mnemonic == "lea":
        if len(inst.operands) < 2:
            return None
        dst, src = inst.operands[0], inst.operands[1]
        
        if dst.type != X86_OP_REG or src.type != X86_OP_MEM:
            return None

        # Check for RIP-relative
        target = self._get_rip_relative_target(inst)
        if target is not None:
            dest = self._normalize_register(inst.reg_name(dst.reg))
            return {"dest_reg": dest, "type": "rip_relative", "target": target, "instruction": insn}
        
        # Also handle LEA from stack (e.g., lea rsi, [rsp + 0xc0])
        base_reg = inst.reg_name(src.mem.base) if src.mem.base != 0 else None
        if base_reg == 'rsp' and src.mem.index == 0:
            dest = self._normalize_register(inst.reg_name(dst.reg))
            offset = src.mem.disp
            # This is a "stack address" - the register gets the ADDRESS of the stack location
            return {"dest_reg": dest, "type": "stack_address", "offset": offset, "instruction": insn}
        
        return None

      # ---------------- MOV ----------------
      if mnemonic in ["mov", "movq", "movabs", "movl"]:
        if len(inst.operands) < 2:
            return None
        dst, src = inst.operands[0], inst.operands[1]
        
        # === Stack store: mov [rsp + offset], imm ===
        if dst.type == X86_OP_MEM and src.type == X86_OP_IMM:
            base_reg = inst.reg_name(dst.mem.base) if dst.mem.base != 0 else None
            
            if base_reg == 'rsp' and dst.mem.index == 0:
                offset = dst.mem.disp
                value = src.imm
                if value < 0:
                    value = value & 0xFFFFFFFFFFFFFFFF
                return {
                    "dest_reg": f"stack_{offset}",
                    "type": "stack_constant",
                    "offset": offset,
                    "value": value,
                    "instruction": insn
                }
        
        # === Stack store: mov [rsp + offset], reg ===
        if dst.type == X86_OP_MEM and src.type == X86_OP_REG:
            base_reg = inst.reg_name(dst.mem.base) if dst.mem.base != 0 else None
            
            if base_reg == 'rsp' and dst.mem.index == 0:
                offset = dst.mem.disp
                src_reg = self._normalize_register(inst.reg_name(src.reg))
                return {
                    "dest_reg": f"stack_{offset}",
                    "type": "stack_from_register",
                    "offset": offset,
                    "src_reg": src_reg,
                    "instruction": insn
                }
        
        # === Register destination ===
        if dst.type != X86_OP_REG:
            return None

        dest = self._normalize_register(inst.reg_name(dst.reg))

        # mov reg, [rip+disp]
        if src.type == X86_OP_MEM:
            target = self._get_rip_relative_target(inst)
            if target is not None:
                return {"dest_reg": dest, "type": "rip_load", "target": target, "instruction": insn}
            
            # mov reg, [rsp+offset] - load from stack
            base_reg = inst.reg_name(src.mem.base) if src.mem.base != 0 else None
            if base_reg == 'rsp' and src.mem.index == 0:
                offset = src.mem.disp
                return {"dest_reg": dest, "type": "stack_load", "offset": offset, "instruction": insn}
            
            return None

        # mov reg, imm
        if src.type == X86_OP_IMM:
            value = src.imm
            if value < 0:
                value = value & 0xFFFFFFFFFFFFFFFF
            return {"dest_reg": dest, "type": "constant", "value": value, "instruction": insn}

        # mov reg, reg
        if src.type == X86_OP_REG:
            src_reg = self._normalize_register(inst.reg_name(src.reg))
            return {"dest_reg": dest, "type": "register_copy", "src_reg": src_reg, "instruction": insn}

        return None

      # ---------------- XOR ----------------
      if mnemonic == "xor":
        if len(inst.operands) < 2:
            return None
        dst, src = inst.operands[0], inst.operands[1]
        
        if dst.type == X86_OP_REG and src.type == X86_OP_REG and dst.reg == src.reg:
            dest = self._normalize_register(inst.reg_name(dst.reg))
            return {"dest_reg": dest, "type": "constant", "value": 0, "instruction": insn}

      return None



    def _normalize_register(self, reg_name: str) -> str:
      """
      Normalize x86 register names to their 64-bit equivalents.
    
      Examples:
        eax -> rax
        ebx -> rbx
        al -> rax
        r8d -> r8
      """
      reg_name = reg_name.lower()
    
      # 32-bit to 64-bit mappings
      reg_32_to_64 = {
        'eax': 'rax', 'ebx': 'rbx', 'ecx': 'rcx', 'edx': 'rdx',
        'esi': 'rsi', 'edi': 'rdi', 'ebp': 'rbp', 'esp': 'rsp',
        'r8d': 'r8', 'r9d': 'r9', 'r10d': 'r10', 'r11d': 'r11',
        'r12d': 'r12', 'r13d': 'r13', 'r14d': 'r14', 'r15d': 'r15',
      }
    
      # 16-bit to 64-bit mappings
      reg_16_to_64 = {
        'ax': 'rax', 'bx': 'rbx', 'cx': 'rcx', 'dx': 'rdx',
        'si': 'rsi', 'di': 'rdi', 'bp': 'rbp', 'sp': 'rsp',
        'r8w': 'r8', 'r9w': 'r9', 'r10w': 'r10', 'r11w': 'r11',
        'r12w': 'r12', 'r13w': 'r13', 'r14w': 'r14', 'r15w': 'r15',
      }
    
      # 8-bit to 64-bit mappings
      reg_8_to_64 = {
        'al': 'rax', 'bl': 'rbx', 'cl': 'rcx', 'dl': 'rdx',
        'ah': 'rax', 'bh': 'rbx', 'ch': 'rcx', 'dh': 'rdx',
        'sil': 'rsi', 'dil': 'rdi', 'bpl': 'rbp', 'spl': 'rsp',
        'r8b': 'r8', 'r9b': 'r9', 'r10b': 'r10', 'r11b': 'r11',
        'r12b': 'r12', 'r13b': 'r13', 'r14b': 'r14', 'r15b': 'r15',
      }
    
      if reg_name in reg_32_to_64:
        return reg_32_to_64[reg_name]
      if reg_name in reg_16_to_64:
        return reg_16_to_64[reg_name]
      if reg_name in reg_8_to_64:
        return reg_8_to_64[reg_name]
    
      return reg_name
    

    
    # =============================================================================
    # Matual Between ALl
    # =============================================================================
    def _get_rip_relative_target(self, inst) -> Optional[int]:
      """
      Get the target address of a RIP-relative memory operand.
      """
      try:
        for opnd in inst.operands:
            if opnd.type != X86_OP_MEM:
                continue
            
            if inst.reg_name(opnd.mem.base) != 'rip':
                continue
            
            target = inst.address + inst.size + opnd.mem.disp
            return target

      except Exception as e:
        pass

      return None
    
    
    
    def _recover_argument_from_registers(self, arg_mapping: Dict, 
                                     register_state: Dict[str, Dict],
                                     stack_state: Optional[Dict[int, Dict]] = None) -> Dict:
      """
      Recover argument value from register assignments (Go 1.17+).
      """
      result = {
        'arg_index': arg_mapping['arg_index'],
        'inferred_type': arg_mapping['inferred_type'],
        'location': arg_mapping['location'],
        'recovered': False,
        'value': None,
        'details': {},
      }

      if arg_mapping['location'] != 'registers':
        result['details']['reason'] = 'stack_argument_not_analyzed'
        return result

      registers = arg_mapping.get('registers', [])
      if not registers:
        result['details']['reason'] = 'no_registers_assigned'
        return result

      inferred_type = arg_mapping['inferred_type']
      param_type = arg_mapping.get('param_type', '')

      # =================================================================
      # Handle string (2 registers: ptr + len)
      # =================================================================
      if (inferred_type == 'string_or_interface' or inferred_type == 'string' or param_type.lower() == 'string') and len(registers) >= 2:
        ptr_reg = registers[0]
        len_reg = registers[1]
        
        ptr_value = self._resolve_register_value(register_state, ptr_reg, stack_state=stack_state)
        len_value = self._resolve_register_value(register_state, len_reg, stack_state=stack_state)
    
        result['details']['ptr_reg'] = ptr_reg
        result['details']['len_reg'] = len_reg
        result['details']['ptr_value_raw'] = ptr_value
        result['details']['len_value_raw'] = len_value
        
        ptr_addr = None
        str_len = None
        
        if ptr_value:
            if ptr_value['type'] == 'rip_relative':
                ptr_addr = ptr_value['target']
            elif ptr_value['type'] == 'rip_load':
                ptr_addr = self._read_pointer_at_address(ptr_value['target'])
            elif ptr_value['type'] == 'constant':
                if ptr_value['value'] > 0x10000:
                    ptr_addr = ptr_value['value']
            elif ptr_value['type'] == 'stack_load_unresolved':
                # Try to read directly from stack memory
                # This requires knowing the actual stack pointer value
                # For now, try to read from the moduledata regions
                offset = ptr_value.get('offset', 0)
                # Large offsets suggest this is a parameter from the caller
                # We can try to read this if we have access to the stack
                result['details']['stack_offset'] = offset
                result['details']['note'] = 'value_on_caller_stack'
        
        if len_value:
            if len_value['type'] == 'constant':
                str_len = len_value['value']
            elif len_value['type'] == 'rip_load':
                str_len = self._read_int_at_address(len_value['target'])
            elif len_value['type'] == 'stack_load_unresolved':
                offset = len_value.get('offset', 0)
                result['details']['len_stack_offset'] = offset
        
        result['details']['ptr_addr'] = ptr_addr
        result['details']['str_len'] = str_len
        
        if ptr_addr and str_len is not None and 0 < str_len < 10000:
            string_value = self._try_read_string_at_address(ptr_addr, str_len)
            if string_value:
                result['recovered'] = True
                result['inferred_type'] = 'string'
                result['value'] = string_value[:str_len]
                return result
        
        # Partial recovery
        if ptr_addr is not None or str_len is not None:
            result['recovered'] = True
            result['value'] = {'ptr': hex(ptr_addr) if ptr_addr else None, 'len': str_len}
            result['details']['note'] = 'partial_recovery'
            return result
        
        # Report why we failed
        if ptr_value:
            result['details']['reason'] = f'ptr_type={ptr_value["type"]}_unhandled'
        else:
            result['details']['reason'] = 'ptr_register_not_found'
        
        return result

      # =================================================================
      # Handle slice (3 registers: ptr + len + cap)
      # =================================================================
      elif inferred_type == 'slice' and len(registers) >= 3:
        ptr_reg = registers[0]
        len_reg = registers[1]
        cap_reg = registers[2]
        
        ptr_value = self._resolve_register_value(register_state, ptr_reg, stack_state=stack_state)
        len_value = self._resolve_register_value(register_state, len_reg, stack_state=stack_state)
        cap_value = self._resolve_register_value(register_state, cap_reg, stack_state=stack_state)
        
        slice_ptr = None
        slice_len = None
        slice_cap = None
        
        if ptr_value:
            if ptr_value['type'] == 'rip_relative':
                slice_ptr = ptr_value['target']
            elif ptr_value['type'] == 'rip_load':
                slice_ptr = self._read_pointer_at_address(ptr_value['target'])
            elif ptr_value['type'] == 'constant':
                slice_ptr = ptr_value['value']
        
        if len_value and len_value['type'] == 'constant':
            slice_len = len_value['value']
        
        if cap_value and cap_value['type'] == 'constant':
            slice_cap = cap_value['value']
        
        if slice_ptr is not None or slice_len is not None:
            result['recovered'] = True
            result['value'] = {
                'ptr': hex(slice_ptr) if slice_ptr else '0x0',
                'len': slice_len,
                'cap': slice_cap,
            }
        else:
            result['details']['reason'] = 'no_values_resolved'

        return result

      # =================================================================
      # Handle simple integer/pointer (1 register)
      # =================================================================
      elif len(registers) == 1:
        reg = registers[0]
        reg_value = self._resolve_register_value(register_state, reg, stack_state=stack_state)
        
        result['details']['reg'] = reg
        
        if reg_value:
            if reg_value['type'] == 'constant':
                result['recovered'] = True
                result['value'] = reg_value['value']
            
            elif reg_value['type'] == 'rip_relative':
                target = reg_value['target']
                result['recovered'] = True
                result['value'] = target
                result['details']['target_address'] = target
            
            elif reg_value['type'] == 'rip_load':
                target = reg_value['target']
                param_type_lower = param_type.lower()
                
                if param_type.startswith('*') or 'ptr' in param_type_lower or 'pointer' in param_type_lower:
                    loaded_ptr = self._read_pointer_at_address(target)
                    if loaded_ptr:
                        result['recovered'] = True
                        result['value'] = loaded_ptr
                        result['details']['loaded_from'] = hex(target)
                    else:
                        result['recovered'] = True
                        result['value'] = target
                else:
                    loaded_val = self._read_int_at_address(target)
                    if loaded_val is not None:
                        result['recovered'] = True
                        result['value'] = loaded_val
                        result['details']['loaded_from'] = hex(target)
                    else:
                        result['recovered'] = True
                        result['value'] = target
            
            elif reg_value['type'] == 'stack_load_unresolved':
                # Value is on the stack - we can't resolve it statically
                offset = reg_value.get('offset', 0)
                result['details']['stack_offset'] = offset
                result['details']['reason'] = 'value_on_stack'
            
            elif reg_value['type'] == 'stack_address':
                # Register contains address of stack location
                offset = reg_value.get('offset', 0)
                result['recovered'] = True
                result['value'] = f'&stack[{offset}]'
                result['details']['stack_offset'] = offset
            
            else:
                result['details']['reason'] = f'unhandled_type_{reg_value["type"]}'
        else:
            result['details']['reason'] = 'register_not_found'

      return result



    # =============================================================================
    # STACK ABI (Go 1.16 and earlier)
    # =============================================================================

    def _map_params_to_stack(self, params: List[Dict]) -> List[Dict]:
      """
      Map parameters to stack offsets (Go 1.16 and earlier).
      """
      mappings = []
      stack_offset = 0

      for param_idx, param in enumerate(params):
        param_name = param.get('name', '')
        param_type = param.get('type', '')
        param_size = param.get('size', 8)
        is_receiver = param.get('is_receiver', False)
        
        inferred_type, num_words = self._get_type_register_info(param_type, param_size)
        
        # Each word occupies consecutive stack slots
        stack_offsets = [stack_offset + i * 8 for i in range(num_words)]
        
        mappings.append({
            'arg_index': param_idx,
            'param_name': param_name,
            'param_type': param_type,
            'location': 'stack',
            'stack_offsets': stack_offsets,
            'inferred_type': inferred_type,
            'num_words': num_words,
            'is_receiver': is_receiver,
        })
        
        stack_offset += num_words * 8

      return mappings


    def _recover_argument_from_stack(self, arg_mapping: Dict, 
                                  register_state: Dict[str, Dict],
                                  stack_state: Dict[int, Dict]) -> Dict:
      """Recover argument from the new stack_state format."""
      result = {
        'arg_index': arg_mapping['arg_index'],
        'inferred_type': arg_mapping['inferred_type'],
        'location': 'stack',
        'recovered': False,
        'value': None,
        'details': {},
      }

      stack_offsets = arg_mapping.get('stack_offsets', [])
      if not stack_offsets:
        result['details']['reason'] = 'no_stack_offsets'
        return result

      param_type = arg_mapping.get('param_type', '').lower()

      # === Single value (int, pointer, etc.) ===
      if len(stack_offsets) == 1:
        offset = stack_offsets[0]
        entry = stack_state.get(offset)
        
        result['details']['stack_offset'] = hex(offset)
        
        if entry:
            result['details']['entry_type'] = entry['type']
            
            if entry['type'] == 'resolved':
                result['recovered'] = True
                result['value'] = entry['value']
            elif entry['type'] == 'runtime':
                result['details']['reason'] = entry.get('reason', 'runtime_value')
            elif entry['type'] == 'unresolved':
                result['details']['reason'] = f"unresolved_from_{entry.get('src_reg', 'unknown')}"
            # Handle OLD format for backwards compatibility
            elif entry['type'] == 'stack_constant':
                result['recovered'] = True
                result['value'] = entry['value']
            elif entry['type'] == 'stack_from_register':
                # Try to resolve using register_state
                src_reg = entry.get('src_reg', '').lower()
                if src_reg and src_reg in register_state:
                    reg_info = register_state[src_reg]
                    if reg_info['type'] == 'constant':
                        result['recovered'] = True
                        result['value'] = reg_info['value']
                    elif reg_info['type'] == 'rip_relative':
                        result['recovered'] = True
                        result['value'] = reg_info['target']
                    elif reg_info['type'] == 'rip_load':
                        loaded = self._read_pointer_at_address(reg_info['target'])
                        if loaded is not None:
                            result['recovered'] = True
                            result['value'] = loaded
        else:
            result['details']['reason'] = 'no_stack_entry'
        
        return result

      # === String (2 slots: ptr + len) ===
      if param_type == 'string' and len(stack_offsets) >= 2:
        ptr_offset = stack_offsets[0]
        len_offset = stack_offsets[1]
        
        ptr_entry = stack_state.get(ptr_offset)
        len_entry = stack_state.get(len_offset)
        
        ptr_value = None
        len_value = None
        
        if ptr_entry:
            if ptr_entry['type'] == 'resolved':
                ptr_value = ptr_entry['value']
            elif ptr_entry['type'] == 'stack_constant':
                ptr_value = ptr_entry['value']
        
        if len_entry:
            if len_entry['type'] == 'resolved':
                len_value = len_entry['value']
            elif len_entry['type'] == 'stack_constant':
                len_value = len_entry['value']
        
        result['details']['ptr'] = hex(ptr_value) if ptr_value else None
        result['details']['len'] = len_value
        
        if ptr_value and len_value and 0 < len_value < 10000:
            string_data = self._try_read_string_at_address(ptr_value, len_value)
            if string_data:
                result['recovered'] = True
                result['inferred_type'] = 'string'
                result['value'] = string_data
        
        return result

      # === Slice (3 slots: ptr + len + cap) ===
      if len(stack_offsets) >= 3:
        def get_value(entry):
            if entry is None:
                return None
            if entry['type'] == 'resolved':
                return entry['value']
            if entry['type'] == 'stack_constant':
                return entry['value']
            return None
        
        ptr_val = get_value(stack_state.get(stack_offsets[0]))
        len_val = get_value(stack_state.get(stack_offsets[1]))
        cap_val = get_value(stack_state.get(stack_offsets[2]))
        
        if ptr_val is not None or len_val is not None:
            result['recovered'] = True
            result['value'] = {
                'ptr': hex(ptr_val) if ptr_val else '0x0',
                'len': len_val,
                'cap': cap_val,
            }
        
        return result

      return result


    def _resolve_stack_value(self, assignment: Dict, register_state: Dict[str, Dict]) -> Optional[int]:
      """
      Resolve a stack assignment to its actual value.
      """
      if assignment is None:
        return None
    
      if assignment['type'] == 'stack_constant':
        return assignment['value']
    
      elif assignment['type'] == 'stack_from_register':
        src_reg = assignment['src_reg']
        reg_value = self._resolve_register_value(register_state, src_reg)
        
        if reg_value:
            if reg_value['type'] == 'constant':
                return reg_value['value']
            elif reg_value['type'] == 'rip_relative':
                return reg_value['target']
            elif reg_value['type'] == 'rip_load':
                return self._read_pointer_at_address(reg_value['target'])
    
      return None
    
    
  

    
    def _get_type_register_info(self, type_str: str, size: int) -> Tuple[str, int]:
      """
      Determine inferred type and number of registers/stack slots needed.
      """
      type_lower = type_str.lower()

      # String: 2 words (ptr + len)
      if type_lower == 'string':
        return ('string_or_interface', 2)

      # Slice: 3 words (ptr + len + cap)
      if type_lower.startswith('[]') or 'slice' in type_lower:
        return ('slice', 3)

      # Interface: 2 words (type + data)
      if type_lower in ['interface{}', 'any', 'error']:
        return ('string_or_interface', 2)

      # Pointer types: 1 word
      if type_str.startswith('*') or 'ptr' in type_lower or 'pointer' in type_lower:
        return ('pointer', 1)

      # Boolean: 1 word
      if type_lower == 'bool':
        return ('bool', 1)

      # Integer types: 1 word
      if type_lower in ['int', 'int8', 'int16', 'int32', 'int64', 
                      'uint', 'uint8', 'uint16', 'uint32', 'uint64',
                      'uintptr', 'byte', 'rune']:
        return ('int64/uint64/pointer/uintptr', 1)

      # Float types: 1 word (simplified)
      if type_lower in ['float32', 'float64']:
        return ('float', 1)

      # Default: estimate from size
      num_words = (size + 7) // 8
      return (f'unknown_{size}bytes', num_words)

    
    
    
     
    def _try_read_string_at_address(self, ptr: int, max_len: int = 1024) -> Optional[str]:
      """
      Try to read a string at the given address.
      """
      if ptr == 0 or ptr is None:
        return None
        
      try:
        layer = self.context.layers[self.layer_name]
        
        if ptr < 0x10000:
            return None
        
        data = layer.read(ptr, max_len, pad=True)
        
        if not data or len(data) == 0:
            return None
        
        # For known-length strings, use exact length
        if max_len <= 256:
            try:
                text = data[:max_len].decode('utf-8', errors='strict')
                return text
            except UnicodeDecodeError:
                text = data[:max_len].decode('utf-8', errors='replace')
                if len(text) > 0:
                    printable_count = sum(1 for c in text if c.isprintable() or c in '\t\n\r ')
                    if printable_count / len(text) >= 0.7:
                        return text
                return None
        
        # For unknown length, find null terminator
        null_idx = data.find(b'\x00')
        if null_idx != -1:
            data = data[:null_idx]
        
        if len(data) == 0:
            return ""
        
        try:
            text = data.decode('utf-8')
            if len(text) > 0:
                printable_count = sum(1 for c in text if c.isprintable() or c in '\t\n\r ')
                if printable_count / len(text) >= 0.7:
                    return text
        except UnicodeDecodeError:
            pass
        
        return None
        
      except Exception as e:
        return None

      
    def _read_pointer_at_address(self, addr: int) -> Optional[int]:
      """
      Read a pointer value from memory address.
      """
      try:
        layer = self.context.layers[self.layer_name]
        data = layer.read(addr, 8, pad=True)
        if len(data) >= 8:
            return int.from_bytes(data, 'little')
        return None
      except:
        return None
    
    
    def _read_int_at_address(self, addr: int, size: int = 8) -> Optional[int]:
      """
      Read an integer value from memory address.
      """
      try:
        layer = self.context.layers[self.layer_name]
        data = layer.read(addr, size, pad=True)
        if len(data) >= size:
            return int.from_bytes(data[:size], 'little')
        return None
      except:
        return None
   
   
   
   
    
        
        
    # =============================================================================
    # Format the outputs
    # =============================================================================
 
    def _print_recovered_args(self, recovered_args: List[Dict]):
      """Print recovered arguments in clean tree format."""
      if not recovered_args:
        print("  └─ (no args)")
        return
    
      for i, arg in enumerate(recovered_args):
        is_last = (i == len(recovered_args) - 1)
        prefix = "└─" if is_last else "├─"
        
        idx = arg['arg_index']
        ptype = arg.get('param_type', arg.get('inferred_type', '?'))
        # Simplify type
        ptype = ptype.replace('int64/uint64/pointer/uintptr', 'int64')
        ptype = ptype.replace('string_or_interface', 'string')
        
        recovered = arg.get('recovered', False)
        value = arg.get('value')
        details = arg.get('details', {})
        
        if recovered:
            if isinstance(value, str):
                val_str = f'"{value}"' if len(value) <= 40 else f'"{value[:37]}..."'
            elif isinstance(value, int):
                val_str = f"{value}" if value < 0x10000 else f"0x{value:x}"
            elif isinstance(value, dict):
                val_str = str(value)
            else:
                val_str = str(value)
        else:
            # Short reason
            stack_offset = details.get('stack_offset', 0)
            if isinstance(stack_offset, str):
                try:
                  stack_offset = int(stack_offset, 16) if stack_offset.startswith('0x') else int(stack_offset)
                except:
                   stack_offset = 0
            if stack_offset > 1000:
                val_str = "<param from caller>"
            elif 'register_not_found' in details.get('reason', ''):
                val_str = "<runtime>"
            else:
                val_str = "<runtime>"
        
        print(f"  {prefix} Arg {idx} ({ptype}): {val_str}")
   
    
    
    def _print_annotated_disassembly(self, instructions: List[Dict], call_index: int, 
                                  recovered_args: List[Dict], callee_name: str):
      """Print disassembly with recovered values as comments (IDA-style)."""
    
      # Build a map of addresses to annotations
      annotations = {}
    
      # Add annotations from recovered args
      for arg in recovered_args:
        if not arg.get('recovered'):
            continue
        
        details = arg.get('details', {})
        value = arg.get('value')
        arg_idx = arg.get('arg_index')
        
        # If we know which instruction set this arg, annotate it
        if 'source_addr' in details:
            addr = details['source_addr']
            if isinstance(value, str):
                short_val = value[:30] + "..." if len(value) > 30 else value
                annotations[addr] = f'arg{arg_idx} = "{short_val}"'
            elif isinstance(value, int):
                annotations[addr] = f'arg{arg_idx} = {value} ({hex(value)})'
    
      # Print last 10 instructions before call
      start = max(0, call_index - 10)
    
      print(f"\n    {'─'*60}")
      for i in range(start, call_index + 1):
        insn = instructions[i]
        addr = insn['address']
        mnemonic = insn['mnemonic']
        op_str = insn['op_str']
        
        # Base disassembly
        line = f"    {hex(addr)}: {mnemonic:<8} {op_str:<35}"
        
        # Add annotation if exists
        if addr in annotations:
            line += f" ; {annotations[addr]}"
        
        # Mark the call instruction
        if i == call_index:
            line += f" ; → {callee_name}()"
        
        print(line)
      print(f"    {'─'*60}")
    

    
    def run(self) -> renderers.TreeGrid:
        return renderers.TreeGrid(
            [("Result", str)],
            self._generator(),
        )


