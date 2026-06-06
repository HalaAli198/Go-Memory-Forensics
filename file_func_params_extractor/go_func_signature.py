#!/usr/bin/env python3
"""
Go Function Line Extractor

Extracts function names, entry line numbers, and parameter information 
from Go source code. Supports both .go files and .s assembly files.

Output includes:
- func_name: Full function name (package.FuncName)
- entry_line: Line number where function starts
- num_params: Number of parameters
- params: List of {type, size} for each parameter

Usage:
    python3 go_func_signature.py --version 1.22.0
    python3 go_func_signature.py --version 1.21.0 --output go_funcs_121.json
"""

import os
import re
import json
import argparse
import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict, field


# Go type sizes (in bytes) for common types
# Based on 64-bit architecture (most common for forensics)
GO_TYPE_SIZES = {
    # Basic types
    "bool": 1,
    "byte": 1,
    "uint8": 1,
    "int8": 1,
    "uint16": 2,
    "int16": 2,
    "uint32": 4,
    "int32": 4,
    "rune": 4,  # alias for int32
    "float32": 4,
    "uint64": 8,
    "int64": 8,
    "float64": 8,
    "complex64": 8,
    "complex128": 16,
    "int": 8,      # platform dependent, 8 on 64-bit
    "uint": 8,     # platform dependent, 8 on 64-bit
    "uintptr": 8,  # platform dependent, 8 on 64-bit
    
    # Pointer types (all 8 bytes on 64-bit)
    "unsafe.Pointer": 8,
    
    # String and slice headers
    "string": 16,  # ptr (8) + len (8)
    
    # Interface
    "interface{}": 16,  # type ptr (8) + data ptr (8)
    "any": 16,          # alias for interface{}
    "error": 16,        # interface type
    
    # Common runtime types
    "g": 8,             # pointer to g struct
    "m": 8,             # pointer to m struct
    "p": 8,             # pointer to p struct
    "funcval": 8,       # pointer
    "itab": 8,          # pointer
    "eface": 16,        # empty interface
    "iface": 16,        # interface with methods
    "_type": 8,         # pointer to type descriptor
    "slice": 24,        # ptr (8) + len (8) + cap (8)
    "hmap": 8,          # pointer to map header
    "hchan": 8,         # pointer to channel
    "sudog": 8,         # pointer
    "waitq": 16,        # head + tail pointers
    "mutex": 8,         # typically 8 bytes
    "note": 8,          # typically 8 bytes
    "lfnode": 16,       # typically two pointers
}


@dataclass
class ParamInfo:
    """Information about a single function parameter."""
    name: str           # Parameter name (may be empty for unnamed params)
    type: str           # Type as string
    size: int           # Size in bytes (-1 if unknown)
    is_pointer: bool    # Whether this is a pointer type
    is_variadic: bool   # Whether this is a variadic parameter (...Type)


@dataclass
class FunctionInfo:
    """Information about a function including parameters."""
    func_name: str              # Full name: package.FuncName
    entry_line: int             # Line number where function starts
    num_params: int             # Number of parameters
    params: List[Dict]          # List of parameter info dicts
    num_returns: int = 0        # Number of return values
    returns: List[Dict] = field(default_factory=list)  # Return type info
    is_asm: bool = False        # True if this is an assembly function
    arg_frame_size: int = 0     # Total argument frame size (bytes) - mainly for asm
    local_frame_size: int = 0   # Local frame size (bytes) - mainly for asm


class GoTypeResolver:
    """Resolves Go types to their sizes."""
    
    def __init__(self):
        self.type_sizes = GO_TYPE_SIZES.copy()
        self.struct_cache = {}  # Cache for struct sizes
    
    def get_size(self, type_str: str) -> int:
        """
        Get the size of a Go type in bytes.
        Returns -1 if size cannot be determined.
        """
        type_str = type_str.strip()
        
        # Handle empty type
        if not type_str:
            return -1
        
        # Check direct match
        if type_str in self.type_sizes:
            return self.type_sizes[type_str]
        
        # Handle pointer types (all 8 bytes on 64-bit)
        if type_str.startswith("*"):
            return 8
        
        # Handle slice types (24 bytes: ptr + len + cap)
        if type_str.startswith("[]"):
            return 24
        
        # Handle array types [N]Type
        array_match = re.match(r'\[(\d+)\](.+)', type_str)
        if array_match:
            count = int(array_match.group(1))
            elem_type = array_match.group(2).strip()
            elem_size = self.get_size(elem_type)
            if elem_size > 0:
                return count * elem_size
            return -1
        
        # Handle map types (pointer to hmap, 8 bytes)
        if type_str.startswith("map["):
            return 8
        
        # Handle channel types (pointer to hchan, 8 bytes)
        if type_str.startswith("chan ") or type_str.startswith("<-chan ") or type_str.startswith("chan<-"):
            return 8
        
        # Handle function types (pointer, 8 bytes)
        if type_str.startswith("func"):
            return 8
        
        # Handle interface types
        if type_str.startswith("interface{"):
            return 16
        
        # Handle qualified types (package.Type)
        if "." in type_str:
            # Usually a struct or named type - assume pointer if not basic
            base_type = type_str.split(".")[-1]
            if base_type in self.type_sizes:
                return self.type_sizes[base_type]
            # Common patterns
            if base_type.endswith("er"):  # Interface-like (Reader, Writer, etc.)
                return 16
            # Unknown struct/type - could be any size
            return -1
        
        # Handle parenthesized types
        if type_str.startswith("(") and type_str.endswith(")"):
            return self.get_size(type_str[1:-1])
        
        # Handle variadic types (...Type -> slice)
        if type_str.startswith("..."):
            return 24  # Variadic becomes slice
        
        # Unknown type
        return -1
    
    def is_pointer_type(self, type_str: str) -> bool:
        """Check if a type is a pointer type."""
        type_str = type_str.strip()
        if type_str.startswith("*"):
            return True
        if type_str.startswith("unsafe.Pointer"):
            return True
        # Maps and channels are reference types (internally pointers)
        if type_str.startswith("map[") or type_str.startswith("chan"):
            return True
        return False


class GoFunctionExtractor:
    """Extract function names, entry lines, and parameters from Go source code."""
    
    # Regex patterns for Go function declarations
    # Matches: func FuncName(params) returns
    FUNC_PATTERN = re.compile(
        r'^func\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)\s*(.*?)(?:\s*\{|$)'
    )
    
    # Matches: func (r *Type) MethodName(params) returns
    METHOD_PATTERN = re.compile(
        r'^func\s+\(\s*(\w+)\s+(\*?\w+)\s*\)\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)\s*(.*?)(?:\s*\{|$)'
    )
    
    # Regex patterns for Go assembly functions
    ASM_TEXT_PATTERN = re.compile(
        r'^TEXT\s+(?:(\w+)·)?(\w+)\(SB\)'
    )
    
    ASM_TEXT_PATTERN_ALT = re.compile(
        r'^TEXT\s+(?:(\w+)(?:\xc2\xb7|·))?(\w+)\(SB\)'
    )
    
    # Assembly function with explicit frame size (contains param info)
    # TEXT runtime·goexit(SB),NOSPLIT,$0-0
    # The $X-Y means: X = local frame size, Y = argument size
    ASM_FRAMESIZE_PATTERN = re.compile(
        r'\$(\d+)-(\d+)'
    )
    
    def __init__(self, go_version: str, src_dir: Optional[str] = None):
        self.go_version = go_version
        self.src_dir = src_dir
        self.download_dir = None
        self.type_resolver = GoTypeResolver()
        
    def download_go_source(self) -> str:
        """Download and extract Go source code."""
        self.download_dir = tempfile.mkdtemp(prefix="go_extract_")
        
        tarball = f"go{self.go_version}.src.tar.gz"
        tarball_path = os.path.join(self.download_dir, tarball)
        url = f"https://golang.org/dl/{tarball}"
        
        print(f" Downloading Go {self.go_version} source...")
        result = subprocess.run(
            ["wget", "-q", "-O", tarball_path, url],
            capture_output=True
        )
        if result.returncode != 0:
            raise RuntimeError(f"Failed to download: {result.stderr.decode()}")
        
        print(f" Extracting source code...")
        result = subprocess.run(
            ["tar", "xzf", tarball_path, "-C", self.download_dir],
            capture_output=True
        )
        if result.returncode != 0:
            raise RuntimeError(f"Failed to extract: {result.stderr.decode()}")
        
        src_dir = os.path.join(self.download_dir, "go")
        if not os.path.exists(src_dir):
            raise RuntimeError(f"Source directory not found: {src_dir}")
        
        return src_dir
    
    def cleanup(self):
        """Remove downloaded files."""
        if self.download_dir and os.path.exists(self.download_dir):
            shutil.rmtree(self.download_dir)
            print(f" Cleaned up temporary files")
    
    def get_package_from_path(self, filepath: str, src_base: str) -> str:
        """Get package name from file path."""
        rel_path = os.path.relpath(filepath, os.path.join(src_base, "src"))
        package = os.path.dirname(rel_path)
        return package.replace(os.sep, "/")
    
    def parse_params(self, params_str: str) -> List[ParamInfo]:
        """
        Parse Go function parameter string into list of ParamInfo.
        
        Handles:
        - Named params: "a int, b string"
        - Multiple same type: "a, b int"
        - Unnamed params: "int, string"
        - Variadic: "args ...int"
        - Complex types: "m map[string]int"
        """
        params = []
        if not params_str or not params_str.strip():
            return params
        
        params_str = params_str.strip()
        
        # Handle multi-line parameters by normalizing whitespace
        params_str = ' '.join(params_str.split())
        
        # Split by comma, but be careful with nested types like map[K,V]
        param_parts = self._split_params(params_str)
        
        # Track type for groups like "a, b, c int"
        pending_names = []
        
        for part in param_parts:
            part = part.strip()
            if not part:
                continue
            
            # Check for variadic
            is_variadic = "..." in part
            
            # Try to split into name and type
            tokens = part.split()
            
            if len(tokens) == 0:
                continue
            elif len(tokens) == 1:
                # Either just a name (type comes later) or just a type
                token = tokens[0]
                if self._looks_like_type(token):
                    # It's a type - apply to pending names or create unnamed param
                    if pending_names:
                        for name in pending_names:
                            type_str = token.replace("...", "")
                            params.append(ParamInfo(
                                name=name,
                                type=type_str,
                                size=self.type_resolver.get_size(type_str),
                                is_pointer=self.type_resolver.is_pointer_type(type_str),
                                is_variadic=is_variadic
                            ))
                        pending_names = []
                    else:
                        type_str = token.replace("...", "")
                        params.append(ParamInfo(
                            name="",
                            type=type_str,
                            size=self.type_resolver.get_size(type_str),
                            is_pointer=self.type_resolver.is_pointer_type(type_str),
                            is_variadic=is_variadic
                        ))
                else:
                    # It's a name, type comes later
                    pending_names.append(token)
            else:
                # Multiple tokens: could be "name type" or "name1, name2 type"
                # Last token(s) form the type, first ones are names
                
                # Special case: if second token starts with map[, chan, [], etc
                # then first token is definitely the name
                if len(tokens) >= 2:
                    second = tokens[1]
                    if (second.startswith("map[") or second.startswith("[]") or 
                        second.startswith("chan") or second.startswith("*") or
                        second.startswith("func") or second.startswith("interface") or
                        second.startswith("...")):
                        # First token is name, rest is type
                        type_start = 1
                    else:
                        # Find where the type starts
                        type_start = self._find_type_start(tokens)
                else:
                    type_start = self._find_type_start(tokens)
                
                names = tokens[:type_start]
                type_tokens = tokens[type_start:]
                type_str = " ".join(type_tokens).replace("...", "").strip()
                
                # Add any pending names with this type
                all_names = pending_names + names
                pending_names = []
                
                if not all_names:
                    # Unnamed parameter
                    all_names = [""]
                
                for name in all_names:
                    params.append(ParamInfo(
                        name=name,
                        type=type_str,
                        size=self.type_resolver.get_size(type_str),
                        is_pointer=self.type_resolver.is_pointer_type(type_str),
                        is_variadic=is_variadic
                    ))
        
        return params
    
    def _split_params(self, params_str: str) -> List[str]:
        """
        Split parameter string by commas, respecting nested brackets.
        """
        parts = []
        current = []
        depth = 0
        
        for char in params_str:
            if char in '([{':
                depth += 1
                current.append(char)
            elif char in ')]}':
                depth -= 1
                current.append(char)
            elif char == ',' and depth == 0:
                parts.append(''.join(current))
                current = []
            else:
                current.append(char)
        
        if current:
            parts.append(''.join(current))
        
        return parts
    
    def _looks_like_type(self, token: str) -> bool:
        """Check if a token looks like a Go type."""
        if not token:
            return False
            
        # Basic types
        if token in GO_TYPE_SIZES:
            return True
        
        # Pointer types
        if token.startswith("*"):
            return True
        
        # Slice types
        if token.startswith("[]"):
            return True
        
        # Array types
        if token.startswith("[") and "]" in token:
            return True
        
        # Map types
        if token.startswith("map["):
            return True
        
        # Channel types
        if token.startswith("chan") or token.startswith("<-chan"):
            return True
        
        # Function types
        if token.startswith("func"):
            return True
        
        # Interface types
        if token.startswith("interface"):
            return True
        
        # Variadic
        if token.startswith("..."):
            return True
        
        # Qualified types (package.Type)
        if "." in token:
            return True
        
        # Capitalized identifiers are likely exported types
        if token[0].isupper():
            return True
        
        return False
    
    def _find_type_start(self, tokens: List[str]) -> int:
        """Find the index where the type starts in a list of tokens."""
        # Work backwards to find the type
        for i in range(len(tokens) - 1, -1, -1):
            if not self._looks_like_type(tokens[i]):
                return i + 1
        return 0
    
    def parse_returns(self, returns_str: str) -> List[ParamInfo]:
        """Parse return type string into list of ParamInfo."""
        if not returns_str or not returns_str.strip():
            return []
        
        returns_str = returns_str.strip()
        
        # Handle parenthesized returns: (int, error)
        if returns_str.startswith("(") and returns_str.endswith(")"):
            returns_str = returns_str[1:-1]
        
        # Handle single return type without parens
        if not "," in returns_str and not " " in returns_str.strip():
            type_str = returns_str.strip()
            if type_str and type_str != "{":
                return [ParamInfo(
                    name="",
                    type=type_str,
                    size=self.type_resolver.get_size(type_str),
                    is_pointer=self.type_resolver.is_pointer_type(type_str),
                    is_variadic=False
                )]
            return []
        
        # Use same parsing as params
        return self.parse_params(returns_str)
    
    def parse_go_file(self, filepath: str, package: str) -> List[FunctionInfo]:
        """Parse a single Go file and extract function info with parameters."""
        functions = []
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception as e:
            print(f"    Failed to read {filepath}: {e}")
            return functions
        
        # Track multi-line function declarations
        in_func_decl = False
        func_decl_lines = []
        func_start_line = 0
        
        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            
            # Skip comments and empty lines
            if not stripped or stripped.startswith("//"):
                continue
            
            # Handle multi-line declarations
            if in_func_decl:
                func_decl_lines.append(stripped)
                if '{' in stripped or (stripped.endswith(')') and not '(' in stripped):
                    # End of declaration
                    full_decl = ' '.join(func_decl_lines)
                    func_info = self._parse_func_declaration(full_decl, package, func_start_line)
                    if func_info:
                        functions.append(func_info)
                    in_func_decl = False
                    func_decl_lines = []
                continue
            
            # Check for function start
            if stripped.startswith("func "):
                # Check if declaration is complete on one line
                if '{' in stripped or self._is_complete_decl(stripped):
                    func_info = self._parse_func_declaration(stripped, package, line_num)
                    if func_info:
                        functions.append(func_info)
                else:
                    # Multi-line declaration
                    in_func_decl = True
                    func_decl_lines = [stripped]
                    func_start_line = line_num
        
        return functions
    
    def _is_complete_decl(self, line: str) -> bool:
        """Check if a function declaration is complete."""
        # Count parentheses
        open_parens = line.count('(')
        close_parens = line.count(')')
        return open_parens == close_parens
    
    def _parse_func_declaration(self, decl: str, package: str, line_num: int) -> Optional[FunctionInfo]:
        """Parse a function declaration string."""
        # Try method pattern first
        method_match = self.METHOD_PATTERN.match(decl)
        if method_match:
            receiver_name = method_match.group(1)
            receiver_type = method_match.group(2)
            method_name = method_match.group(3)
            params_str = method_match.group(4)
            returns_str = method_match.group(5)
            
            # Build full name
            if receiver_type.startswith("*"):
                full_name = f"{package}.({receiver_type}).{method_name}"
            else:
                full_name = f"{package}.{receiver_type}.{method_name}"
            
            params = self.parse_params(params_str)
            returns = self.parse_returns(returns_str)
            
            # Calculate total arg frame size
            arg_frame_size = sum(p.size for p in params if p.size > 0)
            
            return FunctionInfo(
                func_name=full_name,
                entry_line=line_num,
                num_params=len(params),
                params=[asdict(p) for p in params],
                num_returns=len(returns),
                returns=[asdict(r) for r in returns],
                is_asm=False,
                arg_frame_size=arg_frame_size,
                local_frame_size=0  # Can't determine from source
            )
        
        # Try regular function pattern
        func_match = self.FUNC_PATTERN.match(decl)
        if func_match:
            func_name = func_match.group(1)
            params_str = func_match.group(2)
            returns_str = func_match.group(3)
            
            full_name = f"{package}.{func_name}"
            
            params = self.parse_params(params_str)
            returns = self.parse_returns(returns_str)
            
            # Calculate total arg frame size
            arg_frame_size = sum(p.size for p in params if p.size > 0)
            
            return FunctionInfo(
                func_name=full_name,
                entry_line=line_num,
                num_params=len(params),
                params=[asdict(p) for p in params],
                num_returns=len(returns),
                returns=[asdict(r) for r in returns],
                is_asm=False,
                arg_frame_size=arg_frame_size,
                local_frame_size=0  # Can't determine from source
            )
        
        return None
    
    def parse_asm_file(self, filepath: str, package: str) -> List[FunctionInfo]:
        """Parse a Go assembly file (.s) and extract function info."""
        functions = []
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                lines = f.readlines()
        except Exception as e:
            print(f"    Failed to read {filepath}: {e}")
            return functions
        
        for line_num, line in enumerate(lines, start=1):
            original_line = line
            line = line.strip()
            
            if not line or line.startswith("//"):
                continue
            
            # Try patterns
            match = None
            for pattern in [self.ASM_TEXT_PATTERN, self.ASM_TEXT_PATTERN_ALT]:
                match = pattern.match(line)
                if match:
                    break
            
            if not match and line.startswith("TEXT"):
                match = self._parse_asm_text_manual(line)
            
            if match:
                if isinstance(match, tuple):
                    pkg_name, func_name = match
                else:
                    pkg_name = match.group(1)
                    func_name = match.group(2)
                
                if pkg_name:
                    full_name = f"{pkg_name}.{func_name}"
                else:
                    full_name = f"{package}.{func_name}"
                
                # Try to extract argument size from frame info
                # Format: $local_size-arg_size (e.g., $0-24 means 0 local, 24 args)
                frame_match = self.ASM_FRAMESIZE_PATTERN.search(original_line)
                local_size = 0
                arg_size = 0
                
                if frame_match:
                    local_size = int(frame_match.group(1))
                    arg_size = int(frame_match.group(2))
                
                # For assembly functions, we store metadata about the frame
                # but mark it clearly as assembly (no individual param parsing possible)
                functions.append(FunctionInfo(
                    func_name=full_name,
                    entry_line=line_num,
                    num_params=0,  # Unknown for asm - use arg_frame_size instead
                    params=[],     # Can't determine individual params from asm
                    num_returns=0,
                    returns=[],
                    # Store asm-specific info in a way that's clearly asm
                    is_asm=True,
                    arg_frame_size=arg_size,
                    local_frame_size=local_size
                ))
        
        return functions
    
    def _parse_asm_text_manual(self, line: str) -> Optional[tuple]:
        """Manual parsing for assembly TEXT declarations."""
        if not line.startswith("TEXT"):
            return None
        
        rest = line[4:].strip()
        sb_pos = rest.find("(SB)")
        if sb_pos == -1:
            return None
        
        func_id = rest[:sb_pos].strip()
        func_id = func_id.replace('∕', '/')
        
        middle_dot_pos = -1
        for i, char in enumerate(func_id):
            if char == '·' or ord(char) == 0xB7:
                middle_dot_pos = i
        
        if middle_dot_pos == -1:
            if '·' in func_id:
                middle_dot_pos = func_id.rindex('·')
            elif '\xb7' in func_id:
                middle_dot_pos = func_id.rindex('\xb7')
            else:
                return (None, func_id)
        
        pkg_part = func_id[:middle_dot_pos]
        func_name = func_id[middle_dot_pos + 1:]
        
        return (pkg_part, func_name)
    
    def extract_from_directory(self, src_dir: str) -> Dict[str, List[Dict]]:
        """Walk through Go source and extract all functions with parameters."""
        result = {}
        
        package_dirs = [
            "src/runtime",
            "src/internal",
            "src",
        ]
        
        processed_files = set()
        total_functions = 0
        total_go_functions = 0
        total_asm_functions = 0
        total_params = 0
        
        for pkg_dir in package_dirs:
            pkg_path = os.path.join(src_dir, pkg_dir)
            if not os.path.exists(pkg_path):
                continue
            
            category = os.path.basename(pkg_dir)
            if category == "src":
                category = "stdlib"
            print(f" Processing {category} packages...")
            
            pkg_count = 0
            go_count = 0
            asm_count = 0
            param_count = 0
            
            for root, dirs, files in os.walk(pkg_path):
                dirs[:] = [d for d in dirs if d not in [
                    'testdata', 'vendor', 'cmd', '.git'
                ]]
                
                for filename in files:
                    is_go = filename.endswith('.go') and not filename.endswith('_test.go')
                    is_asm = filename.endswith('.s')
                    
                    if not (is_go or is_asm):
                        continue
                    
                    filepath = os.path.join(root, filename)
                    
                    if filepath in processed_files:
                        continue
                    
                    rel_path = os.path.relpath(filepath, os.path.join(src_dir, "src"))
                    if category == "stdlib":
                        if rel_path.startswith("runtime/") or rel_path.startswith("internal/"):
                            continue
                    
                    processed_files.add(filepath)
                    
                    package = self.get_package_from_path(filepath, src_dir)
                    
                    if is_go:
                        functions = self.parse_go_file(filepath, package)
                        go_count += len(functions)
                    else:
                        functions = self.parse_asm_file(filepath, package)
                        asm_count += len(functions)
                    
                    if functions:
                        result[rel_path] = [asdict(f) for f in functions]
                        pkg_count += len(functions)
                        total_functions += len(functions)
                        for f in functions:
                            param_count += len(f.params)
            
            total_go_functions += go_count
            total_asm_functions += asm_count
            total_params += param_count
            print(f"   Extracted {pkg_count} functions ({go_count} Go, {asm_count} asm), {param_count} params")
        
        print(f"\n Total: {total_functions} functions from {len(result)} files")
        print(f"   - Go functions: {total_go_functions}")
        print(f"   - Assembly functions: {total_asm_functions}")
        print(f"   - Total parameters: {total_params}")
        return result
    
    def run(self, output_file: Optional[str] = None) -> Dict:
        """Main entry point - download source, extract functions, save output."""
        try:
            if self.src_dir:
                src_dir = self.src_dir
            else:
                src_dir = self.download_go_source()
            
            print(f"\n Parsing Go {self.go_version} source code...\n")
            file_functions = self.extract_from_directory(src_dir)
            
            output = {
                "go_version": self.go_version,
                "total_files": len(file_functions),
                "total_functions": sum(len(funcs) for funcs in file_functions.values()),
                "total_params": sum(
                    sum(len(f.get("params", [])) for f in funcs)
                    for funcs in file_functions.values()
                ),
                "type_sizes": GO_TYPE_SIZES,
                "files": file_functions
            }
            
            if output_file is None:
                version_str = self.go_version.replace(".", "")
                output_file = f"go_func_lines_v{version_str}.json"
            
            with open(output_file, 'w') as f:
                json.dump(output, f, indent=2)
            
            file_size = os.path.getsize(output_file) / (1024 * 1024)
            print(f"\n Saved to: {output_file}")
            print(f" File size: {file_size:.2f} MB")
            
            return output
            
        finally:
            if not self.src_dir:
                self.cleanup()


def main():
    parser = argparse.ArgumentParser(
        description="Extract Go function names, entry lines, and parameter info"
    )
    parser.add_argument(
        "--version", "-v",
        required=True,
        help="Go version to extract (e.g., 1.22.0)"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output JSON file (default: go_func_lines_v<version>.json)"
    )
    parser.add_argument(
        "--src-dir",
        help="Use local Go source directory instead of downloading"
    )
    
    args = parser.parse_args()
    
    extractor = GoFunctionExtractor(
        go_version=args.version,
        src_dir=args.src_dir
    )
    
    extractor.run(output_file=args.output)


if __name__ == "__main__":
    main()

