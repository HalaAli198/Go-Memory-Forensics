"""
Third-Party Go Package Analyzer

This module handles downloading, caching, and parsing third-party Go packages
to extract function signatures and parameter information for memory forensics.

Usage:
    analyzer = ThirdPartyGoAnalyzer(cache_dir="/path/to/cache")
    func_info = analyzer.get_function_info("github.com/user/repo/pkg/file.go", "FunctionName")
"""

import os
import re
import json
import subprocess
import tempfile
import hashlib
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import ast


class ThirdPartyGoAnalyzer:
    """Analyzer for third-party Go packages."""
    
    # Common Go type sizes (64-bit)
    TYPE_SIZES = {
        # Basic types
        'bool': 1,
        'int': 8, 'int8': 1, 'int16': 2, 'int32': 4, 'int64': 8,
        'uint': 8, 'uint8': 1, 'uint16': 2, 'uint32': 4, 'uint64': 8,
        'uintptr': 8,
        'float32': 4, 'float64': 8,
        'complex64': 8, 'complex128': 16,
        'byte': 1,  # alias for uint8
        'rune': 4,  # alias for int32
        
        # Reference types (pointer size on 64-bit)
        'string': 16,  # ptr + len
        'error': 16,   # interface (ptr + ptr)
        'interface{}': 16,
        'any': 16,
        
        # Common composite types
        'slice': 24,   # ptr + len + cap
        'map': 8,      # pointer to hmap
        'chan': 8,     # pointer to hchan
        'func': 8,     # function pointer
    }
    
    def __init__(self, cache_dir: Optional[str] = None):
        """
        Initialize the analyzer.
        
        Args:
            cache_dir: Directory for caching downloaded packages.
                      Defaults to ~/.go_forensics_cache
        """
        if cache_dir is None:
            cache_dir = os.path.expanduser("~/.go_forensics_cache")
        
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Cache for parsed packages: {package_path: {file: {func_name: info}}}
        self.parsed_cache: Dict[str, Dict] = {}
        
        # Cache file for persistence
        self.cache_index_file = self.cache_dir / "package_index.json"
        self._load_cache_index()
    
    def _load_cache_index(self):
        """Load the cache index from disk."""
        self.cache_index = {}
        if self.cache_index_file.exists():
            try:
                with open(self.cache_index_file, 'r') as f:
                    self.cache_index = json.load(f)
            except Exception as e:
                print(f"[WARN] Could not load cache index: {e}")
    
    def _save_cache_index(self):
        """Save the cache index to disk."""
        try:
            with open(self.cache_index_file, 'w') as f:
                json.dump(self.cache_index, f, indent=2)
        except Exception as e:
            print(f"[WARN] Could not save cache index: {e}")
    
    def _extract_package_from_filepath(self, filepath: str) -> Tuple[Optional[str], str]:
        """
        Extract package import path and relative file path from a Go source filepath.
        
        Args:
            filepath: e.g., "github.com/BurntSushi/xgb/xproto/xproto.go"
        
        Returns:
            Tuple of (package_path, relative_file_path)
            e.g., ("github.com/BurntSushi/xgb", "xproto/xproto.go")
        """
        # Common patterns for third-party packages
        patterns = [
            # GitHub: github.com/user/repo/...
            r'^(github\.com/[^/]+/[^/]+)(?:/(.+))?$',
            # GitLab: gitlab.com/user/repo/...
            r'^(gitlab\.com/[^/]+/[^/]+)(?:/(.+))?$',
            # Bitbucket: bitbucket.org/user/repo/...
            r'^(bitbucket\.org/[^/]+/[^/]+)(?:/(.+))?$',
            # golang.org/x/...: golang.org/x/pkg/...
            r'^(golang\.org/x/[^/]+)(?:/(.+))?$',
            # Google APIs: google.golang.org/...
            r'^(google\.golang\.org/[^/]+)(?:/(.+))?$',
            # Go modules with version: pkg@version/...
            r'^([^@]+)@[^/]+(?:/(.+))?$',
            # Generic: domain.com/path/repo/...
            r'^([^/]+\.[^/]+/[^/]+/[^/]+)(?:/(.+))?$',
        ]
        
        for pattern in patterns:
            match = re.match(pattern, filepath)
            if match:
                package = match.group(1)
                rel_path = match.group(2) if match.group(2) else ""
                return package, rel_path
        
        # Fallback: assume first three components are package
        parts = filepath.split('/')
        if len(parts) >= 3 and '.' in parts[0]:
            package = '/'.join(parts[:3])
            rel_path = '/'.join(parts[3:]) if len(parts) > 3 else ""
            return package, rel_path
        
        return None, filepath
    
    def _get_package_cache_dir(self, package_path: str) -> Path:
        """Get the cache directory for a package."""
        # Create a safe directory name from package path
        safe_name = package_path.replace('/', '_').replace('.', '_')
        return self.cache_dir / safe_name
    
    def _download_package(self, package_path: str) -> Optional[Path]:
        """
        Download a Go package using 'go get' or git clone.
        
        Args:
            package_path: e.g., "github.com/BurntSushi/xgb"
        
        Returns:
            Path to downloaded package, or None on failure
        """
        cache_dir = self._get_package_cache_dir(package_path)
        
        # Check if already cached
        if cache_dir.exists() and any(cache_dir.iterdir()):
            print(f"[*] Using cached package: {package_path}")
            return cache_dir
        
        cache_dir.mkdir(parents=True, exist_ok=True)
        
        print(f"[*] Downloading package: {package_path}")
        
        # Try git clone first (more reliable for source code)
        if package_path.startswith('github.com/'):
            git_url = f"https://{package_path}.git"
        elif package_path.startswith('gitlab.com/'):
            git_url = f"https://{package_path}.git"
        elif package_path.startswith('bitbucket.org/'):
            git_url = f"https://{package_path}.git"
        else:
            git_url = f"https://{package_path}"
        
        try:
            result = subprocess.run(
                ['git', 'clone', '--depth', '1', git_url, str(cache_dir)],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                print(f"[+] Successfully cloned: {package_path}")
                self.cache_index[package_path] = {
                    'path': str(cache_dir),
                    'method': 'git',
                }
                self._save_cache_index()
                return cache_dir
            else:
                print(f"[!] Git clone failed: {result.stderr}")
        except subprocess.TimeoutExpired:
            print(f"[!] Git clone timed out for: {package_path}")
        except FileNotFoundError:
            print(f"[!] Git not found, trying go get...")
        except Exception as e:
            print(f"[!] Git clone error: {e}")
        
        # Fallback: try 'go mod download' approach
        try:
            # Create a temporary module to download the dependency
            with tempfile.TemporaryDirectory() as tmpdir:
                # Initialize a temp module
                subprocess.run(
                    ['go', 'mod', 'init', 'temp'],
                    cwd=tmpdir,
                    capture_output=True,
                    timeout=30
                )
                
                # Get the package
                result = subprocess.run(
                    ['go', 'get', '-d', package_path],
                    cwd=tmpdir,
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                
                if result.returncode == 0:
                    # Find where go downloaded it
                    gopath = os.environ.get('GOPATH', os.path.expanduser('~/go'))
                    pkg_path = Path(gopath) / 'pkg' / 'mod' / package_path.replace('/', os.sep)
                    
                    # Check various version suffixes
                    parent = pkg_path.parent
                    if parent.exists():
                        for item in parent.iterdir():
                            if item.name.startswith(pkg_path.name):
                                # Copy to our cache
                                import shutil
                                if cache_dir.exists():
                                    shutil.rmtree(cache_dir)
                                shutil.copytree(item, cache_dir)
                                print(f"[+] Downloaded via go get: {package_path}")
                                self.cache_index[package_path] = {
                                    'path': str(cache_dir),
                                    'method': 'go_get',
                                }
                                self._save_cache_index()
                                return cache_dir
        except Exception as e:
            print(f"[!] go get failed: {e}")
        
        print(f"[!] Could not download package: {package_path}")
        return None
    
    def register_local_package(self, package_path: str, local_path: str) -> bool:
        """
        Register a local directory as the source for a package.
        
        Use this when you have the package source locally (e.g., extracted from
        a vendor directory or downloaded manually).
        
        Args:
            package_path: Import path, e.g., "github.com/BurntSushi/xgb"
            local_path: Local filesystem path to the package source
        
        Returns:
            True if registration succeeded
        """
        local_path = Path(local_path)
        if not local_path.exists():
            print(f"[!] Local path does not exist: {local_path}")
            return False
        
        # Copy or link to cache
        cache_dir = self._get_package_cache_dir(package_path)
        
        try:
            import shutil
            if cache_dir.exists():
                shutil.rmtree(cache_dir)
            
            # Copy the source
            shutil.copytree(local_path, cache_dir)
            
            self.cache_index[package_path] = {
                'path': str(cache_dir),
                'method': 'local',
                'original_path': str(local_path),
            }
            self._save_cache_index()
            
            print(f"[+] Registered local package: {package_path} -> {local_path}")
            return True
            
        except Exception as e:
            print(f"[!] Failed to register local package: {e}")
            return False
    
    def parse_go_source_string(self, source_code: str, filename: str = "source.go") -> Dict[str, Dict]:
        """
        Parse Go source code from a string.
        
        Useful for testing or when you have source code in memory.
        
        Args:
            source_code: Go source code as string
            filename: Filename to use for reporting
        
        Returns:
            Dict mapping function names to their info
        """
        functions = {}
        
        # Use the same parsing logic as _parse_go_file
        content = source_code
        
        # Parse function declarations
        func_pattern = re.compile(
            r'func\s+(?:\([^)]+\)\s+)?(\w+)\s*\('
            r'(?:\(([^)]*)\)\s+)?'  # Optional receiver: (r *Type)
            r'(\w+)\s*'             # Function name
            r'\(([^)]*)\)'          # Parameters
            r'(?:\s*\(([^)]*)\))?'  # Optional multiple returns: (ret1, ret2)
            r'(?:\s+(\w+(?:\s*\*?\s*\w+)?))?'  # Optional single return type
            r'\s*(?:\{|$)',         # Opening brace or end of line
            re.MULTILINE
        )
        
        for match in func_pattern.finditer(content):
            receiver = match.group(1)
            func_name = match.group(2)
            params_str = match.group(3)
            multi_returns = match.group(4)
            single_return = match.group(5)
            
            # Parse parameters
            params = self._parse_params(params_str)
            
            # Parse returns
            returns = []
            if multi_returns:
                returns = self._parse_params(multi_returns)
            elif single_return:
                returns = [{'name': '', 'type': single_return.strip(), 'size': self._get_type_size(single_return.strip())}]
            
            # Build function info
            func_info = {
                'func_name': func_name,
                'num_params': len(params),
                'num_returns': len(returns),
                'params': params,
                'returns': returns,
                'has_receiver': receiver is not None,
            }
            
            # If has receiver, add it as first parameter
            if receiver:
                receiver_param = self._parse_receiver(receiver)
                if receiver_param:
                    func_info['receiver'] = receiver_param
                    func_info['full_params'] = [receiver_param] + params
                    func_info['num_params'] = len(func_info['full_params'])
            else:
                func_info['full_params'] = params
            
            functions[func_name] = func_info
        
        return functions
    
    def _parse_go_file(self, filepath: Path) -> Dict[str, Dict]:

      functions = {}
    
      try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
      except Exception as e:
        print(f"[!] Could not read file {filepath}: {e}")
        return functions
    

      lines = content.split('\n')
      i = 0
    
      while i < len(lines):
        line = lines[i].strip()
        
        # Look for func keyword at start of line (or after comment/whitespace)
        if not line.startswith('func ') and not line.startswith('func('):
            i += 1
            continue
        
        # Collect the full function signature (may span multiple lines)
        sig_lines = [line]
        brace_count = line.count('{') - line.count('}')
        paren_count = line.count('(') - line.count(')')
        
        # If signature doesn't end on this line, keep collecting
        j = i + 1
        while j < len(lines) and ('{' not in ''.join(sig_lines) or paren_count > 0):
            sig_lines.append(lines[j].strip())
            brace_count += lines[j].count('{') - lines[j].count('}')
            paren_count += lines[j].count('(') - lines[j].count(')')
            j += 1
            if j - i > 10:  # Safety limit
                break
        
        full_sig = ' '.join(sig_lines)
        
        # Now parse the signature
        func_info = self._parse_func_signature(full_sig)
        if func_info and func_info.get('func_name'):
            functions[func_info['func_name']] = func_info
        
        i = j if j > i else i + 1
    
      return functions


    def _parse_func_signature(self, sig: str) -> Optional[Dict]:
      """Parse a single function signature string."""
    
      # Remove 'func ' prefix
      if sig.startswith('func '):
        sig = sig[5:]
      elif sig.startswith('func('):
        sig = sig[4:]
      else:
        return None
    
      receiver = None
      func_name = None
      params_str = ""
      returns_str = ""
    
      # Check for receiver
      if sig.startswith('('):
        # Find matching close paren for receiver
        depth = 0
        end_idx = 0
        for idx, char in enumerate(sig):
            if char == '(':
                depth += 1
            elif char == ')':
                depth -= 1
                if depth == 0:
                    end_idx = idx
                    break
        
        receiver = sig[1:end_idx].strip()
        sig = sig[end_idx + 1:].strip()
    
      # Now sig should be: FuncName(params) returns
      # Find function name (identifier before first paren)
      match = re.match(r'(\w+)\s*\(', sig)
      if not match:
        return None
    
      func_name = match.group(1)
      sig = sig[match.end() - 1:]  # Keep the opening paren
    
      # Extract parameters (content of first set of parens)
      if sig.startswith('('):
        depth = 0
        end_idx = 0
        for idx, char in enumerate(sig):
            if char == '(':
                depth += 1
            elif char == ')':
                depth -= 1
                if depth == 0:
                    end_idx = idx
                    break
        
        params_str = sig[1:end_idx]
        sig = sig[end_idx + 1:].strip()
    
      # Remaining sig is return type(s)
      # Could be: (type1, type2) or just: type or empty
      returns_str = sig.split('{')[0].strip()
    
      # Parse parameters
      params = self._parse_params(params_str)
    
      # Parse returns
      returns = []
      if returns_str:
        if returns_str.startswith('(') and ')' in returns_str:
            # Multiple returns
            returns_content = returns_str[1:returns_str.rfind(')')]
            returns = self._parse_params(returns_content)
        elif returns_str and returns_str != '{':
            # Single return
            returns = [{'name': '', 'type': returns_str, 'size': self._get_type_size(returns_str)}]
    
      # Build result
      func_info = {
        'func_name': func_name,
        'num_params': len(params),
        'num_returns': len(returns),
        'params': params,
        'returns': returns,
        'has_receiver': receiver is not None and len(receiver) > 0,
      }
    
      if func_info['has_receiver']:
        receiver_param = self._parse_receiver(receiver)
        if receiver_param:
            func_info['receiver'] = receiver_param
            func_info['full_params'] = [receiver_param] + params
            func_info['num_params'] = len(func_info['full_params'])
        else:
            func_info['full_params'] = params
      else:
        func_info['full_params'] = params
    
      return func_info
    
    def _parse_params(self, params_str: str) -> List[Dict]:
        """
        Parse a parameter string like "a int, b string, c, d []byte".
        
        Go allows grouped parameters: "a, b int" means both are int.
        """
        if not params_str or not params_str.strip():
            return []
        
        params = []
        
        # Split by comma, but handle complex types like map[string]int, func(int) error
        # Use a state machine approach
        current = ""
        bracket_depth = 0
        raw_params = []
        
        for char in params_str:
            if char in '[{(':
                bracket_depth += 1
                current += char
            elif char in ']})':
                bracket_depth -= 1
                current += char
            elif char == ',' and bracket_depth == 0:
                if current.strip():
                    raw_params.append(current.strip())
                current = ""
            else:
                current += char
        
        if current.strip():
            raw_params.append(current.strip())
        
        # Process raw params, handling grouped params
        pending_names = []
        
        for param in raw_params:
            param = param.strip()
            if not param:
                continue
            
            # Handle variadic parameters: ...Type or name ...Type
            if '...' in param:
                parts = param.split('...')
                if len(parts) == 2:
                    name_part = parts[0].strip()
                    type_part = '[]' + parts[1].strip()  # variadic is essentially a slice
                    
                    # Apply to pending names first
                    for pname in pending_names:
                        params.append({
                            'name': pname,
                            'type': type_part,
                            'size': self._get_type_size(type_part),
                            'variadic': True,
                        })
                    pending_names = []
                    
                    params.append({
                        'name': name_part if name_part else '',
                        'type': type_part,
                        'size': self._get_type_size(type_part),
                        'variadic': True,
                    })
                    continue
            
            # Try to find where the type starts
            # Types can be: basic types, *Type, []Type, map[K]V, chan T, <-chan T, chan<- T, func(...), interface{}, struct{}
            
            type_start_idx = self._find_type_start(param)
            
            if type_start_idx == 0:
                # Whole thing is a type (unnamed parameter)
                param_type = param
                param_name = ""
                
                # Apply to pending names first
                for pname in pending_names:
                    params.append({
                        'name': pname,
                        'type': param_type,
                        'size': self._get_type_size(param_type),
                    })
                pending_names = []
                
                params.append({
                    'name': param_name,
                    'type': param_type,
                    'size': self._get_type_size(param_type),
                })
                
            elif type_start_idx > 0:
                # Has name and type
                name_part = param[:type_start_idx].strip()
                type_part = param[type_start_idx:].strip()
                
                # Apply to pending names first
                for pname in pending_names:
                    params.append({
                        'name': pname,
                        'type': type_part,
                        'size': self._get_type_size(type_part),
                    })
                pending_names = []
                
                params.append({
                    'name': name_part,
                    'type': type_part,
                    'size': self._get_type_size(type_part),
                })
                
            else:
                # Just a name, type will come later
                pending_names.append(param)
        
        # Handle any remaining names without types (shouldn't happen in valid Go)
        for pname in pending_names:
            params.append({
                'name': pname,
                'type': 'unknown',
                'size': 8,
            })
        
        return params
    
    def _find_type_start(self, param: str) -> int:
        """
        Find where the type starts in a parameter declaration.
        Returns the index where the type starts, or -1 if no type found, or 0 if whole thing is type.
        """
        param = param.strip()
        
        # If starts with type indicators, whole thing is a type
        type_prefixes = ['*', '[', 'map[', 'func(', 'interface{', 'struct{', '<-chan', 'chan<-']
        for prefix in type_prefixes:
            if param.startswith(prefix):
                return 0
        
        # 'chan' without <- prefix
        if param.startswith('chan '):
            return 0
        
        # Split by whitespace to analyze
        parts = param.split()
        
        if len(parts) == 1:
            # Single token - either a type or a name
            # If it contains a dot and the part after dot is capitalized, it's a qualified type
            if '.' in param:
                last_part = param.split('.')[-1]
                if last_part and last_part[0].isupper():
                    return 0  # It's a type like context.Context
            # If it starts with uppercase, could be a type
            if param[0].isupper():
                return 0
            # Otherwise it's a name waiting for a type
            return -1
        
        # Multiple tokens - find where name ends and type begins
        # Check if this is "name type" pattern where type might have spaces
        
        basic_types = {'bool', 'string', 'error', 'any',
                      'int', 'int8', 'int16', 'int32', 'int64',
                      'uint', 'uint8', 'uint16', 'uint32', 'uint64',
                      'uintptr', 'byte', 'rune',
                      'float32', 'float64', 'complex64', 'complex128'}
        
        # Look for "name chan type" or "name func(...) type" patterns
        for i, part in enumerate(parts[:-1]):  # Skip last part for now
            # Check if next part starts a multi-word type
            next_part = parts[i + 1]
            
            # chan type (chan elem)
            if next_part == 'chan' or next_part == '<-chan' or next_part == 'chan<-':
                idx = param.find(next_part)
                return idx
            
            # func type
            if next_part.startswith('func('):
                idx = param.find(next_part)
                return idx
            
            # Type starters
            if next_part.startswith(('*', '[', 'map[', 'interface{', 'struct{')):
                idx = param.find(next_part)
                return idx
            
            # Basic types
            if next_part in basic_types:
                idx = param.find(' ' + next_part)
                if idx >= 0:
                    return idx + 1
            
            # Qualified type like pkg.Type or context.Context
            if '.' in next_part:
                last_dot_part = next_part.split('.')[-1]
                if last_dot_part and last_dot_part[0].isupper():
                    idx = param.find(' ' + next_part)
                    if idx >= 0:
                        return idx + 1
            
            # Capitalized identifier (exported type)
            if next_part and next_part[0].isupper():
                idx = param.find(' ' + next_part)
                if idx >= 0:
                    return idx + 1
        
        # Check last part alone
        last = parts[-1]
        if last in basic_types:
            idx = param.rfind(' ' + last)
            if idx >= 0:
                return idx + 1
        if last and last[0].isupper():
            idx = param.rfind(' ' + last)
            if idx >= 0:
                return idx + 1
        if '.' in last:
            last_dot_part = last.split('.')[-1]
            if last_dot_part and last_dot_part[0].isupper():
                idx = param.rfind(' ' + last)
                if idx >= 0:
                    return idx + 1
        
        return -1  # No type found
    
    def _parse_receiver(self, receiver_str: str) -> Optional[Dict]:
        """Parse a receiver like "c *Conn" or "r Reader"."""
        receiver_str = receiver_str.strip()
        if not receiver_str:
            return None
        
        parts = receiver_str.split()
        if len(parts) >= 2:
            name = parts[0]
            type_str = ' '.join(parts[1:])
        else:
            name = ""
            type_str = parts[0]
        
        return {
            'name': name,
            'type': type_str,
            'size': self._get_type_size(type_str),
            'is_receiver': True,
        }
    
    def _looks_like_type(self, s: str) -> bool:
        """Check if a string looks like a Go type."""
        s = s.strip()
        
        if not s:
            return False
        
        # Pointer types
        if s.startswith('*'):
            return True
        
        # Slice/array types
        if s.startswith('['):
            return True
        
        # Map types
        if s.startswith('map['):
            return True
        
        # Channel types
        if s.startswith('chan ') or s.startswith('<-chan') or s.startswith('chan<-'):
            return True
        
        # Function types
        if s.startswith('func(') or s.startswith('func '):
            return True
        
        # Interface types
        if s.startswith('interface{'):
            return True
        
        # Struct types
        if s.startswith('struct{'):
            return True
        
        # Basic types
        basic_types = {'bool', 'string', 'error', 'any',
                      'int', 'int8', 'int16', 'int32', 'int64',
                      'uint', 'uint8', 'uint16', 'uint32', 'uint64',
                      'uintptr', 'byte', 'rune',
                      'float32', 'float64', 'complex64', 'complex128'}
        
        if s in basic_types:
            return True
        
        # Qualified types like pkg.Type or domain.com/pkg.Type
        # These are types, not variable names
        if '.' in s:
            # Check if it's a qualified type (package.Type)
            parts = s.split('.')
            # Last part should start with uppercase (exported type)
            if parts[-1] and parts[-1][0].isupper():
                return True
            # Or it could be a well-known package type
            well_known = ['context.Context', 'time.Time', 'time.Duration', 
                         'io.Reader', 'io.Writer', 'io.ReadWriter', 'io.Closer',
                         'net.Conn', 'net.Listener', 'net.Addr',
                         'http.Request', 'http.Response', 'http.Handler',
                         'sync.Mutex', 'sync.RWMutex', 'sync.WaitGroup',
                         'bytes.Buffer', 'strings.Builder']
            if s in well_known:
                return True
        
        # Capital letter usually indicates a type name (exported identifier)
        # But be careful: "A" could be a variable name too
        # Only consider it a type if it's a single word with no spaces
        if ' ' not in s and s[0].isupper():
            return True
        
        return False
    
    def _get_type_size(self, type_str: str) -> int:
        """Get the size of a Go type in bytes (64-bit)."""
        type_str = type_str.strip()
        
        # Check basic types
        if type_str in self.TYPE_SIZES:
            return self.TYPE_SIZES[type_str]
        
        # Pointer types
        if type_str.startswith('*'):
            return 8
        
        # Slice types
        if type_str.startswith('[]'):
            return 24  # ptr + len + cap
        
        # Array types [N]T
        match = re.match(r'\[(\d+)\](.+)', type_str)
        if match:
            count = int(match.group(1))
            elem_type = match.group(2)
            return count * self._get_type_size(elem_type)
        
        # Map types
        if type_str.startswith('map['):
            return 8  # pointer to hmap
        
        # Channel types
        if 'chan' in type_str:
            return 8  # pointer to hchan
        
        # Function types
        if type_str.startswith('func'):
            return 8  # function pointer
        
        # Interface types
        if type_str.startswith('interface{') or type_str == 'any':
            return 16  # iface: tab + data
        
        # error is an interface
        if type_str == 'error':
            return 16
        
        # struct types - need full parsing, assume pointer size for now
        if type_str.startswith('struct{'):
            return 8  # Conservative estimate
        
        # Custom types - assume pointer or struct
        # Most custom types are passed as pointers
        return 8
    
    def _parse_package(self, package_path: str) -> Dict[str, Dict[str, Dict]]:
        """
        Parse all Go files in a package.
        
        Returns:
            Dict mapping relative file paths to their function info
        """
        if package_path in self.parsed_cache:
            return self.parsed_cache[package_path]
        
        # Download if needed
        pkg_dir = self._download_package(package_path)
        if not pkg_dir:
            return {}
        
        package_funcs = {}
        
        # Walk all .go files
        for root, dirs, files in os.walk(pkg_dir):
            # Skip test files and vendor
            dirs[:] = [d for d in dirs if d not in ['vendor', 'testdata', '.git']]
            
            for filename in files:
                if not filename.endswith('.go'):
                    continue
                if filename.endswith('_test.go'):
                    continue
                
                filepath = Path(root) / filename
                rel_path = filepath.relative_to(pkg_dir)
                
                # Parse the file
                funcs = self._parse_go_file(filepath)
                if funcs:
                    package_funcs[str(rel_path)] = funcs
        
        # Cache the results
        self.parsed_cache[package_path] = package_funcs
        
        # Also save to disk
        cache_file = self._get_package_cache_dir(package_path) / "functions.json"
        try:
            with open(cache_file, 'w') as f:
                json.dump(package_funcs, f, indent=2)
        except Exception as e:
            print(f"[WARN] Could not save parsed cache: {e}")
        
        return package_funcs
    
    def get_function_info(self, filepath: str, func_name: str) -> Optional[Dict]:
        """
        Get function parameter information for a third-party function.
        
        Args:
            filepath: Full path from Go binary, e.g., "github.com/user/repo/pkg/file.go"
            func_name: Name of the function
        
        Returns:
            Dict with function info, or None if not found
        """
        # Extract package path
        package_path, rel_path = self._extract_package_from_filepath(filepath)
        
        if not package_path:
            print(f"[!] Could not determine package from: {filepath}")
            return None
        
        # Check disk cache first
        cache_file = self._get_package_cache_dir(package_path) / "functions.json"
        if cache_file.exists() and package_path not in self.parsed_cache:
            try:
                with open(cache_file, 'r') as f:
                    self.parsed_cache[package_path] = json.load(f)
            except Exception:
                pass
        
        # Parse package if needed
        package_funcs = self._parse_package(package_path)
        
        if not package_funcs:
            print(f"[!] Could not parse package: {package_path}")
            return None
        
        # Look for the function
        # First try the exact relative path
        if rel_path in package_funcs:
            if func_name in package_funcs[rel_path]:
                return package_funcs[rel_path][func_name]
        
        # Try just the filename
        filename = rel_path.split('/')[-1] if '/' in rel_path else rel_path
        for file_path, funcs in package_funcs.items():
            if file_path.endswith(filename) or file_path.endswith('/' + filename):
                if func_name in funcs:
                    return funcs[func_name]
        
        # Search all files in package
        for file_path, funcs in package_funcs.items():
            if func_name in funcs:
                return funcs[func_name]
        
        print(f"[!] Function '{func_name}' not found in package '{package_path}'")
        return None
    
    def get_all_functions_in_file(self, filepath: str) -> Dict[str, Dict]:
        """
        Get all functions in a specific file.
        
        Args:
            filepath: Full path from Go binary
        
        Returns:
            Dict mapping function names to their info
        """
        package_path, rel_path = self._extract_package_from_filepath(filepath)
        
        if not package_path:
            return {}
        
        package_funcs = self._parse_package(package_path)
        
        if not package_funcs:
            return {}
        
        # Try exact match first
        if rel_path in package_funcs:
            return package_funcs[rel_path]
        
        # Try filename match
        filename = rel_path.split('/')[-1] if '/' in rel_path else rel_path
        for file_path, funcs in package_funcs.items():
            if file_path.endswith(filename):
                return funcs
        
        return {}


# Singleton instance for use in the Volatility plugin
_analyzer_instance = None

def get_analyzer(cache_dir: Optional[str] = None) -> ThirdPartyGoAnalyzer:
    """Get or create the global analyzer instance."""
    global _analyzer_instance
    if _analyzer_instance is None:
        _analyzer_instance = ThirdPartyGoAnalyzer(cache_dir)
    return _analyzer_instance


def lookup_third_party_function(filepath: str, func_name: str) -> Optional[Dict]:
    """
    Convenience function to look up a third-party function.
    
    Args:
        filepath: Path from Go binary, e.g., "github.com/user/repo/pkg/file.go"
        func_name: Function name to look up
    
    Returns:
        Dict with function info:
        {
            'func_name': str,
            'num_params': int,
            'num_returns': int,
            'params': [{'name': str, 'type': str, 'size': int}, ...],
            'returns': [{'name': str, 'type': str, 'size': int}, ...],
            'has_receiver': bool,
            'receiver': {...} if has_receiver else None,
            'full_params': [...],  # Including receiver as first param
        }
    """
    analyzer = get_analyzer()
    return analyzer.get_function_info(filepath, func_name)


# Example usage and testing
if __name__ == "__main__":
    # Test the analyzer
    analyzer = ThirdPartyGoAnalyzer()
    
    # Test parsing a parameter string
    print("Testing parameter parsing:")
    test_params = [
        "a int, b string",
        "x, y int, z string",
        "buf []byte",
        "m map[string]int",
        "ch chan int",
        "fn func(int) error",
        "ctx context.Context, opts ...Option",
    ]
    
    for params in test_params:
        result = analyzer._parse_params(params)
        print(f"  '{params}' -> {result}")
    
    print("\nTesting package extraction:")
    test_paths = [
        "github.com/BurntSushi/xgb/xproto/xproto.go",
        "github.com/google/gopacket/layers/ethernet.go",
        "golang.org/x/crypto/ssh/client.go",
        "google.golang.org/grpc/server.go",
    ]
    
    for path in test_paths:
        pkg, rel = analyzer._extract_package_from_filepath(path)
        print(f"  '{path}' -> pkg='{pkg}', rel='{rel}'")
    
    print("\nTesting type sizes:")
    test_types = [
        "int", "*int", "[]byte", "[10]int", "map[string]int",
        "chan int", "func(int) error", "interface{}", "error",
    ]
    
    for t in test_types:
        size = analyzer._get_type_size(t)
        print(f"  '{t}' -> {size} bytes")
