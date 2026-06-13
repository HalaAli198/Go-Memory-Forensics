# Memory Forensics Techniques for Automated Detection and Analysis of Go Malware

This repository accompanies the paper [*"Memory Forensics Techniques for Automated Detection and Analysis of Go Malware"*](https://arxiv.org/abs/2605.14020) and provides a novel suite of [Volatility 3](https://github.com/volatilityfoundation/volatility3) plugins for runtime analysis of Go binaries.

The plugins reconstruct the **runtime state of Go (golang) programs** directly from a process memory image.  Every plugin walks the Go runtime's own metadata ( `pclntab`, `moduledata`, the type system, and the `mheap_` allocator) so each recovered artifact (string, function, argument, goroutine, heap object) is attributed to *where it lives* and *what type it is*.

## Features

- Recovers Go strings, functions, goroutines, types, and heap objects directly from process memory.
- Works on stripped and Garble-obfuscated binaries; no symbols or debugging information required.
- Recovers concrete argument values at function call sites and in goroutine stack frames.
- Classifies functions by origin (runtime, standard library, third-party, application).
- Supports Go 1.2 through current releases on Linux and Windows (x86-64).
- Supports Linux and Windows memory images on x86-64.
---

## Plugins

### `go_strings`
Recovers Go strings from both the heap and the static sections (`.rodata`, `.data`, `.bss`). Unlike the standard `strings` utility, it reconstructs Go string headers together with their backing data and reports their memory locations, distinguishing compile-time constants from dynamically allocated strings. 

### `go_functions`
Recovers function metadata from `pclntab` and `moduledata`, resolves each function's name and source filename (from process memory plus the page-cached binary), classifies functions by origin (runtime, internal, standard library, third-party, application), infers argument types from interface tables, type methods, and `ArgInfo` / `ArgsPointerMaps`, and performs **ABI-aware backward analysis** from call sites to recover argument values.

### `go_goroutines`
Discovers every goroutine via `runtime.allgs` and unwinds each one's saved stack using the `PCSP` tables to reconstruct its complete call chain, down to the function executing at capture time. For each stack frame it recovers typed argument values through a five-tier resolution cascade (the binary's own type methods, runtime/stdlib and third-party signature databases, and `ArgInfo` / `ArgsPointerMaps` structural heuristics), and reports each goroutine's execution state and wait reason (channel receive, mutex, sleep, I/O wait).

### Supporting plugin

- **`go_entire_heap`**: a type-driven recursive walk over *all* reachable heap objects, including booleans, integers, floats, strings, slices, arrays, structs, maps(`hmap` pre-1.24 and Swiss Tables 1.24+), and interfaces. It reports heap address, data address, type, value, and memory region. It also emits the `heap_strings_pid_<PID>.json` used by `go_goroutines` for pointer→string resolution.

---

## Supported Environments

- **Architectures:** x86-64
- **Operating systems:** Linux and Windows memory images
- **Go versions:** Go 1.2 through current releases (version-aware parsing of `pcHeader` and `moduledata`; stack-based ABI ≤ 1.16 and register-based ABI 1.17+)
- **Volatility:** Volatility 3 (framework version 2.0.0+)

---

## Repository layout

```
.
├── Linux_Plugins/                 # Volatility 3 plugins for Linux memory images
│   ├── go_strings.py
│   ├── go_functions.py
│   ├── go_goroutines.py
│   ├── go_entire_heap.py
│   ├── go_file_classifier.py      # helper: source-path → category classifier
│   └── third_party_analyzer.py    # helper: download/parse 3rd-party Go pkgs for signatures
├── Windows_Plugins/               # Windows (PE) variants of the same plugins
├── file_func_params_extractor/    # function-signature database (runtime, stdlib, and itnernal)+ its generator
│   ├── go_func_signature.py       # builds go_func_lines_v<VERSION>.json from Go source
│   ├── go_func_lines_v115.json    # one DB per Go toolchain version
│   ├── go_func_lines_v116.json
│   ├── go_func_lines_v118.json
│   ├── go_func_lines_v1210.json
│   ├── go_func_lines_v12410.json
│   └── go_func_lines_v1255.json
├── required_heap_json_files/      # pre-built heap-address JSON for the sample dumps
│   ├── heap_strings_pid_1100.json   # Obscura
│   ├── heap_strings_pid_2004.json   # BRICKSTORM
│   └── heap_strings_pid_2795.json   # Pantegana
├── Results/                       # reference output for the paper's figures/tables
├── LICENSE
└── README.md
```

---

## Requirements

- Python 3.8 or higher
- [Volatility 3](https://github.com/volatilityfoundation/volatility3) Framework
- [Capstone](https://pypi.org/project/capstone/) disassembly engine (used by `go_functions` for ABI-aware backward analysis)
- `pandas`
- For Linux memory analysis: appropriate kernel debugging symbols (see below)

> **Note:** The Go plugins do **not** require Go-specific debugging symbols. All Go runtime metadata is recovered directly from process memory by parsing embedded structures (`pclntab`, `moduledata`), making the plugins effective even on stripped and obfuscated binaries.

---

## Installation

### 1. Install Volatility 3

The plugins are built on top of the Volatility 3 framework. Clone the Volatility 3 repository and follow the installation instructions at <https://github.com/volatilityfoundation/volatility3>.

### 2. Install Capstone and pandas

```bash
pip install capstone pandas
```

### 3. Install the plugins

Copy the plugins (and their two helper modules) into your Volatility 3 plugin tree:

```bash
# Linux plugins
cp Linux_Plugins/*.py   /path/to/volatility3/volatility3/plugins/linux/

# Windows plugins
cp Windows_Plugins/*.py /path/to/volatility3/volatility3/plugins/windows/
```

`go_file_classifier.py` and `third_party_analyzer.py` must sit alongside the plugins (they are imported as `volatility3.plugins.linux.*` and `volatility3.plugins.windows.*`).

### 4. Generate kernel symbol tables (Linux)

Use the [dwarf2json](https://github.com/volatilityfoundation/dwarf2json) tool to generate the Linux kernel symbol tables Volatility 3 requires. Clone the repository, place it in the Volatility 3 directory, and follow its build instructions.

```bash
./dwarf2json linux --elf /path/to/vmlinux > vmlinux-VERSION.json
# example:
./dwarf2json linux --elf vmlinux-5.15.0-126-generic > vmlinux-5.15.0-126-generic.json
```

Place the resulting `.json` file in `/path/to/volatility3/symbols/`.

---

## Usage

Each plugin runs on a single process by PID, following standard Volatility 3 conventions:

```bash
python3 vol.py -f <memory_image> linux.go_strings.Go_Strings       --pid <PID>
python3 vol.py -f <memory_image> linux.go_functions.Go_Functions   --pid <PID>
python3 vol.py -f <memory_image> linux.go_goroutines.Go_Goroutines --pid <PID>

# Full typed heap walk (also writes heap_strings_pid_<PID>.json)
python3 vol.py -f <memory_image> linux.go_entire_heap.Go_Entire_Heap --pid <PID>
```

Garble-obfuscated binaries need no special flags or separate plugin. Every plugin detects randomized magic bytes and falls back automatically.

For Windows memory images, replace `linux` with `windows`:

```bash
python3 vol.py -f <memory_image> windows.go_strings.Go_Strings --pid <PID>
```

### Recommended order
 
`go_strings` runs on its own. `go_functions` and `go_goroutines` rely on a function-signature database, and `go_goroutines` additionally relies on a heap-address JSON. Prepare these inputs first:
 
1. **`go_func_signature`** → `go_func_lines_v<VERSION>.json`: the function-signature database, consumed by **both `go_functions` and `go_goroutines`** for known runtime/stdlib/third-party signatures. Pre-built databases for several Go versions ship in `file_func_params_extractor/`; only regenerate if your target's version isn't included.
2. **`go_entire_heap`** → `heap_strings_pid_<PID>.json`: the heap-address JSON, consumed by **`go_goroutines`** for pointer→string resolution. Pre-built files for the bundled sample PIDs are in `required_heap_json_files/`.
Then run the analysis plugins: `go_functions` (needs #1) and `go_goroutines` (needs #1 and #2).
 

---

## Configuration

A few inputs are selected per target binary. **`go_functions` and `go_goroutines` currently reference these paths as in-code constants. Set them to match your environment and the analyzed binary's Go version before running:**

- **Function-signature database.** Pick the `go_func_lines_v<VERSION>.json` that matches the target's Go toolchain (e.g. `v1255` → Go 1.25.5, `v116` → Go 1.16, `v115` → Go 1.15, `v12410` → Go 1.24.10). This DB supplies parameter names and types for runtime, internal, and standard library functions; third-party signatures are generated on demand by `third_party_analyzer.py`. Regenerate for other Go versions with `go_func_signature.py`.
- **Heap-address JSON.** Point `go_goroutines` at the `heap_strings_pid_<PID>.json` produced for the same PID.

---

## Supporting components

- **`go_file_classifier.py`**: classifies a Go source-file path into `RUNTIME_CORE`, `RUNTIME_INTERNAL`, `STDLIB_INTERNAL`, `STDLIB_PUBLIC`, `THIRD_PARTY`, `APPLICATION`, `AUTOGENERATED`, `CGO`, or `UNKNOWN`. Handles relative, absolute, GOPATH, vendor, and versioned (`@v1.2.3`) module paths. This is what lets `go_functions` focus disassembly on application code.
- **`third_party_analyzer.py`**: downloads, caches, and parses third-party Go packages to extract function signatures and parameter layouts, feeding the function/goroutine argument-recovery tiers.
- **`file_func_params_extractor/go_func_signature.py`**: generates the `go_func_lines_v<VERSION>.json` signature databases from Go source for a given toolchain version.

---

## Evaluation Samples

The paper evaluates the framework against:

- **BRICKSTORM** (PID 2004): Go-based backdoor attributed to UNC5221. Linux, Go 1.16.3.
- **Obscura** (PID 1100): Go-based ransomware targeting enterprise environments. Windows, Go 1.15.
- **Pantegana** (PID 2795): Go-based RAT abused by RedNovember. Linux, Go 1.25.5.
- **Screenshotter**: open-source Go application included for reproducibility. Go 1.24.10.

Reference output for each figure and table is provided in `Results/`:

| Sample | Plugin | Reference output |
|---|---|---|
| BRICKSTORM | `go_functions` | `Table2+Table3+Table4+Figure5+Figure6_go_functions_BRICKSTORM.txt` |
| Obscura | `go_strings` | `Table1_go_strings_Obsecura.txt` |
| Pantegana | `go_strings` | `Figure7_go_strings_Pantegana.txt` |
| Screenshotter | `go_strings` | `Figure4_go_strings_Screenshotter.txt` |

Pre-built heap-address JSON for the three memory dumps (PIDs 1100, 2004, 2795) is in `required_heap_json_files/`.

---

## Citation

If you use this work, please cite:

```bibtex
@article{ali2026memory,
  title={Memory Forensics Techniques for Automated Detection and Analysis of Go Malware},
  author={Ali, Hala and Case, Andrew and Ahmed, Irfan},
  journal={arXiv preprint arXiv:2605.14020},
  year={2026}
}
```

Full citation details (venue and pages) will be updated upon publication.

---
