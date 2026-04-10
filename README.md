# Memory Forensics Techniques for Automated Detection and Analysis of Go Malware

This repository accompanies the paper **"Memory Forensics Techniques for Automated Detection and Analysis of Go Malware"** and provides a suite of [Volatility 3](https://github.com/volatilityfoundation/volatility3) plugins for runtime analysis of Go binaries in memory.

> **Release status.** This repository is currently a placeholder. The full implementation, documentation, and reproduction materials will be released by the time of the conference presentation. Please check back, or watch this repository for updates.

## Plugins

The framework is implemented as three Volatility 3 plugins:

### `go_strings`
Recovers Go strings from both heap and static sections (`.rodata`, `.data`, `.bss`). Unlike the standard `strings` utility, it reconstructs Go string headers together with their backing data and reports their memory locations, distinguishing compile-time constants from dynamically allocated strings.

### `go_functions`
Recovers function metadata from `pclntab` and `moduledata`, classifies functions by origin (runtime, standard library, third-party, application-level), infers argument types from `ArgInfo` / `ArgsPointerMaps`, and performs ABI-aware backward analysis from call sites to recover argument values. Also recovers types, interfaces, and type methods.

### `go_goroutines`
Enumerates goroutines by locating `runtime.allgs`, unwinds each goroutine's call stack using `pcsp` streams, identifies actively executing functions, and recovers their runtime argument values, including state that exists only at execution time.

## Supported Environments

* **Architectures:** x86-64
* **Operating systems:** Linux and Windows memory images
* **Go versions:** Go 1.2 through current releases (version-aware parsing of `pcHeader` and `moduledata`)
* **Volatility:** Volatility 3

## Evaluation Samples

The paper evaluates the framework against:

* **BRICKSTORM:** Go-based backdoor attributed to UNC5221 (Linux, Go 1.16.3)
* **Obscura:** Go-based ransomware targeting enterprise environments (Windows, Go 1.15)
* **Pantegana:** Go-based RAT abused by RedNovember (Linux, Go 1.25.5)
* **Screenshotter:** open-source Go application for reproducibility (Go 1.24.10)

## Requirements

* Python 3.8 or higher
* Volatility 3 Framework
* Capstone disassembly engine
* For Linux memory analysis: appropriate debugging symbols

## Installation

_Full installation and usage instructions will be provided with the complete release. The steps below outline the planned setup._

**1. Install Volatility 3**

The plugins are built on top of the Volatility 3 framework. Clone the Volatility 3 repository and follow the installation instructions at: <https://github.com/volatilityfoundation/volatility3>

**2. Install Capstone**

The plugins use Capstone for disassembly during ABI-aware backward analysis:

    pip install capstone

**3. Install the dwarf2json Tool**

Use the `dwarf2json` tool to generate Linux kernel symbol tables required by Volatility 3. Clone the `dwarf2json` repository, place it in the Volatility 3 directory, and follow the installation instructions at: <https://github.com/volatilityfoundation/dwarf2json>

**4. Generate Symbol Tables**

For Linux Kernel:

* Command: `./dwarf2json linux --elf /path/to/vmlinux > vmlinux-VERSION.json`
* Example: `./dwarf2json linux --elf vmlinux-5.15.0-126-generic > vmlinux-5.15.0-126-generic.json`
* Place the `.json` file in the `/path/to/Volatility3/symbols/` directory.

**Note:** The Go plugins do not require Go-specific debugging symbols. All Go runtime metadata is recovered directly from process memory by parsing embedded structures (`pclntab`, `moduledata`), making the plugins effective even on stripped and obfuscated binaries.

## Planned Usage

Once released, usage will follow standard Volatility 3 plugin conventions:

    python3 vol.py -f <memory_image> linux.go_strings.GoStrings --pid <PID>
    python3 vol.py -f <memory_image> linux.go_functions.GoFunctions --pid <PID>
    python3 vol.py -f <memory_image> linux.go_goroutines.GoGoroutines --pid <PID>

For Windows memory images, replace `linux` with `windows`:

    python3 vol.py -f <memory_image> windows.go_strings.GoStrings --pid <PID>

## Citation

If you use this work, please cite:

    @inproceedings{ali2026gomemory,
      title     = {Memory Forensics Techniques for Automated Detection and Analysis of Go Malware},
      author    = {Ali, Hala and Case, Andrew and Ahmed, Irfan},
      booktitle = {},
      year      = {2026}
    }

_Full citation details will be updated upon publication._


