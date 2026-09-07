# M8 — ELF File Analyzer

A hand-written Executable and Linkable Format (ELF) parser for Linux binary research and forensics education.

## Overview

This project implements an ELF32/ELF64 parser from scratch using only the Python standard library. It parses ELF headers, program headers, section headers, symbol tables, relocations, and identifies GOT/PLT sections.

## Features

- **Header parsing**: ELF32 and ELF64, both endiannesses
- **Section analysis**: type, address, offset, size, Shannon entropy
- **Program headers**: loadable segments and their mapping
- **Symbol tables**: SYMTAB/DYNSYM with name, type, bind, visibility
- **Relocations**: REL/RELA with x86/x64 type names
- **GOT/PLT detection**: approximates linker tables from section names
- **Architecture detection**: i386, x86_64, ARM, AArch64, MIPS, RISC-V, etc.
- **Minimal ELF builder**: craft ELF32 and ELF64 fixtures for testing

## Usage

```bash
# Analyze an ELF binary
python3 elf_analyzer.py /bin/ls

# JSON output
python3 elf_analyzer.py /bin/ls --json

# List all symbols
python3 elf_analyzer.py /bin/ls --symbols

# Save report
python3 elf_analyzer.py /bin/ls -o reports/analysis.json

# Offline demo with crafted fixture
python3 elf_analyzer.py --demo
```

## Example Output

```
=== M8 - ELF File Analyzer ===
File: /bin/ls (142144 bytes)
Class: ELF64  Endian: little
Type: DYN  Machine: x86_64
Entry: 0x6500
-- Sections --
  .text      PROGBITS             Addr=0x3470 Size=116112 Entropy=6.42
  .dynsym    DYNSYM               Addr=0x3d8 Size=168 Entropy=0.5871
  ...
```

## Tests

```bash
python -m unittest discover -s tests
```

## Live Lab Test Plan

1. Run `--demo` offline and verify exit code 0
2. Parse a gcc-compiled binary and verify real section/symbol data
3. Compare against `readelf -h` output for header field verification
4. Parse both ELF32 and ELF64 crafted fixtures
5. Run the parsing on `/bin/ls`, `/bin/bash` and verify entropy values
6. Verify symbols/relocations from a dynamically-linked binary

## Metrics

- Hand-written parser: ~400 lines, zero external dependencies
- Supports ELF32/ELF64, big/little endian
- Parses sections, symbols, relocations, program headers
- Shannon entropy per section
- Validated against real gcc-compiled binaries
- Minimal ELF32/ELF64 fixture builder

## IMPORTANT: Read before use.

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission from the system owner before using this tool
- Analysis of binaries you do not own or have authorization to test may be illegal
- This tool should ONLY be used on files you own or have written authorization to analyze

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **State Laws**: Many states have additional computer crime statutes

### Acceptable Use
- Malware research in controlled lab environments
- Reverse engineering for authorized security assessments
- Academic research and education
- Forensic analysis of your own systems

### Prohibited Use
- Analyzing binaries belonging to others without authorization
- Using findings to gain unauthorized access
- Any activity that violates applicable laws or regulations

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
