# M8 — ELF Analyzer

An Executable and Linkable Format (ELF) analyzer for Linux/malware research.

## Overview

This project implements an ELF file parser that:
- Parses the ELF32/ELF64 header
- Enumerates and analyzes sections
- Extracts symbol tables (SYMTAB/DYNSYM)
- Dumps relocation entries (REL/RELA)
- Reports machine architecture and entry point

## Features

- **Header parsing**: ELF32/ELF64, both endiannesses
- **Section analysis**: type, address, size, name
- **Symbol table**: locals/globals/weak, functions, objects
- **Relocations**: REL/RELA with Intel x86/x64 type names
- **Architecture detection**: x86, x64, ARM, AArch64, MIPS, RISC-V, etc.

## Usage

```bash
python3 elf_analyzer.py binary
python3 elf_analyzer.py /bin/ls
```

## Example Output

```
=== M8 - ELF Analyzer ===
File: /bin/ls
Size: 142144 bytes
Class: ELF64
Endian: little

-- ELF Header --
  Type:      DYN
  Machine:   x86_64
  Entry:     0x6500
  ...
```

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**. 

### Authorization Requirements
- You MUST have explicit written permission from the network owner before using this tool
- Unauthorized interception of network communications is illegal under federal and state laws
- This tool should ONLY be used on networks you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Intercepting communications on networks you do not own
- Attacking infrastructure without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
