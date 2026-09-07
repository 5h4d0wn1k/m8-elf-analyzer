#!/usr/bin/env python3
"""M8 - ELF File Analyzer: hand-written ELF32/ELF64 parser."""

import argparse
import hashlib
import json
import math
import os
import struct
import sys
from typing import Any, Dict, List, Optional


class ELFParser:
    """Parse an ELF file from raw bytes (ELF32/ELF64, both endian)."""

    ET_TYPES = {
        0: 'NONE', 1: 'REL', 2: 'EXEC', 3: 'DYN', 4: 'CORE',
    }
    MACHINES = {
        0x03: 'i386', 0x3e: 'x86_64', 0x28: 'ARM', 0xb7: 'AArch64',
        0x08: 'MIPS', 0xf3: 'RISC-V', 0x02: 'SPARC', 0x14: 'PowerPC',
    }
    PT_TYPES = {
        0: 'NULL', 1: 'LOAD', 2: 'DYNAMIC', 3: 'INTERP', 4: 'NOTE',
        5: 'SHLIB', 6: 'PHDR', 7: 'TLS', 0x6474e550: 'GNU_EH_FRAME',
        0x6474e551: 'GNU_STACK', 0x6474e552: 'GNU_RELRO',
    }
    SHT_TYPES = {
        0: 'NULL', 1: 'PROGBITS', 2: 'SYMTAB', 3: 'STRTAB', 4: 'RELA',
        5: 'HASH', 6: 'DYNAMIC', 7: 'NOTE', 8: 'NOBITS', 9: 'REL',
        11: 'DYNSYM', 14: 'INIT_ARRAY', 15: 'FINI_ARRAY', 16: 'PREINIT_ARRAY',
        17: 'GROUP', 18: 'SYMTAB_SHNDX', 19: 'RELRO',
    }
    X86_64_RELOC = {
        0: 'R_X86_64_NONE', 1: 'R_X86_64_64', 2: 'R_X86_64_PC32',
        5: 'R_X86_64_COPY', 6: 'R_X86_64_GLOB_DAT', 7: 'R_X86_64_JUMP_SLOT',
        8: 'R_X86_64_RELATIVE', 10: 'R_X86_64_32', 17: 'R_X86_64_GOTPCREL',
    }
    X86_RELOC = {
        0: 'R_386_NONE', 1: 'R_386_32', 2: 'R_386_PC32',
        3: 'R_386_GOT32', 4: 'R_386_PLT32', 7: 'R_386_RELATIVE',
        8: 'R_386_GOTOFF', 9: 'R_386_GOTPC',
    }

    def __init__(self, data: bytes):
        self.data = data
        self.is_64 = False
        self.little_endian = True
        self.ehdr: Dict[str, Any] = {}
        self.program_headers: List[Dict[str, Any]] = []
        self.section_headers: List[Dict[str, Any]] = []
        self.sections: List[Dict[str, Any]] = []
        self.symbols: List[Dict[str, Any]] = []
        self.relocations: List[Dict[str, Any]] = []
        self.entry_point = 0
        self.shstrtab = ''
        self._parse()

    @property
    def endian_char(self) -> str:
        return '<' if self.little_endian else '>'

    def _S(self, fmt: str, offset: int, count: int = 1):
        """Read a struct value of the given format from offset."""
        size = struct.calcsize(fmt)
        if offset + size > len(self.data):
            raise ValueError(f"Truncated ELF at offset {offset}")
        val = struct.unpack_from(self.endian_char + fmt, self.data, offset)
        return val[0] if count == 1 else val

    def _S_c(self, fmt, offset):
        return struct.unpack_from(self.endian_char + fmt, self.data, offset)

    def _parse(self):
        if len(self.data) < 52:
            raise ValueError("File too small for ELF header")
        if self.data[0:4] != b'\x7fELF':
            raise ValueError("Not an ELF file: bad magic")
        self.is_64 = self.data[4] == 2
        ei_data = self.data[5]
        if ei_data == 1:
            self.little_endian = True
        elif ei_data == 2:
            self.little_endian = False
        else:
            raise ValueError("Invalid endianness byte")
        self._parse_ehdr()
        self._parse_program_headers()
        self._parse_section_headers()
        self._parse_symbols()
        self._parse_relocations()

    def _parse_ehdr(self):
        e = self.endian_char
        if self.is_64:
            (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
             e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize,
             e_shnum, e_shstrndx) = struct.unpack_from(
                e + 'HHIQQQIHHHHHH', self.data, 16)
        else:
            (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
             e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize,
             e_shnum, e_shstrndx) = struct.unpack_from(
                e + 'HHIIIIIHHHHHH', self.data, 16)
        self.entry_point = e_entry
        self.ehdr = {
            'Class': 'ELF64' if self.is_64 else 'ELF32',
            'Endian': 'little' if self.little_endian else 'big',
            'Type': self.ET_TYPES.get(e_type, f'0x{e_type:x}'),
            'Machine': self.MACHINES.get(e_machine, f'0x{e_machine:x}'),
            'Version': e_version,
            'EntryPoint': f'0x{e_entry:x}',
            'Flags': f'0x{e_flags:08x}',
            'phoff': e_phoff, 'shoff': e_shoff,
            'phnum': e_phnum, 'shnum': e_shnum,
            'shstrndx': e_shstrndx,
            'phentsize': e_phentsize, 'shentsize': e_shentsize,
        }

    def _parse_program_headers(self):
        e = self.endian_char
        phoff = self.ehdr['phoff']
        phnum = self.ehdr['phnum']
        phentsize = self.ehdr['phentsize']
        if phnum == 0 or phentsize == 0:
            return
        for i in range(phnum):
            off = phoff + i * phentsize
            if off + phentsize > len(self.data):
                break
            if self.is_64:
                (p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz,
                 p_memsz, p_align) = struct.unpack_from(
                    e + 'IIQQQQQQ', self.data, off)
            else:
                (p_type, p_offset, p_vaddr, p_paddr, p_filesz,
                 p_memsz, p_flags, p_align) = struct.unpack_from(
                    e + 'IIIIIIII', self.data, off)
            self.program_headers.append({
                'Type': self.PT_TYPES.get(p_type, f'0x{p_type:x}'),
                'Offset': f'0x{p_offset:x}',
                'VirtAddr': f'0x{p_vaddr:x}',
                'FileSize': p_filesz, 'MemSize': p_memsz,
                'Flags': f'0x{p_flags:x}',
            })

    def _parse_section_headers(self):
        e = self.endian_char
        shoff = self.ehdr['shoff']
        shnum = self.ehdr['shnum']
        shentsize = self.ehdr['shentsize']
        shstrndx = self.ehdr['shstrndx']
        if shnum == 0:
            return
        raw = []
        for i in range(shnum):
            off = shoff + i * shentsize
            if off + shentsize > len(self.data):
                break
            if self.is_64:
                vals = struct.unpack_from(
                    e + 'IIQQQQIIQQ', self.data, off)
                (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
                 sh_link, sh_info, sh_addralign, sh_entsize) = vals
            else:
                vals = struct.unpack_from(
                    e + 'IIIIIIIIII', self.data, off)
                (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size,
                 sh_link, sh_info, sh_addralign, sh_entsize) = vals
            raw.append({
                'name_off': sh_name, 'type': sh_type, 'flags': sh_flags,
                'addr': sh_addr, 'offset': sh_offset, 'size': sh_size,
                'link': sh_link, 'info': sh_info, 'entsize': sh_entsize,
            })
        self.section_headers = raw
        self._load_shstrtab()
        for raw_sec in raw:
            name = self._section_name(raw_sec['name_off'])
            sec_data = b''
            if raw_sec['type'] != 8 and raw_sec['offset'] + raw_sec['size'] <= len(self.data):
                sec_data = self.data[raw_sec['offset']:raw_sec['offset'] + raw_sec['size']]
            entropy = self._shannon_entropy(sec_data) if sec_data else 0.0
            self.sections.append({
                'Name': name,
                'Type': self.SHT_TYPES.get(raw_sec['type'], f'0x{raw_sec["type"]:x}'),
                'Addr': f'0x{raw_sec["addr"]:x}',
                'Offset': f'0x{raw_sec["offset"]:x}',
                'Size': raw_sec['size'],
                'Link': raw_sec['link'],
                'Info': raw_sec['info'],
                'Entropy': round(entropy, 4),
            })

    def _load_shstrtab(self):
        idx = self.ehdr['shstrndx']
        if idx >= len(self.section_headers):
            self.shstrtab = ''
            return
        raw_sec = self.section_headers[idx]
        off = raw_sec['offset']
        size = raw_sec['size']
        if off + size <= len(self.data):
            self.shstrtab = self.data[off:off + size]

    def _section_name(self, name_off: int) -> str:
        if not self.shstrtab or name_off >= len(self.shstrtab):
            return f'<offset {name_off}>'
        end = self.shstrtab.find(b'\x00', name_off)
        if end == -1:
            end = len(self.shstrtab)
        return self.shstrtab[name_off:end].decode('ascii', errors='replace')

    def _get_section(self, index: int):
        if 0 <= index < len(self.sections):
            return self.sections[index]
        return None

    def _string_table_at(self, sec_index: int) -> bytes:
        sec = self._get_section(sec_index)
        if not sec:
            return b''
        off = int(sec['Offset'], 16)
        size = sec['Size']
        if off + size <= len(self.data):
            return self.data[off:off + size]
        return b''

    def _read_str(self, tbl: bytes, offset: int) -> str:
        if offset >= len(tbl):
            return ''
        end = tbl.find(b'\x00', offset)
        if end == -1:
            end = len(tbl)
        return tbl[offset:end].decode('utf-8', errors='replace')

    def _parse_symbols(self):
        e = self.endian_char
        for si, sec in enumerate(self.sections):
            if sec['Type'] not in ('SYMTAB', 'DYNSYM'):
                continue
            sec_off = int(sec['Offset'], 16)
            sec_size = sec['Size']
            entsize = self.section_headers[si]['entsize']
            if entsize == 0:
                entsize = 24 if not self.is_64 else 24
            strtab_idx = self.section_headers[si]['link']
            strtab = self._string_table_at(strtab_idx)
            count = sec_size // entsize if entsize else 0
            for j in range(count):
                off = sec_off + j * entsize
                if off + entsize > len(self.data):
                    break
                if self.is_64:
                    (st_name, st_info, st_other, st_shndx, st_value,
                     st_size) = struct.unpack_from(e + 'IBBHQQ', self.data, off)
                else:
                    (st_name, st_value, st_size, st_info, st_other,
                     st_shndx) = struct.unpack_from(e + 'IIIBBH', self.data, off)
                name = self._read_str(strtab, st_name)
                self.symbols.append({
                    'Name': name, 'Table': sec['Name'],
                    'Value': f'0x{st_value:x}', 'Size': st_size,
                    'Type': self._sym_type(st_info), 'Bind': self._sym_bind(st_info),
                    'Visibility': self._sym_vis(st_other),
                    'Shndx': st_shndx,
                })

    def _sym_type(self, info: int) -> str:
        t = info & 0xf
        types = {0: 'NOTYPE', 1: 'OBJECT', 2: 'FUNC', 3: 'SECTION', 4: 'FILE',
                 5: 'COMMON', 6: 'TLS', 10: 'IFUNC'}
        return types.get(t, f'0x{t:x}')

    def _sym_bind(self, info: int) -> str:
        b = info >> 4
        binds = {0: 'LOCAL', 1: 'GLOBAL', 2: 'WEAK', 10: 'GNU_UNIQUE'}
        return binds.get(b, f'0x{b:x}')

    def _sym_vis(self, other: int) -> str:
        v = other & 0x3
        vis = {0: 'DEFAULT', 1: 'INTERNAL', 2: 'HIDDEN', 3: 'PROTECTED'}
        return vis.get(v, f'0x{v:x}')

    def _parse_relocations(self):
        e = self.endian_char
        for si, sec in enumerate(self.sections):
            if sec['Type'] not in ('REL', 'RELA'):
                continue
            hdr = self.section_headers[si]
            sec_off = hdr['offset']
            sec_size = hdr['size']
            entsize = hdr['entsize']
            if entsize == 0:
                entsize = 24 if self.is_64 else 12
            symtab_idx = hdr['link']
            count = sec_size // entsize if entsize else 0
            reloc_names = self.X86_64_RELOC if self.ehdr['Machine'] == 'x86_64' else self.X86_RELOC
            for j in range(count):
                off = sec_off + j * entsize
                if off + entsize > len(self.data):
                    break
                if self.is_64:
                    if sec['Type'] == 'REL':
                        r_offset, r_info = struct.unpack_from(e + 'QI', self.data, off)
                        r_addend = None
                    else:
                        r_offset, r_info, r_addend = struct.unpack_from(
                            e + 'QQQ', self.data, off)
                    sym_index = r_info >> 32
                    r_type = r_info & 0xffffffff
                else:
                    r_offset, r_info = struct.unpack_from(e + 'II', self.data, off)
                    if sec['Type'] == 'RELA':
                        r_addend = struct.unpack_from(e + 'i', self.data, off + 8)[0]
                    else:
                        r_addend = None
                    sym_index = r_info >> 8
                    r_type = r_info & 0xff
                sym_name = self.symbols[sym_index]['Name'] if sym_index < len(self.symbols) else f'sym{sym_index}'
                self.relocations.append({
                    'Section': sec['Name'],
                    'Type': reloc_names.get(r_type, f'0x{r_type:x}'),
                    'Offset': f'0x{r_offset:x}',
                    'Addend': r_addend,
                    'Symbol': sym_name,
                })

    def _parse_got_plt(self) -> List[Dict]:
        """Approximate GOT/PLT from sections."""
        got_plt = []
        for sec in self.sections:
            if sec['Name'] in ('.got', '.got.plt', '.plt', '.plt.got'):
                got_plt.append({
                    'Section': sec['Name'],
                    'Addr': sec['Addr'],
                    'Size': sec['Size'],
                })
        return got_plt

    def compute_hashes(self) -> Dict[str, str]:
        return {
            'MD5': hashlib.md5(self.data).hexdigest(),
            'SHA1': hashlib.sha1(self.data).hexdigest(),
            'SHA256': hashlib.sha256(self.data).hexdigest(),
        }

    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        length = len(data)
        entropy = 0.0
        for count in freq:
            if count:
                p = count / length
                entropy -= p * math.log2(p)
        return entropy

    def to_dict(self) -> Dict[str, Any]:
        return {
            'Header': self.ehdr,
            'ProgramHeaders': self.program_headers,
            'Sections': self.sections,
            'Symbols': self.symbols,
            'Relocations': self.relocations,
            'GOT_PLT': self._parse_got_plt(),
            'Hashes': self.compute_hashes(),
        }


def build_minimal_elf(is64: bool = False) -> bytes:
    """Build a minimal valid ELF file with a section header + string table."""
    e = '<'
    shstr = b'\x00.text\x00.shstrtab\x00'
    text = b'\x55\x48\x89\xe5' if is64 else b'\x55\x89\xe5'
    ehdr_size = 64 if is64 else 52
    shstr_addr = ehdr_size
    text_addr = shstr_addr + len(shstr)
    shoff_pos = text_addr + len(text)
    shstr_off = ehdr_size
    text_off = ehdr_size + len(shstr)

    if is64:
        ehdr = struct.pack(e + '16sHHIQQQIHHHHHH',
                           b'\x7fELF' + bytes([2, 1, 1, 0]) + bytes(11),
                           2, 0x3e, 1, 0x400078, 0, shoff_pos, 0,
                           64, 64, 0, 64, 3, 1)
        shstr_hdr = struct.pack(e + 'IIQQQQIIQQ',
                                7, 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0)
        text_hdr = struct.pack(e + 'IIQQQQIIQQ',
                               1, 1, 6, 0x400078, text_off, len(text), 0, 0, 1, 0)
        null_hdr = struct.pack(e + 'IIQQQQIIQQ', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        sections = null_hdr + shstr_hdr + text_hdr
    else:
        ehdr = struct.pack(e + '16sHHIIIIIHHHHHH',
                           b'\x7fELF' + bytes([1, 1, 1, 0]) + bytes(11),
                           2, 3, 1, 0x8048080, 0, shoff_pos, 0,
                           52, 40, 0, 40, 3, 1)
        shstr_hdr = struct.pack(e + 'IIIIIIIIII',
                                7, 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0)
        text_hdr = struct.pack(e + 'IIIIIIIIII',
                               1, 1, 6, 0x8048080, text_off, len(text), 0, 0, 1, 0)
        null_hdr = struct.pack(e + 'IIIIIIIIII', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        sections = null_hdr + shstr_hdr + text_hdr
    return ehdr + shstr + text + sections


def main():
    parser = argparse.ArgumentParser(
        description='M8 - ELF File Analyzer',
        epilog='Educational tool for studying the Executable and Linkable Format.')
    parser.add_argument('elf_file', nargs='?', help='Path to ELF binary to analyze')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    parser.add_argument('--output', '-o', help='Write JSON report to file')
    parser.add_argument('--demo', action='store_true', help='Run offline demo with crafted ELF fixture')
    parser.add_argument('--symbols', action='store_true', help='List all symbols')
    parser.add_argument('--strings', action='store_true', help='Extract printable strings')
    args = parser.parse_args()

    if args.demo:
        print("=== M8 - ELF File Analyzer (Demo Mode) ===")
        elf_data = build_minimal_elf()
        p = ELFParser(elf_data)
        result = p.to_dict()
        print(f"  Class: {result['Header']['Class']}")
        print(f"  Machine: {result['Header']['Machine']}")
        print(f"  Type: {result['Header']['Type']}")
        print(f"  Entry: {result['Header']['EntryPoint']}")
        print(f"  Sections: {len(result['Sections'])}")
        for sec in result['Sections']:
            print(f"    {sec['Name']:10s} {sec['Type']:20s} Addr={sec['Addr']} "
                  f"Size={sec['Size']} Entropy={sec['Entropy']}")
        print(f"  Symbols: {len(result['Symbols'])}")
        print(f"  Relocations: {len(result['Relocations'])}")
        print(f"  GOT/PLT: {len(result['GOT_PLT'])} entries")
        print(f"  Hashes: {result['Hashes']['SHA256'][:32]}...")
        if args.json or args.output:
            report = {'tool': 'm8-elf-analyzer', 'demo': True, 'analysis': result}
            if args.output:
                os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)
                with open(args.output, 'w') as f:
                    json.dump(report, f, indent=2)
                print(f"\nReport written to {args.output}")
            else:
                print(json.dumps(report, indent=2))
        print("\nDemo complete. Exit 0.")
        return 0

    if not args.elf_file:
        parser.print_help()
        return 1

    path = args.elf_file
    if not os.path.isfile(path):
        print(f"Error: file not found: {path}", file=sys.stderr)
        return 2

    with open(path, 'rb') as f:
        data = f.read()

    try:
        p = ELFParser(data)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2

    result = p.to_dict()
    if args.json or args.output:
        report = {'tool': 'm8-elf-analyzer', 'file': path, 'size': len(data), 'analysis': result}
        if args.output:
            os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"Report written to {args.output}")
        else:
            print(json.dumps(report, indent=2))
    else:
        print(f"=== M8 - ELF File Analyzer ===")
        print(f"File: {path} ({len(data)} bytes)")
        print(f"Class: {result['Header']['Class']}  Endian: {result['Header']['Endian']}")
        print(f"Type: {result['Header']['Type']}  Machine: {result['Header']['Machine']}")
        print(f"Entry: {result['Header']['EntryPoint']}")
        print(f"-- Sections --")
        for sec in result['Sections']:
            print(f"  {sec['Name']:12s} {sec['Type']:20s} Addr={sec['Addr']} "
                  f"Size={sec['Size']} Entropy={sec['Entropy']}")
        if args.symbols:
            print(f"-- Symbols ({len(result['Symbols'])}) --")
            for sym in result['Symbols']:
                print(f"  {sym['Name']:30s} {sym['Bind']:7s} {sym['Type']:7s} {sym['Value']}")
        print(f"MD5:    {result['Hashes']['MD5']}")
        print(f"SHA256: {result['Hashes']['SHA256']}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
