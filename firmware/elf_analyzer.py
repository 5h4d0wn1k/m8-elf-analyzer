#!/usr/bin/env python3
"""M8 - ELF Analyzer

ELF header parsing, symbol table, section analysis, relocation.
Uses struct, os only.
"""

import struct
import os
import sys

EI_NIDENT = 16
ELFMAG = b"\x7fELF"

ELFCLASS32 = 1
ELFCLASS64 = 2

ET_TYPES = {
    0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE", 5: "LOOS",
    6: "HIOS", 0xfe00: "LOOS", 0xfeff: "HIOS", 0xff00: "LOPROC", 0xffff: "HIPROC",
}

EM_MACHINES = {
    0: "NO_MACHINE", 3: "386", 8: "MIPS", 40: "ARM", 62: "x86_64",
    183: "AARCH64", 243: "RISCV", 53: "MPCORE", 20: "PPC", 21: "PPC64",
    63: "S390", 4: "68K", 2: "SPARC", 18: "SPARCV9",
}

SHT_TYPES = {
    0: "NULL", 1: "PROGBITS", 2: "SYMTAB", 3: "STRTAB", 4: "RELA",
    5: "HASH", 6: "DYNAMIC", 7: "NOTE", 8: "NOBITS", 9: "REL",
    10: "SHLIB", 11: "DYNSYM", 14: "INIT_ARRAY", 15: "FINI_ARRAY",
    16: "PREINIT_ARRAY", 17: "GROUP", 18: "SYMTAB_SHNDX", 19: "RELr",
}

STT_TYPES = {
    0: "NOTYPE", 1: "OBJECT", 2: "FUNC", 3: "SECTION", 4: "FILE",
    5: "COMMON", 6: "TLS", 10: "GNU_IFUNC",
}

STB_BIND = {
    0: "LOCAL", 1: "GLOBAL", 2: "WEAK", 10: "GNU_UNIQUE",
}

R_X86_64 = {
    0: "R_X86_64_NONE", 1: "R_X86_64_64", 2: "R_X86_64_PC32",
    5: "R_X86_64_COPY", 6: "R_X86_64_GLOB_DAT", 7: "R_X86_64_JUMP_SLOT",
    8: "R_X86_64_RELATIVE", 9: "R_X86_64_GOTPCREL",
}
R_I386 = {
    0: "R_386_NONE", 1: "R_386_32", 2: "R_386_PC32", 5: "R_386_COPY",
    6: "R_386_GLOB_DAT", 7: "R_386_JUMP_SLOT", 8: "R_386_RELATIVE",
}


class ELFAnalyzer:
    def __init__(self, path):
        self.path = path
        self.data = open(path, "rb").read()
        self.size = len(self.data)
        self.cls = None
        self.endian = "<"
        self.header = {}
        self.sections = []
        self.symbols = []
        self.relocations = []
        self.strtab = {}
        self.machine = None

    def parse(self):
        if not self.data.startswith(ELFMAG):
            raise ValueError("Not a valid ELF file")
        self.cls = self.data[4]
        endian = self.data[5]
        self.endian = "<" if endian == 1 else ">"
        if self.cls == ELFCLASS64:
            self._parse_header64()
        elif self.cls == ELFCLASS32:
            self._parse_header32()
        else:
            raise ValueError("Unknown ELF class: %d" % self.cls)
        self._parse_sections()
        self._parse_symbols()
        self._parse_relocations()

    def _parse_header64(self):
        e = "<" if self.endian == "<" else ">"
        e_ident = self.data[:EI_NIDENT]
        fields = struct.unpack_from(e + "HHIQQQIHHHHHH", self.data, 16)
        self.header = {
            "e_type": fields[0], "e_machine": fields[1], "e_version": fields[2],
            "e_entry": fields[3], "e_phoff": fields[4], "e_shoff": fields[5],
            "e_flags": fields[6], "e_ehsize": fields[7], "e_phentsize": fields[8],
            "e_phnum": fields[9], "e_shentsize": fields[10], "e_shnum": fields[11],
            "e_shstrndx": fields[12],
        }

    def _parse_header32(self):
        e = "<" if self.endian == "<" else ">"
        fields = struct.unpack_from(e + "HHIIIIIHHHHHH", self.data, 16)
        self.header = {
            "e_type": fields[0], "e_machine": fields[1], "e_version": fields[2],
            "e_entry": fields[3], "e_phoff": fields[4], "e_shoff": fields[5],
            "e_flags": fields[6], "e_ehsize": fields[7], "e_phentsize": fields[8],
            "e_phnum": fields[9], "e_shentsize": fields[10], "e_shnum": fields[11],
            "e_shstrndx": fields[12],
        }
        self.e_shentsize = fields[10]

    def _read_string(self, section, offset):
        off = section["sh_offset"] + offset
        if off >= self.size:
            return ""
        end = self.data.find(b"\x00", off)
        if end == -1:
            end = self.size
        return self.data[off:end].decode("utf-8", errors="replace")

    def _parse_sections(self):
        e = "<" if self.endian == "<" else ">"
        shoff = self.header["e_shoff"]
        shentsize = self.header["e_shentsize"]
        shnum = self.header["e_shnum"]
        if self.cls == ELFCLASS64:
            fmt = "IIQQQQIIQQ"
        else:
            fmt = "IIIIIIIIII"
        for i in range(shnum):
            off = shoff + i * shentsize
            if off + struct.calcsize(fmt) > self.size:
                break
            v = struct.unpack_from(e + fmt, self.data, off)
            self.sections.append({
                "index": i,
                "sh_name": v[0], "sh_type": v[1],
                "sh_flags": v[2], "sh_addr": v[3],
                "sh_offset": v[4], "sh_size": v[5],
                "sh_link": v[6], "sh_info": v[7],
                "sh_addralign": v[8], "sh_entsize": v[9],
            })
        # resolve names via shstrtab
        shstrndx = self.header["e_shstrndx"]
        if shstrndx < len(self.sections):
            shstr = self.sections[shstrndx]
            for s in self.sections:
                s["name"] = self._read_string(shstr, s["sh_name"])
        else:
            for s in self.sections:
                s["name"] = "[%d]" % s["index"]

    def _parse_symbols(self):
        e = "<" if self.endian == "<" else ">"
        for s in self.sections:
            if s["sh_type"] not in (2, 11):  # SYMTAB / DYNSYM
                continue
            entsize = s["sh_entsize"] or (24 if self.cls == ELFCLASS64 else 16)
            count = s["sh_size"] // entsize if entsize else 0
            strtab_sec = self.sections[s["sh_link"]] if s["sh_link"] < len(self.sections) else None
            strt = strtab_sec["sh_offset"] if strtab_sec else 0
            for i in range(count):
                off = s["sh_offset"] + i * entsize
                if off + entsize > self.size:
                    break
                if self.cls == ELFCLASS64:
                    st_name, st_info, st_other, st_shndx, st_value, st_size = \
                        struct.unpack_from(e + "IBBHQQ", self.data, off)
                else:
                    st_name, st_value, st_size, st_info, st_other, st_shndx = \
                        struct.unpack_from(e + "IIIBBH", self.data, off)
                name = self._read_string_abs(strt, st_name)
                bind = (st_info >> 4) & 0xF
                typ = st_info & 0xF
                self.symbols.append({
                    "name": name,
                    "type": STT_TYPES.get(typ, "UNK_%d" % typ),
                    "bind": STB_BIND.get(bind, "UNK_%d" % bind),
                    "value": st_value,
                    "size": st_size,
                    "shndx": st_shndx,
                })

    def _read_string_abs(self, strt, offset):
        off = strt + offset
        if off >= self.size:
            return ""
        end = self.data.find(b"\x00", off)
        if end == -1:
            end = self.size
        return self.data[off:end].decode("utf-8", errors="replace")

    def _parse_relocations(self):
        e = "<" if self.endian == "<" else ">"
        for s in self.sections:
            if s["sh_type"] not in (4, 9):  # RELA / REL
                continue
            entries = []
            if s["sh_type"] == 4:  # RELA
                entsize = s["sh_entsize"] or 24
                count = s["sh_size"] // entsize
                for i in range(count):
                    off = s["sh_offset"] + i * entsize
                    if off + entsize > self.size:
                        break
                    r_offset, r_info, r_addend = struct.unpack_from(e + "QQq", self.data, off) if self.cls == ELFCLASS64 \
                        else struct.unpack_from(e + "IIi", self.data, off)
                    typ = r_info & 0xFF if self.cls == ELFCLASS64 else r_info & 0xFF
                    entries.append((r_offset, typ, r_addend))
            else:  # REL
                entsize = s["sh_entsize"] or 16
                count = s["sh_size"] // entsize
                for i in range(count):
                    off = s["sh_offset"] + i * entsize
                    if off + entsize > self.size:
                        break
                    r_offset, r_info = struct.unpack_from(e + "QQ", self.data, off) if self.cls == ELFCLASS64 \
                        else struct.unpack_from(e + "II", self.data, off)
                    typ = r_info & 0xFF if self.cls == ELFCLASS64 else r_info & 0xFF
                    entries.append((r_offset, typ, 0))
            self.relocations.append({"section": s["name"], "entries": entries})

    def report(self):
        e = "<" if self.endian == "<" else ">"
        lines = []
        lines.append("=== M8 - ELF Analyzer ===")
        lines.append("File: %s" % self.path)
        lines.append("Size: %d bytes" % self.size)
        lines.append("Class: %s" % ("ELF64" if self.cls == 2 else "ELF32"))
        lines.append("Endian: %s" % ("little" if e == "<" else "big"))

        lines.append("\n-- ELF Header --")
        lines.append("  Type:      %s" % ET_TYPES.get(self.header["e_type"], "UNKNOWN"))
        lines.append("  Machine:   %s" % EM_MACHINES.get(self.header["e_machine"], "UNKNOWN"))
        lines.append("  Entry:     0x%x" % self.header["e_entry"])
        lines.append("  Flags:     0x%x" % self.header["e_flags"])

        lines.append("\n-- Sections --")
        for s in self.sections:
            lines.append("  [%3d] %-20s type=%-12s addr=0x%-8x size=%d"
                         % (s["index"], s["name"], SHT_TYPES.get(s["sh_type"], "?"),
                            s["sh_addr"], s["sh_size"]))

        lines.append("\n-- Symbols (%d) --" % len(self.symbols))
        for sym in self.symbols[:40]:
            lines.append("  %-30s %-8s %-8s value=0x%-8x size=%d"
                         % (sym["name"], sym["bind"], sym["type"], sym["value"], sym["size"]))
        if len(self.symbols) > 40:
            lines.append("  ... (%d more)" % (len(self.symbols) - 40))

        lines.append("\n-- Relocations --")
        total = sum(len(r["entries"]) for r in self.relocations)
        lines.append("  Total relocations: %d" % total)
        for rel in self.relocations:
            reloc_name_map = R_X86_64 if self.header["e_machine"] == 62 else R_I386
            for off, typ, add in rel["entries"][:15]:
                lines.append("  %-16s off=0x%-8x type=%-20s addend=%d"
                             % (rel["section"], off,
                                reloc_name_map.get(typ, "R_?/%d" % typ), add))
            if len(rel["entries"]) > 15:
                lines.append("    ... (%d more)" % (len(rel["entries"]) - 15))

        return "\n".join(lines)


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 elf_analyzer.py <file>")
        return 1
    path = sys.argv[1]
    if not os.path.isfile(path):
        print("Error: %s not found" % path)
        return 1
    try:
        ea = ELFAnalyzer(path)
        ea.parse()
        print(ea.report())
        return 0
    except Exception as e:
        print("Error: %s" % e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
