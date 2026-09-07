#!/usr/bin/env python3
"""Tests for M8 - ELF File Analyzer."""

import hashlib
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from elf_analyzer import ELFParser, build_minimal_elf


class TestBuildMinimalELF(unittest.TestCase):
    def test_elf32_magic(self):
        self.assertEqual(build_minimal_elf(False)[0:4], b'\x7fELF')

    def test_elf64_magic(self):
        self.assertEqual(build_minimal_elf(True)[0:4], b'\x7fELF')


class TestELFParserELF32(unittest.TestCase):
    def setUp(self):
        self.parser = ELFParser(build_minimal_elf(False))

    def test_class(self):
        self.assertEqual(self.parser.ehdr['Class'], 'ELF32')

    def test_machine(self):
        self.assertEqual(self.parser.ehdr['Machine'], 'i386')

    def test_type(self):
        self.assertEqual(self.parser.ehdr['Type'], 'EXEC')

    def test_entry(self):
        self.assertEqual(self.parser.ehdr['EntryPoint'], '0x8048080')

    def test_section_count(self):
        self.assertEqual(len(self.parser.sections), 3)

    def test_section_names(self):
        names = [s['Name'] for s in self.parser.sections]
        self.assertIn('.text', names)
        self.assertIn('.shstrtab', names)

    def test_text_section_type(self):
        text = [s for s in self.parser.sections if s['Name'] == '.text'][0]
        self.assertEqual(text['Type'], 'PROGBITS')


class TestELFParserELF64(unittest.TestCase):
    def setUp(self):
        self.parser = ELFParser(build_minimal_elf(True))

    def test_class(self):
        self.assertEqual(self.parser.ehdr['Class'], 'ELF64')

    def test_machine(self):
        self.assertEqual(self.parser.ehdr['Machine'], 'x86_64')

    def test_entry(self):
        self.assertEqual(self.parser.ehdr['EntryPoint'], '0x400078')

    def test_section_names(self):
        names = [s['Name'] for s in self.parser.sections]
        self.assertIn('.text', names)

    def test_hashes(self):
        hashes = self.parser.compute_hashes()
        self.assertEqual(hashes['SHA256'], hashlib.sha256(build_minimal_elf(True)).hexdigest())


class TestELFParserReal(unittest.TestCase):
    def setUp(self):
        here = os.path.dirname(os.path.abspath(__file__))
        fixture = os.path.join(here, '..', 'fixtures', 'sample_elf')
        if os.path.isfile(fixture):
            with open(fixture, 'rb') as f:
                self.parser = ELFParser(f.read())
            self.has_fixture = True
        else:
            self.has_fixture = False

    def test_bin_ls_parses(self):
        if os.path.isfile('/bin/ls'):
            with open('/bin/ls', 'rb') as f:
                p = ELFParser(f.read())
            self.assertEqual(p.ehdr['Class'], 'ELF64')
            self.assertGreaterEqual(len(p.sections), 5)
            self.assertGreaterEqual(len(p.symbols), 1)
        else:
            self.skipTest('/bin/ls not found')


class TestELFParserInvalid(unittest.TestCase):
    def test_too_small(self):
        with self.assertRaises(ValueError):
            ELFParser(b'\x00' * 10)

    def test_bad_magic(self):
        with self.assertRaises(ValueError):
            ELFParser(b'XXXX' + b'\x00' * 100)


class TestELFGeneration(unittest.TestCase):
    def test_roundtrip_is64(self):
        data = build_minimal_elf(True)
        p = ELFParser(data)
        text = [s for s in p.sections if s['Name'] == '.text'][0]
        self.assertEqual(text['Size'], 4)

    def test_roundtrip_is32(self):
        data = build_minimal_elf(False)
        p = ELFParser(data)
        text = [s for s in p.sections if s['Name'] == '.text'][0]
        self.assertEqual(text['Size'], 3)


if __name__ == '__main__':
    unittest.main()
