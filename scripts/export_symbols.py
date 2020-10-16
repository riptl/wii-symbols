#!/usr/bin/env python3

import argparse
from io import BytesIO
import itertools
import re
from pathlib import Path
from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.relocation import RelocationSection
import subprocess

parser = argparse.ArgumentParser(
    prog="export_symbols.py", description="Export symbols from game ELF.",
)
parser.add_argument("elf", metavar="ELF", type=str, help="ELF game file to dump")
args = parser.parse_args()

with open(args.elf, "rb") as elf_file:
    elf = ELFFile(elf_file)
    strtab = elf.get_section_by_name(".strtab")  # String table
    symtab = elf.get_section_by_name(".symtab")  # Symbol table
    # Find text section
    for i, section in enumerate(elf.iter_sections()):
        if section.name == ".text":
            text_shndx = i
            text_offset = section.header["sh_addr"]
            break
    for sym in symtab.iter_symbols():
        sym_type = sym.entry["st_info"]["type"]
        sym_name = strtab.get_string(sym["st_name"])
        if len(sym_name) == 0:
            continue
        if sym_type != "STT_FUNC":
            continue
        if sym["st_shndx"] != text_shndx:
            continue
        # Get section in .text referenced by symbol.
        func_value_ptr = sym["st_value"]
        if func_value_ptr > text_offset:
            func_value_ptr -= text_offset
        # Output
        pos = text_offset + func_value_ptr
        size = sym["st_size"]
        print("pos=%08x len=%d sym=%s" % (pos, size, sym_name))
