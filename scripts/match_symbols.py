#!/usr/bin/env python3

import argparse
from bisect import bisect_left, bisect_right
from io import BytesIO
import re
from pathlib import Path
from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.relocation import RelocationSection
import subprocess

parser = argparse.ArgumentParser(
    prog="match_symbols.py",
    description="Match symbols from static lib with memory dump.",
)
parser.add_argument("haystack", metavar="memdump", type=str, help="Memdump to search")
parser.add_argument(
    "needles",
    metavar="lib",
    type=str,
    nargs="+",
    help="Static libraries containing objects to find",
)
parser.add_argument(
    "--haystack_base",
    type=lambda x: int(x, 0),
    default=0x80000000,
    help="Haystack base address",
)
parser.add_argument(
    "--haystack_size",
    type=lambda x: int(x, 0) if x is not None else None,
    default=None,
    help="Haystack max size",
)
parser.add_argument(
    "-o", "--output", type=str, default=None, help="Append symbols to file"
)
args = parser.parse_args()


# RelocationMap is a sorted dict of relocation entries supporting efficient range lookups.
# https://code.activestate.com/recipes/577197-sortedcollection/
class RelocationMap(object):
    def __init__(self, iterable=()):
        self._items = [*iterable]
        self._keys = [rela["r_offset"] for rela in self._items]

    def slice_range(self, base, size):
        if size <= 0:
            return []
        # take the first item after base.
        i = bisect_left(self._keys, base)
        if not i or i >= len(self._keys):
            return []
        # take the first item PAST the right boundary.
        j = bisect_left(self._keys, base + size)
        if not j or j >= len(self._keys):
            return []
        # ignore if no overlap
        if i > j:
            return []
        return self._items[i:j]


with open(args.haystack, "rb") as f:
    haystack = f.read()

if args.output is not None:
    output_file = open(args.output, "a+")

if args.haystack_size is not None and len(haystack) > args.haystack_size:
    haystack = haystack[: args.haystack_size]

print(f"haystack_base = 0x{'%08x' % args.haystack_base}")
print(f"len(haystack) = 0x{'%08x' % len(haystack)}")


def match_symbol_reloc(haystack, sym, text, strtab, relas_map):
    sym_type = sym.entry["st_info"]["type"]
    sym_name = strtab.get_string(sym["st_name"])
    if len(sym_name) == 0:
        return
    if sym_type != "STT_FUNC":
        return
    # Get section in .text referenced by symbol.
    func_value_ptr = sym["st_value"]
    func_value_size = sym["st_size"]
    sym_value = text[func_value_ptr : func_value_ptr + func_value_size]
    if len(sym_value) < func_value_size:
        print(f"[!] Malformed sym={sym_name}")
        return
    # Create a mask of static vs fuzzy bytes, based on relocatable entries.
    mask = [0] * func_value_size
    for rela in relas_map.slice_range(func_value_ptr, func_value_size):
        rela_offset = rela["r_offset"] - func_value_ptr
        # TODO 4 byte mask not applicable to all
        mask[rela_offset : rela_offset + 4] = [1, 1, 1, 1]
    # Formulate a regex string.
    regex = b""
    for i, mask_bit in enumerate(mask):
        if mask_bit == 0:
            regex += b"\\x%02x" % sym_value[i]
        else:
            regex += b"."
    # Seach for symbol.
    matches = list(re.finditer(regex, haystack))
    if len(matches) <= 0:
        print(f"[-] Unknown sym={sym_name}")
        return
    if len(matches) >= 16:
        print(f"[-] Vague sym={sym_name}")
        return
    for match in matches:
        haystack_pos = args.haystack_base + match.start()
        match_str = f"pos={'%08x' % haystack_pos} len={func_value_size} sym={sym_name}"
        print("[+] Match " + match_str)
        if output_file is not None:
            output_file.write(match_str + "\n")


def match_elf(haystack, elf):
    symtab = elf.get_section_by_name(".symtab")  # Symbol table
    strtab = elf.get_section_by_name(".strtab")  # String table
    textrela = elf.get_section_by_name(".rela.text")  # Relocation table
    text_section = elf.get_section_by_name(".text")  # Text section
    if text_section is None:
        return
    text = text_section.data()
    relas_iter = ()
    if textrela is not None:
        relas_iter = textrela.iter_relocations()
    relas_map = RelocationMap(relas_iter)
    for sym in symtab.iter_symbols():
        match_symbol_reloc(haystack, sym, text, strtab, relas_map)


for needle_path in args.needles:
    needle_short = Path(needle_path).name
    print(f"[~] Opening {needle_short}")
    # List the files in the (ar)chive.
    ar_table = subprocess.run(["ar", "t", needle_path], capture_output=True, check=True)
    ar_table_stdout = ar_table.stdout.decode("utf-8")
    object_files = ar_table_stdout.split()
    # Open each file (might not scale well, but whatever).
    for object_file in object_files:
        print(f"[~] Crawling {needle_short}/{object_file}")
        # Extract and parse ELF
        elf_buf_call = subprocess.run(
            ["ar", "p", needle_path, object_file], capture_output=True, check=True
        )
        elf_buf = elf_buf_call.stdout
        try:
            elf = ELFFile(BytesIO(elf_buf))
        except ELFError:
            print(f"[!] Malformed ELF: {needle_short}/{object_file}")
            continue
        match_elf(haystack, elf)


output_file.close()  # TODO use "with" construction
