#!/usr/bin/env python3

import argparse
import binascii
from capstone import Cs, CS_ARCH_PPC, CS_MODE_32, CS_MODE_BIG_ENDIAN
import sys
from wiisymbolsutil import parse_dkvp

parser = argparse.ArgumentParser(
    prog="compare_dumps.py",
    description="Compare function bodies of symbols with each other.",
)
parser.add_argument(
    "dumps",
    metavar="DUMP:SYMBOL",
    type=str,
    nargs="+",
    help="Dump/symbol pairs to compare.",
)
parser.add_argument(
    "--base", type=lambda x: int(x, 0), default=0, help="Base address"
)
args = parser.parse_args()

md = Cs(CS_ARCH_PPC, CS_MODE_32 + CS_MODE_BIG_ENDIAN)

# Load symbols into map
symbols = {}
for i, dump_pair in enumerate(args.dumps):
    dump_parts = dump_pair.split(":")
    if len(dump_parts) != 2:
        print(f"Invalid dump: {dump_pair}", file=sys.stderr)
    dump_path = dump_parts[0]
    with open(dump_path, 'rb') as f:
        dump = f.read()
    symbol_path = dump_parts[1]
    with open(symbol_path, 'r') as f:
        for line in f.readlines():
            entry = parse_dkvp(line)
            pos = int(entry['pos'], 16)
            sym_name = entry['sym']
            sym_len = int(entry['len'])
            offset = pos - args.base
            buf = dump[offset : offset + sym_len]
            if symbols.get(sym_name) is None:
                symbols[sym_name] = [None] * len(args.dumps)
            symbols[sym_name][i] = (pos, buf)

# Compare symbols
for name, sym_list in symbols.items():
    num_matches = sum(1 if x is not None else 0 for x in sym_list)
    if num_matches <= 1:
        continue
    sym_short = []
    for sym in sym_list:
        if sym is not None:
            sym_short.append(sym)
    offset = 0
    printed_name = False
    while offset < len(sym_short[0][1]):
        parts = [x[1][offset:offset+4] for x in sym_short]
        offset += 4
        if all(x == parts[0] for x in parts):
            continue
        line = '\t%08x' % offset 
        for part in parts:
            line += '\t' + binascii.hexlify(part).decode('utf-8')
        for i, part in enumerate(parts):
            base = sym_short[i][0]
            inst = list(md.disasm(part, base + offset))[0]
            line += '\t' + f'"{inst.mnemonic} {inst.op_str}"'
        if not printed_name:
            print(name)
            printed_name = True
        print(line)
