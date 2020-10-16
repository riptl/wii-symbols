#!/usr/bin/env python3

import argparse
import sys

parser = argparse.ArgumentParser(
    prog="filter_symbols.py",
    description="Filter symbol exports. Files have to be sorted and deduped before using.",
)
parser.add_argument(
    "symbols", metavar="SYMBOLS", type=str, nargs="+", help="Symbol match file to read"
)
parser.add_argument(
    "-o", "--output", type=str, default=None, help="Output path, '-' is stdout"
)
args = parser.parse_args()


def parse_dkvp(line):
    obj = {}
    for kvp in line.split(" "):
        kvp = kvp.strip()
        if len(kvp) == 0:
            continue
        parts = kvp.split("=", maxsplit=2)
        if len(parts) != 2:
            raise ValueError(f"invalid kvp: {kvp}")
        obj[parts[0]] = parts[1]
    return obj


def dump_dkvp(obj):
    kvps = []
    for k, v in obj.items():
        kvp = f"{k}={v}"
        kvps.append(kvp)
    return " ".join(kvps)


# Load all matches into memory.
matches = []
for match_path in args.symbols:
    with open(match_path, "r") as match_file:
        for line in match_file.readlines():
            obj = parse_dkvp(line)
            matches.append(obj)
print(f"Loaded {len(matches)} matches", file=sys.stderr)

# Stage 1 map by address
by_address = {}
for match in matches:
    pos = match["pos"]
    if by_address.get(pos) is None:
        by_address[pos] = []
    by_address[pos].append(match)
print(f"Found {len(by_address)} symbol addresses", file=sys.stderr)

# Stage 1 reduce by match count
matches = []
for pos, sub_matches in by_address.items():
    if len(sub_matches) != 1:
        continue
    matches.append(sub_matches[0])
print(f"Found {len(matches)} unambiguous matches by address", file=sys.stderr)

# Stage 2 map by symbol name
by_sym = {}
for match in matches:
    sym = match["sym"]
    if by_sym.get(sym) is None:
        by_sym[sym] = []
    by_sym[sym].append(match)
print(f"Found {len(by_sym)} symbol names", file=sys.stderr)

# Stage 2 reduce by match count
matches = []
for pos, sub_matches in by_sym.items():
    if len(sub_matches) != 1:
        continue
    matches.append(sub_matches[0])
print(f"Found {len(matches)} unambiguous matches by name", file=sys.stderr)


def write_matches(file, matches):
    for match in matches:
        file.write(dump_dkvp(match) + "\n")


# Output
if args.output == "-":
    write_matches(sys.stdout, matches)
elif args.output is not None:
    with open(args.output, "w+") as f:
        write_matches(f, matches)
