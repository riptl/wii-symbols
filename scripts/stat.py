#!/usr/bin/env python3

import argparse
from pathlib import Path
from pytablewriter import MarkdownTableWriter

parser = argparse.ArgumentParser(
    prog="stat.py",
    description="Generates a Markdown table with stats about symbol files.",
)
parser.add_argument(
    "tables", metavar="TABLE", type=str, nargs="+", help="File name of symbol table"
)
parser.add_argument(
    "--wiitdb", type=str, required=True, help="Game table from https://www.gametdb.com/wiitdb.txt"
)
args = parser.parse_args()


# Read wiitdb.txt.
with open(args.wiitdb, "r") as f:
    wiitdb = {}
    for line in f.readlines():
        parts = line.split(" = ", maxsplit=2)
        if len(parts) != 2:
            continue
        wiitdb[parts[0]] = parts[1]

# Open files.
table = []
for table_path in args.tables:
    game_id = Path(table_path).stem
    with open(table_path) as f:
        num_lines = sum(1 for line in f)
    name = wiitdb[game_id]
    table.append([game_id, num_lines, name])

# Render table
writer = MarkdownTableWriter(
    headers=["Game ID", "Symbol Count", "Name"],
    value_matrix=table,
)
writer.write_table()
