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
