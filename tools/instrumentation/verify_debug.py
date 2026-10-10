"""Validate real WinAFL DynamoRIO debug logs and their raw 64-KiB coverage maps."""
from __future__ import annotations
import argparse
import hashlib
import json
import re
from pathlib import Path

class DebugLogError(ValueError):
    pass

BITMAP_SIZE = 65536
PARSER_MODULES = ("PdfFilter.dll", "libmupdf.dll")

def inspect_debug_log(raw: bytes, *, expected_cycles: int, require_nonzero: bool) -> dict:
    if not 1 <= expected_cycles <= 100000:
        raise DebugLogError("expected_cycles out of range")
    marker = re.search(rb"Coverage map follows:\r?\n", raw)
    if marker is None:
        raise DebugLogError("WinAFL debug coverage map marker missing")
    bitmap = raw[marker.end():]
    if len(bitmap) != BITMAP_SIZE:
        raise DebugLogError(f"Raw coverage bitmap length {len(bitmap)} != {BITMAP_SIZE}")
    prefix = raw[:marker.start()].decode("utf-8", "replace")
    pre = len(re.findall(r"(?m)^In pre_fuzz_handler\r?$", prefix))
    post = len(re.findall(r"(?m)^In post_fuzz_handler\r?$", prefix))
    if pre != expected_cycles or post != expected_cycles:
        raise DebugLogError(f"Handler mismatch: pre={pre}, post={post}, expected={expected_cycles}")
    if "Everything appears to be running normally." not in prefix:
        raise DebugLogError("WinAFL debug did not confirm normal loop exit")
    if re.search(r"(?mi)^(WARNING:|Exception caught:|crashed\b)", prefix):
        raise DebugLogError("Exception or warning reported by WinAFL")
    loaded = re.findall(r"(?mi)^Module loaded, ([^\r\n]+)\r?$", prefix)
    loaded_by_name = {name.casefold(): name for name in loaded}
    missing = [name for name in PARSER_MODULES if name.casefold() not in loaded_by_name]
    if missing:
        raise DebugLogError("Genuine parser modules not observed: " + ", ".join(missing))
    nonzero = sum(bool(b) for b in bitmap)
    if require_nonzero and nonzero == 0:
        raise DebugLogError("Confirmed parser coverage bitmap has zero nonzero bytes")
    return {
      "sha256": hashlib.sha256(raw).hexdigest(),
      "pre_count": pre, "post_count": post,
      "loaded_modules": loaded,
      "confirmed_coverage_modules": [loaded_by_name[name.casefold()] for name in PARSER_MODULES],
      "bitmap_nonzero_bytes": nonzero,
      "bitmap_units": "WinAFL edge bitmap bytes (not source coverage percentage)",
      "discovery_only": not require_nonzero
    }

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--log", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--expected-cycles", type=int, default=10)
    p.add_argument("--discovery-only", action="store_true")
    a = p.parse_args()
    try:
        result = inspect_debug_log(a.log.read_bytes(), expected_cycles=a.expected_cycles,
                                   require_nonzero=not a.discovery_only)
    except (OSError, DebugLogError) as exc:
        p.exit(1, f"FAILED: {exc}\n")
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("Verified raw WinAFL log:", a.log, "nonzero map bytes:", result["bitmap_nonzero_bytes"])
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
