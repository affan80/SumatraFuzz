#!/usr/bin/env python3
"""Generate tiny, self-contained, deterministic PDF seeds; no third-party corpus."""
import argparse
import pathlib


def _pdf(producer: str) -> bytes:
    if not producer.isascii() or not producer.replace(" ", "").isalnum():
        raise ValueError("producer must be simple ASCII")
    data = bytearray(b"%PDF-1.4\n")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] >>",
        f"<< /Producer ({producer}) >>".encode("ascii"),
    ]
    offsets = []
    for i, obj in enumerate(objects, 1):
        offsets.append(len(data))
        data += f"{i} 0 obj\n".encode("ascii") + obj + b"\nendobj\n"
    xref = len(data)
    data += b"xref\n0 5\n0000000000 65535 f \n"
    for pos in offsets:
        data += f"{pos:010d} 00000 n \n".encode("ascii")
    data += b"trailer\n<< /Root 1 0 R /Size 5 >>\n"
    data += f"startxref\n{xref}\n%%EOF\n".encode("ascii")
    return bytes(data)


def generate(directory: pathlib.Path) -> list[pathlib.Path]:
    directory.mkdir(parents=True, exist_ok=True)
    files = []
    for name, producer in [
        ("01-minimal.pdf", "SumatraFuzz Minimal"),
        ("02-alternate.pdf", "SumatraFuzz Alternate"),
    ]:
        path = directory / name
        path.write_bytes(_pdf(producer))
        files.append(path)
    return files


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=pathlib.Path, required=True)
    args = parser.parse_args()
    for path in generate(args.output_dir):
        print(path.resolve())


if __name__ == "__main__":
    main()
