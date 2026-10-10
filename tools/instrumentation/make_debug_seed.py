"""Write deterministic, minimal valid PDF for real A4 debug runs."""
import argparse
from pathlib import Path

def pdf_bytes() -> bytes:
    chunks = [b"%PDF-1.4\n"]
    offsets = [0]
    for number, body in enumerate((
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] >>",
    ), 1):
        offsets.append(sum(map(len, chunks)))
        chunks.append(f"{number} 0 obj\n".encode() + body + b"\nendobj\n")
    xref = sum(map(len, chunks))
    chunks.append(b"xref\n0 4\n0000000000 65535 f \n")
    chunks.extend(f"{n:010d} 00000 n \n".encode() for n in offsets[1:])
    chunks.append(b"trailer\n<< /Root 1 0 R /Size 4 >>\nstartxref\n")
    chunks.append(str(xref).encode() + b"\n%%EOF\n")
    return b"".join(chunks)

if __name__ == "__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--out", type=Path, required=True)
    args=p.parse_args()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(pdf_bytes())
    print("Wrote deterministic PDF:", args.out)
