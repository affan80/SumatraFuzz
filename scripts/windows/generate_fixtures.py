"""Generate small deterministic well-formed PDF seeds; no downloaded corpus."""
from __future__ import annotations
import argparse
from pathlib import Path

SAMPLES = {"page-100.pdf": (100, 100), "page-180.pdf": (180, 220), "page-300.pdf": (300, 400)}

def build_pdf(width: int, height: int) -> bytes:
    body=bytearray(b'%PDF-1.4\n')
    offsets=[0]
    objects=[
      '<< /Type /Catalog /Pages 2 0 R >>',
      '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
      f'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {width} {height}] >>',
    ]
    for idx,obj in enumerate(objects,1):
        offsets.append(len(body))
        body.extend(f'{idx} 0 obj\n{obj}\nendobj\n'.encode('ascii'))
    xref=len(body)
    body.extend(f'xref\n0 {len(offsets)}\n0000000000 65535 f \n'.encode('ascii'))
    for off in offsets[1:]:
        body.extend(f'{off:010d} 00000 n \n'.encode('ascii'))
    body.extend(f'trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n'.encode('ascii'))
    return bytes(body)

def generate(directory:Path)->list[Path]:
    if directory.exists() and any(directory.iterdir()):
        names={p.name for p in directory.iterdir()}
        if names - set(SAMPLES):
            raise ValueError('Refusing to overwrite an unrecognized seed directory')
    directory.mkdir(parents=True,exist_ok=True)
    result=[]
    for name,(width,height) in SAMPLES.items():
        dest=directory/name
        data=build_pdf(width,height)
        if dest.exists() and dest.read_bytes()!=data:
            raise ValueError(f'Refusing to overwrite modified seed: {dest}')
        if not dest.exists():dest.write_bytes(data)
        result.append(dest)
    return result

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--out',required=True,type=Path)
    opts=parser.parse_args()
    for p in generate(opts.out):print(p)

if __name__=='__main__':main()
