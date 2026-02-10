#!/usr/bin/env python3

import sys
import shutil
from pathlib import Path

# ---- PDF library (robust import) ----
try:
    from pypdf import PdfReader, PdfWriter
except Exception:
    try:
        from PyPDF2 import PdfFileReader as PdfReader
        from PyPDF2 import PdfFileWriter as PdfWriter
    except Exception:
        print("ERROR: Install pypdf with: python3 -m pip install --user pypdf")
        sys.exit(1)

# ---- helpers ----

def is_pdf(p):
    return p.is_file() and p.suffix.lower() == ".pdf"

def page_count(path):
    r = PdfReader(str(path))
    return len(r.pages) if hasattr(r, "pages") else r.getNumPages()

def combine_pdfs(pdf_files, output_path):
    writer = PdfWriter()
    for p in pdf_files:
        r = PdfReader(str(p))
        if hasattr(r, "pages"):
            for page in r.pages:
                writer.add_page(page)
        else:
            for i in range(r.getNumPages()):
                writer.addPage(r.getPage(i))
    with open(output_path, "wb") as f:
        writer.write(f)

def process_directory(directory):
    pdfs = sorted(
        [p for p in directory.iterdir() if is_pdf(p)],
        key=lambda x: x.name.lower()
    )

    if len(pdfs) < 2:
        return  # nothing to do

    combined_name = directory.name.replace(".", "-") + ".pdf"
    combined_path = directory / combined_name

    print("\nDirectory:", directory)
    print("Original PDFs:")

    total_original_pages = 0
    for p in pdfs:
        pc = page_count(p)
        total_original_pages += pc
        print(f"  {p.name} — {pc} pages")

    print("Total original pages:", total_original_pages)

    combine_pdfs(pdfs, combined_path)

    combined_pages = page_count(combined_path)
    print(f"Combined PDF: {combined_path.name} — {combined_pages} pages")

    if combined_pages != total_original_pages:
        print("❌ PAGE COUNT MISMATCH — originals preserved")
        return

    print("✅ Verification passed")

    answer = input("Delete original PDFs (keep combined)? [y/N]: ").strip().lower()
    if answer != "y":
        print("Originals preserved")
        return

    for p in pdfs:
        if p.resolve() != combined_path.resolve():
            p.unlink()

    print("Original PDFs deleted")

# ---- main ----

def walk_directories(root, recursive):
    if not recursive:
        yield root
        return
    for p in sorted(root.rglob("*")):
        if p.is_dir():
            yield p

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 combine_pdfs_safe.py <directory> [--recursive]")
        sys.exit(1)

    root = Path(sys.argv[1]).expanduser().resolve()
    recursive = "--recursive" in sys.argv

    if not root.is_dir():
        print("Not a directory:", root)
        sys.exit(1)

    for d in walk_directories(root, recursive):
        process_directory(d)
