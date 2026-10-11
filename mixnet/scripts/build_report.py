#!/usr/bin/env python3
"""Render REPORT.md to REPORT.pdf.

Converts the Markdown report to HTML (with fenced code, tables, and a generated
table of contents), wraps it in a print stylesheet, and produces a PDF with
wkhtmltopdf. Local image references (the benchmark plots) are rewritten to
absolute paths so they embed correctly.

Usage: python3 scripts/build_report.py [--md REPORT.md] [--out REPORT.pdf]
"""
import argparse
import os
import re
import subprocess
import sys

import markdown

CSS = """
@page { size: A4; margin: 20mm 18mm; }
body {
  font-family: "DejaVu Sans", "Helvetica Neue", Arial, sans-serif;
  font-size: 10.5pt; line-height: 1.5; color: #1a1a1a; max-width: 100%;
}
h1 { font-size: 22pt; margin: 0 0 4pt; line-height: 1.2; }
h1 + p, h1 + p + p { color: #444; }
h2 {
  font-size: 15pt; margin: 22pt 0 6pt; padding-bottom: 3pt;
  border-bottom: 2px solid #2c3e50; color: #2c3e50;
  page-break-after: avoid;
}
h3 { font-size: 12pt; margin: 14pt 0 4pt; color: #34495e; page-break-after: avoid; }
p { margin: 6pt 0; text-align: justify; }
a { color: #2c3e50; text-decoration: none; }
code {
  font-family: "DejaVu Sans Mono", monospace; font-size: 9pt;
  background: #f3f4f6; padding: 1px 4px; border-radius: 3px;
}
pre {
  font-family: "DejaVu Sans Mono", monospace; font-size: 8.3pt; line-height: 1.35;
  background: #f6f8fa; border: 1px solid #e1e4e8; border-radius: 5px;
  padding: 9px 11px; overflow-x: auto; page-break-inside: avoid;
  white-space: pre;
}
pre code { background: none; padding: 0; font-size: inherit; }
table {
  border-collapse: collapse; width: 100%; margin: 8pt 0; font-size: 9.3pt;
  page-break-inside: avoid;
}
th, td { border: 1px solid #cfd6dd; padding: 5px 8px; text-align: left; vertical-align: top; }
th { background: #eef1f4; font-weight: 600; }
tr:nth-child(even) td { background: #fafbfc; }
img { max-width: 100%; display: block; margin: 10pt auto 4pt; page-break-inside: avoid; }
strong { color: #1a1a1a; }
hr { border: none; border-top: 1px solid #d0d7de; margin: 16pt 0; }
ul, ol { margin: 6pt 0; padding-left: 22pt; }
li { margin: 3pt 0; }
blockquote { color: #555; border-left: 3px solid #cfd6dd; margin: 8pt 0; padding-left: 12pt; }
"""

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<style>{css}</style></head>
<body>{body}</body></html>
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--md", default="REPORT.md")
    ap.add_argument("--out", default="REPORT.pdf")
    args = ap.parse_args()

    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    md_path = os.path.join(repo, args.md)
    out_path = os.path.join(repo, args.out)
    html_path = os.path.join(repo, "report.html")

    with open(md_path, encoding="utf-8") as f:
        text = f.read()

    body = markdown.markdown(
        text,
        extensions=["extra", "fenced_code", "tables", "sane_lists", "toc", "nl2br"],
        output_format="html5",
    )

    # Rewrite local image srcs to absolute paths for wkhtmltopdf.
    def absolutize(m):
        src = m.group(1)
        if src.startswith(("http://", "https://", "/")):
            return m.group(0)
        return 'src="%s"' % os.path.join(repo, src)

    body = re.sub(r'src="([^"]+)"', absolutize, body)

    html = HTML_TEMPLATE.format(css=CSS, body=body)
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    cmd = [
        "wkhtmltopdf",
        "--enable-local-file-access",
        "--encoding", "utf-8",
        "--print-media-type",
        "--margin-top", "18mm", "--margin-bottom", "18mm",
        "--margin-left", "16mm", "--margin-right", "16mm",
        "--footer-center", "[page] / [topage]",
        "--footer-font-size", "8",
        "--footer-spacing", "5",
        "--quiet",
        html_path, out_path,
    ]
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print("wkhtmltopdf failed:", e, file=sys.stderr)
        sys.exit(1)

    print("wrote", out_path, "(%d KB)" % (os.path.getsize(out_path) // 1024))


if __name__ == "__main__":
    main()
