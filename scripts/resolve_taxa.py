#!/usr/bin/env python3
"""Download JBB taxa list, extract scientific names, and run gnverifier."""

from __future__ import annotations

import argparse
import csv
import re
import subprocess
import sys
import urllib.request
import unicodedata
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path


XLSX_URL = "https://florabog.jbb.gov.co/files/Lista_taxones_FdBog_v1.4_20241130.xlsx"
HEADER_NAME = "Nombre científico del taxón"


def download_file(url: str, dest: Path, force: bool) -> None:
    if dest.exists() and not force:
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url) as response, dest.open("wb") as handle:
        handle.write(response.read())


def _xlsx_shared_strings(zf: zipfile.ZipFile) -> list[str]:
    try:
        data = zf.read("xl/sharedStrings.xml")
    except KeyError:
        return []
    root = ET.fromstring(data)
    ns = _ns(root)
    strings = []
    for si in root.findall(f"./{ns}si"):
        parts = []
        for t in si.findall(f".//{ns}t"):
            if t.text:
                parts.append(t.text)
        strings.append("".join(parts))
    return strings


def _ns(root: ET.Element) -> str:
    match = re.match(r"\{.*\}", root.tag)
    return match.group(0) if match else ""


def _col_index(cell_ref: str) -> int:
    match = re.match(r"([A-Z]+)", cell_ref)
    if not match:
        raise ValueError(f"Unexpected cell reference: {cell_ref}")
    letters = match.group(1)
    idx = 0
    for char in letters:
        idx = idx * 26 + (ord(char) - ord("A") + 1)
    return idx


def _cell_value(cell: ET.Element, shared_strings: list[str], ns: str) -> str:
    cell_type = cell.attrib.get("t")
    if cell_type == "inlineStr":
        text = cell.find(f"{ns}is/{ns}t")
        return text.text if text is not None and text.text else ""
    value_node = cell.find(f"{ns}v")
    if value_node is None or value_node.text is None:
        return ""
    if cell_type == "s":
        try:
            return shared_strings[int(value_node.text)]
        except (ValueError, IndexError):
            return ""
    return value_node.text


def sanitize_header(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value)
    ascii_value = normalized.encode("ascii", "ignore").decode("ascii")
    cleaned = re.sub(r"[^A-Za-z0-9_]+", "_", ascii_value.strip())
    cleaned = re.sub(r"_+", "_", cleaned)
    return cleaned.strip("_")


def parse_sheet_rows(xlsx_path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with zipfile.ZipFile(xlsx_path) as zf:
        try:
            sheet_data = zf.read("xl/worksheets/sheet1.xml")
        except KeyError as exc:
            raise FileNotFoundError("Missing sheet1.xml in xlsx") from exc
        root = ET.fromstring(sheet_data)
        ns = _ns(root)
        shared_strings = _xlsx_shared_strings(zf)

        headers: list[str] = []
        rows: list[dict[str, str]] = []
        for row in root.findall(f"{ns}sheetData/{ns}row"):
            row_idx = row.attrib.get("r")
            if row_idx == "1":
                col_to_header: dict[int, str] = {}
                for cell in row.findall(f"{ns}c"):
                    cell_ref = cell.attrib.get("r")
                    if not cell_ref:
                        continue
                    value = _cell_value(cell, shared_strings, ns).strip()
                    if value:
                        col_to_header[_col_index(cell_ref)] = sanitize_header(value)
                if not col_to_header:
                    raise ValueError("Header row is empty")
                headers = [col_to_header[col] for col in sorted(col_to_header)]
                continue

            if not headers:
                continue

            row_data: dict[str, str] = {header: "" for header in headers}
            for cell in row.findall(f"{ns}c"):
                cell_ref = cell.attrib.get("r")
                if not cell_ref:
                    continue
                col_idx = _col_index(cell_ref)
                if col_idx <= len(headers):
                    row_data[headers[col_idx - 1]] = _cell_value(
                        cell,
                        shared_strings,
                        ns,
                    ).strip()
            if any(row_data.values()):
                rows.append(row_data)

    return headers, rows


def extract_column_values(rows: list[dict[str, str]], header_name: str) -> list[str]:
    if not rows:
        return []
    sanitized = sanitize_header(header_name)
    if sanitized not in rows[0]:
        raise ValueError(f"Header '{header_name}' not found (sanitized as '{sanitized}')")
    return [row.get(sanitized, "").strip() for row in rows if row.get(sanitized, "").strip()]


def write_names(names: list[str], dest: Path, force: bool) -> None:
    if dest.exists() and not force:
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("w", encoding="utf-8") as handle:
        for name in names:
            handle.write(f"{name}\n")


def run_gnverifier(names_path: Path, results_path: Path, force: bool) -> None:
    if results_path.exists() and not force:
        return
    results_path.parent.mkdir(parents=True, exist_ok=True)
    with results_path.open("w", encoding="utf-8") as handle:
        subprocess.run(
            [
                "gnverifier",
                "-f",
                "csv",
                "-q",
                str(names_path),
            ],
            check=True,
            stdout=handle,
        )


def merge_results(
    headers: list[str],
    rows: list[dict[str, str]],
    results_path: Path,
    merged_path: Path,
    force: bool,
) -> None:
    if merged_path.exists() and not force:
        return
    merged_path.parent.mkdir(parents=True, exist_ok=True)
    with results_path.open("r", encoding="utf-8", newline="") as results_file:
        reader = csv.DictReader(results_file)
        result_rows = list(reader)

    if len(result_rows) != len(rows):
        raise ValueError(
            f"Row count mismatch: {len(rows)} names vs {len(result_rows)} gnverifier rows"
        )

    merged_headers = headers + reader.fieldnames
    with merged_path.open("w", encoding="utf-8", newline="") as out_file:
        writer = csv.DictWriter(out_file, fieldnames=merged_headers)
        writer.writeheader()
        for row, result in zip(rows, result_rows):
            combined = {**row, **result}
            writer.writerow(combined)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=XLSX_URL, help="Source XLSX URL")
    parser.add_argument(
        "--xlsx",
        default="data/Lista_taxones_FdBog_v1.4_20241130.xlsx",
        help="Path to the downloaded XLSX file",
    )
    parser.add_argument(
        "--names",
        default="data/nombres_cientificos.txt",
        help="Output path for extracted names",
    )
    parser.add_argument(
        "--results",
        default="data/gnverifier_results.csv",
        help="Output path for gnverifier results",
    )
    parser.add_argument(
        "--merged",
        default="data/gnverifier_merged.csv",
        help="Output path for merged results",
    )
    parser.add_argument(
        "--header",
        default=HEADER_NAME,
        help="Header to extract scientific names from",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing downloaded/derived files",
    )
    parser.add_argument(
        "--skip-gnverifier",
        action="store_true",
        help="Only download and extract names",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    xlsx_path = Path(args.xlsx)
    names_path = Path(args.names)
    results_path = Path(args.results)
    merged_path = Path(args.merged)

    download_file(args.url, xlsx_path, args.force)
    headers, rows = parse_sheet_rows(xlsx_path)
    names = extract_column_values(rows, args.header)
    write_names(names, names_path, args.force)

    if not args.skip_gnverifier:
        run_gnverifier(names_path, results_path, args.force)
        merge_results(headers, rows, results_path, merged_path, args.force)

    return 0


if __name__ == "__main__":
    sys.exit(main())
