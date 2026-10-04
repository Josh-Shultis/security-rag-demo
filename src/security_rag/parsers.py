from __future__ import annotations

import csv
import io
import json
import re
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

PARSER_VERSION = "2"
SUPPORTED_SUFFIXES = {".txt", ".md", ".log", ".json", ".jsonl", ".csv", ".html", ".xml", ".har", ".py", ".js", ".yaml", ".yml", ".docx", ".pdf", ".zip", ""}
ZIP_TEXT_SUFFIXES = {".txt", ".md", ".log", ".json", ".jsonl", ".csv", ".html", ".xml", ".har", ".py", ".js", ".yaml", ".yml"}
MAX_ZIP_ENTRIES = 250
MAX_ZIP_MEMBER_BYTES = 2 * 1024 * 1024
MAX_ZIP_TOTAL_BYTES = 25 * 1024 * 1024
UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b")
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
NOTE_RE = re.compile(r"\b(?:Note|Test)-\d+\b")
CWE_RE = re.compile(r"\bCWE-\d+\b", re.I)
PATH_RE = re.compile(r"(?<!\w)/(?:[A-Za-z0-9._~!$&'()*+,;=:@%-]+/)*[A-Za-z0-9._~!$&'()*+,;=:@%-]*")
METHOD_RE = re.compile(r"\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b")


@dataclass
class ParsedRecord:
    text: str
    metadata: dict[str, str] = field(default_factory=dict)
    evidence_class: str = "E"


class TextHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        data = data.strip()
        if data:
            self.parts.append(data)


def base_meta(parser_name: str) -> dict[str, str]:
    return {"parser_name": parser_name, "parser_version": PARSER_VERSION}


def source_type(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".har":
        return "har"
    if suffix == ".html":
        return "html"
    if suffix == ".xml":
        return "xml"
    if suffix in {".json", ".jsonl"}:
        return "json"
    if suffix == ".csv":
        return "csv"
    if suffix in {".py", ".js"}:
        return "script"
    if suffix in {".yaml", ".yml"}:
        return "yaml"
    if suffix == ".docx":
        return "docx"
    if suffix == ".pdf":
        return "pdf"
    if suffix == ".zip":
        return "archive"
    return "text"


def parse_file(path: Path) -> list[ParsedRecord]:
    suffix = path.suffix.lower()
    if suffix not in SUPPORTED_SUFFIXES:
        return []
    data = path.read_bytes()
    if suffix == ".zip":
        return parse_zip(data, path.name)
    if suffix == ".docx":
        return parse_docx(data)
    if suffix == ".pdf":
        return parse_pdf(data)
    text = data.decode("utf-8", errors="replace")
    if suffix == ".har":
        return parse_har(text)
    if suffix == ".json":
        return parse_json(text)
    if suffix == ".jsonl":
        return parse_jsonl(text)
    if suffix == ".csv":
        return parse_csv(text)
    if suffix == ".html":
        return parse_html(text)
    if suffix == ".xml":
        return parse_xml(text)
    if looks_like_http(text):
        return parse_http_export(text)
    lines = text.splitlines()
    meta = {**base_meta("text"), "line_start": "1", "line_end": str(max(len(lines), 1))}
    return [ParsedRecord(text=text, metadata=meta, evidence_class=infer_evidence_class(path, text))]



def parse_xml(text: str) -> list[ParsedRecord]:
    try:
        root = ET.fromstring(text)
        parts = [value.strip() for value in root.itertext() if value and value.strip()]
        rendered = "\n".join(parts) if parts else text
        return [ParsedRecord(rendered, {**base_meta("xml"), "xml_root": strip_xml_ns(root.tag)}, "B")]
    except ET.ParseError:
        return [ParsedRecord(text, {**base_meta("xml"), "malformed": "true"}, "E")]


def parse_docx(data: bytes) -> list[ParsedRecord]:
    records: list[ParsedRecord] = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()
            targets = [name for name in names if name.startswith("word/") and name.endswith(".xml") and any(part in name for part in ["document", "header", "footer", "comments", "footnotes", "endnotes"])]
            for name in targets:
                raw = zf.read(name)
                if len(raw) > MAX_ZIP_MEMBER_BYTES:
                    records.append(ParsedRecord(f"DOCX member skipped because it exceeded {MAX_ZIP_MEMBER_BYTES} bytes: {name}", {**base_meta("docx"), "archive_member": name, "skipped": "too_large"}, "E"))
                    continue
                xml_text = raw.decode("utf-8", errors="replace")
                parts = xml_text_parts(xml_text)
                if parts:
                    records.append(ParsedRecord("\n".join(parts), {**base_meta("docx"), "archive_member": name}, "B"))
    except (zipfile.BadZipFile, KeyError, RuntimeError) as exc:
        return [ParsedRecord(f"DOCX parse failed: {exc}", {**base_meta("docx"), "malformed": "true"}, "E")]
    return records or [ParsedRecord("DOCX contained no extractable text.", base_meta("docx"), "E")]


def parse_pdf(data: bytes) -> list[ParsedRecord]:
    try:
        from pypdf import PdfReader  # type: ignore
    except Exception:
        return [ParsedRecord("PDF text extraction requires optional dependency pypdf; file was indexed as metadata only.", {**base_meta("pdf"), "parser_unavailable": "pypdf"}, "E")]
    try:
        reader = PdfReader(io.BytesIO(data))
        records = []
        for idx, page in enumerate(reader.pages, 1):
            text = page.extract_text() or ""
            if text.strip():
                records.append(ParsedRecord(text, {**base_meta("pdf"), "page": str(idx)}, "B"))
        return records or [ParsedRecord("PDF contained no extractable text.", base_meta("pdf"), "E")]
    except Exception as exc:
        return [ParsedRecord(f"PDF parse failed: {exc}", {**base_meta("pdf"), "malformed": "true"}, "E")]


def parse_zip(data: bytes, archive_name: str = "") -> list[ParsedRecord]:
    records: list[ParsedRecord] = []
    total_uncompressed = 0
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()
            if len(infos) > MAX_ZIP_ENTRIES:
                records.append(ParsedRecord(f"Archive has {len(infos)} entries; only first {MAX_ZIP_ENTRIES} were inspected.", {**base_meta("zip"), "archive": archive_name, "skipped": "entry_limit"}, "E"))
            for info in infos[:MAX_ZIP_ENTRIES]:
                name = info.filename
                suffix = Path(name).suffix.lower()
                unsafe = is_unsafe_archive_member(name)
                nested = suffix in {".zip", ".7z", ".rar", ".tar", ".gz", ".tgz"}
                total_uncompressed += max(info.file_size, 0)
                if unsafe:
                    records.append(ParsedRecord(f"Unsafe archive member path skipped: {name}", {**base_meta("zip"), "archive": archive_name, "archive_member": name, "skipped": "unsafe_path"}, "E"))
                    continue
                if nested:
                    records.append(ParsedRecord(f"Nested archive member inventoried but not extracted: {name}", {**base_meta("zip"), "archive": archive_name, "archive_member": name, "skipped": "nested_archive"}, "E"))
                    continue
                if info.file_size > MAX_ZIP_MEMBER_BYTES:
                    records.append(ParsedRecord(f"Archive member skipped because it exceeded {MAX_ZIP_MEMBER_BYTES} bytes: {name}", {**base_meta("zip"), "archive": archive_name, "archive_member": name, "skipped": "too_large"}, "E"))
                    continue
                if total_uncompressed > MAX_ZIP_TOTAL_BYTES:
                    records.append(ParsedRecord(f"Archive scan stopped after {MAX_ZIP_TOTAL_BYTES} uncompressed bytes.", {**base_meta("zip"), "archive": archive_name, "archive_member": name, "skipped": "total_size_limit"}, "E"))
                    break
                if suffix not in ZIP_TEXT_SUFFIXES:
                    records.append(ParsedRecord(f"Archive member inventoried but not text-indexed: {name}", {**base_meta("zip"), "archive": archive_name, "archive_member": name, "skipped": "unsupported_member_type"}, "E"))
                    continue
                member_text = zf.read(info).decode("utf-8", errors="replace")
                member_records = parse_text_member(member_text, suffix)
                for rec in member_records:
                    rec.metadata = {**rec.metadata, "archive": archive_name, "archive_member": name, "compressed_size": str(info.compress_size), "uncompressed_size": str(info.file_size)}
                    rec.text = f"ARCHIVE: {archive_name}\nMEMBER: {name}\n" + rec.text
                    records.append(rec)
    except zipfile.BadZipFile as exc:
        return [ParsedRecord(f"Archive parse failed: {exc}", {**base_meta("zip"), "archive": archive_name, "malformed": "true"}, "E")]
    return records or [ParsedRecord("Archive contained no extractable text members.", {**base_meta("zip"), "archive": archive_name}, "E")]


def parse_text_member(text: str, suffix: str) -> list[ParsedRecord]:
    if suffix == ".har":
        return parse_har(text)
    if suffix == ".json":
        return parse_json(text)
    if suffix == ".jsonl":
        return parse_jsonl(text)
    if suffix == ".csv":
        return parse_csv(text)
    if suffix == ".html":
        return parse_html(text)
    if suffix == ".xml":
        return parse_xml(text)
    if looks_like_http(text):
        return parse_http_export(text)
    lines = text.splitlines()
    return [ParsedRecord(text, {**base_meta("archive-text"), "line_start": "1", "line_end": str(max(len(lines), 1))}, "B")]


def xml_text_parts(xml_text: str) -> list[str]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return []
    return [value.strip() for value in root.itertext() if value and value.strip()]


def strip_xml_ns(tag: str) -> str:
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def is_unsafe_archive_member(name: str) -> bool:
    normalized = name.replace("\\", "/")
    return normalized.startswith("/") or normalized.startswith("../") or "/../" in normalized or re.match(r"^[A-Za-z]:", normalized) is not None

def parse_html(text: str) -> list[ParsedRecord]:
    parser = TextHTMLParser()
    parser.feed(text)
    return [ParsedRecord("\n".join(parser.parts), {**base_meta("html"), "mime_type": "text/html"}, "C")]


def parse_json(text: str) -> list[ParsedRecord]:
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return [ParsedRecord(text, {**base_meta("json"), "malformed": "true"}, "E")]
    return [ParsedRecord(flatten_json(obj), {**base_meta("json"), "json_path": "$", "json_fields": ",".join(sorted(json_fields(obj))[:200])}, "B")]


def parse_jsonl(text: str) -> list[ParsedRecord]:
    records = []
    for line_no, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
            records.append(ParsedRecord(flatten_json(obj), {**base_meta("jsonl"), "line_start": str(line_no), "line_end": str(line_no), "json_path": f"$[{line_no}]", "json_fields": ",".join(sorted(json_fields(obj))[:80])}, "B"))
        except json.JSONDecodeError:
            records.append(ParsedRecord(line, {**base_meta("jsonl"), "line_start": str(line_no), "line_end": str(line_no), "malformed": "true"}, "E"))
    return records or [ParsedRecord("", base_meta("jsonl"), "E")]


def parse_csv(text: str) -> list[ParsedRecord]:
    rows = list(csv.DictReader(text.splitlines()))
    if not rows:
        return [ParsedRecord(text, base_meta("csv"), "E")]
    out = []
    for idx, row in enumerate(rows, 1):
        parts = [f"{k}: {v}" for k, v in row.items()]
        out.append(ParsedRecord("\n".join(parts), {**base_meta("csv"), "row": str(idx), "line_start": str(idx + 1), "line_end": str(idx + 1), "json_fields": ",".join(row.keys())}, "B"))
    return out


def parse_har(text: str) -> list[ParsedRecord]:
    try:
        har = json.loads(text)
    except json.JSONDecodeError:
        return [ParsedRecord(text, {**base_meta("har"), "malformed": "true"}, "E")]
    entries = har.get("log", {}).get("entries", [])
    records: list[ParsedRecord] = []
    for idx, entry in enumerate(entries, 1):
        req = entry.get("request", {})
        res = entry.get("response", {})
        url = req.get("url", "")
        method = req.get("method", "")
        path = path_from_url(url)
        req_body = req.get("postData", {}).get("text", "")
        res_body = res.get("content", {}).get("text", "")
        started = entry.get("startedDateTime", "")
        req_headers = headers_text(req.get("headers", []))
        res_headers = headers_text(res.get("headers", []))
        text_parts = [
            f"HAR entry {idx}",
            f"timestamp: {started}",
            f"method: {method}",
            f"url: {url}",
            f"path: {path}",
            f"status: {res.get('status', '')}",
            f"mime_type: {res.get('content', {}).get('mimeType', '')}",
            "request_headers:",
            req_headers,
            "request_body:",
            req_body,
            "response_headers:",
            res_headers,
            "response_body:",
            res_body,
        ]
        records.append(
            ParsedRecord(
                "\n".join(text_parts),
                {
                    **base_meta("har"),
                    "timestamp": started,
                    "http_method": method,
                    "endpoint": path,
                    "status_code": str(res.get("status", "")),
                    "mime_type": str(res.get("content", {}).get("mimeType", "")),
                    "request_body_hash": sha_text(req_body),
                    "response_body_hash": sha_text(res_body),
                    "har_entry_index": str(idx),
                    "json_path": f"$.log.entries[{idx - 1}]",
                    "request_response_side": "request+response",
                },
                "A",
            )
        )
    return records or [ParsedRecord(text, {**base_meta("har"), "malformed": "empty-har"}, "E")]


def parse_http_export(text: str) -> list[ParsedRecord]:
    blocks = re.split(r"\n\s*\n(?=(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+/)", text)
    records = []
    line_cursor = 1
    for idx, block in enumerate(blocks, 1):
        first = block.strip().splitlines()[0] if block.strip().splitlines() else ""
        method = ""
        endpoint = ""
        match = re.match(r"(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)", first)
        if match:
            method, endpoint = match.group(1), match.group(2)
        line_count = max(len(block.splitlines()), 1)
        records.append(ParsedRecord(block, {**base_meta("http-export"), "http_method": method, "endpoint": endpoint, "request_index": str(idx), "line_start": str(line_cursor), "line_end": str(line_cursor + line_count - 1)}, "A"))
        line_cursor += line_count + 1
    return records


def looks_like_http(text: str) -> bool:
    return bool(re.search(r"(?m)^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+/\S*", text))


def flatten_json(obj: Any, prefix: str = "") -> str:
    lines: list[str] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(value, (dict, list)):
                lines.append(f"{name}:")
                lines.append(flatten_json(value, name))
            else:
                lines.append(f"{name}: {value}")
    elif isinstance(obj, list):
        for idx, value in enumerate(obj):
            lines.append(flatten_json(value, f"{prefix}[{idx}]"))
    else:
        lines.append(f"{prefix}: {obj}")
    return "\n".join(line for line in lines if line)


def json_fields(obj: Any, prefix: str = "") -> set[str]:
    fields: set[str] = set()
    if isinstance(obj, dict):
        for key, value in obj.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            fields.add(name)
            fields |= json_fields(value, name)
    elif isinstance(obj, list):
        for value in obj:
            fields |= json_fields(value, prefix)
    return fields


def extract_identifiers(text: str) -> list[tuple[str, str]]:
    items: list[tuple[str, str]] = []
    for kind, regex in [("uuid", UUID_RE), ("hash", HASH_RE), ("note_or_test", NOTE_RE), ("cwe", CWE_RE), ("endpoint", PATH_RE)]:
        for match in regex.finditer(text):
            items.append((kind, match.group(0)))
    return sorted(set(items))


def infer_metadata(text: str) -> dict[str, str]:
    meta: dict[str, str] = {}
    method = METHOD_RE.search(text)
    if method:
        meta["http_method"] = method.group(1)
    path = PATH_RE.search(text)
    if path:
        meta["endpoint"] = path.group(0)
    uuid = UUID_RE.search(text)
    if uuid:
        meta["object_id"] = uuid.group(0)
    note = NOTE_RE.search(text)
    if note:
        value = note.group(0)
        if value.startswith("Test-"):
            meta["test_id"] = value
        else:
            meta["object_id"] = value
    op = re.search(r"\b(operation|tool|action|op)\s*[:=]\s*([A-Za-z0-9_.:-]+)", text, re.I)
    if op:
        meta["operation_name"] = op.group(2)
    role = re.search(r"\b(attacker|victim|admin|owner|viewer|editor)\b", text, re.I)
    if role:
        meta["account_role"] = role.group(1).lower()
    ts = re.search(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?\b", text)
    if ts:
        meta["timestamp"] = ts.group(0)
    return meta


def infer_evidence_class(path: Path, text: str) -> str:
    lower = str(path).lower()
    if ".har" in lower or "burp" in lower or looks_like_http(text):
        return "A"
    if "screenshot" in lower or path.suffix.lower() == ".html":
        return "C"
    if "draft" in lower or "hypothesis" in text.lower() or "infer" in text.lower():
        return "E"
    return "B"


def path_from_url(url: str) -> str:
    match = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://[^/]+([^?#]*)", url)
    return match.group(1) or "/" if match else url


def headers_text(headers: list[dict[str, Any]]) -> str:
    return "\n".join(f"{h.get('name', '')}: {h.get('value', '')}" for h in headers)


def sha_text(text: str) -> str:
    import hashlib

    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest() if text else ""
