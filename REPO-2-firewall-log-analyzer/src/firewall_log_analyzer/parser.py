import csv
import re
from datetime import datetime
from io import StringIO
from pathlib import Path

from firewall_log_analyzer.models import FirewallEvent

TIMESTAMP_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%d/%m/%Y %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
)

FIELD_ALIASES = {
    "timestamp": ("timestamp", "time", "datetime", "event_time"),
    "src_ip": ("src_ip", "source", "src", "source_ip", "saddr"),
    "dst_ip": ("dst_ip", "destination", "dst", "dest_ip", "daddr"),
    "dst_port": ("dst_port", "dport", "dest_port", "port"),
    "action": ("action", "verdict", "disposition", "result"),
    "protocol": ("protocol", "proto", "ip_protocol"),
}


def _normalize_key(key: str) -> str:
    return key.strip().lower().replace(" ", "_")


def _pick(row: dict[str, str], canonical: str) -> str | None:
    for alias in FIELD_ALIASES[canonical]:
        for k, v in row.items():
            if _normalize_key(k) == alias and v is not None and str(v).strip():
                return str(v).strip()
    return None


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    for fmt in TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(value.strip(), fmt)
        except ValueError:
            continue
    return None


def _parse_port(value: str | None) -> int | None:
    if not value:
        return None
    try:
        return int(re.sub(r"[^\d]", "", value))
    except ValueError:
        return None


def _detect_delimiter(sample: str) -> str:
    if "|" in sample and sample.count("|") >= sample.count(","):
        return "|"
    if "\t" in sample:
        return "\t"
    return ","


def _rows_from_text(text: str) -> list[dict[str, str]]:
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    if not lines:
        return []
    delimiter = _detect_delimiter(lines[0])
    reader = csv.DictReader(StringIO("\n".join(lines)), delimiter=delimiter)
    return [{k: (v or "") for k, v in row.items() if k} for row in reader]


def parse_events(path: Path) -> list[FirewallEvent]:
    text = path.read_text(encoding="utf-8", errors="replace")
    events: list[FirewallEvent] = []
    for row in _rows_from_text(text):
        src = _pick(row, "src_ip")
        dst = _pick(row, "dst_ip")
        action = _pick(row, "action")
        if not src or not dst or not action:
            continue
        events.append(
            FirewallEvent(
                timestamp=_parse_timestamp(_pick(row, "timestamp")),
                src_ip=src,
                dst_ip=dst,
                dst_port=_parse_port(_pick(row, "dst_port")),
                action=action.upper(),
                protocol=(_pick(row, "protocol") or "").upper() or None,
                raw_line=str(row),
            )
        )
    return events
