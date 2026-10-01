from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class FirewallEvent:
    timestamp: datetime | None
    src_ip: str
    dst_ip: str
    dst_port: int | None
    action: str
    protocol: str | None
    raw_line: str
