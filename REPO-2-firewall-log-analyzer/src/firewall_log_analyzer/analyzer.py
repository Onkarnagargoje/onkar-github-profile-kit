from collections import Counter
from dataclasses import dataclass

from firewall_log_analyzer.mitre import summarize_hints
from firewall_log_analyzer.models import FirewallEvent

BLOCK_ACTIONS = frozenset({"DENY", "DROP", "REJECT", "BLOCK", "FAILED"})


@dataclass
class AnalysisReport:
    total_events: int
    unique_src_ips: int
    action_counts: Counter[str]
    top_blocked_sources: list[tuple[str, int]]
    mitre_hints: dict[str, tuple[str, str]]
    ports_by_src: dict[str, int]


def _is_blocked(action: str) -> bool:
    return action.upper() in BLOCK_ACTIONS


def analyze(events: list[FirewallEvent], *, action_filter: str | None = None, top_n: int = 10) -> AnalysisReport:
    filtered = events
    if action_filter:
        af = action_filter.upper()
        filtered = [e for e in events if e.action.upper() == af]

    action_counts: Counter[str] = Counter(e.action for e in filtered)
    blocked = [e for e in filtered if _is_blocked(e.action)]

    block_by_src: Counter[str] = Counter(e.src_ip for e in blocked)
    port_sets: dict[str, set[int]] = {}
    for e in blocked:
        if e.dst_port is not None:
            port_sets.setdefault(e.src_ip, set()).add(e.dst_port)

    port_counts = Counter({src: len(ports) for src, ports in port_sets.items()})
    mitre_hints = summarize_hints(port_counts, block_by_src)

    top_blocked = block_by_src.most_common(top_n)

    return AnalysisReport(
        total_events=len(filtered),
        unique_src_ips=len({e.src_ip for e in filtered}),
        action_counts=action_counts,
        top_blocked_sources=top_blocked,
        mitre_hints=mitre_hints,
        ports_by_src=dict(port_counts),
    )
