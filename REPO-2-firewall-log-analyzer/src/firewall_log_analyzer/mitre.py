"""Educational MITRE ATT&CK hints — not a substitute for human analysis."""

from collections import Counter

# Heuristic labels for portfolio demos
SCAN_PORT_THRESHOLD = 8
REPEAT_BLOCK_THRESHOLD = 10


def hint_for_source(unique_ports: int, block_count: int) -> tuple[str, str] | None:
    if unique_ports >= SCAN_PORT_THRESHOLD:
        return (
            "T1046",
            "Network Service Discovery — many distinct destination ports from one source",
        )
    if block_count >= REPEAT_BLOCK_THRESHOLD:
        return (
            "T1110",
            "Brute Force — sustained blocked attempts from single source (verify in SIEM)",
        )
    return None


def summarize_hints(port_counts: Counter[str], block_counts: Counter[str]) -> dict[str, tuple[str, str]]:
    hints: dict[str, tuple[str, str]] = {}
    for src, blocks in block_counts.items():
        ports = port_counts.get(src, 0)
        hint = hint_for_source(ports, blocks)
        if hint:
            hints[src] = hint
    return hints
