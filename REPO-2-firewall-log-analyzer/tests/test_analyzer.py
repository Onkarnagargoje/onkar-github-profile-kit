from pathlib import Path

from firewall_log_analyzer.analyzer import analyze
from firewall_log_analyzer.parser import parse_events

SAMPLE = Path(__file__).resolve().parents[1] / "sample_logs" / "firewall.log"


def test_parse_sample_log():
    events = parse_events(SAMPLE)
    assert len(events) >= 20
    assert all(e.src_ip for e in events)


def test_detect_scan_hint():
    events = parse_events(SAMPLE)
    report = analyze(events, top_n=5)
    assert report.mitre_hints.get("203.0.113.50")
    tid, _ = report.mitre_hints["203.0.113.50"]
    assert tid == "T1046"


def test_brute_force_hint():
    events = parse_events(SAMPLE)
    report = analyze(events, top_n=5)
    assert "203.0.113.77" in dict(report.top_blocked_sources)
    assert report.mitre_hints.get("203.0.113.77")
