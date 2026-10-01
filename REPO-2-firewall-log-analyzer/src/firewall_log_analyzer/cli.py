import argparse
import json
import sys
from pathlib import Path

from firewall_log_analyzer.analyzer import analyze
from firewall_log_analyzer.parser import parse_events


def _format_text(report) -> str:
    lines = [
        "Firewall Log Analysis",
        "=====================",
        f"Events parsed:     {report.total_events}",
        f"Unique src IPs:    {report.unique_src_ips}",
        "",
        "Actions:",
    ]
    for action, count in report.action_counts.most_common():
        lines.append(f"  {action:<12} {count}")

    lines.extend(["", "Top blocked sources:"])
    if not report.top_blocked_sources:
        lines.append("  (none)")
    else:
        for src, count in report.top_blocked_sources:
            hint = report.mitre_hints.get(src)
            suffix = ""
            if hint:
                suffix = f"  ({hint[0]} {hint[1][:50]}...)" if len(hint[1]) > 50 else f"  ({hint[0]} {hint[1]})"
            ports = report.ports_by_src.get(src, 0)
            port_note = f", {ports} distinct dst ports" if ports else ""
            lines.append(f"  {src:<18} {count:>4}{port_note}{suffix}")

    if report.mitre_hints:
        lines.extend(["", "MITRE hints (heuristic):"])
        for src, (tid, desc) in report.mitre_hints.items():
            lines.append(f"  {src}: {tid} — {desc}")

    return "\n".join(lines) + "\n"


def _format_json(report) -> str:
    payload = {
        "total_events": report.total_events,
        "unique_src_ips": report.unique_src_ips,
        "actions": dict(report.action_counts),
        "top_blocked_sources": [
            {"src_ip": src, "count": count} for src, count in report.top_blocked_sources
        ],
        "mitre_hints": {
            src: {"technique_id": tid, "description": desc}
            for src, (tid, desc) in report.mitre_hints.items()
        },
        "distinct_dst_ports_by_src": report.ports_by_src,
    }
    return json.dumps(payload, indent=2) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Analyze firewall logs for triage practice (educational)."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    analyze_p = sub.add_parser("analyze", help="Parse a log file and print a summary")
    analyze_p.add_argument("log_file", type=Path, help="Path to CSV or pipe-delimited log")
    analyze_p.add_argument("--top", type=int, default=10, help="Top N blocked sources")
    analyze_p.add_argument("--action", type=str, default=None, help="Filter by action (e.g. DENY)")
    analyze_p.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="Output format",
    )

    args = parser.parse_args(argv)

    if args.command == "analyze":
        if not args.log_file.is_file():
            print(f"Error: file not found: {args.log_file}", file=sys.stderr)
            return 1
        events = parse_events(args.log_file)
        if not events:
            print("Error: no parseable events (check column names).", file=sys.stderr)
            return 1
        report = analyze(events, action_filter=args.action, top_n=args.top)
        if args.format == "json":
            sys.stdout.write(_format_json(report))
        else:
            sys.stdout.write(_format_text(report))
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
