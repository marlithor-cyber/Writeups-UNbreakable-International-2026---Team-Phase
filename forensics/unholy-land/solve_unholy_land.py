#!/usr/bin/env python3
import argparse
import json
from collections import Counter
from pathlib import Path


def solve(eve_path: Path) -> tuple[str, str, str, str]:
    total_events = 0
    flow_proto_counts = Counter()
    dns_request_counts = Counter()

    with eve_path.open() as handle:
        for line in handle:
            total_events += 1
            event = json.loads(line)

            if event.get("event_type") == "flow":
                proto = event.get("proto")
                if proto == "TCP":
                    flow_proto_counts["tcp"] += 1
                elif proto == "UDP":
                    flow_proto_counts["udp"] += 1
                elif proto == "IPv6-ICMP":
                    flow_proto_counts["icmpv6"] += 1

            if event.get("event_type") == "dns":
                dns = event.get("dns", {})
                if dns.get("type") != "request":
                    continue
                for query in dns.get("queries", []):
                    rrname = query.get("rrname")
                    if rrname:
                        dns_request_counts[rrname] += 1

    top3 = [name for name, _ in dns_request_counts.most_common(3)]

    q1 = (
        f"UNR{{{flow_proto_counts['tcp']}, {flow_proto_counts['udp']}, "
        f"{flow_proto_counts['icmpv6']}}}"
    )
    q2 = f"UNR{{{total_events}}}"
    q3 = f"UNR{{{top3[0]}, {top3[1]}, {top3[2]}}}"
    q4 = "UNR{holycat}"
    return q1, q2, q3, q4


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("eve_json", type=Path)
    args = parser.parse_args()

    for idx, answer in enumerate(solve(args.eve_json), 1):
        print(f"Q{idx}: {answer}")


if __name__ == "__main__":
    main()
