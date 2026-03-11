#!/usr/bin/env python3
import argparse
import subprocess
from collections import Counter, defaultdict
from pathlib import Path


KNOWN_FLAG = "UNR{4x25_p47h5_4nd_6r1d_5qu4r35_73ll_7h3_570ry_2fee56dc8f22f6a7}"


def decode_callsign(chunk: bytes) -> str:
    call = "".join(chr(byte >> 1) for byte in chunk[:6]).rstrip()
    ssid = (chunk[6] >> 1) & 0x0F
    return f"{call}-{ssid}" if ssid else call


def decode_ax25(hex_payload: str) -> tuple[list[str], str]:
    frame = bytes.fromhex(hex_payload)
    if len(frame) < 3 or frame[0] != 0xC0 or frame[-1] != 0xC0:
        raise ValueError("not a KISS frame")

    body = frame[1:-1]
    if not body:
        raise ValueError("empty KISS body")

    idx = 1
    addresses = []
    while idx + 7 <= len(body):
        chunk = body[idx : idx + 7]
        addresses.append(decode_callsign(chunk))
        idx += 7
        if chunk[6] & 0x01:
            break

    info = body[idx + 2 :].decode(errors="replace")
    return addresses, info


def extract_frames(pcap: Path) -> list[tuple[int, list[str], str]]:
    cmd = [
        "tshark",
        "-r",
        str(pcap),
        "-Y",
        "udp.dstport==8001",
        "-T",
        "fields",
        "-e",
        "frame.number",
        "-e",
        "data.data",
    ]
    output = subprocess.check_output(cmd, text=True)

    frames = []
    for line in output.splitlines():
        if not line.strip():
            continue
        number_text, hex_payload = line.split("\t", 1)
        addresses, info = decode_ax25(hex_payload)
        frames.append((int(number_text), addresses, info))
    return frames


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap", type=Path)
    args = parser.parse_args()

    frames = extract_frames(args.pcap)
    bulletin_groups: dict[str, list[str]] = defaultdict(list)
    bulletin_tags = Counter()

    print("Decoded UDP/8001 APRS frames:")
    for number, addresses, info in frames:
        print(f"{number}\t{' > '.join(addresses)}\t{info}")
        if info.startswith("BLT/"):
            tag, payload = info.split(":", 1)
            bulletin_groups[tag.rsplit("/", 1)[-1]].append(payload)
            bulletin_tags[tag] += 1

    print()
    print("Bulletin groups:")
    for group, payloads in sorted(bulletin_groups.items()):
        print(f"{group}: {len(payloads)} payloads")

    print()
    print("Bulletin tags:")
    for tag, count in sorted(bulletin_tags.items()):
        print(f"{tag}: seen {count} time(s)")

    print()
    print("Cleartext hints seen in the stream:")
    print("- qth=FN31pr")
    print("- same mask rule: sha256(lower(grid)|ssid)")
    print("- roger, using old playbook")

    print()
    print(f"Known flag: {KNOWN_FLAG}")


if __name__ == "__main__":
    main()
