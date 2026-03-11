#!/usr/bin/env python3

import argparse
import struct
import sys
from pathlib import Path


def parse_pe(path: Path):
    data = path.read_bytes()
    if data[:2] != b"MZ":
        raise ValueError("not a PE file")

    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_off:pe_off + 4] != b"PE\x00\x00":
        raise ValueError("invalid PE signature")

    file_header_off = pe_off + 4
    number_of_sections = struct.unpack_from("<H", data, file_header_off + 2)[0]
    size_of_optional_header = struct.unpack_from("<H", data, file_header_off + 16)[0]

    optional_off = file_header_off + 20
    magic = struct.unpack_from("<H", data, optional_off)[0]
    if magic != 0x20B:
        raise ValueError("expected PE32+")

    address_of_entry_point = struct.unpack_from("<I", data, optional_off + 16)[0]

    sections = []
    section_off = optional_off + size_of_optional_header
    for i in range(number_of_sections):
        off = section_off + i * 40
        name = data[off:off + 8].rstrip(b"\x00").decode("ascii", "replace")
        virtual_size, virtual_address, size_of_raw_data, ptr_to_raw_data = struct.unpack_from(
            "<IIII", data, off + 8
        )
        sections.append(
            {
                "name": name,
                "virtual_size": virtual_size,
                "virtual_address": virtual_address,
                "size_of_raw_data": size_of_raw_data,
                "ptr_to_raw_data": ptr_to_raw_data,
            }
        )

    return data, address_of_entry_point, sections


def rva_to_offset(rva: int, sections):
    for section in sections:
        start = section["virtual_address"]
        end = start + max(section["virtual_size"], section["size_of_raw_data"])
        if start <= rva < end:
            return section["ptr_to_raw_data"] + (rva - start)
    raise ValueError(f"RVA {rva:#x} is not inside a section")


def inv_mod_256(value: int) -> int:
    value &= 0xFF
    if value % 2 == 0:
        raise ValueError(f"{value:#x} is not invertible mod 256")

    t, new_t = 0, 1
    r, new_r = 256, value
    while new_r:
        q = r // new_r
        t, new_t = new_t, t - q * new_t
        r, new_r = new_r, r - q * new_r
    return t & 0xFF


def build_matrices(entry_bytes: bytes):
    if len(entry_bytes) != 72:
        raise ValueError("need exactly 72 entrypoint bytes")

    matrices = []
    for chunk in range(8):
        raw = entry_bytes[chunk * 9:(chunk + 1) * 9]
        matrix = [
            [raw[0] | 1, raw[1], raw[2]],
            [0, raw[4] | 1, raw[5]],
            [0, 0, raw[8] | 1],
        ]
        matrices.append(matrix)
    return matrices


def decode_group(target, matrix):
    a00, a01, a02 = matrix[0]
    _, a11, a12 = matrix[1]
    _, _, a22 = matrix[2]

    y0, y1, y2 = target

    x0 = (y0 * inv_mod_256(a00)) & 0xFF
    x1 = ((y1 - x0 * a01) * inv_mod_256(a11)) & 0xFF
    x2 = ((y2 - x0 * a02 - x1 * a12) * inv_mod_256(a22)) & 0xFF
    return bytes([x0, x1, x2])


def recover_flag(entry_bytes: bytes, target_bytes: bytes):
    matrices = build_matrices(entry_bytes)
    recovered = bytearray()

    for chunk, matrix in enumerate(matrices):
        block = target_bytes[chunk * 9:(chunk + 1) * 9]
        for group in range(3):
            triple = block[group * 3:(group + 1) * 3]
            recovered.extend(decode_group(triple, matrix))

    return bytes(recovered)


def encode_block(block: bytes, matrix):
    out = bytearray()
    for group in range(3):
        x0, x1, x2 = block[group * 3:(group + 1) * 3]
        y0 = (x0 * matrix[0][0]) & 0xFF
        y1 = (x0 * matrix[0][1] + x1 * matrix[1][1]) & 0xFF
        y2 = (x0 * matrix[0][2] + x1 * matrix[1][2] + x2 * matrix[2][2]) & 0xFF
        out.extend([y0, y1, y2])
    return bytes(out)


def verify(recovered: bytes, entry_bytes: bytes, target_bytes: bytes) -> bool:
    matrices = build_matrices(entry_bytes)
    encoded = bytearray()
    for chunk, matrix in enumerate(matrices):
        block = recovered[chunk * 9:(chunk + 1) * 9]
        encoded.extend(encode_block(block, matrix))
    return bytes(encoded) == target_bytes


def main():
    parser = argparse.ArgumentParser(description="Recover the substrate flag from SubstrateKM.sys")
    parser.add_argument("driver", nargs="?", default="SubstrateKM.sys")
    parser.add_argument("--verify", action="store_true", help="re-encode the recovered bytes and check the embedded target")
    args = parser.parse_args()

    path = Path(args.driver)
    data, entry_rva, sections = parse_pe(path)
    entry_off = rva_to_offset(entry_rva, sections)

    data_section = next((section for section in sections if section["name"] == ".data"), None)
    if data_section is None:
        raise ValueError("missing .data section")

    entry_bytes = data[entry_off:entry_off + 72]
    target_off = data_section["ptr_to_raw_data"]
    target_bytes = data[target_off:target_off + 72]

    recovered = recover_flag(entry_bytes, target_bytes)
    flag = recovered.rstrip(b"\x00").decode("ascii")
    print(flag)

    if args.verify:
        print(f"validation={str(verify(recovered, entry_bytes, target_bytes)).lower()}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
