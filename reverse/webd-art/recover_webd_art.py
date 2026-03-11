#!/usr/bin/env python3

import argparse
import re


MASK = [
    218, 78, 141, 70, 79, 33, 46, 234, 174, 75,
    4, 130, 143, 169, 189, 93, 127, 4, 198, 150,
    239, 47, 94, 136, 89, 231, 203, 209, 88, 150,
    122, 147, 60, 167, 251, 224, 198, 100, 50, 163,
]

SEED = 0x13564E1D
STEP = 0x9E3779B9
FLAG_RE = re.compile(r"^CTF\{[ -~]{8,80}\}$")


def mix_byte(value: int) -> int:
    value &= 0xFFFFFFFF
    value = ((value ^ (value >> 16)) * 0x85EBCA6B) & 0xFFFFFFFF
    value = ((value ^ (value >> 13)) * 0xC2B2AE35) & 0xFFFFFFFF
    value ^= value >> 16
    return value & 0xFF


def recover_flag(seed: int = SEED) -> str:
    out = []
    state = seed & 0xFFFFFFFF
    for index, mask in enumerate(MASK):
        state = (state + STEP) & 0xFFFFFFFF
        out.append(chr(mix_byte(state) ^ mask))
    return "".join(out)


def main() -> None:
    parser = argparse.ArgumentParser(description="Recover the webd-art flag from the reversed seed and mask")
    parser.add_argument("--seed", default=f"0x{SEED:08x}", help="override the recovered 32-bit seed")
    parser.add_argument("--verify", action="store_true", help="check the standard CTF flag regex")
    args = parser.parse_args()

    seed = int(args.seed, 0) & 0xFFFFFFFF
    flag = recover_flag(seed)
    print(flag)

    if args.verify:
        print(f"regex_match={str(bool(FLAG_RE.fullmatch(flag))).lower()}")


if __name__ == "__main__":
    main()
