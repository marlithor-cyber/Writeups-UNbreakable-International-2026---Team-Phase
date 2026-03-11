#!/usr/bin/env python3
import argparse
import ctypes
import tempfile
from pathlib import Path


TAIL_LINES = (
    "Cu măsălarița-mireasă,",
    "Să-i ție de împărăteasă.",
)
TRAILER = "f4abc8120c3d2a57"
LEET_MAP = str.maketrans(
    {
        "a": "4",
        "ă": "4",
        "e": "3",
        "i": "1",
        "î": "1",
        "s": "5",
        "t": "7",
        "ț": "7",
    }
)


def build_flag_body() -> str:
    text = " ".join(TAIL_LINES).lower()
    text = text.replace(",", "").replace(".", "")
    text = text.replace(" ", "_")
    return text.translate(LEET_MAP)


def build_flag() -> str:
    return f"UNR{{{build_flag_body()}_{TRAILER}}}"


def verify_with_library(flag: str, lib_path: Path, cipher_path: Path) -> bool:
    lib = ctypes.CDLL(str(lib_path))
    lib.EncryptFileHex.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_char_p)]
    lib.EncryptFileHex.restype = ctypes.c_char_p

    with tempfile.TemporaryDirectory() as tmpdir:
        flag_file = Path(tmpdir) / "flag.txt"
        flag_file.write_text(flag, encoding="utf-8")

        out_ptr = ctypes.c_char_p()
        hex_ct = lib.EncryptFileHex(str(flag_file).encode(), ctypes.byref(out_ptr))
        produced = bytes.fromhex(hex_ct.decode())

    return produced == cipher_path.read_bytes()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lib", type=Path, help="Path to extracted libmylib.so")
    parser.add_argument("--cipher", type=Path, help="Path to flag.enc")
    args = parser.parse_args()

    flag = build_flag()
    print(flag)

    if args.lib and args.cipher:
        ok = verify_with_library(flag, args.lib, args.cipher)
        print(f"cipher_match={str(ok).lower()}")


if __name__ == "__main__":
    main()
