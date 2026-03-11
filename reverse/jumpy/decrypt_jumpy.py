#!/usr/bin/env python3

import argparse
import hashlib
from pathlib import Path


SEED_LABEL = b"UNBR26::GrayInterleaveSbox::v1"
SEED_KEY = bytes.fromhex("1337c0de26aabbccdeadbeef42241999")
BLOCK_SIZE = 32


def rol8(value, amount):
    amount &= 7
    if amount == 0:
        return value & 0xFF
    return ((value << amount) | (value >> (8 - amount))) & 0xFF


def ror8(value, amount):
    amount &= 7
    if amount == 0:
        return value & 0xFF
    return ((value >> amount) | ((value << (8 - amount)) & 0xFF)) & 0xFF


def gray(value):
    return value ^ (value >> 1)


def gray_inverse(value):
    value ^= value >> 1
    value ^= value >> 2
    value ^= value >> 4
    return value & 0xFF


def interleave_nibbles(left, right):
    return ((left & 0xF0) | (right & 0x0F), (right & 0xF0) | (left & 0x0F))


def seed_digest():
    return hashlib.sha256(SEED_LABEL + SEED_KEY).digest()


def build_sboxes():
    digest = seed_digest()
    sbox = list(range(256))
    counter = 0
    stream = b""
    stream_index = BLOCK_SIZE

    for slot in range(255, 0, -1):
        if stream_index > 31:
            stream = hashlib.sha256(digest + counter.to_bytes(4, "little")).digest()
            counter += 1
            stream_index = 0
        swap_index = stream[stream_index] % (slot + 1)
        stream_index += 1
        sbox[slot], sbox[swap_index] = sbox[swap_index], sbox[slot]

    inv_sbox = [0] * 256
    for index, value in enumerate(sbox):
        inv_sbox[value] = index
    return bytes(sbox), bytes(inv_sbox)


def chunk_hash(seed, chunk_index):
    return hashlib.sha256(seed + b"KS" + chunk_index.to_bytes(4, "little")).digest()


def encrypt_chunk(chunk, chunk_index, sbox, seed):
    chunk = bytearray(chunk)
    mask = chunk_hash(seed, chunk_index)

    for offset in range(0, BLOCK_SIZE, 2):
        left = gray(((chunk[offset] ^ mask[offset]) + (31 * chunk_index + 17 * offset)) & 0xFF)
        right = gray(
            ((chunk[offset + 1] ^ mask[offset + 1]) + (31 * chunk_index + 17 * (offset + 1))) & 0xFF
        )
        left, right = interleave_nibbles(left, right)
        left = rol8(sbox[left], (mask[offset] + 8) & 7)
        right = rol8(sbox[right], (mask[offset + 1] + 8) & 7)
        chunk[offset] = left
        chunk[offset + 1] = right

    return bytes(chunk)


def decrypt_chunk(chunk, chunk_index, inv_sbox, seed):
    chunk = bytearray(chunk)
    mask = chunk_hash(seed, chunk_index)

    for offset in range(0, BLOCK_SIZE, 2):
        left = inv_sbox[ror8(chunk[offset], (mask[offset] + 8) & 7)]
        right = inv_sbox[ror8(chunk[offset + 1], (mask[offset + 1] + 8) & 7)]
        left, right = interleave_nibbles(left, right)
        left = (gray_inverse(left) - (31 * chunk_index + 17 * offset)) & 0xFF
        right = (gray_inverse(right) - (31 * chunk_index + 17 * (offset + 1))) & 0xFF
        chunk[offset] = left ^ mask[offset]
        chunk[offset + 1] = right ^ mask[offset + 1]

    return bytes(chunk)


def pkcs7_pad(message):
    pad_length = BLOCK_SIZE - (len(message) % BLOCK_SIZE)
    if pad_length == 0:
        pad_length = BLOCK_SIZE
    return message + bytes([pad_length]) * pad_length


def pkcs7_unpad(message):
    if not message:
        raise ValueError("empty plaintext")
    pad_length = message[-1]
    if pad_length == 0 or pad_length > BLOCK_SIZE:
        raise ValueError("invalid PKCS#7 padding")
    if message[-pad_length:] != bytes([pad_length]) * pad_length:
        raise ValueError("invalid PKCS#7 padding")
    return message[:-pad_length]


def encrypt_message(message, sbox, seed):
    padded = pkcs7_pad(message)
    chunks = []
    for chunk_index in range(0, len(padded), BLOCK_SIZE):
        chunk = padded[chunk_index : chunk_index + BLOCK_SIZE]
        chunks.append(encrypt_chunk(chunk, chunk_index // BLOCK_SIZE, sbox, seed))
    return b"".join(chunks)


def decrypt_message(ciphertext, inv_sbox, seed):
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("ciphertext size must be a multiple of 32 bytes")
    chunks = []
    for chunk_index in range(0, len(ciphertext), BLOCK_SIZE):
        chunk = ciphertext[chunk_index : chunk_index + BLOCK_SIZE]
        chunks.append(decrypt_chunk(chunk, chunk_index // BLOCK_SIZE, inv_sbox, seed))
    return pkcs7_unpad(b"".join(chunks))


def main():
    parser = argparse.ArgumentParser(description="Decrypt the jumpy enc.sky ciphertext")
    parser.add_argument("ciphertext", type=Path, help="Path to enc.sky")
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Re-encrypt the recovered plaintext and compare it with the input ciphertext",
    )
    args = parser.parse_args()

    ciphertext = args.ciphertext.read_bytes()
    seed = seed_digest()
    sbox, inv_sbox = build_sboxes()
    plaintext = decrypt_message(ciphertext, inv_sbox, seed)

    print(plaintext.decode("utf-8"))

    if args.verify:
        rebuilt = encrypt_message(plaintext, sbox, seed)
        print(f"cipher_match={str(rebuilt == ciphertext).lower()}")


if __name__ == "__main__":
    main()
