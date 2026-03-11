# jumpy

`jumpy` is a stripped 64-bit ELF plus a 96-byte `enc.sky` blob. The key observation is that the binary is an encryptor, not a decryptor: it reads up to `0x100` bytes from stdin, pads the data to 32-byte blocks, transforms each block, and writes the result to `enc.sky`.

So the solve is to reverse that custom transform and apply the inverse to the supplied ciphertext file.

Final flag:

```text
UNBR{daca_faci_challu_esti_magnat_si_ai_furat_34_67_date_personales_boss}
```

## Triage

`file`/`checksec` is unremarkable apart from the binary being stripped:

```text
ELF 64-bit, dynamically linked, NX enabled, canary found, no PIE
```

The main function is tiny and immediately jumps into one large worker routine. That routine:

1. `mmap`s a page, preferring address `0x133700`
2. reads stdin into that page
3. applies PKCS#7 padding to a 32-byte block size
4. transforms each block into a scratch buffer
5. overwrites `enc.sky`

That already tells us `enc.sky` is an output artifact from the same algorithm.

## Seed Material

Two constants are hidden in `.rodata`.

The first is XOR-obfuscated with `0xa5` byte-by-byte and decodes to:

```text
UNBR26::GrayInterleaveSbox::v1
```

The second is split across two 16-byte arrays and recovered with XOR:

```text
1337c0de26aabbccdeadbeef42241999
```

The binary hashes both pieces together:

```text
seed_digest = SHA256("UNBR26::GrayInterleaveSbox::v1" || 0x1337c0de26aabbccdeadbeef42241999)
```

That digest is then used twice:

1. to build a 256-byte S-box
2. to derive a per-chunk 32-byte mask

## Recovering the Real CFG

The code between `0x401fd3` and `0x40274b` is split into small handlers. At runtime the program:

1. stores all handler entry points in a table
2. `mprotect`s the region as RWX
3. decrypts a handler just before jumping into it
4. re-encrypts the previously used handler

The mask is simple once lifted from the dispatcher:

```text
block_byte ^= ((37 * block_id + 13 * offset) ^ 0xCB) & 0xff
```

There is also a decoy `NOP` island from `0x401bda` to `0x401cc2`.

Setting `X=1` is a useful hint during reversing because the program prints the handler boundaries and exits before touching `enc.sky`.

After decrypting the handlers, most of the scary control flow collapses. The real path only uses a small subset of blocks; several handlers are dead obfuscation.

## S-box Generation

The binary starts from the identity permutation `[0, 1, ..., 255]` and shuffles it with a reverse Fisher-Yates loop.

The random stream is generated in 32-byte chunks as:

```text
stream_i = SHA256(seed_digest || u32le(counter))
```

and each shuffle step consumes one byte:

```text
j = stream_byte mod (i + 1)
swap(sbox[i], sbox[j])
```

The inverse S-box is also built, but the forward direction of the cipher uses the shuffled table itself.

## Per-Chunk Transform

Each 32-byte chunk gets its own hash:

```text
chunk_hash = SHA256(seed_digest || "KS" || u32le(chunk_index))
```

The live handlers process the block two bytes at a time. If the pair starts at offset `p`, the plaintext bytes `a` and `b` go through:

```python
a = gray(((a ^ chunk_hash[p]) + (31 * chunk_index + 17 * p)) & 0xff)
b = gray(((b ^ chunk_hash[p + 1]) + (31 * chunk_index + 17 * (p + 1))) & 0xff)

a, b = interleave_nibbles(a, b)

a = rol8(sbox[a], (chunk_hash[p] + 8) & 7)
b = rol8(sbox[b], (chunk_hash[p + 1] + 8) & 7)
```

where:

```python
gray(x) = x ^ (x >> 1)
interleave_nibbles(a, b) = ((a & 0xf0) | (b & 0x0f),
                            (b & 0xf0) | (a & 0x0f))
```

Two cleanup points make the obfuscation much less intimidating:

1. block 8 computes `(x ^ c) + 2 * (x & c)`, which is just `x + c`
2. the state-update handlers around `-0x60c` are dead on the real path

So the challenge name is accurate: the bytes keep "jumping" between tiny handlers, but the actual cipher is compact.

## Inverting It

The last stage is bijective, so we run it backwards:

```python
a = inv_sbox[ror8(a, (chunk_hash[p] + 8) & 7)]
b = inv_sbox[ror8(b, (chunk_hash[p + 1] + 8) & 7)]

a, b = interleave_nibbles(a, b)   # same function, it is its own inverse

a = gray_inverse(a)
b = gray_inverse(b)

a = (a - (31 * chunk_index + 17 * p)) & 0xff
b = (b - (31 * chunk_index + 17 * (p + 1))) & 0xff

a ^= chunk_hash[p]
b ^= chunk_hash[p + 1]
```

`gray_inverse` is the standard iterative undo:

```python
x ^= x >> 1
x ^= x >> 2
x ^= x >> 4
```

Running that over the three 32-byte blocks in `enc.sky` yields a valid PKCS#7-padded plaintext, and stripping the final `0x17` padding bytes gives the flag above.

## Solver

[decrypt_jumpy.py](./decrypt_jumpy.py) reconstructs the S-box exactly and decrypts the provided ciphertext:

```bash
python3 decrypt_jumpy.py /path/to/enc.sky --verify
```

On the supplied file it prints:

```text
UNBR{daca_faci_challu_esti_magnat_si_ai_furat_34_67_date_personales_boss}
```

and `--verify` re-encrypts the recovered plaintext to confirm it matches the original `enc.sky`.
