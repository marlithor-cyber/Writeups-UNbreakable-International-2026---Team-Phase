# substrate

`substrate` ships a userland checker (`SubstrateUM.exe`) plus the signed kernel driver it talks to (`SubstrateKM.sys`). The userland binary is mostly plumbing: it reads a candidate string from stdin, pushes it into the driver one byte at a time, and asks the driver for a final verdict.

The solve is in the driver. Its `EvtIoDeviceControl` callback turns the first 72 bytes of `DriverEntry` into eight small `3x3` matrices, applies those matrices to the submitted data in `9`-byte blocks, and compares the result against a 72-byte target stored at the start of `.data`.

Final flag:

```text
CTF{1c41e1d89f95c6c6b45f256f06e554f904257c884f683528302bacbde8b9484f}
```

## Triage

The challenge directory contains:

- `SubstrateUM.exe`: 64-bit console PE
- `SubstrateKM.sys`: 64-bit KMDF driver
- `SubstrateKM.inf` / `substratekm.cat`: install metadata and catalog

Useful strings immediately show the split:

```text
UM: \\.\SubstrateDeviceLink
KM: \Device\SubstrateDevice
KM: \??\SubstrateDeviceLink
```

So the first question is not "what is the flag?" but "what exactly does the driver validate?"

## Userland Protocol

The important part of `SubstrateUM.exe` starts after `ReadConsoleA`. It:

1. reads `0x45` bytes into a stack buffer
2. opens `\\.\SubstrateDeviceLink`
3. loops `bl = 0 .. 0x44`
4. sends a 2-byte buffer with:
   - byte `0`: the index
   - byte `1`: the user-supplied character
5. uses `DeviceIoControl(..., 0x228124, ...)` for each byte
6. sends one final `DeviceIoControl(..., 0x228128, ...)` to request the verdict

So the driver sees a 69-byte candidate string as indexed writes, then one "check everything" command.

## Driver Handler

The real validation routine sits at `0x140001730` in `SubstrateKM.sys`. It branches on:

```text
IoControlCode - 0x228124
```

That gives two interesting cases.

### `0x228124`: store one byte

The first branch fetches the input buffer and does:

```c
if (index >= 0x48) return STATUS_BUFFER_OVERFLOW;
state[index] = value;
```

`state` lives at `0x14000c5d8`, so the driver keeps a 72-byte global buffer. The userland program only fills indices `0..68`, which means the last three bytes stay zero.

### `0x228128`: validate all 72 bytes

The second branch is the actual puzzle.

For each of 8 blocks:

1. take the next 9 bytes from `DriverEntry`
2. interpret them as a `3x3` row-major matrix seed
3. zero the strict lower triangle
4. force the diagonal bytes odd with `byte |= 1`
5. apply that upper-triangular matrix to three 3-byte groups from the current 9-byte input block
6. compare the resulting 9 bytes against the next 9 bytes of the target at `.data:0x14000c000`

For chunk 0, the first 9 `DriverEntry` bytes are:

```text
48 89 5c 24 08 57 48 83 ec
```

and the constructed matrix becomes:

```text
[49 89 5c]
[00 09 57]
[00 00 ed]
```

The same construction is repeated on the next 9 bytes, and so on for 8 chunks total.

## Algebra

Each 9-byte block is split into three groups of three bytes. For one group `x = [x0, x1, x2]` and one chunk matrix

```text
[a00 a01 a02]
[  0 a11 a12]
[  0   0 a22]
```

the driver computes:

```text
y0 = x0*a00
y1 = x0*a01 + x1*a11
y2 = x0*a02 + x1*a12 + x2*a22
```

with all arithmetic modulo `256`.

Because `a00`, `a11`, and `a22` are forced odd, every diagonal entry is invertible modulo `256`. So each 3-byte system can be solved by back-substitution:

```text
x0 = y0 / a00
x1 = (y1 - x0*a01) / a11
x2 = (y2 - x0*a02 - x1*a12) / a22
```

Doing that for all 24 triples recovers 72 bytes. The last three come out as `00 00 00`, which matches the indexed-write protocol, so the real answer is the first 69 bytes:

```text
CTF{1c41e1d89f95c6c6b45f256f06e554f904257c884f683528302bacbde8b9484f}
```

## Solver

[solve_substrate.py](./solve_substrate.py) extracts everything directly from `SubstrateKM.sys`:

- entrypoint bytes for the 8 matrices
- the first 72 bytes of `.data` as the target
- the inverse solve over `mod 256`
- a forward check that the recovered bytes re-encode to the embedded target

Usage:

```bash
python3 solve_substrate.py /path/to/SubstrateKM.sys --verify
```

On the supplied driver it prints the flag above and `validation=true`.
