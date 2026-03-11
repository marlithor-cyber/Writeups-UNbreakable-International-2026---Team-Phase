# webd-art

`webd-art` looks like a browser graphics challenge: an `index.html`, a tiny `main.mjs` loader, and a large `main.wasm` produced by `dart2wasm`. The canvas UI is a decoy. The real secret is a deterministic byte stream hidden in the WebAssembly bundle.

The key observation is that the app is not using "random" in any meaningful way for the flag. It derives the flag from a fixed 32-bit state and a 40-byte mask table, then only checks that the user input matches the resulting string.

Final flag:

```text
CTF{7h3_w3b_15_4_l13_rng_15_d373rm1n15m}
```

## Surface Triage

The HTML is minimal:

- one canvas
- one input box `#phrase`
- one button `#renderBtn`
- `main.mjs` loading `main.wasm`

`main.mjs` is just the standard `dart2wasm` runtime shim, so almost all challenge logic lives in `main.wasm`.

Strings from the module already reveal the important pieces:

```text
#phrase
#renderBtn
^CTF\{[ -~]{8,80}\}$
Render OK  #
CERTIFICATE UNLOCKED
stamp: verified locally
SplitMix32
XorShift32
```

That tells us:

1. the UI only expects a printable `CTF{...}` string
2. success prints a certificate banner on the canvas
3. the challenge author wants us looking at deterministic PRNG code, not the drawing code

## What Matters in the WASM

After lifting the relevant logic from the WASM, the flag generation reduces to:

```c
seed += 0x9e3779b9;
z = seed;
z = (z ^ (z >> 16)) * 0x85ebca6b;
z = (z ^ (z >> 13)) * 0xc2b2ae35;
z ^= z >> 16;
byte = (z & 0xff) ^ mask[i];
```

for `i = 0..39`.

So the flag is:

```text
flag[i] = next_byte(seed, i)
```

where `mask` is a fixed 40-byte table extracted during reversing:

```text
[218, 78, 141, 70, 79, 33, 46, 234, 174, 75,
 4, 130, 143, 169, 189, 93, 127, 4, 198, 150,
 239, 47, 94, 136, 89, 231, 203, 209, 88, 150,
 122, 147, 60, 167, 251, 224, 198, 100, 50, 163]
```

This is a tiny SplitMix-style generator with a MurmurHash3-style avalanche finalizer. The challenge name is accurate: the "web art" layer is mostly noise, while the actual flag logic is just a deterministic PRNG plus a mask.

## Recovering the Seed

The state space is only 32 bits, so brute force is practical in optimized native code.

The early-rejection strategy is straightforward:

1. require the first four bytes to equal `CTF{`
2. require bytes `4..38` to stay inside printable ASCII
3. require the last byte to be `}`

That cuts the search down quickly enough that a simple C helper with OpenMP finds the unique seed:

```text
0x13564e1d
```

Feeding that seed through the generator yields:

```text
CTF{7h3_w3b_15_4_l13_rng_15_d373rm1n15m}
```

## Why This Works

Nothing in the browser environment influences the secret:

- no server calls
- no clock dependency
- no genuine entropy

The canvas output is deterministic decoration. Once the seed and mask are known, the flag is reconstructed offline with no need to interact with the page at all.

## Solver

[recover_webd_art.py](./recover_webd_art.py) rebuilds the byte stream from the recovered seed and mask and checks the expected flag format:

```bash
python3 recover_webd_art.py --verify
```

On the supplied challenge it prints:

```text
CTF{7h3_w3b_15_4_l13_rng_15_d373rm1n15m}
regex_match=true
```
