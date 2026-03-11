# riga-crypto

`riga-crypto` is a fake npm package challenge. At first glance it looks like a harmless text-processing module around *Rigă Crypto și lapona Enigel*, but the package also ships an obfuscated dropper and a protected native encryptor.

The provided files were:

- `riga-crypto-0.1.0.tar`
- `flag.enc`
- the unpacked `package/` directory

## 1. Ignore the obvious decoy

`package/package.json` contains a fake-looking flag field:

```json
"flag": "UNR{b5418b5d5d3636c5e659b142ef99a89663e9985f36a4bddc44ef31148622fb51}"
```

That value is not related to `flag.enc`.

## 2. The npm module drops a hidden executable

The real behavior is wired through `package/index.js`, which imports `components/config.js` on load. `scripts/build-config.js` shows how that file is generated: it base64-embeds a compiled binary, writes it to `/tmp/app`, marks it executable, and launches it.

So the npm package is really a loader.

## 3. Extract the real payload

After running the config module once, `/tmp/app` appears. It is a PyInstaller-packed Python binary. Listing the archive shows the interesting pieces:

```text
main
pyarmor_runtime_000000/pyarmor_runtime.so
encr_so/libmylib.so
ida.png
unbreakable.png
PYZ.pyz
```

So the actual challenge logic is:

- Python + PyArmor-protected `main`
- a Go shared library `libmylib.so`
- a pygame front-end

## 4. Use the bundled encryptor as an oracle

Running the protected app headless is enough to see a useful side path:

```text
[encrypt] skipped: flag file not found (.../flag.txt)
```

If a `flag.txt` exists in the working directory, the app encrypts it into `flag.enc`.

Hooking `ctypes.CDLL` shows the exact native call:

```python
EncryptFileHex.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_char_p)]
EncryptFileHex.restype = ctypes.c_char_p
```

Calling it directly is enough to reproduce the challenge ciphertext for any candidate plaintext.

## 5. The visible poem gives the real flag text

The package itself already contains the full poem in `package/shared/poem.js`. The flag body comes from the final two lines:

```text
Cu măsălarița-mireasă,
Să-i ție de împărăteasă.
```

Transform them as follows:

1. lowercase
2. remove comma and period
3. replace spaces with `_`
4. keep the hyphen
5. l33t-map letters with:
   `a/ă -> 4`, `e -> 3`, `i/î -> 1`, `s -> 5`, `t/ț -> 7`

That gives:

```text
cu_m454l4r174-m1r3454_54-1_713_d3_1mp4r473454
```

The full candidate that matches the bundled ciphertext is:

```text
UNR{cu_m454l4r174-m1r3454_54-1_713_d3_1mp4r473454_f4abc8120c3d2a57}
```

## 6. Verification

Re-encrypting that exact string with the extracted `EncryptFileHex` export reproduces the provided `flag.enc` byte-for-byte:

```text
21662504e41be94eaaeaddd9e84af55f8f79be16a7eb2a9b9ded488c503890f2
ce93ab6f2775b8d368d5d22aaf36641671a825e6ca058fa60221ba2edb7d4e91
b29e736185cceec250162a3b16631f00dff8e85af86a16d12c061cd8ae02d76d
```

So the flag is:

```text
UNR{cu_m454l4r174-m1r3454_54-1_713_d3_1mp4r473454_f4abc8120c3d2a57}
```

## Helper

The helper script in [recover_flag.py](./recover_flag.py) rebuilds the poem-derived flag text and can optionally verify it against `flag.enc` if you provide the extracted `libmylib.so`.
