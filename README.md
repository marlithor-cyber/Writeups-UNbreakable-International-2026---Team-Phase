# Writeups - UNbreakable International 2026 - Team Phase

- [crypto/toxicwaste](./crypto/toxicwaste/README.md): recover a shuffled KZG SRS with pairings, extend it with the leaked toxic-waste relation, and forge a degree-41 opening.
- [crypto/riga-crypto](./crypto/riga-crypto/README.md): peel open the npm dropper, extract the hidden PyInstaller payload, and recover the poem-based flag that matches `flag.enc`.
- [forensics/unholy-land](./forensics/unholy-land/README.md): parse a Suricata `eve.json`, count flows/events/DNS requests, and identify the malware family as `holycat`.
- [network/relay](./network/relay/README.md): peel the fake UDP chatter away from the real KISS/AX.25 relay stream, recover the APRS hints, and extract the final `Relay in the Noise` flag.
- [pwn/atypical-heap](./pwn/atypical-heap/README.md): recover musl `mallocng` metadata from an over-read, turn it into a libc leak, and hijack musl's exit hooks to execute `system("cat flag.txt")`.
- [pwn/atypical-heap-revenge](./pwn/atypical-heap-revenge/README.md): combine an out-of-bounds read with a mislabeled hidden arbitrary-write primitive, then hijack musl's exit hooks to execute `system("cat flag.txt")`.
- [reverse/jumpy](./reverse/jumpy/README.md): peel away the self-decrypting handler noise, reconstruct the `GrayInterleaveSbox` block cipher, and run it backwards to recover the flag from `enc.sky`.
- [reverse/substrate](./reverse/substrate/README.md): follow the userland-to-driver IOCTL protocol, lift eight upper-triangular matrices from `DriverEntry`, and invert the per-block byte algebra to recover the validated flag.
- [reverse/webd-art](./reverse/webd-art/README.md): peel the Dart-to-WASM canvas app apart, recover the masked 32-bit byte generator behind the fake randomness, and rebuild the hidden flag.
- [threat-hunting/control](./threat-hunting/control/README.md): mine a Winlogbeat/Sysmon export for the download source, execution chain, privilege escalation, lateral movement, persistence, process migration, and LSASS dump path behind the `control` intrusion.
