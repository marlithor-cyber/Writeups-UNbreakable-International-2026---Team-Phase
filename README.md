# Writeups - UNbreakable International 2026 - Team Phase

- [crypto/toxicwaste](./crypto/toxicwaste/README.md): recover a shuffled KZG SRS with pairings, extend it with the leaked toxic-waste relation, and forge a degree-41 opening.
- [crypto/riga-crypto](./crypto/riga-crypto/README.md): peel open the npm dropper, extract the hidden PyInstaller payload, and recover the poem-based flag that matches `flag.enc`.
- [forensics/unholy-land](./forensics/unholy-land/README.md): parse a Suricata `eve.json`, count flows/events/DNS requests, and identify the malware family as `holycat`.
- [network/relay](./network/relay/README.md): peel the fake UDP chatter away from the real KISS/AX.25 relay stream, recover the APRS hints, and extract the final `Relay in the Noise` flag.
- [pwn/atypical-heap-revenge](./pwn/atypical-heap-revenge/README.md): combine an out-of-bounds read with a mislabeled hidden arbitrary-write primitive, then hijack musl's exit hooks to execute `system("cat flag.txt")`.
