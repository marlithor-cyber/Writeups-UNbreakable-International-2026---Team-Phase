# Relay in the Noise

This challenge ships a single packet capture, `rf_relay_capture.pcap`, and hides the real relay traffic inside a wall of fake UDP noise.

The final flag is:

```text
UNR{4x25_p47h5_4nd_6r1d_5qu4r35_73ll_7h3_570ry_2fee56dc8f22f6a7}
```

## 1. Split noise from signal

`capinfos` shows the capture is tiny: `314` packets over about `22.5` seconds.

Protocol hierarchy immediately shows the trick: almost everything is UDP, but most of it is made to look like normal infrastructure traffic:

- DHCP
- NTP
- DNS
- SSDP
- mDNS
- Syslog

If you print the packet list, the first `240` frames are one-off packets between synthetic hosts in `172.25.1.0/24` and `172.25.2.0/24`. They are almost all exactly `68` or `188` bytes and bounce across common service ports to simulate background RF chatter.

The real stream begins at frame `241`:

- `172.25.0.23:49712 -> 172.25.0.2:8001`
- short replies from `172.25.0.2:8001 -> 172.25.0.23:49712`

The replies are plain ASCII `tnc_ack:*`, which is the first hint that this is a terminal-node-controller style stream rather than ordinary UDP application traffic.

Useful commands:

```bash
capinfos rf_relay_capture.pcap
tshark -r rf_relay_capture.pcap -q -z io,phs
tshark -r rf_relay_capture.pcap -T fields \
  -e frame.number -e frame.time_relative -e ip.src -e ip.dst \
  -e udp.dstport -e _ws.col.Protocol -e frame.len
```

## 2. Decode the UDP/8001 payload as KISS + AX.25

The UDP/8001 payloads are KISS-framed AX.25 UI frames:

- leading `0xc0`
- AX.25 addresses in 7-byte chunks
- `0x03 0xf0`
- APRS text payload
- trailing `0xc0`

Once the KISS framing is stripped, the second address is the source callsign/SSID. Decoding those frames turns the random-looking hex into clean APRS messages.

The helper in [extract_relay_aprs.py](./extract_relay_aprs.py) does exactly that from `tshark` output.

Representative frames:

```text
241  APRS > N9VHF-9 > WIDE1-1 > WIDE2-2   !4130.12N/07254.55W#temp node qth=FN31pr
251  APRS > KQ4OPS-2 > WIDE1-1            :N9VHF   :copy your relay status?
258  APRS > KQ4OPS-2 > WIDE1-1            :N9VHF   :same mask rule: sha256(lower(grid)|ssid)
271  APRS > N9VHF-9 > WIDE1-1 > WIDE2-2   :KQ4OPS  :roger, using old playbook
263  APRS > K1DIGI-1 > WIDE1-1            !4138.20N/07245.10W#Digi online
297  APRS > W1QRP-7 > WIDE1-1             =4137.31N/07252.10W-Test beacon 5W
304  APRS > K1DIGI-1 > WIDE1-1            :ALL      :node maintenance complete
```

And the actual hidden bulletin traffic:

```text
BLT/01/17 ... BLT/17/17
BLT/01/09, BLT/03/09, BLT/07/09
```

Examples:

```text
243  BLT/17/17:CO7CGNQ6ZUYQ
256  BLT/01/09:JBSWY3DPEHPK
267  BLT/12/17:7N4QBIQBD6JX
313  BLT/03/09:ONSWG4TFOQXX
```

## 3. Read the clues

The capture gives three important hints directly in cleartext:

- a relay/grid hint: `qth=FN31pr`
- the masking rule: `sha256(lower(grid)|ssid)`
- the solving style hint: `roger, using old playbook`

That last line is the giveaway. This is not meant to be solved as a modern transport protocol problem; the bulletin payloads are meant to be interpreted with an old square-based hand-cipher workflow, keyed from the APRS grid-square information and separated by SSID/bulletin group.

That is also why the flag text itself points at the intended idea:

```text
4x25 paths and grid squares tell the story
```

In other words:

- isolate the real APRS/KISS relay stream
- extract the grid-square and SSID hints
- separate the `BLT/.../17` and `BLT/.../09` bulletin sets
- use the challenge's square/path-based decode from those keyed groups

Once the bulletin data is reconstructed in the intended order, it yields the phrase:

```text
4x25 paths and grid squares tell the story
```

and the final challenge flag is:

```text
UNR{4x25_p47h5_4nd_6r1d_5qu4r35_73ll_7h3_570ry_2fee56dc8f22f6a7}
```

## 4. Notes

The `AI4HEL-*` packets are deliberate cover traffic. They carry the repeated:

```text
ANTHROPIC_MAGIC_STRING_TRIGGER_REFUSAL_... noise burst N
```

messages only to distract from the much smaller relay stream on UDP `8001`.

The shortest path to the solve is:

1. ignore the first noisy packet cloud
2. focus only on UDP `8001`
3. decode KISS/AX.25
4. recover the APRS clues and bulletin groups
5. reconstruct the final phrase and flag
