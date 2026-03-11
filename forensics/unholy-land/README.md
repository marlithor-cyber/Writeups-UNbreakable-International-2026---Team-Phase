# Unholy Land

This challenge gives a single Suricata EVE file, `eve.json`, and asks four questions.

The important detail is that EVE is not a one-packet-per-line export. It mixes `flow`, `dns`, `tls`, `http`, `alert`, `stats`, and other record types. So each question has to be answered from the right event type.

## Q1. TCP / UDP / ICMPv6 packet counts

Question:

```text
How many TCP, UDP, and ICMPv6 packets are present in the eve.json file?
```

The expected answer matches the number of `flow` records per protocol, not the cumulative `stats.decoder.*` counters and not the total number of lines containing `proto`.

Use:

```python
if event["event_type"] == "flow":
    proto = event["proto"]
```

Count the `flow` entries:

- `TCP`: `3391`
- `UDP`: `2452`
- `IPv6-ICMP`: `15`

So:

```text
UNR{3391, 2452, 15}
```

## Q2. Total number of events

This one is just the number of JSON lines in the file.

For a newline-delimited EVE export:

```python
sum(1 for _ in open("eve.json"))
```

Result:

```text
15551
```

So:

```text
UNR{15551}
```

## Q3. Top 3 DNS requests

Only `dns` events with:

```text
dns.type == "request"
```

should be counted.

The queried hostname is nested under:

```text
dns.queries[].rrname
```

Counting those request hostnames gives:

1. `ncs.roblox.com` with `172`
2. `users.roblox.com` with `141`
3. `edge.microsoft.com` with `136`

So:

```text
UNR{ncs.roblox.com, users.roblox.com, edge.microsoft.com}
```

## Q4. Malware family

The family answer used by the challenge is:

```text
UNR{holycat}
```

The EVE file itself mostly contains normal Windows update / Microsoft traffic mixed with a few noisy decoys such as:

- `testmyids.com`
- `testmyid.com`
- `BlackSun` user-agent alerts
- Discord lookups / TLS SNI alerts

Those are useful to isolate suspicious activity, but the challenge’s final identification answer is the family name `holycat`.

## Final Answers

```text
Q1: UNR{3391, 2452, 15}
Q2: UNR{15551}
Q3: UNR{ncs.roblox.com, users.roblox.com, edge.microsoft.com}
Q4: UNR{holycat}
```

## Helper

The script in [solve_unholy_land.py](./solve_unholy_land.py) recomputes Q1, Q2, and Q3 from an `eve.json` file and prints the known Q4 answer.
