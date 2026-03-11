# svfgp

`svfgp` is not an XSS. The secret never leaves the browser. The bot writes the flag into `localStorage`, the app exposes a prefix check on that sealed note, and `probe` mode turns that prefix check into a measurable timing oracle.

Final flag:

```text
CTF{1390e7327d4c2069a97e3a7f1eafed37e389f9fb9598b183455dc9f6cc2da658}
```

## Surface Triage

The server in `app.py` is tiny. It only renders `index.html` and reflects four query parameters into a JSON boot blob:

- `mode`
- `q`
- `sid`
- `rid`
- `note`

The real logic lives in `static/app.js`.

At first glance the challenge looks like a local note app with DOMPurify and a CSP. Those are decoys. The winning path never needs HTML injection.

## Where The Flag Lives

The admin bot in `bot.js` visits the challenge origin and stores a sealed note directly into `localStorage`:

```javascript
localStorage.setItem(
  "svfgp.notes.v1",
  JSON.stringify([
    {
      id: "sealed-0",
      title: "classified",
      content: flag,
      sealed: true,
    },
  ])
);
```

So the flag is only available inside the bot's browser state for `https://svfgp.breakable.live/`.

## The Prefix Oracle

The note search logic treats sealed notes differently:

```javascript
function noteMatchesQuery(note, q) {
  if (!q) return true;
  if (note.sealed) return note.content.startsWith(q);
  return note.title.includes(q) || note.content.includes(q);
}
```

That already leaks whether a query is a prefix of the secret note content. The regular UI does not show sealed content, but `probe` mode makes the leak measurable.

## Probe Mode Turns It Into Timing

`runProbeMode()` loads the sealed note and only does expensive work when the candidate prefix matches:

```javascript
if (secret && candidate && secret.startsWith(candidate)) {
  await deriveHash(secret);
}
```

`deriveHash()` runs PBKDF2 with:

```javascript
const KDF_ITERATIONS = 1000 * 1000 * 3;
```

That is a 3,000,000-iteration `SHA-256` PBKDF2 call, which is slow enough to stand out clearly from the no-match case.

After the optional delay, the probe page signals completion:

```javascript
window.opener.postMessage({ type: "svfgp-probe-done", sid, rid }, "*");
```

So the attacker only has to measure how long each popup takes to answer.

## Why Cross-Origin Popups Still Work

The app deliberately sets:

```text
Cross-Origin-Opener-Policy: unsafe-none
```

That keeps the opener relationship intact. An attacker page on another origin can open many challenge popups, and each popup can still `postMessage()` back to the opener.

No origin check is enforced on the receiving side. The attacker page simply timestamps each popup open and records the delay until the matching `svfgp-probe-done` message arrives.

## Attack Strategy

The remote attack is:

1. host an attacker page on a public URL
2. submit that URL to the admin bot
3. from the attacker page, open one popup per candidate next character:

```text
https://svfgp.breakable.live/?mode=probe&q=<candidate>&sid=<session>&rid=<char>
```

4. measure completion time for each popup
5. keep the slowest candidate, because only the correct prefix triggers PBKDF2
6. repeat until the closing brace is recovered

For the deployed instance I restricted the alphabet to:

```text
0123456789abcdef}
```

because the flag format was `CTF{<64 hex>}`. If the format is unknown, widen the alphabet and accept slower rounds.

## Why It Is Reliable

The challenge itself gives the attacker a very strong signal:

- wrong prefix: almost immediate `postMessage`
- correct prefix: expensive PBKDF2 before `postMessage`

The helper uses repeated rounds and median ranking to smooth out scheduler noise. That is enough to recover the flag remotely without reading `localStorage` directly and without injecting into the challenge origin.

## Solver

[solve_svfgp.py](./solve_svfgp.py) hosts an attack page plus `/collect` and `/latest` endpoints. It prints the public URL to submit to the bot and tracks the best recovered prefix.

Typical usage:

```bash
python3 solve_svfgp.py --public-base https://your-vps-or-tunnel.example
```

Then submit the printed `/attack` URL to the bot. The status endpoint shows progress:

```text
https://your-vps-or-tunnel.example/latest
```

## Result

Running the popup timing oracle to completion recovers:

```text
CTF{1390e7327d4c2069a97e3a7f1eafed37e389f9fb9598b183455dc9f6cc2da658}
```
