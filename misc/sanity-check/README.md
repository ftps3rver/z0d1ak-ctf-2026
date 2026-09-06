# z0d1ak CTF 2026 — Sanity Check

**Solved by:** ftps3rver
**Category:** Miscellaneous | **Points:** 199 | **Solves:** 31 | **Author:** ludicrouslytrue

---

## 1. Executive Summary

`Sanity Check` looks like nothing at all: a bare Vite/React landing page at `z0d1ak.org` advertising the CTF, with no visible challenge surface, no input field, no API to poke at. The trick is that the challenge author edge-injects a small, hostname-dependent `<style>` fragment into the served HTML — one value for the apex domain, a different value for `www.` — and the two values are not random noise but two halves of a single Base58-encoded message. Concatenate them in the right order (apex-first) and decode as Base58: the payload is a plaintext sentence, not a binary blob, and *is* the flag body once wrapped in the CTF's format string.

**Answer:** `zdk{all the best, we hope you enjoy the ctf}`

---

## 2. Challenge Description

> z0d1ak.org

Instance: `https://z0d1ak.org/` (the CTF's own public marketing site, not `ctf.z0d1ak.org` where the platform/scoreboard lives).

No attachment, no further hints. The category (`Miscellaneous`) and the name (`Sanity Check`) both signal "make sure you can find things on the infra before the real challenges start" — but the low solve count relative to points (31 solves, 199 pts, well below the median difficulty for a true sanity check) was the first indicator that the obvious reading (just visit the site) was incomplete.

---

## 3. Initial Reconnaissance

```bash
curl -s -i -L https://z0d1ak.org/
```

Standard Cloudflare-fronted static SPA response: `Server: cloudflare`, `cf-cache-status: DYNAMIC`, a Vite-built `index-*.js` / `index-*.css` bundle, and a hand-authored `<head>`. Nothing in the headers stood out (no custom `X-*` header, no flag-shaped cookie, no `Set-Cookie` at all).

The one anomaly in the raw HTML, absent from the compiled bundle itself:

```html
<style id="sanity-check-fragment">:root{--sanity-fragment:"26cPm361Zq4WTj89j2HhnestsgA"}</style>
```

This tag does not exist in `index-9lCObJG5.js` or `index-CtZAp8dI.css` (confirmed by downloading both and grepping for `sanity`), which means it is injected server-side / at the edge on every response, not shipped as part of the built frontend. That, plus the deliberately on-brand id (`sanity-check-fragment`), was the signal that this *is* the challenge.

---

## 4. Attack Surface / Important Observations

**The fragment is stable, not random.** Repeated requests, a request routed through an external proxy (different egress IP/colo), HTTP/1.0 vs HTTP/1.1, and a dozen different `User-Agent` strings (Googlebot, Twitterbot, Discordbot, GPTBot, curl, Chrome) all returned the **same** value for the same hostname. This ruled out "per-request nonce, look elsewhere" and confirmed it's a fixed, hostname-keyed secret.

**The fragment differs by hostname:**

| Host | `--sanity-fragment` value |
|---|---|
| `z0d1ak.org` (apex) | `26cPm361Zq4WTj89j2HhnestsgA` |
| `www.z0d1ak.org` | `U9aCPzuwzja87fh1RiE83aGLBR7` |
| `ctf.z0d1ak.org` (the real CTFd-style platform, a completely separate SvelteKit app) | *no fragment at all* — different app, different templating, confirmed by diffing the served HTML |

Both values are exactly 27 characters and use only characters from the Base58 alphabet (`123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`) — notably **absent** are `0`, `O`, `I`, `l`, which is what first suggested Base58 over Base64 (Base64 would have no reason to systematically avoid four specific printable characters across two independently-generated-looking strings).

27 Base58 characters decode to ~20 bytes each — too short and too high-entropy-looking individually to be a flag on their own, and neither one alone decodes to anything printable. That pointed at "these two pieces need to be combined."

---

## 5. Failed Attempts

**Attempt 1 — Decode each fragment independently as Base58/Base64.** Both individually decode to 20 bytes of non-printable binary garbage. **Dead end** — confirmed these are fragments of something, not complete secrets.

**Attempt 2 — Look for a third fragment / more hostnames.** Brute-forced a wordlist of plausible subdomains (`api`, `sanity`, `quals`, `beta`, `dev`, `cdn`, …) via targeted DNS existence checks; only `www` and `ctf` actually resolve alongside the apex. Tried `.well-known/`, `robots.txt`, `sitemap.xml`, PNG metadata (`og-v3.png` tEXt/iTXt chunks and trailing bytes after `IEND`), DNS TXT records, and Wayback Machine snapshots for a possible third piece or a flag string directly. **Nothing found** — confirmed there are exactly two fragments, and the payload has to be reconstructed from just those two.

**Attempt 3 — XOR the two 20-byte decodings together.** A tempting move given they're the same length, but this produces more binary garbage, not plaintext. **Dead end** — the relationship between the two values isn't bitwise; it's concatenation of a single Base58 stream that happened to be split into two pieces of unequal *decoded* length (20 and 19 bytes respectively, from 27 encoded characters each — Base58 doesn't preserve fixed byte-per-character ratios the way Base64 does).

**Attempt 4 — Try `www + apex` order.** Concatenating the raw Base58 strings in the "natural" listing order (www second) and decoding: garbage. **Rejected** — order matters, and it isn't the order you'd casually guess in a table.

---

## 6. Investigation — Building the Exploit

**Step 1 — Confirm the encoding is Base58, not Base64/Base32.**
```python
alpha = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
for s in (apex_frag, www_frag):
    assert all(c in alpha for c in s)   # both pass; Base64 alphabet check fails (mixed case + no 0/O/I/l exclusion makes no sense for b64)
```

**Step 2 — Try both concatenation orders and decode.**
```python
def b58decode(s):
    n = 0
    for c in s:
        n = n * 58 + alpha.index(c)
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b

apex = "26cPm361Zq4WTj89j2HhnestsgA"
www  = "U9aCPzuwzja87fh1RiE83aGLBR7"

print(b58decode(apex + www))   # -> b'all the best, we hope you enjoy the ctf'
print(b58decode(www + apex))   # -> garbage
```

`apex + www` decodes to a clean, fully printable 39-byte ASCII sentence on the first try. `www + apex` does not. This one-sided success is itself strong confirmation there is no third fragment hiding anywhere: a genuine subset of *N* pieces would only coincidentally decode cleanly if exactly the right *N* were combined in exactly the right order — getting a clean decode from just 2 of however-many candidate hostnames, on the very first correct ordering tried, is the signature of "that's the whole message," not a lucky partial match.

**Step 3 — Wrap in the platform's flag format.**

The CTFd-style platform at `ctf.z0d1ak.org` exposes its client config unauthenticated:
```bash
curl -s https://ctf.z0d1ak.org/api/v1/integrations/client/config | grep -o '"flagFormatPlaceholder":"[^"]*"'
# "flagFormatPlaceholder":"zdk{}"
```
confirming the wrapper is `zdk{...}`, not the more obvious `z0d1ak{...}` guess.

**Step 4 — Submit.**
```
zdk{all the best, we hope you enjoy the ctf}
```
Accepted.

---

## 7. Root Cause / Why This Chain Works

1. **A single secret was deliberately split across two otherwise-identical-looking deployments of the same static site.** The apex and `www` hosts serve byte-identical JS/CSS bundles (confirmed via MD5) and differ *only* in this one injected style tag — the split is the entire challenge design, not a bug being exploited.
2. **Base58 was chosen specifically because it doesn't leak fixed-length structure the way Base64 does.** Two 27-character Base58 strings decode to 20 and 19 bytes respectively (not a clean 20/20), which is a small deliberate speed bump against naively assuming symmetric halves.
3. **Order is part of the puzzle.** Concatenation order (apex before www) isn't discoverable from the page itself — it has to be brute-forced or guessed from context (apex domain is "canonical," `www` is the alias, so apex-first is the more natural default to try first).
4. **The category name is the real hint.** "Sanity Check" plus the low relative solve rate signals: don't stop at "the site loads fine," inspect *what the site actually serves*, byte for byte, against every hostname that resolves for the domain.

---

## 8. Answer

```
zdk{all the best, we hope you enjoy the ctf}
```

---

## 9. Reconstruction Chain

```
z0d1ak.org  (Vite/React SPA, Cloudflare-fronted)
        |
        v
Diff raw HTML vs compiled JS/CSS bundle
        -> <style id="sanity-check-fragment"> is edge-injected, not shipped in the build
        |
        v
Fetch same path across every resolvable hostname
        -> z0d1ak.org      : --sanity-fragment = "26cPm361Zq4WTj89j2HhnestsgA"
        -> www.z0d1ak.org  : --sanity-fragment = "U9aCPzuwzja87fh1RiE83aGLBR7"
        -> ctf.z0d1ak.org  : different app entirely, no fragment
        |
        v
Confirm values are stable (not per-request) across proxies / UAs / HTTP versions
        |
        v
Alphabet-fingerprint the two strings -> Base58 (no 0/O/I/l, 27 chars ~20 bytes)
        |
        v
Try concatenation orders: apex+www decodes cleanly, www+apex does not
        |
        v
b58decode(apex + www) = "all the best, we hope you enjoy the ctf"
        |
        v
Confirm flag wrapper via unauthenticated platform config API -> "zdk{}"
        |
        v
zdk{all the best, we hope you enjoy the ctf}
```

---

## 10. Key Takeaways

- **A static-looking marketing site is still in scope if the CTF says it is.** "Nothing to click" doesn't mean "nothing to diff" — always compare the raw response against the compiled/shipped assets when something in the `<head>` looks hand-placed.
- **Check every hostname that resolves for the domain, not just the one linked in the challenge description.** A challenge secret split across `apex` vs `www` is invisible if you only ever fetch one of them.
- **Fingerprint an unfamiliar alphabet before guessing an encoding.** Systematic absence of specific characters (here, `0/O/I/l`) is a strong, cheap signal for Base58 over Base64/Base32/hex, and saves time versus trying every decoder blind.
- **A clean, printable decode on the first correctly-ordered combination of exactly the pieces you have is itself evidence you're not missing a piece.** Don't keep hunting for a phantom third fragment once concatenation produces coherent plaintext.
- **Check the platform's own public config endpoints for the flag format placeholder** (`flagFormatPlaceholder` on CTFd-style `/api/v1|v2/integrations/client/config`) rather than guessing between `zdk{}` and the more "obvious" `z0d1ak{}`.

---

## 11. Tooling Notes (for reproduction)

```python
ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def b58decode(s: str) -> bytes:
    n = 0
    for c in s:
        n = n * 58 + ALPHA.index(c)
    return n.to_bytes((n.bit_length() + 7) // 8, "big")

apex_frag = "26cPm361Zq4WTj89j2HhnestsgA"   # from z0d1ak.org
www_frag  = "U9aCPzuwzja87fh1RiE83aGLBR7"   # from www.z0d1ak.org

print(b58decode(apex_frag + www_frag).decode())
# -> all the best, we hope you enjoy the ctf
```

```bash
# Pull the style fragment for a given host
curl -s https://z0d1ak.org/     | grep -o 'sanity-fragment:"[^"]*"'
curl -s https://www.z0d1ak.org/ | grep -o 'sanity-fragment:"[^"]*"'

# Confirm the flag wrapper format
curl -s https://ctf.z0d1ak.org/api/v1/integrations/client/config \
  | grep -o '"flagFormatPlaceholder":"[^"]*"'
```
