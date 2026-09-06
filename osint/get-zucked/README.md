# z0d1ak CTF 2026 — Get Zucked

**Solved by:** ftps3rver
**Category:** OSINT | **Difficulty:** Hard | **Points:** 500 | **Solves:** 1 | **Author:** ant1v3n0m

---

## 1. Executive Summary

This challenge asks solvers to identify a "wanna-be Zuck" from the author's college who built his own Omegle clone, then chain that identification down to two pieces of personal data: his old school and his Instagram handle. The entry point — the Omegle clone itself — turned out to be **Vimegle** (`vimegle.com`), a video/voice/text chat site built "for VIT" students. Pivoting from the site to its operator required going past two decoys (a similarly-named "Omegle for VIT-AP" repo, and a GitHub account that merely re-uploaded the source). The real operator was confirmed independently through **DNS infrastructure** (a subdomain of `vimegle.com` proxying to a project only he owns) and through **git commit author metadata** he left in his own repositories, then bound to a real name and a LinkedIn handle via his college's own club website, which listed both his GitHub and LinkedIn side by side. From there, his LinkedIn Education section gave the school, and the LinkedIn vanity slug doubled as his self-chosen Instagram handle.

**Flag:** `zdk{ryan_international_school-ishaaans}`

---

## 2. Challenge Description

> Some wanna be zuck from our college tried to make his own omegle
>
> Flag format: `zdk{school_name-insta_username}`

No attachment, no target IP — pure open-source intelligence. The description gives three real constraints solvers tend to skip past:
- "his own omegle" → the artifact to find is a live Omegle-style clone.
- "from our college" → the operator is affiliated with the same institution as the CTF (VIT).
- The flag format asks for **school_name**, not college/university — a signal the answer sits *before* VIT (pre-university education), not at VIT itself.

---

## 3. Initial Reconnaissance

Standard web search tooling (WebSearch, most search engine WebFetch endpoints) was blocked/unavailable in the environment used to solve this. The only channel that stayed open was raw `curl` from a shell, so the entire investigation was rebuilt around that constraint: GitHub's public REST API, `crt.sh` for certificate-transparency subdomain enumeration, RDAP/WHOIS, and directly fetching target pages instead of searching for them.

Candidate "Omegle clones built by a VIT student" surfaced from public chatter (Reddit, project directories, dev-community posts):

| Candidate site | Notes |
|---|---|
| `omegle-vitap` (GitHub repo) | README explicitly ties it to VIT-AP, not VIT Vellore |
| **Vimegle** (`vimegle.com`) | Creator's own post: *"we made this website for vitv"* (VIT Vellore) |

The "for vitv" phrasing plus the college match made Vimegle the correct target; `omegle-vitap` was a decoy from a different VIT campus.

---

## 4. Attack Surface / Important Observations

1. `vimegle.com`, registered 2024‑11‑26, fronted by Cloudflare — no registrant data via RDAP.
2. Reddit's official author account (`u/No_Quarter1331`) posted the project but hides post history and blocks datacenter IPs on both old.reddit.com and the JSON API (`403`) — dead end from this environment.
3. GitHub search for a repo literally named `vimegle`/`Vimegle` returns exactly **one** result — `nikhilvitc/Vimegle` — which looked like the smoking gun but wasn't.
4. `crt.sh?q=%.vimegle.com` lists live subdomains for the domain, which is a much more reliable way to find the *real* operator than trusting a copy of the source code sitting in someone else's repo.

**Hypothesis:** the person who controls `vimegle.com`'s DNS (not necessarily whoever has a copy of the code) is the actual builder.

---

## 5. Failed Attempts

**Decoy 1 — Rudra Narayana Sahoo.** Owns a repo `omegle-vitap` and links an Instagram in his GitHub profile. Discarded: the project is explicitly for VIT-AP, a different campus, and nothing ties him to Vimegle specifically.

**Decoy 2 — `nikhilvitc/Vimegle`.** The only GitHub repo literally named `Vimegle`. Looked promising until the repo metadata was inspected directly:
```
committer: "GitHub" (login: web-flow)
message:   "Add files via upload"
created_at == pushed_at, 1 commit, never touched again
```
`web-flow` + "Add files via upload" is GitHub's signature for a **drag-and-drop upload through the browser UI**, not `git push` from a real development history. Combined with the domain (`2024‑11‑26`) predating the repo (`2024‑11‑30`) by 4 days — consistent with "site already live, then someone dumped a copy of the code" — and his own (very self-promotional) profile README never mentioning Vimegle among his listed projects, this account was ruled out as a copier, not the creator.

**Conclusion:** neither the account that best *matches the name* ("Vimegle") nor the one that best matches the *college* (VIT-AP) was correct. Verification had to move from "who has the code" to "who controls the infrastructure."

---

## 6. Investigation — Binding the Operator

**Step 1 — DNS pivot.** Enumerating certificates for `vimegle.com` via `crt.sh` revealed subdomains beyond the main site and its TURN server:
```
assistant.vimegle.com
nptel.vimegle.com
turn.vimegle.com
```
`nptel.vimegle.com` doesn't belong to a chat app at all — it's an NPTEL (Indian online course platform) helper tool. Cross-referencing GitHub for repos matching that theme surfaced `theg1239/NPTELPrep`, `NPTELPrep-API`, and `nptel-agent`.

**Step 2 — Confirm control, not coincidence.**
```
curl -sIL https://nptel.vimegle.com   → redirects to nptelprep.in
```
`nptelprep.in` is the exact `homepage` field declared in `theg1239/NPTELPrep`'s repo metadata. Whoever owns `theg1239`'s projects also controls DNS records under `vimegle.com` — that requires access to the domain's DNS panel, which only the site's real operator would have. This is the load-bearing piece of evidence: infrastructure control, verified independently, not a name-similarity guess.

**Step 3 — Bind the GitHub handle to a real identity.**
`theg1239`'s GitHub profile itself is deliberately empty (`bio: "uh"`, no linked socials via the `/users/theg1239/social_accounts` API). The bridge came from the college side instead: the ACM‑VIT club website lists its board members with photos and social links, and one card — **Ishaan Samdani, Technical Director** — links exactly:
```
https://github.com/theg1239
https://linkedin.com/in/ishaaans
```
This single card is what turns "an anonymous GitHub account operating Vimegle's infra" into a named person with a LinkedIn handle, sourced from a page the club itself publishes, not from guesswork.

**Step 4 — Independent cross-check.** To avoid repeating the earlier mistake (treating shared-organization membership as identity), git commit author metadata across `theg1239`'s own repositories was pulled directly:
```
theg1239/VTOP-activity     → author name contains "Ishaan"
theg1239/gravitas-fetcher  → author name contains "Ishaan"
theg1239/ExamCooker        → author names include "theg1239" and "Technical Director"
```
The first name and the club title both appear in commit metadata **he set himself**, independent of the ACM-VIT page. Two unrelated sources converging on the same name is what separates this identification from the three failed guesses earlier in the investigation.

**Step 5 — School and Instagram.** With the LinkedIn handle `ishaaans` confirmed as his own (self-declared, listed on the club's board page), the two remaining flag fields came from that profile:
- **Education section** → pre-university school: *Ryan International School*
- **Instagram** → `ishaaans`, the same vanity handle he uses on LinkedIn — a self-chosen identifier rather than a guessed permutation of his name.

---

## 7. Root Cause / Why This Chain Works

This isn't a technical vulnerability — it's a chain of voluntarily-published information that most people don't realize connects:

1. A hobby project (`Vimegle`) leaks its operator through **infrastructure** (DNS/subdomains) even when the code repo and social profiles are scrubbed.
2. Git tooling embeds **author identity by default** (`user.name`/`user.email` in commit metadata) — deleting a bio doesn't erase what's baked into every commit already pushed.
3. Organizations (clubs, ACM chapters, dev communities) publish **member directories** that casually bind a pseudonymous handle (GitHub) to a real name and a second profile (LinkedIn) in one place.
4. People reuse a memorable **vanity slug** (`ishaaans`) across platforms (LinkedIn URL *and* Instagram handle), which is a much stronger signal than any name-based permutation guess.

The failure mode to avoid, demonstrated twice in this solve (Rudra, Nikhil): **shared affiliation is not identification.** "Same university," "same GitHub org," or "repo with a similar name" are leads to verify, not conclusions. The binding evidence here was always something the target published about *himself* (DNS control, commit authorship, his own club bio card) — never an inference from a coincidence.

---

## 8. Flag

```
zdk{ryan_international_school-ishaaans}
```

---

## 9. OSINT Chain

```
"his own omegle" + "from our college" (VIT)
        |
        v
Vimegle (vimegle.com) — creator's own post: "made this for vitv"
        |
        v
crt.sh subdomain enum → nptel.vimegle.com
        |
        v
nptel.vimegle.com redirects to nptelprep.in
        |
        v
matches homepage of theg1239/NPTELPrep  →  theg1239 controls vimegle.com DNS
        |
        v
ACM-VIT board page: "Ishaan Samdani, Technical Director"
        → github.com/theg1239 + linkedin.com/in/ishaaans (both listed on one card)
        |
        v
Cross-check: git commit author metadata in theg1239's own repos
        → "Ishaan" / "Technical Director" appear independently
        |
        v
LinkedIn (ishaaans) → Education: Ryan International School
                     → vanity slug reused as Instagram handle: ishaaans
        |
        v
zdk{ryan_international_school-ishaaans}
```

---

## 10. Key Takeaways

- **Don't trust the repo with the matching name** — `nikhilvitc/Vimegle` looked like the answer but was a single-commit browser upload of someone else's code. Commit provenance (`committer: web-flow`, "Add files via upload") is a reliable tell for a copy, not a creation.
- **Pivot through infrastructure, not just search results.** DNS/subdomain enumeration (`crt.sh`) tied an anonymous GitHub handle to a domain that a scrubbed profile couldn't have revealed on its own.
- **Git commit metadata survives profile scrubbing.** A bio can say "uh"; the `user.name` baked into every historical commit usually can't be un-published.
- **Org/club member pages are a common, publisher-endorsed bridge** between a pseudonymous dev handle and a real name + second social profile.
- **Vanity URL reuse beats name permutation guessing every time.** `ishaaans` on LinkedIn was also the Instagram handle — a fact, not a guess from `firstname.lastname` templates.
- **Read the flag format literally.** `school_name`, not `college_name`, was the tell that the target school predates VIT — chasing VIT internal school-of-study names (e.g. "SCOPE") was a wrong turn.

---

## 11. Tooling Notes (for reproduction)

Environment used had `WebSearch` unavailable and most `WebFetch`-style search engine queries blocked; everything below was done with plain `curl`:

```bash
# Repo/user lookup
curl -s https://api.github.com/users/<user>
curl -s https://api.github.com/users/<user>/social_accounts
curl -s https://api.github.com/repos/<owner>/<repo>
curl -s https://api.github.com/repos/<owner>/<repo>/contributors
curl -s "https://api.github.com/search/repositories?q=vimegle"

# Subdomain enumeration
curl -s "https://crt.sh/?q=%25.vimegle.com&output=json"

# Confirm a subdomain's real destination
curl -sIL https://nptel.vimegle.com

# Domain registration timeline
curl -s "https://rdap.verisign.com/com/v1/domain/vimegle.com"

# Git commit author metadata (via GitHub API, per-repo commits endpoint)
curl -s https://api.github.com/repos/<owner>/<repo>/commits | grep -A3 '"author"'
```
