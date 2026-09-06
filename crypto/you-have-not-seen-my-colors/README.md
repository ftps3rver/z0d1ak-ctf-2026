# z0d1ak CTF 2026 — You Have Not Seen My Colors

**Solved by:** _\<isi handle CTF kamu\>_
**Category:** Cryptography | **Points:** 415 | **Solves:** 5 | **Author:** TitanCode

---

## 1. Executive Summary

This challenge hands out a single 100×100 PNG that looks like pure RGB noise, plus a live endpoint that accepts a lowercase, underscore-joined phrase. The noise is a decoy for two of the three color channels: only the **Blue channel** carries a signal, and that signal isn't a bitmap — it's **166 marked pixels** forming glyphs from **Elian Script**, a real (if obscure) constructed writing system that is a variant of the pigpen cipher, invented by artist C.C. Elian. The challenge title and the flavor text ("Elian gave you this challenge") are the cipher ID, not just flavor. Decoding the glyphs required hand-deriving Elian's grid/tick-mark rules from first principles (no canonical reference table was findable online); that decode yields four words, but only one pair of them — the actual answer phrase — is what the live verifier wants, with the rest turning out to be red herrings baked into the flag itself.

**Flag:** `zdk{mAST3r_OF_C0L0rS_aNd_c7F}`

---

## 2. Challenge Description

> Elian gave you this challenge. Find meaning in the noise, then prove what you decoded to the private endpoint.
>
> The answer is lowercase with words joined by underscores.

Files: `image.png` (100×100, 8-bit RGB). Instance: a small web server at `/` (download link + a `POST /solve` form with a single `answer` field).

Two words do a lot of work here:
- **"Elian"** — capitalized, mid-sentence, attributed as a person who "gave you this challenge." That's unusual phrasing for flavor text and is the strongest hint in the whole prompt: it names the cipher family (Elian Script), not just a fictional NPC.
- **"noise"** — the image genuinely looks like uniform RGB static at a glance; the task is finding the signal *inside* noise that's mostly real per-channel randomness.

---

## 3. Initial Reconnaissance

```bash
file image.png          # PNG image data, 100 x 100, 8-bit/color RGB, non-interlaced
curl -s .../image.png -o server_image.png
md5sum server_image.png image.png   # identical — the image is static, not per-session
```

The served image and the local attachment hash-match, so the target never regenerates the picture; whatever's encoded is fixed and can be worked on entirely offline. `GET /` also revealed the exact solve contract:

```html
<form method=post action=/solve><input name=answer autocomplete=off><button>Submit</button></form>
```

`POST /solve` with `answer=<phrase>` → `403 incorrect` or `200 {"flag": "..."}`.

---

## 4. Attack Surface / Important Observations

Per-channel statistics on the raw pixel array immediately separated signal from noise:

| Channel | min | max | unique values | anomaly |
|---|---|---|---|---|
| R | 1 | 255 | 255 | none — uniform |
| G | 1 | 255 | 255 | none — uniform |
| **B** | **0** | 255 | 256 | **value `0` occurs 166× vs. an expected ~39× for uniform noise** |

That's a z-score of **+20.3** on a single value in an otherwise-flat distribution — far too strong to be chance. Everywhere else, `B` behaves like independent uniform noise (mean ≈ 128, all 256 values roughly equally likely). The mask `B == 0` isolates exactly 166 pixels, and plotting them shows deliberate line-art: short horizontal/vertical strokes and a few isolated dots, clustered into small multi-stroke groups rather than scattered — clearly synthetic marks, not noise collision.

**Hypothesis:** the Blue channel is a covert bi-level ink layer; R and G are pure noise/decoy.

---

## 5. Failed Attempts

**Attempt 1 — PNG-container steganography.** Before touching pixel statistics, the file's chunk structure, filter-byte sequence per scanline, and IDAT/zlib framing were all inspected for a secondary payload (custom filter-type patterns, LSB-in-filter-byte tricks, etc.). All chunks had valid CRCs, the deflate stream decompressed cleanly to exactly `100×(1+300)` bytes as expected, and the per-row PNG filter types (`{0,1,2,4}`) showed no structure correlated with any readable message — a dead end. This ruled out "container-level" stego and pointed back at the pixel *values* themselves.

**Attempt 2 — Treating the marks as a broken/handwritten alphabet.** The first read of the extracted 166-pixel mask looked like fragments of Latin letters with strokes missing (e.g., a shape that could be read as a broken "L" or "F"). Naively OCR'ing/eyeballing the raw connected components without a governing grammar produced garbage. This attempt was abandoned once the title/flavor text was taken literally: the shapes are not damaged Latin letters, they're **complete pigpen-style glyphs** — the "missing strokes" are the actual encoding (a pigpen letter is drawn as only the interior grid-cell walls it touches, not a full letterform).

**Attempt 3 — Assuming a canonical, citable Elian Script mapping table exists online.** Wikipedia's "Elian Script" article and the artist's own site (`ccelian.com`) describe the *concept* (a pigpen/tic-tac-toe grid variant with tick-mark layers) but do not publish a definitive, unambiguous letter-to-glyph table usable for decoding blind. Relying on search results alone stalled here; the mapping had to be **reverse-engineered from the data itself** (see below), using the general pigpen structure as a scaffold rather than a plug-in answer key.

---

## 6. Investigation — Decoding the Glyphs

**Step 1 — Isolate and segment the ink layer.**
```python
mask = (img[:, :, 2] == 0)        # Blue channel, exact zero
```
Connected-component labeling on `mask` (8-connectivity) split the 166 pixels into **18 components**: 14 multi-pixel glyphs plus 4 single-pixel dots, arranged in four horizontal bands (rows ≈1–4, 11–18, 24–31, 36–39) — i.e., **four words**, matching the "lowercase, underscore-joined" answer format up front.

**Step 2 — Recover the pigpen grid rule from the strokes themselves.**
Each glyph is a small set of line segments corresponding to the **interior walls of a 3×3 grid cell** — a classic pigpen construction where a letter is drawn as only the cell walls adjacent to it (the outer 3×3 grid itself is never drawn, only each letter's local walls). From the pixel geometry:
- `R` (right wall) present ⟺ the cell's column < 2
- `L` (left wall) present ⟺ column > 0
- `T` (top wall) present ⟺ row > 0
- `B` (bottom wall) present ⟺ row < 2

This wall-set uniquely identifies one of the 9 cells in a 3×3 grid for every glyph observed.

**Step 3 — Recover letter ordering and the tick-mark layer by brute force.**
Classic pigpen assigns letters A–I to grid cells in reading order, then uses dots (or in Elian's variant, extended "tick" strokes) to shift into a second and third alphabet band (J–R, S–Z), the same way Freemason's cipher uses 1–2 dots per symbol. What's *not* standardized is (a) which of the 8 dihedral symmetries of the grid the letters follow, and (b) whether tick-count 0/1/2 maps to bands in ascending or descending order. Both were unknown and not documented anywhere citable, so they were **brute-forced**: all 8 grid symmetries × 2 reading orders (row-major/column-major) × several tick→band mappings were tried against the 14 decoded glyphs, scored by "does this produce English words." Out of 96 candidate mappings, **exactly one** produced clean English:

- Column ordering: **left→right**, and **within each column, bottom→top** (so `a` = bottom-left cell).
- Tick count = band: **0 ticks → a–i, 1 tick → j–r, 2 ticks → s–z.**

Applying that single consistent rule to all four bands decoded to:

```
zdk  /  master  /  of  /  ctf
```

Three of those four groups (`master`, `of`, `ctf`) being clean English words under one single, symmetric mapping is what confirmed the grid orientation and tick semantics were correct — a wrong mapping produces garbage across *all* four groups simultaneously, not just one.

**Step 4 — Reconcile the decode with the live server.**
The obvious full guess `zdk_master_of_ctf` was rejected (`403 incorrect`). Systematically trying subsets of the decoded words revealed the actual expected phrase was just the middle two words:

```bash
curl -X POST -d "answer=master_of_ctf" https://<instance>/solve
# {"flag":"zdk{mAST3r_OF_C0L0rS_aNd_c7F}"}
```

`zdk` (the CTF's own flag prefix) and `ctf` were both **decoy tokens baked into the image itself**, planted specifically to bait a solver who decodes correctly but doesn't test which subset the verifier actually wants.

---

## 7. Root Cause / Why This Chain Works

This is a straightforward crypto-stego challenge, but its difficulty is almost entirely in the "no canonical answer key" step, not the extraction:

1. **A statistical outlier in one channel of an otherwise-uniform-noise image is a strong, testable stego signal** — a single value occurring far more than its expected count is not something that happens by chance across 10,000 uniform samples.
2. **The challenge names the cipher family in-fiction** ("Elian gave you this challenge") rather than in a hint file — solvers who don't recognize "Elian" as C.C. Elian's constructed script (a real, documented but non-mainstream cipher) will spend most of their time trying OCR or ad hoc pattern matching on "broken letters" instead of applying pigpen grammar.
3. **Public documentation of Elian Script describes the concept but not a machine-usable lookup table**, forcing solvers to derive the letter ordering and tick semantics empirically from the ciphertext — effectively a known-plaintext-style brute force (96 candidate mappings, score by English-word yield) rather than a lookup.
4. **The decoded message intentionally contains more tokens than the verifier wants**, punishing solvers who submit their full raw decode instead of testing subsets — a light "read the fine print" gate on top of the stego/cipher work.

---

## 8. Flag

```
zdk{mAST3r_OF_C0L0rS_aNd_c7F}
```

---

## 9. Decode Chain

```
image.png (100x100, "pure noise" RGB)
        |
        v
Per-channel stats: R,G uniform / B has value 0 at z=+20.3 (166 vs ~39 expected)
        |
        v
mask = (B == 0)  ->  166 ink pixels, 18 connected components, 4 row-bands
        |
        v
Title/flavor text: "Elian gave you this challenge" -> Elian Script (pigpen variant, C.C. Elian)
        |
        v
Glyph = interior 3x3-grid cell walls (T/B/L/R) -> unique cell per glyph
        |
        v
Brute-force 96 candidates (8 grid symmetries x 2 reading orders x tick-band mappings)
        |
        v
Only "col left->right, bottom->top; 0/1/2 ticks = a-i/j-r/s-z" yields English
        |
        v
Decoded bands: zdk / master / of / ctf
        |
        v
POST /solve answer=master_of_ctf  (zdk, ctf were decoy tokens)
        |
        v
zdk{mAST3r_OF_C0L0rS_aNd_c7F}
```

---

## 10. Key Takeaways

- **A single-value statistical outlier in one color channel is enough to prove hidden data exists**, before you even know what the encoding is — always run per-channel histograms on "noise" images before assuming they're truly random.
- **Take in-fiction proper nouns literally.** "Elian gave you this challenge" is the cipher's name, not flavor — capitalized names dropped mid-sentence in a challenge description are worth a search on their own.
- **When no canonical answer key exists, brute-force the missing degrees of freedom and score by output plausibility** (English-word yield here) rather than searching harder for a source that may not exist in a convenient form.
- **A correct decode is not automatically the correct submission.** The live verifier can want a strict subset of what you decoded — test partial phrases before assuming the full string is wrong and re-deriving the cipher from scratch.
- **Container-level PNG stego and pixel-value stego are different failure surfaces** — check chunk/filter integrity first to rule it out, then move to per-channel pixel statistics.

---

## 11. Tooling Notes (for reproduction)

```python
import numpy as np
from PIL import Image
from scipy import ndimage

img = np.array(Image.open("image.png"))
mask = (img[:, :, 2] == 0)                       # Blue-channel ink layer

# per-channel outlier check
for c, name in enumerate("RGB"):
    vals, counts = np.unique(img[:, :, c], return_counts=True)
    exp = img.shape[0] * img.shape[1] / 256
    z = (counts - exp) / np.sqrt(exp)
    print(name, vals[np.argmax(z)], counts.max(), z.max())

# segment glyphs
lab, n = ndimage.label(mask, structure=np.ones((3, 3)))
objs = ndimage.find_objects(lab)

# glyph -> (row, col) in a 3x3 pigpen grid, from wall presence
def cell(has_T, has_B, has_L, has_R):
    col = 1 if (has_L and has_R) else (0 if has_R else 2)
    row = 1 if (has_T and has_B) else (0 if has_B else 2)
    return row, col

# letter index: columns left->right, each column bottom->top;
# tick count (0/1/2) selects band a-i / j-r / s-z
def decode(row, col, ticks):
    idx = col * 3 + (2 - row)
    return "abcdefghijklmnopqrstuvwxyz"[ticks * 9 + idx]
```

```bash
# solve endpoint
curl -s -X POST -d "answer=master_of_ctf" https://<instance>/solve
```
