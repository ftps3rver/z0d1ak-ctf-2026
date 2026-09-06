# z0d1ak CTF 2026 — Black Tide Survey

**Solved by:** ftps3rver
**Category:** Reverse Engineering | **Points:** 216 | **Solves:** 26 | **Author:** pokymono

---

## 1. Executive Summary

This challenge hands out a recovered autonomous underwater survey vehicle's raw sonar log (a proprietary `.bts` container), a reference calibration image, and a stripped Linux decoder binary that only *half* does its job — it converts the container to a raw grayscale image but gets the row order, channel placement, and channel orientation all wrong, on purpose. The `RECOVERY_NOTE.txt` flavor text isn't decoration: its two maintenance-label riddles ("Near water is not near ground." / "Port comes home; starboard goes away.") are the literal spec for the two geometric corrections the provided binary doesn't make. Getting the container format, the row-interleaving, the channel-compositing, and a wobble-correction all right in sequence reconstructs a clean side-scan sonar mosaic showing a vessel hull painted with **SABLE-7319**, plus a separate wrapped telemetry caption reading **Sable_54_T3l0** — the string the challenge actually wants, ambiguous-glyph-and-all.

**Answer:** `Sable_54_T3l0`

---

## 2. Challenge Description

> Survey unit BT-04 was recovered twelve nautical miles east of its assigned transect.
>
> Recover the final surveyed image and identify the marked vessel.

Files: `RECOVERY_NOTE.txt`, `SHA256SUMS`, `dock_calibration.bts` (300 pings), `final_transect.bts` (720 pings), `dock_reference.png` (640×640, 8-bit grayscale — the *correctly decoded* dock calibration run, given as ground truth), and `sonar_diag` (stripped x86-64 ELF, `usage: sonar_diag INPUT.bts OUTPUT.pgm`).

`RECOVERY_NOTE.txt` is the real hint sheet:

```
Vehicle recovered with the SSX head torn away and the navigation clock 3.8 s
ahead of the hull clock. Storage remained sealed. The last complete dock
calibration and final mission transect were copied without conversion.

The new workstation recognizes the container but refuses this head revision.
Field diagnostics still opens both recordings, although its file format and
sample ordering were never documented outside the missing workstation.

M. Kade's maintenance label is still inside the battery hatch:

    Near water is not near ground.
    Port comes home; starboard goes away.
```

Every sentence here maps to a concrete bug we have to fix ourselves:
- **"copied without conversion" / "recognizes the container but refuses this head revision"** → the `.bts` files are raw, untranscoded sonar logs; `sonar_diag` can *parse* them but won't render them correctly.
- **"sample ordering were never documented"** → the rows in the file are not stored in playback order; we have to recover the real order from the data itself.
- **"navigation clock 3.8 s ahead of the hull clock"** → a literal wrap-around bug in how the recording buffer's start/end line up.
- **The two maintenance-label lines** → two geometric corrections (channel placement, channel orientation) that the workstation used to apply automatically and that we now have to derive by hand.

---

## 3. Initial Reconnaissance

```bash
file dock_calibration.bts final_transect.bts dock_reference.png sonar_diag
# dock_calibration.bts:  data
# final_transect.bts:    data
# dock_reference.png:    PNG image data, 640 x 640, 8-bit grayscale
# sonar_diag:             ELF 64-bit LSB pie executable, x86-64, stripped, dynamically linked
```

Both `.bts` files share an identical 4-byte magic and a chunked layout when hex-dumped:

```
42 54 53 32 02 00 20 00 ...        # "BTS2", version 2, header size 0x20
...
4d 45 54 41 39 00 00 00 ...        # "META" chunk, length, crc32
unit=BT-04
head=SSX-27R
mission=DOCK-CAL            (or BLACK-TIDE for the mission file)
operator=M.KADE
```

Running `sonar_diag` against both files works without error and produces a `.pgm`:

```bash
./sonar_diag dock_calibration.bts dock.pgm     # wrote 300 survey rows
./sonar_diag final_transect.bts final.pgm      # wrote 720 survey rows
```

But viewed as images, both outputs look like a **double-exposed photograph** — two overlapping copies of the same scene, offset vertically — instead of a clean sonar waterfall. That's the "sample ordering... never documented" problem made visible: `sonar_diag` writes ping rows in raw file order, and file order isn't playback order.

---

## 4. Attack Surface / Important Observations

**The `.bts` container is a simple TLV chunk format**, verified byte-for-byte with a hand-rolled parser and CRC32 checks (`poly = 0xEDB88320`) on every chunk:

| Chunk | Contents |
|---|---|
| `META` | `key=value\n` text: unit, head revision, mission, operator |
| `CALB` | 64 bytes, identical fixed calibration table in both files |
| `PING` × N | 1176 bytes: 24-byte header + 2×576-byte sample blocks |
| `DONE` | terminator, zero length |

**Each `PING`'s 24-byte header** decodes to six fields (`u32,i32,i32,i32,u32,u32`):

```
[0] seq          — this ping's true sequence number
[1] t_ms         — elapsed time, always steps by 80 ms
[2] along-track position (mm), signed, monotonic across the run
[3] cross-track "sway" offset (mm), signed, oscillates — this is the vehicle's yaw wobble
[4] slowly drifting value — unused for the image
[5] constant 3
```

**Critically, `[0] seq` is not sorted in file order** (`idx == sorted(idx)` is `False` for every ping in both files) — this is the exact, deliberate cause of the double-exposure artifact.

**`sonar_diag`'s decode logic**, recovered by disassembling it in a Kali WSL environment (`objdump -d`, no symbols):
- Each 576-byte block holds 384 packed 12-bit-ish samples; an SSE loop (`psrlw $4` / `pand` / `packuswb`) shows the tool converts each 16-bit little-endian sample to an 8-bit pixel by keeping the high byte's low nibble shifted down — i.e. `pixel = sample >> 4`.
- A second loop, using paired `movzwl`/`mov` instructions walking two pointers toward each other, **reverses one of the two 576-byte blocks per ping in place** — meaning the tool already treats the two channels asymmetrically, but doesn't get their relative placement or orientation right on its own.
- The tool writes each ping as one 768-px-wide row (`2 × 384`), in raw file order, with no motion compensation.

**`dock_reference.png` is the "known-plaintext"** for this whole exercise: it shows two rows of 4 mirrored calibration targets (top and bottom), two mirrored right-angle calibration brackets, and — most importantly — an unmistakable **dark, no-return "water column" running down the vertical center** of the image, with real seafloor content flanking it on both sides.

---

## 5. Failed Attempts

**Attempt 1 — Trust `sonar_diag`'s raw output.** The tool runs cleanly and writes a plausible-looking `.pgm` with no errors, which initially looked like "the" decode. It isn't — the ghosted/doubled appearance is only obvious once you know what a real sonar waterfall should look like, which is exactly why `dock_reference.png` is provided as ground truth.

**Attempt 2 — Assume the 768-px row is already correctly laid out.** Before consulting `dock_reference.png` closely, the raw per-channel column statistics were checked for the "blank/near-range" band (mean ≈14–21 vs. ≈60–65 for real seafloor return) and it was found sitting at the **outer edges** of the 768-px row (columns ≈0 and ≈767), not the center. Compositing attempts that kept this edge placement never matched the reference's central dark band no matter how the two channels were flipped — a dead end that forced re-reading "Near water is not near ground" as a literal placement instruction rather than flavor text.

**Attempt 3 — Guess the channel flip by brute force on the mission data directly.** Trying all four combinations of (swap channels) × (mirror channel) against `final_transect.bts` without first nailing the transform down on `dock_calibration.bts` produced several superficially plausible-looking but subtly wrong mosaics (calibration lines present but not symmetric). Anchoring the transform against `dock_reference.png`'s exact, mirrored, symmetric geometry — instead of eyeballing the mission data — was what actually pinned it down unambiguously.

---

## 6. Investigation — Reconstructing the Survey Image

**Step 1 — De-interleave rows by true ping sequence.**
```python
seqs = [struct.unpack("<I", ping[:4])[0] for ping in pings]
order = np.argsort(seqs)
rows  = raw_rows[order]           # fixes the "double exposure" immediately
```
Applied to `dock_calibration.bts`, this alone turns the ghosted output into a clean, single-exposure image — confirming the file literally stores pings out of playback order and that the `seq` header field is the real index.

**Step 2 — Recenter the water column ("Near water is not near ground").**
Each 768-px row is really two independent 384-px channel scanlines. The blank near-range band was landing at the outer edges instead of the center, so the two channels were recomposited as
```
composite_row = channel_B  +  mirror(channel_A)
```
so each channel's near-range (blank) column now sits adjacent to the other's, forming the dark central strip visible in `dock_reference.png`.

**Step 3 — Fix orientation per channel ("Port comes home; starboard goes away").**
One channel's raw sample order already runs near→far in the direction that lands correctly after the Step 2 recompositing ("comes home" — no flip needed); the other channel's raw order runs the opposite way ("goes away" — needs the horizontal mirror). This is exactly the assignment that was validated against `dock_reference.png`: once applied, the reconstructed dock-calibration image reproduces the reference's mirrored targets, mirrored brackets, and centered dark band pixel-for-pixel.

**Step 4 — Apply the validated pipeline to `final_transect.bts`.**
Same seq-sort → recenter → orient-fix pipeline, now on 720 pings, produces a 768×720 mosaic. One channel shows a distinct vessel silhouette with painted hull lettering:
```
SABLE-7319
```
readable once a per-row along-track wobble (the vehicle's yaw, visible directly in header field `[3]`, the sway offset) is removed by tracking a stable edge (the vessel's own outline) per row and re-aligning via median-filtered boundary tracking / subpixel cross-correlation.

**Step 5 — Unwrap the burn-in caption ("navigation clock 3.8 s ahead of the hull clock").**
Independent of the hull paint, a handful of rows at the very start and very end of the recording carry a small fixed-font telemetry caption, but it appears split and unreadable at both the top (rows 0–1) and bottom (rows ~676–719) of the raw mosaic — a direct consequence of the recording buffer wrapping before the mission actually ended, exactly as described by the clock-offset detail in the note. Treating the ping rows as circular and re-ordering:
```python
unwrapped = np.vstack([rows[676:720], rows[0:676]])
```
stitches the caption into one continuous, readable line at the top of the image:
```
Sable_54_T3l0
```

**Step 6 — Disambiguate the font (is that a `1` or a lowercase `l`? a `9` or a `0`?).**
Both the hull paint and the caption use the same fixed bitmap font. Every glyph was extracted as a connected component, normalized to a common bounding box, and compared pixel-for-pixel (IoU) against every other glyph found in both strings. The ambiguous character in the caption is **bit-for-bit identical** to the lowercase `l` glyphs elsewhere in the same string, and clearly distinct from the digit `1`'s bitmap (which carries a top serif flag and a wider base) — settling `Sable_54_T3l0` (lowercase L) over the visually similar `Sable_54_T310`.

---

## 7. Root Cause / Why This Chain Works

This challenge is really three separate, independently-checkable reverse-engineering steps stacked on top of each other:

1. **A provided decoder that's deliberately incomplete.** `sonar_diag` proves you can parse the container (chunk types, CRCs, ping headers) but withholds the two things that turn a parse into a viewable image: correct row ordering and correct channel geometry. This forces engagement with the header fields and the raw byte layout instead of trusting a black-box tool.
2. **A known-plaintext reference image removes all guesswork from the geometric transform.** Without `dock_reference.png`, the channel-placement and orientation fixes would be a blind 2×2 (or worse) search against noisy mission data; with it, the transform is uniquely and cheaply verifiable before ever touching the real target file.
3. **The flavor text is literally the missing engineering spec**, written as two riddles instead of a datasheet: "near water ≠ near ground" is a channel-placement instruction, "port comes home, starboard goes away" is a channel-orientation instruction, and the clock-offset detail is a buffer-wraparound instruction. None of it is atmospheric filler.
4. **Two independent renderings of the same font (hull paint + caption) let a genuinely ambiguous character be resolved by direct pixel comparison** rather than by squinting at one blurry instance — a reproducible, falsifiable check instead of a guess.

---

## 8. Answer

```
Sable_54_T3l0
```

(the fourth character before the final `0` is a **lowercase L**, verified pixel-for-pixel against other `l` glyphs in the same caption — not the digit `1`)

---

## 9. Reconstruction Chain

```
dock_calibration.bts / final_transect.bts  (BTS2 container, undocumented sample order)
        |
        v
Hand-parse TLV chunks (META / CALB / PING x N / DONE), verify CRC32 per chunk
        |
        v
sonar_diag INPUT.bts OUTPUT.pgm  -> raw 768-wide PGM, but rows "double exposed"
        |
        v
Disassemble sonar_diag (objdump, WSL/Kali) -> confirms 12-bit->8-bit unpack,
        one 576B block reversed per ping, rows written in raw file order
        |
        v
Sort ping rows by header field [0] seq  -> fixes double exposure
        |
        v
dock_reference.png (known-plaintext): dark water column must sit at CENTER,
        not at the outer edges  ("Near water is not near ground")
        |
        v
Recomposite each 768px row as channel_B | mirror(channel_A)
        |
        v
Assign per-channel flip using "Port comes home; starboard goes away"
        -> validated bit-for-bit against dock_reference.png
        |
        v
Apply identical pipeline to final_transect.bts (720 pings)
        |
        v
De-wobble via vessel-edge tracking (yaw from header field [3]) -> hull text: SABLE-7319
        |
        v
Unwrap rows[676:720]+rows[0:676] ("nav clock 3.8s ahead" buffer wraparound)
        -> caption: Sable_54_T3l0
        |
        v
Pixel-exact glyph IoU cross-check (hull font vs caption font) -> confirms lowercase "l", not "1"
        |
        v
Sable_54_T3l0
```

---

## 10. Key Takeaways

- **A provided tool that "runs without error" is not the same as a tool that's correct.** `sonar_diag` parses the format perfectly and still produces a wrong image — always sanity-check binary output against a reference before trusting it.
- **Flavor text in a recovery/maintenance-log framing device is often a literal spec, not atmosphere.** Both riddles in `RECOVERY_NOTE.txt` map one-to-one onto a specific geometric transform; the clock-offset detail maps onto a specific buffer-wraparound bug.
- **A "known-plaintext" reference image turns a blind geometric search into a cheap, verifiable equation.** Always validate a reconstruction pipeline on the calibration/reference data before trusting it on the real target.
- **Ping/frame sequence fields inside a binary header should never be assumed to match file order** — sort by the field, don't trust position-in-file, especially when a note explicitly calls out undocumented "sample ordering."
- **When two independent renderings of the same font exist, use pixel-level comparison (IoU on normalized glyph bitmaps) to resolve visually ambiguous characters** (`1` vs `l`, `0` vs `9`) instead of guessing from a single noisy instance.

---

## 11. Tooling Notes (for reproduction)

```python
import struct, numpy as np

def parse_bts(path):
    d = open(path, "rb").read()
    off = 32                       # fixed 32-byte header
    pings = []
    while off + 12 <= len(d):
        typ = d[off:off+4]
        ln, crc = struct.unpack("<II", d[off+4:off+12])
        if typ == b"PING":
            pings.append(d[off+12:off+12+ln])
        off += 12 + ln
    return pings

def ping_header(p):
    return struct.unpack("<Iiii II", p[:24])   # seq, t_ms, pos, sway, drift, const(3)

pings = parse_bts("final_transect.bts")
order = np.argsort([ping_header(p)[0] for p in pings])   # true playback order
```

```bash
# WSL/Kali toolchain used for static analysis of sonar_diag
wsl -d kali-linux
objdump -d --no-show-raw-insn sonar_diag > sonar_diag.asm
readelf -h sonar_diag
strings -n 5 sonar_diag
```

```python
# channel recomposite: water column to center, per-channel orientation fix
row_768 = decoded_row               # sonar_diag's raw per-ping output
chan_a, chan_b = row_768[:384], row_768[384:]
composite = np.concatenate([chan_b, chan_a[::-1]])   # validated against dock_reference.png

# unwrap the unwrap-around caption
unwrapped = np.vstack([rows[676:720], rows[0:676]])
```
