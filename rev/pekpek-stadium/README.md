# z0d1ak CTF 2026 — pekpek-stadium-64

**Solved by:** ftps3rver
**Category:** Reverse Engineering | **Points:** 167 | **Solves:** 46 | **Author:** n1cogum

---

## 1. Executive Summary

`pekpek.z64` / `pekpek.v64` is a real, bootable Nintendo 64 ROM (built with the open-source **libdragon** SDK) themed as a fake multicart menu, "PEKPEK STADIUM 64 — 9999 IN 1," listing a shelf of parody game titles (`MARIO 128`, `ZELDA MASK 2`, `KART 64 TURBO`, `SMASH 64 PLUS`, …). The description — *"dumped this. sticker still says PEKPEK STADIUM 64"* — signals a real cartridge dump to pick apart, not a puzzle wrapped in a fictional format.

A naive `strings` pass over the ROM immediately turns up something that *looks* like the flag sitting in plaintext: `zdk{w0mb0_c7h47_41n7_f41c0}`. This is a trap. The real flag lives inside a **Nintendo `MIO0`-compressed blob** hidden near the end of the ROM, which decompresses to a second, embedded Game Boy Advance ROM (title `PEKKIOSK`) — a nod to the real *Pokémon Stadium*'s Transfer Pak "GB Tower" feature that let N64 hardware run Game Boy cartridges. The compressed stream stores the flag as a mix of literal bytes and an **LZ77 back-reference** for a repeated substring (`w0mb0_` → `c0mb0_` share the pattern `0mb0_`). Plain byte-scanning of the raw ROM can only see the literal bytes, silently drops the back-referenced middle chunk, and reconstructs a shorter string that still happens to parse as a plausible, well-formed flag. Writing a small MIO0 decompressor and re-extracting the string from the *decompressed* data recovers the genuine flag with the missing segment restored.

**Answer:** `zdk{w0mb0_c0mb0_7h47_41n7_f41c0}`

---

## 2. Challenge Description

> dumped this. sticker still says PEKPEK STADIUM 64.

Files: `pekpek.z64` and `pekpek.v64` (440,842 bytes each — the two standard N64 ROM dump byte-orderings of the same cartridge image). No remote instance; a fully offline reversing/forensics-flavored challenge built around one real, playable ROM file.

---

## 3. Initial Reconnaissance

```
xxd pekpek.z64 | head -4
00000000: 8037 1240 0000 0000 8000 0400 0000 0000  .7.@............
00000010: 78c7 9bc1 820d b746 0000 0000 0000 0000  x......F........
00000020: 5045 4b50 454b 3634 0000 0000 0000 0000  PEKPEK64........
00000030: 0000 0000 0000 0000 0000 004e 0000 0000  ...........N....

xxd pekpek.v64 | head -4
00000000: 3780 4012 0000 0000 0080 0004 0000 0000  7.@.............
00000010: c778 c19b 0d82 46b7 0000 0000 0000 0000  .x....F.........
00000020: 4550 504b 4b45 3436 0000 0000 0000 0000  EPPKKE46........
00000030: 0000 0000 0000 0000 0000 4e00 0000 0000  ..........N.....
```

`pekpek.z64` opens with the native N64 big-endian magic `80 37 12 40` and a readable cartridge title `PEKPEK64`; `pekpek.v64` is the same ROM with every 16-bit halfword byte-swapped (`37 80 40 12`, title garbled to `EPPKKE46`) — the two files are byte-identical after undoing that swap, so only `pekpek.z64` was analyzed further.

`strings -n 5 pekpek.z64` (1629 hits) confirmed this is a genuine **libdragon**-built homebrew ROM: the IPL3 bootcode string `Libdragon IPL3  Coded by Rasky` sits at `0x2f0`, and the back half of the ROM is full of libdragon build noise — source paths (`libdragon/src/audio.c`, `libdragon/src/graphics.c`, `libdragon/src/inspector.c`), an embedded crash-backtrace module (`inspector_page_exception`, `finalize_exception_frame`), and toolchain paths (`/opt/n64/mips64-elf/include/rdpq_rect.h`). This is a real compiled ROM, not a hand-crafted binary blob — the flag has to be *in* it somewhere, not derived from some external computation.

The menu/UI strings paint the theme immediately:

```
PRESS START
PEKPEK STADIUM 64
9999 IN 1
GB TOWER
PAK OK?
INSERT GB CART
agb.bin
MARIO 128 / ZELDA MASK 2 / GOLDEN PAK 007 / BANJO TOOIE DX / KART 64 TURBO / SMASH 64 PLUS
```

`GB TOWER` + `agb.bin` + `TRANSFER PAK CHANNEL 0` is a direct reference to the real *Pokémon Stadium*'s "GB Tower," which used the N64's Transfer Pak accessory to run an actual Game Boy cartridge image from inside the N64 game — a strong hint that a real embedded **Game Boy/GBA ROM image** is hiding somewhere in this file.

Available tooling (Windows host, WSL/Ubuntu for the actual work): `objdump`, `readelf`, `strings`, `xxd`, Python 3. No `capstone` (installing it failed — no outbound network from the WSL sandbox), so no MIPS disassembler was used; the solve never needed to read code, only to map and decompress data.

---

## 4. Attack Surface / Important Observations

A coarse per-4KB entropy sweep (byte-value histogram: zero count, printable count, unique-byte count) over the ROM mapped out its rough layout:

| Range | Content |
|---|---|
| `0x00000–0x30000` | MIPS machine code (IPL3 + libdragon runtime) |
| `0x30000–0x48000` | rodata / libdragon debug symbol & source-path strings |
| `0x48000–0x6B4C0` | high-entropy filler, terminated by a run of `0xFF` padding bytes |
| `0x6B4C0–end (0x6BA0A)` | small, dense, non-uniform region — worth a closer look |

A **fine-grained 64-byte-window** re-scan of that last region is what actually mattered — it showed the byte statistics change character sharply at `0x6B500`, and a direct `zdk{` regex search over the raw file landed at `0x6B98B`, deep inside that same tail region:

```
0006b980: 0054 4f59 5320 5220 5553 007a 646b 7b77   .TOYS R US.zdk{w
0006b990: 306d 6230 5f63 3768 3437 5f34 316e 375f   0mb0_c7h47_41n7_
0006b9a0: 6634 3163 307d 00                          f41c0}.
```

This reads perfectly cleanly as `zdk{w0mb0_c7h47_41n7_f41c0}` — a complete, well-formed-looking flag sitting in plain ASCII in the ROM. **This is the trap** (see §5/§7): it is real ROM data, but it is a *sub-slice* of a larger structure the naive scan doesn't understand.

Scanning specifically for Nintendo's `MIO0` compression magic (`re.finditer(b"MIO0", data)`) found exactly one hit, at `0x6B510` — just 0x47B bytes *before* the "flag" string above, and within the same high-entropy tail region:

```
magic="MIO0"  usize=0xf2c (3884)  compOffset=0x7c  literalOffset=0x2bc
```

`MIO0` is the classic Nintendo 64 LZ77-style compression format (used throughout Super Mario 64, Ocarina of Time, etc.): a 16-byte header, then a **control bitstream** (1 bit per output token, MSB-first), a **back-reference stream** (2-byte big-endian tokens: top 4 bits = length−3, low 12 bits = distance−1), and a **literal byte pool** — the latter two pointed to by the `compOffset`/`literalOffset` header fields, both relative to the start of the `MIO0` block.

Critically: the raw "flag" text found by `strings` at `0x6B98B` sits at `0x6B98B − (0x6B510+0x2BC) = 0x1B4` bytes into that block's **literal byte pool** — i.e. it genuinely is a chunk of the compressed structure's raw literal data, just not the *whole* decompressed output.

---

## 5. Failed Attempts

**Attempt 1 — Trust the `strings` hit as the flag.** `zdk{w0mb0_c7h47_41n7_f41c0}` is syntactically perfect: correct prefix, correct brace, plausible leet-speak content, no visible corruption. Submitting this fails. **Root cause identified in §7** — it is five characters short (`_c0mb0` → `_c7h47`, the `0mb0` chunk of the repeated `_c0mb0_` is simply missing), because that repeated substring was LZ77-deduplicated by the compressor into a back-reference that a plain byte scan cannot see.

**Attempt 2 — Blind decompression guesses.** Before recognizing the `MIO0` magic for what it was, `zlib.decompress`, raw-deflate, `gzip`, `lzma`, and `bz2` were all tried against the high-entropy tail blob at a handful of candidate offsets, on the general principle of "high entropy near an ASCII flag hint often means a bespoke or standard compressor." All failed immediately (`Error -3 while decompressing`/`Compressed file ended before...`) — this is a console-native LZ77 variant, not a general-purpose stream format, so no off-the-shelf decompressor was ever going to work. Abandoned in favor of format-specific magic-byte hunting.

**Attempt 3 — MIPS pointer/relocation-delta analysis to find a load-time string table.** Scanned every `lui`/`addiu`-style register-load pair in the disassembled instruction stream, clustering the resulting 32-bit "address" operands by their high 16 bits, hoping to spot a `.data` pointer table referencing the flag location by virtual address (the way the earlier `rival-battle` challenge's data tables worked). This surfaced plausible-looking load-address deltas (`~0x7ffff400`) and a genuine pointer table at `0x80029xxx`/`0x8002axxx` pointing into the ROM's `.rodata` UI-string region — interesting for understanding the menu code, but it never pointed anywhere near the `MIO0` blob or the flag. **Abandoned** as a dead end once the direct `MIO0`-magic byte search succeeded in a fraction of the time.

---

## 6. Investigation — Building the Exploit

**Step 1 — Coarse entropy map, then refine.** A 4KB-granularity histogram scan (zero-count / printable-count / unique-byte-count per block) across the whole ROM located the boundary between "readable libdragon code/strings" (`<0x48000`) and "opaque tail data" (`≥0x48000`), bounded by a stretch of `0xFF` padding around `0x46000–0x48000`. Re-running the same histogram at 64-byte granularity over just the tail pinpointed exactly where the byte statistics changed shape again, near `0x6B4C0` — small enough to eyeball directly with `xxd`.

**Step 2 — Recognize the format instead of guessing at it.** A direct regex search for `b"MIO0"` (rather than another blind decompression attempt) is what actually cracked this — Nintendo's own N64 SDK compression format announces itself with an unambiguous 4-byte magic, and finding it took one line of Python once the *idea* "this is probably first-party N64 tooling, not a generic zip/gzip" was in mind.

**Step 3 — Implement the MIO0 format from its known layout.** MIO0 headers give three big-endian `u32` fields after the magic: uncompressed size, and the offsets (from the start of the block) of the back-reference stream and the literal-byte pool. The control bitstream itself starts immediately after the 16-byte header:

```python
def mio0(buf, off):
    magic, usize, coff, uoff = struct.unpack(">4sIII", buf[off:off+16])
    out = bytearray()
    lay = off + 16      # control bitstream: 1 bit per output token, MSB first
    cp  = off + coff    # back-reference stream: 2-byte BE tokens
    up  = off + uoff    # literal byte pool
    bit = 0
    cur = 0
    while len(out) < usize:
        if bit == 0:
            cur = buf[lay]; lay += 1; bit = 8
        bit -= 1
        if cur & (1 << bit):              # 1 -> copy one literal byte
            out.append(buf[up]); up += 1
        else:                              # 0 -> LZ77 back-reference
            v = struct.unpack(">H", buf[cp:cp+2])[0]; cp += 2
            length = (v >> 12) + 3
            dist   = (v & 0xFFF) + 1
            for _ in range(length):
                out.append(out[-dist])
    return bytes(out)
```

Run against the block at `0x6B510`, this decodes exactly `0xF2C` (3884) bytes — matching the header's declared uncompressed size precisely, a strong self-check that the format was reconstructed correctly.

**Step 4 — Inspect the decompressed payload.** The output is a **complete, well-formed Game Boy Advance ROM header**: a 12-byte title field `PEKPEKKIOSK`, a 4-byte game code `KIOS`, a 2-byte maker code `00`, and the mandatory fixed checksum byte `0x96` at offset `0xB2` — every field lines up exactly where the real GBA header spec puts them. Immediately after the header sits genuine ARM startup code (`LDR r0,[pc,#imm]` / `LDR r1,[pc,#imm]` / `STRH r1,[r0]` patterns — the classic idiom for writing a 16-bit value into a memory-mapped hardware register at boot), confirming this is a real embedded "GB Tower" cartridge image, exactly as the `agb.bin` / `TRANSFER PAK CHANNEL 0` strings from §4 promised.

**Step 5 — Re-extract the flag from the decompressed data, not the raw ROM.**

```
strings -t x mio_6b510.bin | grep -i pak
   0a0  PEKPEKKIOSK
   0ac  KIOS00
   2c0  TRANSFER PAK KIOSK
   2d3  PAK CHANNEL 0
   2e1  TOYS R US
   2eb  zdk{w0mb0_c0mb0_7h47_41n7_f41c0}
```

Compared byte-for-byte with the raw-ROM `strings` hit from §4, the decompressed version restores exactly the five missing characters (`0mb0_`) in the middle of the flag — the LZ77 back-reference that a plain scan couldn't see.

---

## 7. Root Cause / Why This Chain Works

1. **LZ77-family compression deduplicates repeated substrings into back-references, which are invisible to naive text/byte scanning.** The flag's plaintext contains the pattern `w0mb0_c0mb0_` — two adjacent occurrences of `0mb0_`. A general-purpose LZ77 compressor (which `MIO0` is) will encode the second occurrence as "copy N bytes from D bytes back" instead of emitting it as literal bytes, purely because that's smaller. `strings`/`grep`/raw hex-dumping only ever see the **literal byte pool**, so they silently reconstruct a shorter string with the back-referenced chunk missing — and because the missing chunk happens to be an interior repeat, the result is *still syntactically valid*, not obviously truncated or corrupted. That's what makes this a genuinely deceptive trap rather than a simple "the flag is scrambled" puzzle.
2. **A compressed sub-blob is not "just more ROM bytes."** The instant a region of a binary shows a jump in entropy and stops matching known code/data-table shapes, that's a strong signal it's a distinct compressed or encrypted payload with its own internal addressing scheme (here, byte offsets *relative to the compression block's own start*, not the ROM's start) — indexing into it as if it were flat, contiguous file data (as `strings` implicitly does) will get parts of the structure right by coincidence and other parts wrong.
3. **Recognizing a first-party format beats generic decompression guessing.** Once the `MIO0` magic was searched for directly instead of throwing `zlib`/`gzip`/`lzma`/`bz2` at the blob, the correct format was identified in seconds; console reverse-engineering rewards knowing (or looking up) platform-specific container/compression formats rather than treating every high-entropy blob as "probably a standard archive."
4. **The theming was not just flavor — it was a genuine pointer to where to look.** `GB TOWER`, `agb.bin`, and `TRANSFER PAK CHANNEL 0` are not incidental jokes; they describe *exactly* the real N64 hardware feature (Transfer Pak passthrough of a physical Game Boy cartridge) that the challenge reimplements by embedding a real, validly-headered GBA ROM inside the N64 ROM via `MIO0` compression — reading the UI strings correctly predicted both what to expect (an embedded second ROM) and roughly why it wouldn't be sitting in plaintext (real cartridge/asset data on Nintendo platforms of this era is compressed by convention).

---

## 8. Answer

```
zdk{w0mb0_c0mb0_7h47_41n7_f41c0}
```

---

## 9. Reconstruction Chain

```
pekpek.z64 / pekpek.v64 (identical ROM, native vs. byte-swapped dump)
        |
        v
xxd headers -> confirm libdragon-built N64 ROM, title PEKPEK64
strings -> "GB TOWER" / "agb.bin" / "TRANSFER PAK CHANNEL 0" (Pokemon Stadium homage)
        -> hints at an embedded second (GB/GBA) ROM image
        |
        v
Coarse 4KB entropy sweep -> code/rodata (<0x48000) vs. opaque tail (>=0x48000)
Fine 64-byte entropy sweep -> pinpoint tail sub-region around 0x6B4C0-0x6BA0A
        |
        v
Direct strings/regex hit: "zdk{w0mb0_c7h47_41n7_f41c0}" at 0x6B98B
        -> looks complete and valid -> TRAP (5 chars short, see below)
        |
        v
Regex search for b"MIO0" magic -> exactly one hit, at 0x6B510
        (Nintendo N64 first-party LZ77 compression format)
        |
        v
Blind zlib/gzip/lzma/bz2 attempts on the blob -> all fail (wrong format family)
        |
        v
Implement MIO0 from its known header/bitstream/back-reference layout
        -> decompress 0xF2C (3884) bytes, matches header's declared size exactly
        |
        v
Decompressed payload = valid GBA ROM (title PEKPEKKIOSK, header checksum 0x96,
        real ARM boot code) -> confirms the "GB Tower" cartridge-in-cartridge theme
        |
        v
strings on decompressed data at offset 0x2EB:
        zdk{w0mb0_c0mb0_7h47_41n7_f41c0}
        (the "0mb0_" chunk missing from the raw-ROM scan is restored --
         it was stored as an LZ77 back-reference, not literal bytes)
        |
        v
zdk{w0mb0_c0mb0_7h47_41n7_f41c0}
```

---

## 10. Key Takeaways

- **A perfectly well-formed-looking flag string is not proof it's the complete flag.** LZ77-style dictionary compression can cause a naive byte/text scan to silently drop an interior repeated substring while still producing something that parses as valid — always cross-check a "found in plaintext" hit against the surrounding structure (is this region actually flat, uncompressed data?) before trusting it.
- **A sharp entropy jump in a binary is a strong signal of a distinct sub-container**, not just "more of the same file." Once code/rodata gives way to high-entropy opaque bytes, stop treating offsets as flat file positions — the sub-blob almost certainly has its own internal, relative addressing scheme.
- **Identify the specific format before reaching for generic decompressors.** Trying `zlib`/`gzip`/`lzma`/`bz2` against an unknown blob is a reasonable first probe, but console/first-party formats (here, Nintendo's `MIO0`) have their own unambiguous magic bytes — a quick magic-byte search can save far more time than repeated blind-decompression guessing.
- **In-game flavor text and UI strings are often literal hints, not just theming.** `GB TOWER` / `agb.bin` / `TRANSFER PAK CHANNEL 0` directly described the real mechanism (an embedded, real second-console ROM) the challenge implemented — reading them carefully predicted exactly what to look for and roughly why it would be hidden (compressed, not plaintext).
- **A successful decode against a format's own self-check is strong validation.** The MIO0 decompressor's output landing on *exactly* the header's declared uncompressed size (`0xF2C` bytes, no more, no less) before any flag was even found was the signal that the format had been reconstructed correctly, rather than merely "producing output that happened to look right."

---

## 11. Tooling Notes (for reproduction)

```bash
# Environment: WSL/Ubuntu, Python 3, no capstone/disassembler needed
xxd pekpek.z64 | head -4                       # confirm native N64 magic + title
strings -n 5 pekpek.z64 | head -100            # libdragon build noise + UI/theme strings
```

```python
# Locate the trap: raw literal-pool text that LOOKS like a complete flag
import re
d = open("pekpek.z64", "rb").read()
for m in re.finditer(rb"zdk\{[^}]*\}", d):
    print(hex(m.start()), m.group())            # -> 0x6b98b zdk{w0mb0_c7h47_41n7_f41c0}  (WRONG, 5 chars short)
```

```python
# Find the real container: Nintendo MIO0 compression magic
import re, struct
for m in re.finditer(b"MIO0", d):
    off = m.start()
    magic, usize, coff, uoff = struct.unpack(">4sIII", d[off:off+16])
    print(hex(off), "usize", hex(usize), "coff", hex(coff), "uoff", hex(uoff))
    # -> 0x6b510 usize=0xf2c coff=0x7c uoff=0x2bc
```

```python
# Minimal MIO0 decompressor (Nintendo 64 LZ77-family format)
def mio0(buf, off):
    magic, usize, coff, uoff = struct.unpack(">4sIII", buf[off:off+16])
    out = bytearray()
    lay, cp, up = off + 16, off + coff, off + uoff
    bit = 0; cur = 0
    while len(out) < usize:
        if bit == 0:
            cur = buf[lay]; lay += 1; bit = 8
        bit -= 1
        if cur & (1 << bit):
            out.append(buf[up]); up += 1
        else:
            v = struct.unpack(">H", buf[cp:cp+2])[0]; cp += 2
            length, dist = (v >> 12) + 3, (v & 0xFFF) + 1
            for _ in range(length):
                out.append(out[-dist])
    return bytes(out)

payload = mio0(d, 0x6b510)          # -> exactly 3884 bytes, matches usize
open("mio_6b510.bin", "wb").write(payload)
```

```bash
# Final confirmation: re-scan the DECOMPRESSED data, not the raw ROM
strings -t x mio_6b510.bin | grep -i -E "pak|zdk"
#  0a0  PEKPEKKIOSK
#  2c0  TRANSFER PAK KIOSK
#  2e1  TOYS R US
#  2eb  zdk{w0mb0_c0mb0_7h47_41n7_f41c0}
```
