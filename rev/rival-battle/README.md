# z0d1ak CTF 2026 — rival-battle

**Solved by:** ftps3rver
**Category:** Reverse Engineering | **Points:** 179 | **Solves:** 39 | **Author:** Abhi404

---

## 1. Executive Summary

`battle` is a stripped, PIE x86-64 ELF that simulates a 3-vs-3, 14-turn Pokemon-style link-cable battle against a "rival" AI, seeded entirely from a shipped 64-byte `trainer.sav` file. The challenge description all but hands you the bug: *"it always starts from the same trainer card"* and *"old handheld games are not very random"* — the RNG is a 16-bit multiplicative-additive LCG initialized from two fixed bytes in the save file, and it only advances at a handful of well-defined trigger points (specific move rolls, paralysis checks, the rival's move choice). Because both the seed and every advance-point are static and fully reconstructable from the binary, the entire battle — including everything the "rival" will ever do — is a pure, deterministic function of the 14 commands the operator types. "Unbeatable" is a red herring: there is no opponent to outplay, only a finite command tree to search.

At the end of turn 14 (or on an early win/loss), the binary computes a 32-bit avalanche hash over the final battle state (HP totals, active Pokemon, RNG state, an internal "route score," and a few status flags) and compares it against a hardcoded target. On a match, it XOR-decrypts an embedded 33-byte ciphertext with a splitmix64 keystream seeded from the *same* final state, and prints the result as the flag.

Because the hash is only 32 bits wide but the reachable state space is many orders of magnitude larger, the check has **exploitable collisions** — the first 14-command sequence our brute-forcer found that satisfied the hash check decrypted to garbage, not a flag. The real solve required an additional filter ("hash matches **and** the decrypted bytes are printable and shaped like `zdk{...}`") before a second hit surfaced the genuine sequence, which was then replayed against the actual `battle` binary to obtain the flag from the program itself.

**Answer:** `zdk{S9U1rTLe_1s_7HE_8eST_5t4RTeR}`

---

## 2. Challenge Description

> The rival says this old battle simulator is unbeatable. It always starts from the same trainer card, though, and old handheld games are not very random.

Files: `battle` (18648 bytes, ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped, GNU/Linux 3.2.0, BuildID present, no source), `trainer.sav` (64 bytes).

No remote instance — this is a fully offline, local reversing challenge. The two sentences in the description are the whole hint: *fixed starting state* + *weak PRNG*, i.e. "this is deterministic, go compute the winning line instead of trying to play well."

---

## 3. Initial Reconnaissance

```bash
file battle
# battle: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked,
# interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=..., for GNU/Linux 3.2.0, stripped

xxd trainer.sav
# 00000000  5A 44 4B 4D 4F 4E 01 00 00 00 00 00 00 00 00 00  ZDKMON..........
# 00000010  5C F4 00 00 00 00 00 00 00 00 00 00 00 00 00 00  \...............
# (remaining bytes zero, 64 total)
```

`trainer.sav` is a trivial fixed-format save: magic `"ZDKMON"`, a version byte (`0x01`), and a little-endian 16-bit value at offset `0x10` (`0xF45C`) that turns out to be the RNG seed material, XORed with a constant baked into the binary (`0x8748`) to produce the actual initial LCG state `0x7314`.

**Available environment tooling** (Windows host, no native GNU toolchain): used WSL/Ubuntu for `objdump`, `readelf`, `strings`, and `python3`; no `gdb`, `radare2`, `ltrace`, or `strace` were present, so the entire logic was reconstructed from a serial read of `objdump -d -M intel --no-show-raw-insn` output plus targeted `strings -t x` / `objdump -s -j .rodata` dumps of the data tables, rather than dynamic tracing.

A first blind run confirmed the interactive shape of the program:
```bash
printf "" | ./battle
```
prints the ROUTE 151 banner, loads the trainer card, shows an ASCII HP-bar UI for both 3-Pokemon teams, and — on empty/EOF input — prints `The battle was abandoned.` This immediately showed the program is a straightforward `fgets`-driven turn loop, not something with a hidden network or file-write side effect to chase.

---

## 4. Attack Surface / Important Observations

**Command menu** — the printed menu and its underlying numeric input change meaning depending on the currently active Pokemon:

| Active | 1 | 2 | 3 | 4 |
|---|---|---|---|---|
| CHARMANDER | SCRATCH | GROWL | FOCUS ENERGY | EMBER |
| BULBASAUR | TACKLE | VINE WHIP | LEECH SEED | GROWTH |
| PIKACHU | QUICK ATTACK | THUNDER SHOCK | TAIL WHIP | AGILITY |

...plus, always available: `5` switch→CHARMANDER, `6` switch→BULBASAUR, `7` switch→PIKACHU, `8` POTION (usable exactly once, heals `0x14`). The binary also accepts the equivalent lowercase move-name strings (`"scratch"`, `"switch bulbasaur"`, `"thundershock"`, …) via a long chain of packed 8-byte `movabs`/`memcmp` comparisons in the disassembly — a second, textual input syntax layered over the same numeric menu, confirmed but not needed for the solve since the printed menu already tells you the digits to send.

**The RNG is a 16-bit LCG, not real randomness:**
```
seed  = u16_le(trainer.sav[0x10:0x12]) ^ 0x8748        # = 0x7314
mix(x) = t ^ rol16(t, 5), where t = (x*0x41C6 + 0x4E6D) & 0xFFFF
```
Critically, `mix()` is only called at specific points: EMBER's crit/bonus-damage roll, THUNDER SHOCK's paralysis roll, the paralysis-recovery check at the start of the rival's turn, and the rival's own move-selection roll. Every other action (switching, GROWL, FOCUS ENERGY, GROWTH, TAIL WHIP, AGILITY, POTION, etc.) is 100% deterministic damage/buff math with no RNG involvement at all. Since the seed is fixed and every advance point is a direct function of *which commands you already chose*, the entire 14-turn transcript — our team's damage, the rival's chosen moves, paralysis, everything — is a pure function of our own command sequence.

**Damage/buff formulas** (reconstructed from the disassembly, later validated against the live binary — see §6):
- `SCRATCH`: `dmg = EFF(normal,target)*3 + atk`
- `GROWL`: `defense_buff += 4`
- `FOCUS ENERGY`: `focus += 1`
- `EMBER`: rolls RNG; `dmg = (focus*5 + atk) + EFF(fire,target)*2 [+4 crit bonus on high roll]`; consumes `focus`
- `TACKLE`: `dmg = (EFF(normal,target)*5)/2 + atk`
- `VINE WHIP`: `dmg = (growth+2)*EFF(grass,target)*2 + atk`; consumes `growth`
- `LEECH SEED`: applies a 4-turn HP-drain-to-us effect on the rival's active Pokemon
- `GROWTH`: `growth += 1`
- `QUICK ATTACK`: `dmg = atk + EFF(normal,target)*2`
- `THUNDER SHOCK`: rolls RNG; `dmg = EFF(electric,target)*5 + atk`, chance to paralyze the rival for 2 turns
- `TAIL WHIP`: `atk += 3` (raises our own attack stat, despite the real game's Tail Whip lowering the opponent's defense — a deliberate reflavor)
- `AGILITY`: `defense_buff += 6`
- A type-effectiveness table in `.rodata` gives Electric 0× against GEODUDE and Normal 0× against GASTLY, matching Pokemon type logic (Ground immune to Electric, Ghost immune to Normal).

**The win condition** is a 32-bit keyed hash over 14 packed fields of the final state (our/rival HP × 3 each, active indices, an internal "route score" that every action nudges up or down, the final RNG value, the last per-action mix value, potion/leech/paralysis flags), combined via `XOR-multiply-rotate` against 14 tuned 32-bit constants, compared against a hardcoded `0x9218A78C`. On match, a 33-byte ciphertext embedded at a fixed `.rodata` offset is XORed with a splitmix64 keystream whose 64-bit seed is derived by folding those same 14 final-state fields through an FNV-1a-style accumulator seeded with the ASCII constant `"route151"` (a nod to the ROUTE 151 banner) — and the result is printed as the flag.

---

## 5. Failed Attempts

**Attempt 1 — Assume this requires actually playing well / RNG luck.** A first read of the description ("unbeatable," "not very random") could be mistaken for "grind attempts until a lucky RNG roll lets you win." Dropped immediately once the LCG and its sparse, fully static advance points were reconstructed from the disassembly — there is no luck to grind for; every seed-consuming roll is 100% predictable in advance from the command sequence alone.

**Attempt 2 — Naive breadth-first search with full state deduplication.** Built a BFS that expanded all legal command sequences turn-by-turn, deduplicating on the full gameplay state (HP/actives/buffs/flags, excluding volatile RNG bookkeeping) to avoid revisiting equivalent positions. The live-state set exploded past **1.15 million** entries by turn 8 and kept growing — the dedup key wasn't collapsing nearly as much of the tree as hoped, because the RNG-consuming action's *value*, not just which action was taken, threads through every subsequent turn's outcome, defeating most of the intended state-merging. **Abandoned** in favor of a direct depth-first traversal that never stores more than one root-to-leaf path at a time (see §6) — since only *terminal* states matter for the hash check, per-leaf work is O(1) and doesn't need a live frontier at all.

**Attempt 3 — Trust the first "hash matches" hit as the answer.** A first full run surfaced a 14-command sequence whose final-state hash matched `0x9218A78C` and which the *real* binary confirmed with `RIVAL: ...fine. That route was perfect.` — but the subsequent decrypted "flag" was non-printable binary garbage, not `zdk{...}`. **Rejected.** This is a genuine 32-bit hash collision: the reachable terminal-state space is vastly larger than 2^32 possible hash outputs, so multiple distinct 14-command routes are expected to collide on the hash check while decrypting to different (mostly garbage) plaintexts. The acceptance criterion had to be tightened to "hash matches **and** the decrypted bytes are printable ASCII shaped like `zdk{...}`" before trusting a result.

**Attempt 4 (debugging note) — Differential test harness initially reported false-positive mismatches.** The first version of the Python-vs-binary differential tester used a regex to parse the ASCII HP-bar UI that didn't account for the leading `>` cursor marking the active Pokemon's row, causing spurious "MISMATCH" reports against an actually-correct simulator. Fixed by relaxing the regex to search rather than anchor-match each HP-bar line; re-run confirmed 0 real mismatches across 40 randomized battles.

---

## 6. Investigation — Building the Exploit

**Step 1 — Reconstruct the full turn-resolution logic by hand from `objdump -d -M intel`.** No dynamic tracing was available, so the entire `main()` state machine (RNG, type table, per-move formulas, rival AI thresholds, turn-limit/faint/wipe end conditions, the final hash+decrypt routine) was read serially out of the disassembly and re-typed as Python:

```python
def mix(x):
    t = (x * 0x41C6 + 0x4E6D) & 0xFFFF
    return t ^ rol16(t, 5)

def eff(row, target_idx):        # type effectiveness lookup
    return TBL[ROW_OFFSET[row] + 4 + target_idx]
```

**Step 2 — Differentially test the reimplementation against the real binary.** Rather than trust a hand-transcribed ~1300-line disassembly blindly, a harness drove `./battle` with randomized legal command sequences via subprocess and compared the rendered HP-bar percentages turn-by-turn against the Python simulator's own state:

```python
for _ in range(40):
    cmds = random_legal_route()
    assert parse_hp_bars(run_binary(cmds)) == sim_hp_bars(cmds)
# 0 mismatches after fixing the HP-bar regex (see Failed Attempts, Attempt 4)
```

**Step 3 — Port the validated simulator to a fast tuple-based core, and cross-check *that* against the already-validated version** (300 more randomized trials, 0 mismatches) before spending any real compute trusting it for brute force — a hand-reconstructed emulator earns trust incrementally, not by inspection alone.

**Step 4 — Size the search space and pick a search strategy.** Up to 4 move choices (move set depends on the active Pokemon) + up to 2 legal switches (can't switch into a fainted or already-active Pokemon) + a one-time potion option gives up to 7 legal actions per turn, over 14 turns — a full BFS with state deduplication still blew up past a million live states by turn 8 (§5, Attempt 2). Switched to a **parallel depth-first search**: expand the first 4 turns serially into ~2160 prefixes, then hand each prefix to one of 12 worker threads that DFS the remaining 10 turns independently, doing an O(1) hash check only at terminal leaves (turn 14, or an early win/faint/wipe).

**Step 5 — Reimplement in C# for throughput, JIT-compiled via PowerShell.** The Python prototype, while correct, was far too slow for ~2.4×10¹¹ total leaves. With no C/C++ toolchain readily available on the host, `Add-Type -Path RB.cs` (PowerShell's built-in Roslyn JIT) compiled a from-scratch, allocation-free re-implementation of the same validated logic, sustaining roughly 4×10⁷ terminal leaves/sec across 12 threads.

**Step 6 — Filter hits by decrypted printability, not just hash match** (per §5, Attempt 3):
```csharp
if (HashOk(ref finalState)) {
    string flag = DecryptFlag(ref finalState);   // splitmix64 keystream XOR
    if (LooksLikeFlag(flag)) ReportHit(path, flag);
}
```

**Step 7 — A second hit, found before the exhaustive search finished, decrypted cleanly:**
```
route (internal cmd indices): 1,2,3,5,10,8,6,12,11,5,10,8,10,8
-> as raw menu digits typed into the real binary:
   2  3  4  6  4  2  7  2  1  6  4  2  4  2
```
i.e. **GROWL → FOCUS ENERGY → EMBER → switch BULBASAUR → GROWTH → VINE WHIP → switch PIKACHU → THUNDER SHOCK → QUICK ATTACK → switch BULBASAUR → GROWTH → VINE WHIP → GROWTH → VINE WHIP**.

**Step 8 — Replay against the real binary to get the flag from the program itself**, since the offline reimplementation's prediction is only a lead, not the authoritative acceptance criterion:
```bash
printf "2\n3\n4\n6\n4\n2\n7\n2\n1\n6\n4\n2\n4\n2\n" | ./battle | tail -3
# RIVAL: ...fine. That route was perfect.
# PROF.OAK: Here is the professor's secret:
# zdk{S9U1rTLe_1s_7HE_8eST_5t4RTeR}
```

---

## 7. Root Cause / Why This Chain Works

1. **A PRNG seeded from static, always-shipped data is not random from an attacker's point of view.** Once `trainer.sav`'s seed bytes and the LCG's constants are recovered, every "random" roll the program will ever make is precomputable for any given command sequence — full reverse engineering plus replay always beats a weak PRNG, regardless of how the game is dressed up.
2. **The RNG only advances at a small, enumerable set of trigger points**, so the *choice and order* of the operator's own commands fully controls which pseudo-random values get consumed and when — turning "beat an unbeatable AI" into "search a finite, fully-known game tree for one accepting leaf."
3. **A 32-bit acceptance hash over a search space far larger than 2³² is not injective.** Treating "the hash check passed" as sufficient proof of a correct solution is a mistake; the actual payload the check is meant to gate (here, a printable flag) has to be validated independently, because collisions are not just theoretically possible but were hit in practice on the very first full search pass.
4. **The description's two sentences are the entire vulnerability class, stated plainly.** "Always starts from the same trainer card" (static seed) and "not very random" (weak/limited-period PRNG) are a direct pointer at "reverse the RNG and search," which is exactly why this sits in Reverse Engineering rather than requiring any actual battle strategy skill.

---

## 8. Answer

```
zdk{S9U1rTLe_1s_7HE_8eST_5t4RTeR}
```

---

## 9. Reconstruction Chain

```
battle (stripped PIE ELF) + trainer.sav (64-byte fixed save)
        |
        v
Static RE via objdump -d -M intel (no gdb/radare2 available)
        -> 16-bit LCG seeded from trainer.sav[0x10] XOR 0x8748
        -> type-effectiveness table + per-move damage/buff formulas in .rodata
        -> rival AI move-choice also driven off the same RNG stream
        |
        v
Hand-port logic to Python -> differential-test against real ./battle
        (40 randomized routes, HP-bar parity, 0 mismatches after regex fix)
        |
        v
Port to a fast tuple-based core -> cross-check vs. validated Python sim
        (300 more randomized routes, 0 mismatches)
        |
        v
BFS with dedup blows up (1.15M+ live states by turn 8) -> abandoned
        |
        v
Parallel DFS (12 threads, C# via PowerShell Add-Type JIT)
        over ~2.4x10^11 leaves at ~4x10^7 leaves/sec
        |
        v
First "hash == 0x9218A78C" hit decrypts to garbage -> 32-bit hash collision
        -> tighten filter: hash match AND printable zdk{...} decode
        |
        v
Second hit: 2 3 4 6 4 2 7 2 1 6 4 2 4 2
        (GROWL, FOCUS ENERGY, EMBER, ->BULBASAUR, GROWTH, VINE WHIP,
         ->PIKACHU, THUNDER SHOCK, QUICK ATTACK, ->BULBASAUR,
         GROWTH, VINE WHIP, GROWTH, VINE WHIP)
        |
        v
Replay against the real ./battle binary (authoritative, not just offline sim)
        |
        v
zdk{S9U1rTLe_1s_7HE_8eST_5t4RTeR}
```

---

## 10. Key Takeaways

- **A PRNG seeded from static, shipped data is fully deterministic to an attacker who reverses it.** "Random" only means something against an adversary who doesn't control or know the seed and the mixing function — neither was true here.
- **RNG that only advances on specific actions turns "randomness" into a controllable resource.** Recognizing exactly which commands consume a roll (and which don't) is what makes a 7-choices-per-turn, 14-turn tree small enough to brute-force instead of astronomically large.
- **A check with a narrower output domain than its input space (here, a 32-bit hash over a >2³²-sized search space) will have collisions — plan for it.** Never treat "the gate accepted my candidate" as proof of correctness when the gate's output space is smaller than what you're searching; validate the actual downstream artifact (the decrypted flag) independently.
- **Differential-test a hand-reconstructed emulator against the real target before trusting it for expensive compute.** Two rounds of randomized cross-validation (Python-vs-binary, then fast-core-vs-Python) caught a real parsing bug early and made the eventual brute-force result trustworthy.
- **When a naive BFS with deduplication doesn't collapse the tree the way you expect, check whether dedup is even buying you anything** — if only terminal states matter and per-leaf work is cheap, an undeduplicated parallel DFS can be both simpler and faster than a memory-bound BFS.
- **Prototype in a language you can reason in (Python), then port to something fast (JIT-compiled C#, via PowerShell's `Add-Type`) once the logic is proven correct**, rather than fighting to make the prototype itself fast enough for a 10¹¹-leaf brute force.

---

## 11. Tooling Notes (for reproduction)

```bash
# Environment: WSL/Ubuntu for static RE (no gdb/radare2/ltrace/strace available)
file battle
xxd trainer.sav
objdump -d -M intel --no-show-raw-insn battle > dis.txt
objdump -s -j .rodata battle          # type table, max-HP constants, embedded ciphertext
strings -t x battle | grep -i route   # locate the win/lose message offsets
```

```python
# Core RNG + hash skeleton, reconstructed from the disassembly
def mix(x):
    t = (x * 0x41C6 + 0x4E6D) & 0xFFFF
    return t ^ ((t << 5) | (t >> 11)) & 0xFFFF

SEED = 0x5C | (0xF4 << 8)      # u16_le from trainer.sav[0x10:0x12]
RNG0 = SEED ^ 0x8748           # = 0x7314

# Differential test skeleton: real binary vs. reimplementation
def check(cmds):
    real = parse_hp_bars(run_subprocess(["./battle"], input=to_menu_digits(cmds)))
    sim  = sim_hp_bars(cmds)
    assert real == sim
```

```powershell
# Fast brute-force core, JIT-compiled without any C/C++ toolchain on the host
Add-Type -Path C:\path\to\RB.cs
[RB]::Run(4)     # expand 4 turns serially -> ~2160 prefixes, DFS the rest on 12 threads
foreach ($h in [RB]::Hits) { Write-Output $h }   # only hits with a printable zdk{...} decode
```

```bash
# Final confirmation against the real binary
printf "2\n3\n4\n6\n4\n2\n7\n2\n1\n6\n4\n2\n4\n2\n" | ./battle | tail -3
# zdk{S9U1rTLe_1s_7HE_8eST_5t4RTeR}
```
