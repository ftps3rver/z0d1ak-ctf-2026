# z0d1ak CTF 2026 — stars-below

**Solved by:** ftps3rver
**Category:** Reverse Engineering | **Points:** 188 | **Solves:** 35 | **Author:** afish

---

## 1. Executive Summary

This challenge hands out a single stripped, SDL2-linked Linux ELF (`stars_below`) that role-plays as an old terminal "link-cable" battle sim gated behind a three-part login: a `ROUTE` (an 8-digit permutation), a `CALLSIGN` (derived from the route), and a `TICKET` (a 58-character custom-base32 blob). All three are checked against a modified SHA-256 sponge baked into the binary. Recovering `ROUTE` and `CALLSIGN` is a straightforward brute force once the sponge is treated as an oracle. `TICKET` looks like it hides behind an unsolvable system of 8 modular ARX equations — and a large amount of effort here went into treating that system as the real gate, using every SMT solver available (z3, bitwuzla, cvc5, Cadical) plus memory scanning and structured-payload guessing. All of it failed, because the equation system is a **one-way check built backward from the correct answer**, not a forward gate. The actual gate is a chain of two custom 32-byte-block VMs (a 24-round ARX register machine and a 19-round ARX stack machine) that transform the ticket's 32-byte payload into a value that must equal a payload-independent `target` hash. Every primitive in both VMs is invertible mod 2^32, so the whole chain can be run backward from `target` to recover the one payload that was ever meant to exist — which also, not coincidentally, satisfies all 8 of the "unsolvable" equations, proving they were derived *from* this payload rather than constraining it.

**Answer:** `zdk{ThE_L0aDEr_Dre4MS_in_pAg3_b0uND4ri35}`

---

## 2. Challenge Description

> The drowned observatory still charts a sky.

Files: a single ELF, `stars_below` — a PIE, dynamically linked x86-64 binary that runs as an interactive SDL2 terminal-style game, or headless via:

```
./stars_below --headless <ROUTE> <CALLSIGN> <TICKET>
```

The game presents itself as an old handheld-style Pokemon-adjacent "link cable battle" login screen. There is no separate hint file, and everything has to be pulled out of the binary itself:

- **A fragment string and a route** to assemble the callsign — the callsign is not typed in free-form; it is built by permuting a fixed 8-character fragment string according to the 8-digit route.
- **A sponge/hash primitive used for everything** — route validity, callsign validity, and ticket MAC all reduce to the same modified-SHA-256 sponge (`sp_init` / `sp_absorb` / `sp_final`), so recovering that primitive as a reusable oracle pays for itself three times over.
- **A ticket that decodes to a 32-byte payload plus a 4-byte MAC** — the payload is the actual secret; the MAC only proves you know the callsign, it says nothing about whether the payload is correct.
- **An 8-equation modular "invariant" system on the payload** — looks like the gate, is not the gate (see Section 5 and Section 7).

---

## 3. Initial Reconnaissance

```bash
file stars_below
# stars_below: ELF 64-bit LSB pie executable, x86-64, ... stripped, for GNU/Linux
```

Running the binary directly shows a route/callsign/ticket login gate before anything resembling gameplay is reachable:

```bash
./stars_below --headless 16403752 PELAGOS9 AAAA
# the relay remains silent
```

Disassembly (`objdump -d`, no debug symbols) around the login path shows three independent checks, each ending in a call into the same three functions at `0x405ec0` / `0x405ef0` / `0x405fa0` — a strong signal that the binary implements one hash/sponge primitive and reuses it everywhere: route hash, callsign guard, ticket MAC, and — as it later turns out — the VM round keys and the final target too.

**Objdump's own PLT labeling for this binary is not trustworthy.** Several call sites that objdump auto-labels with plausible-sounding libc/SDL names do not behave like those functions when single-stepped in GDB. Confirmed behaviorally while building the harness in Section 4:

| objdump label | address | actual runtime behavior |
|---|---|---|
| `SDL_ShowSimpleMessageBox@plt` | `0x4020e0` | zeroes a buffer (`memset`) |
| `strstr@plt` | `0x402180` | copies bytes (`memcpy`) |
| `strchr@plt` | `0x4022c0` | scans for a byte, standard `strchr` |
| `SDL_CreateTexture@plt` | `0x402250` | returns a fresh heap pointer (`malloc`) |

Every load-bearing call site used later in this writeup was confirmed this way, by observing what it actually does in GDB, rather than trusted from its disassembly label.

---

## 4. Attack Surface / Important Observations

**The sponge primitive** (`sp_init`/`sp_absorb`/`sp_final` at `0x405ec0`/`0x405ef0`/`0x405fa0`) is a modified SHA-256: the first IV word is patched from the standard `0x6a09e667` to `0x6b08e647`, padding is zero-only (no `0x80` terminator byte and no appended bit-length), and the 32-byte digest is emitted as the raw internal state words in little-endian rather than SHA-256's usual big-endian. It is used, with different fixed domain-separation strings, for essentially everything:

| domain string | absorbs | produces |
|---|---|---|
| `stars-below/name/v1` | uppercased callsign + length byte | `H1` — the callsign identity hash |
| `stars-below/invariant-mask/v1` | a fixed salt + `H1` | the XOR-mask applied to the invariant target constants |
| `stars-below/ticket/v1` | `H1` + 32-byte payload | ticket MAC (first 4 bytes used) |
| `stars-below/target/v1` | `H1` + a fixed salt | `target` — the value the whole VM chain must reach |
| `stars-below/schedule/v1`, `.../vm-a-key/v1`, `.../vm-b-key/v1` | `H1` + various | round-key material and bytecode decryption keys for the two VMs |

**Building an oracle instead of reimplementing the hash.** Rather than reverse-engineer every twist of the modified SHA-256 by hand, the binary's own ELF segments were `mmap`-ed at their real virtual addresses from disk, two GOT slots were patched to real libc functions (`GOT_MEMSET @ 0x40f058`, `GOT_MEMCPY @ 0x40f0a8`), and `sp_init`/`sp_absorb`/`sp_final` were then called directly as C function pointers from a small harness. This produces byte-identical output to the running binary by construction — it is the binary's code — and was cross-checked against live GDB state to confirm.

**Callsign construction.** A fixed 8-character fragment string, `AP9GLSEO`, sits at `0x407660`. The 8-digit `ROUTE` is a permutation of the digits `0`-`7`; indexing the fragment string in that order assembles the callsign. There is also a length/charset quirk in the input validator worth noting: it accepts uppercase letters, lowercase letters (upper-cased on the fly), and **digits** — a detail that matters because the correct callsign turns out to contain a digit.

**Ticket container.** The ticket is a 58-character string over a custom base32-style alphabet, `87RJF2ACZLVUMXB3D6GH9WNSYP5QK4ET`, at `0x407680`. 58 characters times 5 bits equals 290 bits, decoding to 36 bytes: a 32-byte payload followed by a 4-byte MAC. The MAC is checked as `first4(H(domain="stars-below/ticket/v1", H1, payload))` — this only proves the payload was sealed for the given callsign, it places no constraint on the payload's content.

**Two encrypted bytecode blobs.** Two `.rodata` regions (11336 bytes and 8672 bytes) turn out to be CTR-mode-encrypted with an `H1`-derived key, decrypting at runtime into two custom instruction streams: VM A (register machine, 8-byte fixed-width instructions, 1417 instructions) and VM B (stack machine, same instruction width, 1084 instructions). Both dispatch through a function-pointer table (`call *(%rbx,%rax,8)`) indexed by a linear scan over a small opcode byte-table — which is why grepping for `jmp *`/opcode switch patterns in the raw disassembly initially found nothing; the dispatch table only exists after runtime decryption.

---

## 5. Failed Attempts

**Attempt 1 — Solve the 8-equation invariant system with SMT.** The payload's 32 bytes (as eight 32-bit words) satisfy an 8-equation ARX system of the shape `rol(P[a] xor P[b], r) + sum(P[j] * M[j]) == T (mod 2^32)`. This looked like the gate — it is checked right before the VM chain even starts — so it absorbed the bulk of early effort:

- Default z3, three different seeds/heuristic configurations, and a row-reduced (Gaussian-eliminated mod 2^32) redundant-constraint variant, all left running for 20-90 minutes each with no result.
- `bitwuzla` and `cvc5` both hung with no result inside the same time budgets.
- The equations bit-blasted to CNF (26,423 variables / 183,310 clauses) and handed to Cadical directly, again no result.
- **The decisive test:** a synthetic instance built with the exact same shape (same rotation amounts, same multiplier matrix) but with a known solution planted in it — z3 could not solve that either inside 110 seconds. This proved the system's difficulty is structural, not a solver-tuning problem, and reframed the whole approach as a dead end (confirmed correct in Section 7: the system is one-way by construction).
- Structured-payload hypotheses (payload as printable ASCII, alphanumeric, uppercase-plus-digits, or low-entropy/small words) added as extra z3 constraints on top of the same equations, all unsat or timed out.

**Attempt 2 — Look for the payload in memory instead of computing it.** Generated a core dump at the point right after MAC verification and wrote a C scanner checking every 32-byte sliding window (the core dump, 3.3 MB; the binary image itself; the two decrypted VM bytecode blobs; and the round-key "grid" structures) against the 8 invariant equations. Zero matches anywhere. This ruled out "the payload is derived and cached somewhere" and confirmed the binary genuinely verifies a payload it never computes itself.

**Attempt 3 — Guess the payload as a hash of the callsign.** Tried roughly 1,700 candidates: 11 plausible domain-separation strings (`final/v1`, `permutation/v1`, `tag/v1`, `vm-a-key/v1`, and so on) times 13 salt offsets pulled from nearby `.rodata` times 4 absorb orderings times 3 domain-byte prefixes, all computed through the same sponge oracle from Section 4. None satisfied even one of the 8 invariant equations. This ruled out "the payload is just another sponge output" and forced actually reverse-engineering the VM chain that consumes it.

**Attempt 4 — Assume the VM output is linear and skip modeling it.** Before committing to writing a full instruction-level VM A emulator, a cheap differential probe was run: flip bit 0 of payload word 0, flip bit 0 of word 1, flip both, and check whether the output XORs the way a GF(2)-affine function would. It did not — 271 of 512 output bits disagreed with the linear prediction — closing off any shortcut through linear cryptanalysis and confirming the actual round structure had to be modeled and inverted exactly.

---

## 6. Investigation — Recovering ROUTE, CALLSIGN, and the Login Gate

**Step 1 — Brute-force ROUTE.** The route-hash check (confirmed live in GDB, target `0xf06f770b`) only has 8! = 40,320 possible inputs, a permutation of one digit each of 0 through 7. Running each permutation through the sponge oracle from Section 4 finds the unique match: `ROUTE = 16403752`.

**Step 2 — Derive CALLSIGN from ROUTE.** Indexing the fragment string `AP9GLSEO` in the order given by `16403752` (fragment[1], fragment[6], fragment[4], fragment[0], fragment[3], fragment[7], fragment[5], fragment[2]) spells `PELAGOS9`. This passes the callsign name-guard hash exactly, confirming ROUTE and CALLSIGN independently agree with each other.

**Step 3 — Build a working ticket for arbitrary payloads.** With `H1 = H(name/v1, len, uppercase(CALLSIGN))` computable via the sponge oracle, a small tool (`mkticket`) was written that, given any 32-byte payload, computes the correct 4-byte MAC and base32-encodes the full 36 bytes into a valid 58-character ticket string. This turns "does this payload validate" into a single command-line round-trip against the real binary — the verification oracle used for the rest of the challenge.

---

## 7. Investigation — Reverse-Engineering the VM Chain (the real gate)

**Step 1 — Reverse-engineer VM A's instruction set.** Once the encrypted `.rodata` blobs were decrypted (via a debugger breakpoint right after the CTR-mode decrypt call, dumping the plaintext bytecode directly rather than reimplementing the keystream), the 8-byte instruction format and its 15 opcodes were recovered by reading each of the 15 handler functions behind the function-pointer table:

```
LOAD_SLOT / STORE_SLOT / LOAD_DW / LOAD_B / XOR / ADD / MUL / ROL / ROR /
LOADI / ADDI / LOAD_SLOT_IND / CMPLT / BRANCH / HALT
```

A Python emulator implementing all 15 was validated byte-for-byte against the real binary in GDB: instruction count (2257 steps), a running "trace hash" the VM itself maintains, and the final 8-word output slots all matched exactly across multiple test payloads.

**Step 2 — Recognize the round structure.** VM A's 1417 instructions turned out to be 24 perfectly uniform 59-instruction rounds, each performing two independent ARX ("half-block") transforms on a shared 8-word state, keyed by a 24-entry "grid" of round material (a byte permutation, 6 round dwords, and 6 rotation amounts) derived from `H1` via `schedule/v1`. Each half-block reduces to four operations on four of the eight state words:

```
A += rol(B xor dw0, b0)
C ^=  A * dw2
D  = ror(D + C, b1)
B ^= rol(D + dw1, b2)
```

VM B (the stack machine, 1084 instructions across 19 rounds of 57 instructions) turned out to be the same four-operation ARX shape, just re-expressed as stack pushes and pops instead of register operands.

**Step 3 — Every primitive here is invertible mod 2^32.** `+=`, `^=`, and rotate-of-XOR are each trivially undone (subtract, rotate the other way, XOR again). This means an exact, closed-form inverse exists for a whole round, no brute force, no approximation, for both VM A and VM B. Both inverses were implemented and validated by round-tripping random inputs through `forward()` then `inverse()` and confirming the identity holds.

**Step 4 — Recover the word permutation linking VM A's output to VM B's input.** A "mix" step sits between the two VMs: `S2[i] = rol(H1[i], i+1) xor S1[perm[i]]`. The permutation `perm = [0,2,6,3,5,1,4,7]` was recovered by differential probing, comparing VM A's output word-by-word against VM B's input word-by-word for two different payloads and matching up which output word, once XORed against `rol(H1[i], i+1)`, produced which input word.

**Step 5 — Compute `target` (payload-independent) and invert the whole chain.** `target = H(target/v1, H1, salt)` needs no payload at all; it was already computable via the sponge oracle from Section 4. The full recovery is then a straight backward walk:

```
S2      = VM_B_inverse(target)
S1      = unmix(S2)                       # undo the rol(H1)-XOR-permute step
payload = VM_A_inverse(S1)
```

The result, `686a5e569650dcc9eecc2f5b1ad4cc0908e464cfea3c1f4f01a2c901dce88e6e`, forward-verifies exactly back through VM_A then mix then VM_B to reproduce `target`, and independently satisfies all 8 of the "unsolvable" invariant equations from Section 5 — 8 out of 8. This confirms the invariant was never meant to be solved forward: the challenge author picked this payload first, ran it through the invariant's forward direction to get the required constants, and baked those constants into the binary. Solving it as a standalone SMT problem was always going to be intractable by design.

**Step 6 — Build the ticket and read the flag.**

```bash
./mkticket stars_below PELAGOS9 686a5e569650dcc9eecc2f5b1ad4cc0908e464cfea3c1f4f01a2c901dce88e6e
# X7W2KW9NVJBMHQNM24X6WWAM7FFBZPA34ZE7EHY79UFDJSCZ6PSV8MSKRD

./stars_below --headless 16403752 PELAGOS9 X7W2KW9NVJBMHQNM24X6WWAM7FFBZPA34ZE7EHY79UFDJSCZ6PSV8MSKRD
# zdk{ThE_L0aDEr_Dre4MS_in_pAg3_b0uND4ri35}
```

---

## 8. Root Cause / Why This Chain Works

1. **A shared crypto primitive reused as a MAC, a name-guard, a KDF, and a target hash simultaneously.** Building one verified oracle for the modified SHA-256 sponge, instead of reimplementing it from scratch or trusting a guess at its internals, paid off at every single stage of the challenge: route hash, callsign guard, ticket MAC, round-key schedules, and the final target.
2. **A ticket MAC that authenticates the sender, not the content.** The 4-byte MAC only proves "this payload was sealed under this callsign's identity hash"; it says nothing about whether the 32-byte payload inside is the correct one. That distinction is what makes the invariant-equation rabbit hole in Section 5 so effective: it is checked immediately after the MAC, in the same code region, and looks exactly like the next layer of the gate.
3. **A system of equations that is only satisfiable in one direction.** The invariant's constants were computed from the correct payload by the challenge's build process, not chosen independently as a puzzle to invert. Nothing about the equations themselves signals this; the synthetic-instance test in Section 5 (a same-shaped system with a planted known solution, still intractable for every SMT solver tried) is what actually proved the difficulty was structural rather than a matter of solver tuning, and justified abandoning that line of attack entirely.
4. **ARX primitives chosen specifically because they are bijective per word.** Every operation in both VMs (`+=`, `^=`, `rol`/`ror`) is invertible mod 2^32 individually, and the rounds built from them compose to invertible rounds. This is what turns "reverse two custom VMs" from an intractable search into a closed-form backward computation, once the round structure is correctly identified from the decrypted bytecode.
5. **Runtime ground truth beats static disassembly for an obfuscated binary.** Every load-bearing fact in this writeup — the PLT mislabeling in Section 3, the VM instruction semantics in Section 7, the round boundaries, the permutation in the mix step — was pinned down by single-stepping the real binary in GDB and comparing against a from-scratch model, not by reading disassembly and trusting it.

---

## 9. Reconstruction Chain

```
stars_below (stripped PIE ELF)
        |
        v
mmap the binary's own ELF segments at their real vaddrs, patch GOT[memset]/GOT[memcpy]
        -> call sp_init/sp_absorb/sp_final directly as C function pointers
        -> exact oracle for the binary's modified-SHA-256 sponge
        |
        v
Brute-force ROUTE over 8! = 40,320 permutations against the route-hash target
        -> ROUTE = 16403752
        |
        v
fragment_string[route[i]] for i in ROUTE's digit order  ("AP9GLSEO" @ 0x407660)
        -> CALLSIGN = PELAGOS9  (validated against the name-guard hash)
        |
        v
H1 = H(name/v1, len, CALLSIGN)  -- computed via the sponge oracle
        |
        v
mkticket: build any 32-byte payload into a valid 58-char base32 ticket
        (payload || first4(H(ticket/v1, H1, payload)))  -> passes MAC unconditionally
        |
        v
[DEAD END, extensively explored] 8-equation ARX "invariant" on the payload
        -> z3 / bitwuzla / cvc5 / Cadical-via-CNF all fail, even on a synthetic
           instance with a KNOWN planted solution -> structurally one-way, abandon
        |
        v
Decrypt VM A / VM B bytecode blobs at runtime (CTR-mode, H1-derived key)
        -> reverse both instruction sets from their handler functions
        -> emulators validated byte-exact against GDB (step counts, trace hash)
        |
        v
Recognize both VMs as 24-round / 19-round ARX ciphers over an 8-word state
        -> every primitive (+=, ^=, rol/ror) is invertible mod 2^32
        -> write closed-form inverse() for both VMs, validate round-trip
        |
        v
Recover the word-permutation "mix" step between VM A and VM B via differential probing
        -> perm = [0,2,6,3,5,1,4,7]
        |
        v
target = H(target/v1, H1, salt)   -- payload-independent, computed via the oracle
        |
        v
payload = VM_A_inverse( unmix( VM_B_inverse( target ) ) )
        -> forward-verifies exactly back to target
        -> ALSO satisfies the "unsolvable" invariant, 8/8  (proves it was one-way)
        |
        v
mkticket stars_below PELAGOS9 <payload>  ->  valid 58-char TICKET
        |
        v
./stars_below --headless 16403752 PELAGOS9 <TICKET>
        |
        v
zdk{ThE_L0aDEr_Dre4MS_in_pAg3_b0uND4ri35}
```

---

## 10. Key Takeaways

- **When a binary calls the same hash/sponge routine from five different places, build one verified oracle for it instead of reimplementing it five times (or once, badly).** Patching just enough of the GOT to call the binary's own crypto functions directly is faster and strictly more correct than reverse-engineering a modified primitive by hand.
- **A MAC or signature check proves authenticity, never correctness of content.** Passing a MAC check is a necessary condition to reach the next gate, not evidence that the payload behind it is the right one; do not stop investigating just because a check turned green.
- **An "unsolvable" equation system next to a MAC check is a strong hint it is one-way, not the gate.** If every SMT solver you own fails on a synthetic instance of the same shape with a known solution planted in it, that is decisive evidence the difficulty is structural (the puzzle was built backward from an answer); stop feeding it to solvers and go find the forward computation instead.
- **Prefer runtime ground truth over static disassembly for anything load-bearing in an obfuscated binary**, including symbol/PLT labels from objdump; behaviorally confirm what a call site actually does before building on top of it.
- **ARX ciphers are chosen by challenge authors specifically because each primitive operation is bijective.** Recognizing round structure (uniform instruction-count blocks, a small fixed set of `+=`/`^=`/rotate ops) turns "reverse this custom VM" into "write four one-line inverse functions and validate the round-trip", a mechanical, low-risk task once the structure is spotted.

---

## 11. Tooling Notes (for reproduction)

```c
/* harness.c -- exact oracle for the binary's modified-SHA-256 sponge,
   built by mmapping the binary's own segments at their real vaddrs. */
#define GOT_MEMSET 0x40f058UL
#define GOT_MEMCPY 0x40f0a8UL
typedef void (*fn_init_t)(void *st);
typedef void (*fn_abs_t)(void *st, const void *p, unsigned long n);
typedef void (*fn_fin_t)(void *st, void *out);
static fn_init_t sp_init   = (fn_init_t)0x405ec0UL;
static fn_abs_t  sp_absorb = (fn_abs_t)0x405ef0UL;
static fn_fin_t  sp_final  = (fn_fin_t)0x405fa0UL;
/* mmap each PT_LOAD segment at (vaddr & ~0xfff) with the on-disk bytes,
   then: *(void**)GOT_MEMSET = memset; *(void**)GOT_MEMCPY = memcpy; */
```

```python
# VM round primitive and its exact inverse (mod 2**32) -- the load-bearing
# insight that makes the whole chain invertible.
M32 = 0xffffffff
def rol(x, n): n &= 31; return ((x << n) | (x >> (32 - n))) & M32 if n else x
def ror(x, n): n &= 31; return ((x >> n) | (x << (32 - n))) & M32 if n else x

def half_fwd(S, A, B, C, D, dw0, dw1, dw2, b0, b1, b2):
    S[A] = (S[A] + rol(S[B] ^ dw0, b0)) & M32
    S[C] = S[C] ^ ((S[A] * dw2) & M32)
    S[D] = ror((S[D] + S[C]) & M32, b1)
    S[B] = S[B] ^ rol((S[D] + dw1) & M32, b2)

def half_inv(S, A, B, C, D, dw0, dw1, dw2, b0, b1, b2):
    S[B] = S[B] ^ rol((S[D] + dw1) & M32, b2)
    S[D] = (rol(S[D], b1) - S[C]) & M32
    S[C] = S[C] ^ ((S[A] * dw2) & M32)
    S[A] = (S[A] - rol(S[B] ^ dw0, b0)) & M32
```

```bash
# WSL/Kali toolchain used throughout
wsl -d kali-linux
objdump -d --no-show-raw-insn stars_below > stars_below.asm
gdb -batch -ex 'break *<addr>' -ex 'run --headless <ROUTE> <CALLSIGN> <TICKET>' \
    -ex 'x/32bx $rsp+<off>' stars_below
```

```bash
# final recovery and verification
./mkticket stars_below PELAGOS9 686a5e569650dcc9eecc2f5b1ad4cc0908e464cfea3c1f4f01a2c901dce88e6e
./stars_below --headless 16403752 PELAGOS9 "$(cat ticket.txt)"
```
