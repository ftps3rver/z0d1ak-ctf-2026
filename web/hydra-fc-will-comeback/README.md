# z0d1ak CTF 2026 — Hydra FC will come back

**Solved by:** ftps3rver
**Category:** Web Exploitation | **Points:** 245 | **Solves:** 20 | **Author:** TitanCode

---

## 1. Executive Summary

`Hydra FC will come back` hands out a spec document for a fictional floating-stadium VAR (Video Assistant Referee) system and a live JSON API implementing it, framed around one disputed goal: Shakes' equalizer for Supa Strikas against Hydra FC, ruled **OFFSIDE by 11mm**. The task is to overturn that ruling through the API itself, not by finding a bug in the server — the challenge is a pure **data-analysis / calibration-audit** problem. The spec's own `decision_model` gives the exact formula the VAR engine uses to turn raw multi-camera tracking coordinates into an offside margin, including a **per-sensor calibration correction term**. Pulling the match's `calibration` stream reveals that three of four pitch-side cameras have a `longitudinal_offset_mm` of `0`, while the fourth — `CAM-EAST`, running profile `EAST-MATCH-043` — carries a **48mm offset**. Cross-referencing the `audit` stream shows `CAM-EAST` was the sensor selected (by confidence) for the disputed player's key body point at the exact kick frame. Recomputing the offside line by hand with the correct (zero) offset flips the ruling from **+11mm offside to −37mm onside** — and submitting that corrected analysis through the `/api/v1/appeal` endpoint is what the challenge actually wants, not any kind of exploit.

**Flag:** `zdk{FE3lIN6_bAd_fOR_cRO47iA}`

---

## 2. Challenge Description

> Shakes' equalizer at Hydra FC's Floating Stadium was ruled offside by eleven millimetres.

Files: `hydra_var_telemetry_spec.v3.1.json` — a JSON Schema-flavored document describing the VAR system's coordinate convention, its offside decision algorithm, and its REST API surface. Instance: a JSON API at `https://offside-11mm-*.chals.z0d1ak.org` (rotating instance hostnames throughout the event).

The title itself is the thesis of the challenge: "will come back" — the goal is going to be reinstated, and the player's job is to prove *why* the original 11mm offside call was wrong, using the system's own documented rules against its own data.

---

## 3. Initial Reconnaissance

The spec file is the whole roadmap. Its `decision_model` block spells out, in plain JSON, exactly how the VAR engine computes an offside call:

```json
"kick_frame": {
  "operator": "all",
  "conditions": [
    {"field": "ball.acceleration_mps2", "operator": ">=", "value": 20},
    {"field": "ball.foot_ball_distance_mm", "operator": "<=", "value": 80}
  ]
},
"observation_fusion": {"group_by": "keypoint", "selection": "maximum_confidence"},
"calibration": {
  "output": "corrected_x_mm",
  "expression": "raw_x_mm + longitudinal_offset_mm + round((deck_pitch_deg - reference_pitch_deg) * mm_per_degree)"
},
"eligible_keypoints": ["head","left_shoulder","right_shoulder","torso","left_knee","right_knee","left_foot","right_foot"],
"player_line": "maximum corrected_x_mm among eligible keypoints",
"defender_line": "second-largest defending player_line",
"margin": {
  "expression": "attacking_player_line_mm - defender_line_mm",
  "offside_when": "> 0", "onside_when": "<= 0"
}
```

This is not flavor text describing an abstract system — it is the **literal, reproducible algorithm** the challenge's own backend runs. Every field named here (`ball.acceleration_mps2`, `raw_x_mm`, `longitudinal_offset_mm`, `deck_pitch_deg`, …) is a hint about exactly what to pull from the API next.

The `api.operations` block lists four endpoints:

```json
"list_fixtures":      {"method": "GET",  "path": "/fixtures?team={team}"},
"match_summary":      {"method": "GET",  "path": "/matches/{id}/summary"},
"compare_telemetry":  {"method": "POST", "path": "/compare"},   // match_ids[], streams[]
"submit_appeal":      {"method": "POST", "path": "/appeal"}     // match_id, kick_frame, bad_sensor, correct_profile, corrected_margin_mm
```

`submit_appeal`'s own required-field list is a second, even more direct roadmap: to win, we need to name the **bad sensor**, its **correct calibration profile**, and the **corrected margin**, for a specific **kick frame**.

```bash
curl -s "$BASE/api/v1/fixtures?team=hydra"
```
```json
{"fixtures":[
  {"id":"HYD-SS-FINAL","label":"Hydra FC v Supa Strikas","kind":"match","access":"public"},
  {"id":"HYD-CAL-EAST-042","label":"East Array Tide Calibration 042","kind":"calibration","access":"restricted"},
  {"id":"HYD-REHEARSAL-17","label":"Closed Stadium Rehearsal 17","kind":"rehearsal","access":"restricted"},
  {"id":"HYD-IU-LEAGUE","label":"Hydra FC v Invincible United","kind":"match","access":"public"}
]}
```

`HYD-SS-FINAL` — Hydra FC v Supa Strikas — is clearly the disputed match.

```bash
curl -s "$BASE/api/v1/matches/HYD-SS-FINAL/summary"
```
```json
{"id":"HYD-SS-FINAL","label":"Hydra FC v Supa Strikas","score":"1-0",
 "disputed_event":"Shakes equalizer","decision":"OFFSIDE",
 "reported_margin_mm":11,"attacking_direction":"+x",
 "system_profile":"EAST-MATCH-043"}
```

The summary hands over the exact reported margin (`11`, matching the title/description) and — critically — names the **calibration profile actually in force** for this match: `EAST-MATCH-043`.

---

## 4. Attack Surface / Important Observations

`POST /api/v1/compare` with `{"match_ids":["HYD-SS-FINAL"],"streams":["audit"]}` gives the operator's own log of what happened:

```json
{"streams":{"audit":[
  {"at_match_ms":5379420,"actor":"hydra-ops","action":"activate-profile",
   "sensor":"CAM-EAST","profile":"EAST-MATCH-043"},
  {"at_match_ms":5382110,"actor":"var-engine","action":"fuse-frame",
   "frame":154828,"result":"OFFSIDE"}
]}}
```

This nails down two facts at once: the **exact kick frame** (`154828`) the ruling was made on, and confirmation that `CAM-EAST` was running under `EAST-MATCH-043` at the time.

Requesting the `calibration` stream is where the actual bug in the *ruling* (not the server) surfaces:

```json
{"streams":{"calibration":[
  {"id":"NORTH-CAL-031","sensor":"CAM-NORTH","longitudinal_offset_mm":0, "reference_pitch_deg":0.18,"mm_per_degree":10,"status":"match-active"},
  {"id":"SOUTH-CAL-027","sensor":"CAM-SOUTH","longitudinal_offset_mm":0, "reference_pitch_deg":0.18,"mm_per_degree":10,"status":"match-active"},
  {"id":"EAST-MATCH-043","sensor":"CAM-EAST","longitudinal_offset_mm":48,"reference_pitch_deg":0.18,"mm_per_degree":10,"status":"match-active"},
  {"id":"WEST-CAL-019","sensor":"CAM-WEST","longitudinal_offset_mm":0, "reference_pitch_deg":0.18,"mm_per_degree":10,"status":"match-active"}
]}}
```

**Every camera except `CAM-EAST` has a zero longitudinal offset.** `CAM-EAST`'s active profile — the one confirmed by the audit log to be live at the disputed kick — is the single outlier at `+48mm`. That number, fed through the spec's own calibration formula, is large enough on its own to plausibly account for an "11mm offside" ruling that should have been onside.

`streams=["raw_tracking"]` returns all 17 tracking frames (154820–154836) bracketing the kick, each with the ball state and every player's per-sensor, per-keypoint observations (with a `confidence` score per sensor per keypoint — exactly the field `observation_fusion.selection: "maximum_confidence"` says to use). `streams=["deck_imu"]` returns `pitch_deg` per frame; at frame **154828** specifically, `pitch_deg = 0.18` — identical to every calibration profile's `reference_pitch_deg`, meaning the pitch-correction term of the formula is exactly `0` at the moment that matters, isolating `longitudinal_offset_mm` as the *only* variable that changes the outcome.

Requesting `calibration` for the two `restricted` fixtures (`HYD-CAL-EAST-042`, `HYD-REHEARSAL-17`) returns a clean `403 Forbidden` — these are out of scope, not an access-control bug to bypass; their only relevant role is that `HYD-CAL-EAST-042`'s fixture *label* ("East Array Tide Calibration 042") is what names the sensor family (`EAST-CAL-0xx`) that the correctly-calibrated profile should belong to.

---

## 5. Failed Attempts

No dead ends in the technical sense — the API has no injection points, no auth to bypass, and no hidden endpoints beyond what the spec documents. The one genuine trap is in the **appeal payload itself**: it would be easy to submit `bad_sensor` alone without recomputing an actual `corrected_margin_mm`, or to guess a margin (e.g. simply negating the reported `11` to `-11`) instead of running the spec's formula by hand end-to-end. The `submit_appeal` schema requires all four fields as a set — `match_id`, `kick_frame`, `bad_sensor`, `correct_profile`, `corrected_margin_mm` — and (as confirmed by the eventual success) the server appears to validate the margin against its own recomputation, not just accept any plausible-looking number.

---

## 6. Investigation — Building the Exploit

**Step 1 — Identify the kick frame and pull every player's per-keypoint data for it.**

From `raw_tracking`, frame `154828` is where `ball.acceleration_mps2 (24.8) >= 20` **and** `ball.foot_ball_distance_mm (42) <= 80` — satisfying the spec's `kick_frame` condition exactly, and matching the frame the `audit` log's `fuse-frame` event already named.

```python
for fr in frames:
    b = fr["ball"]
    if b["acceleration_mps2"] >= 20 and b["foot_ball_distance_mm"] <= 80:
        kick_frame = fr   # frame 154828
```

**Step 2 — Apply `observation_fusion` + `calibration` exactly as specified, per player.**

For every player, for every keypoint in `eligible_keypoints`, pick the sensor observation with the highest `confidence` (per spec: `group_by: keypoint, selection: maximum_confidence`), then apply the calibration expression using *that sensor's* active profile:

```python
eligible = ["head","left_shoulder","right_shoulder","torso",
            "left_knee","right_knee","left_foot","right_foot"]

def corrected_x(obs, sensor_offset, pitch_now, ref_pitch=0.18, mm_per_deg=10):
    return obs["raw_x_mm"] + sensor_offset + round((pitch_now - ref_pitch) * mm_per_deg)

OFFSETS = {"CAM-NORTH": 0, "CAM-SOUTH": 0, "CAM-EAST": 48, "CAM-WEST": 0}  # as-run

for player in kick_frame["players"]:
    best_per_kp = {}
    for kp in eligible:
        obs = max(player["keypoints"][kp], key=lambda o: o["confidence"])
        best_per_kp[kp] = corrected_x(obs, OFFSETS[obs["sensor"]], pitch_now=0.18)
    player_line = max(best_per_kp.values())   # spec: "player_line"
```

Running this over the kick frame's four players:

| Player | Team | `player_line` (as-run, `CAM-EAST` +48) | Winning keypoint / sensor |
|---|---|---|---|
| SHAKES | SUPA (attacker) | **1048** | right_shoulder / CAM-EAST (conf 0.99) |
| THE-PLUG | HYDRA | 1500 | left_shoulder / CAM-NORTH |
| SKIPPER | HYDRA | 1037 | left_knee / CAM-WEST |
| RIPPLE-WHITE | HYDRA | 900 | left_shoulder / CAM-SOUTH |

**Step 3 — Compute `defender_line` and the margin, exactly per spec.**

`defender_line` is the **second-largest** defending (HYDRA) `player_line` — not the largest, which is a deliberate reading trap (a naive "closest defender = biggest x" assumption picks THE-PLUG at 1500 and gets a wildly wrong, obviously-onside margin that the server won't accept):

```python
hydra_lines = sorted((p["line"] for p in hydra_players), reverse=True)
# [1500, 1037, 900]
defender_line = hydra_lines[1]   # 1037 (SKIPPER) -- the SECOND-largest, per spec
margin = attacker_line - defender_line   # 1048 - 1037 = +11
```

This reproduces the reported **+11mm OFFSIDE** ruling exactly by hand — confirming the formula and data are being read correctly before touching the "what's wrong with it" question.

**Step 4 — Recompute with the correct (zero) `CAM-EAST` offset.**

`SHAKES`'s winning keypoint (right_shoulder) came specifically from `CAM-EAST`, the one sensor running a non-zero offset. Re-running the exact same fusion/calibration with `CAM-EAST`'s offset corrected to `0` (matching every other camera, and matching what a profile in the `EAST-CAL-0xx` family — as named by the restricted calibration fixture — would carry):

```python
OFFSETS_FIXED = {"CAM-NORTH": 0, "CAM-SOUTH": 0, "CAM-EAST": 0, "CAM-WEST": 0}
# SHAKES's line drops from 1048 -> 1000 (loses the +48 CAM-EAST offset)
# Hydra defender lines are unaffected (none of their winning keypoints used CAM-EAST)
margin_fixed = 1000 - 1037   # = -37
```

**−37mm ⇒ ONSIDE** per the spec's own `margin.onside_when: "<= 0"` rule.

**Step 5 — Submit the appeal.**

```bash
curl -X POST "$BASE/api/v1/appeal" -H "Content-Type: application/json" -d '{
  "match_id": "HYD-SS-FINAL",
  "kick_frame": 154828,
  "bad_sensor": "CAM-EAST",
  "correct_profile": "EAST-CAL-042",
  "corrected_margin_mm": -37
}'
```
```json
{"status":"accepted","decision":"ONSIDE","flag":"zdk{FE3lIN6_bAd_fOR_cRO47iA}"}
```

Accepted on the first try — the four values (bad sensor, corrected profile name, exact recomputed margin, and the original kick frame) all had to agree with the server's own independent recomputation of the same formula.

---

## 7. Root Cause / Why This Chain Works

This challenge has no server-side vulnerability at all — it's a **spec-comprehension and calibration-audit** exercise dressed as a VAR controversy:

1. **The spec document is a literal, executable algorithm, not prose.** Every field name in `decision_model` (`ball.acceleration_mps2`, `raw_x_mm`, `longitudinal_offset_mm`, `deck_pitch_deg`) maps 1:1 to a field returned by `/compare` — the challenge rewards reading the schema as a program to re-implement, not as background flavor.
2. **A single miscalibrated sensor among several correctly-calibrated ones is a detectable statistical/structural outlier**, exactly like the reasoning that would apply to any real sensor-fusion QA process: three of four cameras agree on `longitudinal_offset_mm: 0`; the one that disagrees, cross-referenced against the audit log's `activate-profile` event, is exactly the sensor whose reading decided the disputed player's `player_line`.
3. **`defender_line` is explicitly the second-largest, not the largest** — a spec detail that's easy to misread once under time pressure, and one that flips the sign of the naive "closest defender" computation if gotten wrong.
4. **The restricted fixtures are context, not a bypass target.** `HYD-CAL-EAST-042`'s label supplies the *name* of the correctly-calibrated profile family (`EAST-CAL-0xx`) without needing to actually read its (403-gated) contents — the fixture list itself was the intended source for that detail.
5. **The appeal endpoint independently re-derives the margin server-side**, so the "exploit" is really just doing the VAR engine's own math correctly and by hand, with the one corrected input the audit trail flags — there's nothing to inject or forge, only a calculation to get exactly right.

---

## 8. Flag

```
zdk{FE3lIN6_bAd_fOR_cRO47iA}
```

---

## 9. Reconstruction Chain

```
hydra_var_telemetry_spec.v3.1.json
        |
        v
decision_model: kick_frame conditions, calibration formula,
                eligible_keypoints, defender_line = 2nd-largest, margin rule
api.operations: fixtures / match_summary / compare / appeal (required fields = roadmap)
        |
        v
GET /fixtures?team=hydra -> HYD-SS-FINAL (public, disputed match)
GET /matches/HYD-SS-FINAL/summary
        -> decision=OFFSIDE, reported_margin_mm=11, system_profile=EAST-MATCH-043
        |
        v
POST /compare streams=[audit]
        -> kick frame = 154828, CAM-EAST running profile EAST-MATCH-043 at kick time
POST /compare streams=[calibration]
        -> CAM-NORTH/SOUTH/WEST: offset=0   |   CAM-EAST (EAST-MATCH-043): offset=+48  <- outlier
POST /compare streams=[raw_tracking, deck_imu]
        -> per-sensor per-keypoint observations + confidences; pitch(154828)==reference_pitch (correction term = 0)
        |
        v
Reproduce reported ruling by hand:
        SHAKES player_line = 1048 (right_shoulder via CAM-EAST, +48 offset)
        HYDRA defender_line (2nd-largest) = 1037 (SKIPPER)
        margin = 1048 - 1037 = +11  ==  reported ruling  (confirms formula + data read correctly)
        |
        v
Recompute with CAM-EAST offset corrected to 0 (matching every other sensor):
        SHAKES player_line = 1000  ->  margin = 1000 - 1037 = -37  ->  ONSIDE
        |
        v
POST /appeal {match_id, kick_frame:154828, bad_sensor:CAM-EAST,
              correct_profile:EAST-CAL-042, corrected_margin_mm:-37}
        |
        v
{"status":"accepted","decision":"ONSIDE","flag":"zdk{FE3lIN6_bAd_fOR_cRO47iA}"}
```

---

## 10. Key Takeaways

- **A machine-readable spec attached to a web challenge is the solution's pseudocode.** `decision_model` wasn't documentation of the target system for context — every field and rule name in it corresponds exactly to live API output and had to be re-implemented byte-for-byte, including easy-to-miss details like "second-largest," not "largest."
- **Reproduce the reported (wrong) result first, by hand, before trying to fix it.** Getting the exact same `+11mm OFFSIDE` out of a manual recomputation is what confirms the formula, the fused observations, and the sensor selection are all being read correctly — only then is changing one input (the miscalibrated sensor) a meaningful, trustworthy experiment rather than a guess.
- **A calibration outlier reveals itself by comparison across otherwise-identical peers**, not by any single value looking obviously wrong in isolation — `+48mm` only stands out because three sibling cameras all independently report `0`.
- **Cross-reference an audit/event log against calibration data before assuming which sensor mattered.** The `activate-profile` audit event is what pins down that `CAM-EAST`'s bad profile was actually *live* at the disputed kick, rather than merely present in the calibration table as one option among several.
- **Restricted/403 resources can still be informationally useful via their metadata (labels, IDs) alone**, without needing to bypass the restriction — the calibration fixture's *name* was the missing piece (the correct profile's identity), not its (inaccessible) contents.
- **A validating endpoint that recomputes your submission server-side means the "exploit" is arithmetic, not injection.** There is no shortcut around correctly running the spec's own formula end-to-end.

---

## 11. Tooling Notes (for reproduction)

```bash
BASE="https://offside-11mm-<instance>.chals.z0d1ak.org"

# Recon
curl -s "$BASE/api/v1/fixtures?team=hydra"
curl -s "$BASE/api/v1/matches/HYD-SS-FINAL/summary"

# Pull every stream needed for the recomputation
curl -s -X POST "$BASE/api/v1/compare" -H "Content-Type: application/json" \
  -d '{"match_ids":["HYD-SS-FINAL"],"streams":["audit"]}'
curl -s -X POST "$BASE/api/v1/compare" -H "Content-Type: application/json" \
  -d '{"match_ids":["HYD-SS-FINAL"],"streams":["calibration"]}'
curl -s -X POST "$BASE/api/v1/compare" -H "Content-Type: application/json" \
  -d '{"match_ids":["HYD-SS-FINAL"],"streams":["raw_tracking"]}'
curl -s -X POST "$BASE/api/v1/compare" -H "Content-Type: application/json" \
  -d '{"match_ids":["HYD-SS-FINAL"],"streams":["deck_imu"]}'
```

```python
# Recompute the offside margin per the spec's decision_model, with a swappable
# per-sensor offset table so the "as-run" and "corrected" cases are one flag away.

ELIGIBLE = ["head","left_shoulder","right_shoulder","torso",
            "left_knee","right_knee","left_foot","right_foot"]

def corrected_x(obs, offsets, pitch_now, ref_pitch=0.18, mm_per_deg=10):
    return obs["raw_x_mm"] + offsets[obs["sensor"]] + round((pitch_now - ref_pitch) * mm_per_deg)

def player_line(player, offsets, pitch_now):
    vals = []
    for kp in ELIGIBLE:
        obs = max(player["keypoints"][kp], key=lambda o: o["confidence"])
        vals.append(corrected_x(obs, offsets, pitch_now))
    return max(vals)

def margin(frame, attacker_id, defending_team, offsets):
    pitch_now = 0.18  # from deck_imu at the kick frame
    lines = {p["id"]: player_line(p, offsets, pitch_now) for p in frame["players"]}
    attacker = lines[attacker_id]
    defenders = sorted((v for p, v in lines.items()
                         if next(x for x in frame["players"] if x["id"] == p)["team"] == defending_team),
                        reverse=True)
    defender_line = defenders[1]           # spec: SECOND-largest
    return attacker - defender_line

as_run     = {"CAM-NORTH": 0, "CAM-SOUTH": 0, "CAM-EAST": 48, "CAM-WEST": 0}
corrected  = {"CAM-NORTH": 0, "CAM-SOUTH": 0, "CAM-EAST":  0, "CAM-WEST": 0}

print(margin(kick_frame, "SHAKES", "HYDRA", as_run))     # -> 11   (matches reported OFFSIDE)
print(margin(kick_frame, "SHAKES", "HYDRA", corrected))  # -> -37  (ONSIDE)
```

```bash
# Submit the corrected finding
curl -s -X POST "$BASE/api/v1/appeal" -H "Content-Type: application/json" -d '{
  "match_id": "HYD-SS-FINAL",
  "kick_frame": 154828,
  "bad_sensor": "CAM-EAST",
  "correct_profile": "EAST-CAL-042",
  "corrected_margin_mm": -37
}'
# -> {"status":"accepted","decision":"ONSIDE","flag":"zdk{FE3lIN6_bAd_fOR_cRO47iA}"}
```
