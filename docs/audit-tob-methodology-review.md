# DKLs23 Self-Audit — Trail of Bits Methodology Pass (`kawasekit-dkls23`)

> **The honest ceiling (read first).** This is a **self-audit that emulates** the methodology of Trail of
> Bits' public *Silence Laboratories Silent Shard* DKLs23 review (2024-02) — its 15 finding classes, its
> review-question set, its side-channel/RVOLE method, its maturity rubric. **Emulating their methodology
> reaches their *checklist floor*; it does not confer their *assurance*.** No independence, no liability, no
> **measured** side-channels (ToB ran timing analysis; this pass reasons about source), no discovery of
> *novel* breaks (ToB themselves flag the DKLs23 "framing"-attack class as possibly-incomplete). It does
> **not** clear a mainnet / real-value gate; a third-party cryptographic audit remains MANDATORY.
>
> **⏱ Point-in-time.** Verified against `dev` at the time of writing; line numbers are as-of that baseline
> and are not drift-checked (the living model is [`audit-context.md`](audit-context.md)).

---

## §1. Executive Summary

**Verdict: `Value-gating-adjacent — one High key-destruction-class gap (H1) to close (or justify) before the paid audit; no key-extraction defect found in the core; third-party audit still MANDATORY.`**

> **Update (2026-06-18):** the one High gap, **H1**, is now **RESOLVED** (PR #38, fix approach 1 — in-core
> Fiat-Shamir root-agreement echo). See §3 H1 for the resolution note. The point-in-time analysis below is
> kept as-written; the third-party crypto audit remains MANDATORY and is **not** cleared by this fix.

Walking all 15 TOB-SILA classes + the side-channel and RVOLE appendices against the core, the fork's own
second-round hardening had **already converged on ToB's two High findings** — selective-abort (TOB-SILA-12 =
the fork's H1) and setup-threshold (TOB-SILA-15 = M2) are both **COVERED** — and on most of the Medium/Info
classes. The pass found **one genuinely new gap the self-audit missed** (chain-code / session-id cross-party
*agreement*, TOB-SILA-7+8), plus a handful of pre-audit hardening items, and confirmed that the
**transport-layer** classes (TOB-SILA-6/9/14) live in the out-of-scope backend and must be carried there.

**Strengths (genuine):**
- **Selective-abort is correctly handled (TOB-SILA-12 / H1).** The leak-bearing COTe/`verify_r` failure
  returns a typed, party-attributed `Abort::ban(counterparty)` via a machine-readable `error.kind` — *not* a
  panic (SilentShard's exact High bug). Benign dimension errors downgrade to recoverable.
- **No attacker-reachable panic on the protocol path** (TOB-SILA-3). DKG degenerate inputs return typed
  `Abort` (trivial-PK / trivial-share guards); the residual `.expect`s are infallible length-invariants or
  the M6-gated hex path. SilentShard's `feldman_verify → None → .expect()` has no analogue (no Feldman
  vector exists — DKG uses one DLog proof per party + Lagrange-window consistency).
- **Canonical, length-delimited `tagged_hash`** for every oracle/consistency digest (no SilentShard-style
  hand-rolled XOF substitute), constant-time `ct_eq` comparisons, and a **constant-time `field_mul`** (M1).
- **Pairwise OT-extension session ids** (TOB-SILA-5) and **sid-bound masking hashes** (TOB-SILA-11b) —
  both gaps in SilentShard, both present here.
- **Genuine adversarial tests** for the leak-bearing checks (tampered `verify_r`, COTe, γ_u, deferred-detection
  refresh) — unlike SilentShard's positive-only suite — and **custody-gated `re_key`** (`compile_error`).
- **Auditor-grade paper provenance** (every OT piece cited with eprint + figure) and a clean,
  byte-identical-to-upstream protocol core.

**Value-gating themes:** one — **H1 (chain-code / session-id agreement)**: divergence between honest parties
resolves to an *irreversible ban* (key-destruction class), not a recoverable/identifiable abort, because the
in-core agreement check ToB requires (bind the agreed root into a Fiat-Shamir transcript) is absent.
Exploitability for the immediate 2-of-2 routes through the (out-of-scope) transport; at the library level
(general t-of-n) an equivocating participant triggers it directly. It is the one item to fix or explicitly
justify before the paid audit.

## §2. Findings matrix

| ID | Severity | Class | Title | Est. effort | Value-gating |
|---|---|---|---|---|---|
| H1 ✅ | 🟠 High | `[ssid]` `[abort]` | Chain-code / session-id cross-party agreement unverified → honest-party ban (TOB-SILA-7+8) — **RESOLVED PR #38** | 1–2d | strongly rec. (library-level) |
| M1 ✅ | 🟡 Medium | `[const-time]` | Three residual secret-choice-bit branches beyond `field_mul` (TOB appendix D) — **RESOLVED PR #40** | 1d | pre-audit |
| M2 | 🟡 Medium | `[ssid]` | No early protocol-version-mismatch abort (TOB-SILA-11a) | 0.5d | pre-audit |
| L1 | 🟢 Low | `[supply-chain]` `[boundary]` | RVOLE/OTE 256-vs-128 security-level over-provisioning undocumented (TOB appendix F) | 0.25d | polish (doc) |
| L2 | 🟢 Low | `[validation]` | Missing negative tests: γ_v ban + base-OT `s≠0`; no property-based testing | 0.5d | pre-audit |
| L3 | 🟢 Low | `[supply-chain]` | `cargo-llvm-cov` + `dylint` not in CI (ToB's tooling) | 0.25d | polish |
| L4 | 🟢 Low | `[validation]` | `zip` (not `zip_eq`) at the COTe consistency fold | 0.1d | polish |

**Total ≈ 4–5 engineer-days.** Close **H1** (and **L2**'s γ_v/`s≠0` tests) before commissioning the audit — H1
is the one that changes the artifact's robustness story. M1/M2/L1/L3/L4 are hardening/polish the auditor would
otherwise note. **Carry to the backend** (not closeable in this crate): TOB-SILA-6 (P2P nonce reuse), -9
(cross-session replay / `InstanceId`), -14 (abort-on-inauthentic-message), and the transport origin of H1.
**Reserved for the paid audit regardless:** the OT/VOLE multiplication soundness + selective-failure
resistance, the SoftSpoken sub-protocol-combination proof (TOB-SILA-13), the fast-refresh proactive-security
argument, and all *measured* side-channel work.

## §3. Per-finding detail

### H1. Chain-code / session-id cross-party agreement is unverified in-core `[ssid]` `[abort]`

> **✅ RESOLVED (2026-06-18, PR #38, fix approach 1).** `sign_phase1` now broadcasts a Fiat-Shamir echo
> `tagged_hash(TAG_ROOT_AGREEMENT, [session_id ‖ sign_id ‖ chain_code])` on `TransmitPhase1to2`, and
> `sign_phase2` constant-time cross-checks every counterparty's echo against its own **before** any
> leak-bearing OT/multiplication → `AbortReason::RootAgreementMismatch` (**recoverable + identifiable**,
> not `BanCounterparty`). Two negative tests drive divergent `chain_code` / `session_id` and assert the
> recoverable abort fires before the phase-2 ban. This closes the **honest-divergence** case; a *malicious*
> equivocator forging a matching echo while signing under a different root still bans at phase 2 — full
> equivocation resistance remains the authenticated-broadcast / transport layer's job (TOB-SILA-6/9/14,
> backend). The third-party crypto audit remains MANDATORY. *(The line numbers below are as-of-review and
> predate the fix; current locations are in `docs/audit-context.md` §3.7.)*

**Problem.** The root chain code is a committed-XOR: each party commits then reveals its `aux_chain_code`
(`dkg.rs:552-553`, `:709-713`), and every party verifies *each counterparty's* commitment-vs-opening and XORs
locally (`dkg.rs:1093-1109`). **The assembled root is never cross-verified between parties**, and `session_id`
flows into the keyshare with no agreement (or even length) check at DKG (`dkg.rs:480/508/594/762`). Binding ≠
agreement: a party (or a relay) that delivers a *different* valid `(commitment, opening)` view to different
honest parties makes them compute different roots, and **DKG raises nothing**. The divergence first surfaces
at signing's leak-bearing phase-2 COTe consistency check — `chain_code`/`session_id` feed `mul_sid` →
`ote_sid` → the OTE `chi` derivation (`signing.rs:351-359` → `multiplication.rs:316` → `extension.rs:314-318`)
— which fails → `ErrorOT::consistency` → **`Abort::ban(counterparty)`** (`signing.rs:581`). The only entry
guard, L1, checks **length not agreement** (`signing.rs:263-270`), so a same-length divergent view sails
through. ToB's accepted fix for the identical SilentShard issue (TOB-SILA-7) was to **bind the chain code
into the Fiat-Shamir transcript** so disagreement is an *early, identifiable* abort.

**Impact.** Key-destruction class: two honest parties holding divergent views **ban each other** at the
leak-bearing check; repeat until the threshold is unreachable → permanent inability to sign (for a 2-of-2,
fund-lock). The fault is *non-identifiable* (an honest party is blamed). For the immediate 2-of-2 product the
trigger is a malicious relay/transport (→ backend, ToB-SILA-6/9 class); at the **library level (t-of-n ≥ 3)**
a malicious *participant* equivocating the broadcast triggers it directly — within the malicious-minority
key-destruction model ToB rates this High.

**Fix approach.** (1, recommended) In-core, ToB-style: bind the agreed root `chain_code` (and the final
`session_id`) into a Fiat-Shamir transcript / an early echo-hash exchanged right after reveal, and **abort
recoverably + identifiably** on mismatch — *before* any leak-bearing check. (2) Add an explicit cross-party
equality confirmation round on the assembled root. (3, weakest) Document that agreement is delegated to a
trusted broadcast layer and require the backend to guarantee it — only acceptable if the backend's review
proves the relay cannot equivocate. Prefer (1): it removes the dependence on an out-of-scope assumption and
future-proofs the general t-of-n library.

**Done definition.** A DKG/signing entry path detects a chain-code/session-id view mismatch and returns a
*recoverable, identifiable* abort (not `BanCounterparty`); a negative test drives two parties with divergent
roots and asserts the recoverable abort fires *before* phase-2; `grep` shows the agreed root bound into an
FS transcript or an explicit equality check.

**Claude Code prompt**
````
In kawasekit-dkls23, the DKG root chain code (committed-XOR, dkg.rs:1093-1109) and the keyshare session_id
are never cross-verified for agreement between parties; a divergent-but-valid view currently surfaces only at
signing's leak-bearing phase-2 COTe check and triggers Abort::ban (signing.rs:581) — banning an honest party
(key-destruction). This mirrors Trail of Bits TOB-SILA-7/8. Using TDD: (1) write a failing test that drives a
2-party DKG+sign where the two parties end with different chain_code/session_id and assert that signing
returns a RECOVERABLE, identifiable abort BEFORE the phase-2 ban (not BanCounterparty). (2) Implement the ToB
fix: bind the agreed root chain_code (and final session_id) into a Fiat-Shamir transcript / early echo-hash
and abort recoverably on mismatch. Keep the change additive; do not weaken any existing check. Run cargo test.
do not commit — leave the diff for PR review.
````

### M1. Residual secret-choice-bit branches beyond `field_mul` `[const-time]`

> **✅ RESOLVED (2026-06-20, PR #40).** All three secret-choice-bit branches now compute both sides and
> `subtle::ConditionallySelectable::conditional_select` by a `Choice` derived from the bit — no
> data-dependent branch remains: `extension.rs` `t_b`, `multiplication.rs` gadget-fold `b`, and the
> `verify_u` entry. Full lib suite green (behaviour unchanged). The *measured*-timing verdict stays
> paid-audit-reserved. *(Line numbers below are as-of-review; current locations in `docs/audit-context.md` §3.2.)*

**Problem.** M1 made the GF(2²⁰⁸) `field_mul` comb branch-free (`extension.rs:917-921`, verified). But three
production paths still branch on the receiver's **secret OT choice bits**: `extension.rs:804`
(`if choice_bits[j] { t_b_j = tau[j] + t_b_j }`), `multiplication.rs:535` (`if current_bit { b += public_gadget[i] }`),
`multiplication.rs:669` (`if choice_bits[j] { entry += verify_u[i] }`). These are milder than SilentShard's
`eval_pprf` (no secret-indexed write, no skipped iteration — loop indices are public), but they are
data-dependent control flow on a secret.

**Impact.** Potential local timing side-channel on the reused OT correlation; same *class* as the ToB
appendix-D finding. Practical exploitability is low (local attacker, heavy noise) and **unmeasurable from
source** — the verdict is the paid audit's.

**Fix approach.** Replace each `if bit { x += y }` with a `subtle`-style constant-time conditional add/select
(compute both, select by `Choice`), as M1 did for `field_mul`. **Done:** `grep` shows no secret-bit `if` on
these lines; behaviour unchanged (tests green). Note in the review that measured timing stays paid-audit-reserved.

**Claude Code prompt**
````
In kawasekit-dkls23, three production paths branch on secret OT choice bits: extension.rs:804,
multiplication.rs:535, multiplication.rs:669. Using TDD (the existing multiplication/OTE tests must stay
green), replace each secret-dependent `if bit { acc += val }` with a constant-time subtle::ConditionalSelect
/ Choice-masked add (compute unconditionally, select by the secret Choice), mirroring the field_mul M1 fix.
Behaviour identical; no secret-dependent branch remains on those lines. Run cargo test.
do not commit — leave the diff for PR review.
````

### M2. No early protocol-version-mismatch abort `[ssid]`

**Problem.** Oracle tags are versioned (`b".../v1"`) and centralized (`oracle_tags.rs:7-69`, uniqueness-tested),
but there is **no runtime protocol-version field / handshake**. A version/tag mismatch between parties
running different library versions surfaces only *implicitly* as a later consistency-fold or proof failure —
not as an early, identifiable abort. ToB's TOB-SILA-11 recommends binding a library version so a mismatch
aborts early (important after a security fix).

**Impact.** Defense-in-depth / robustness: cross-version interaction degrades to an opaque failure (and, given
H1's machinery, possibly a ban) instead of a clear "version mismatch." Not key-affecting.

**Fix approach.** Add a protocol-version constant bound into an early transcript / setup check so mismatched
versions abort identifiably. **Done:** two parties with different version constants abort with a dedicated
reason; test asserts it.

**Claude Code prompt**
````
In kawasekit-dkls23, add a protocol-version constant and bind it into an early DKG/sign setup check so two
parties on different library versions abort with a dedicated, identifiable AbortReason (not an opaque later
consistency failure). TDD: failing test for version mismatch first, then implement. cargo test.
do not commit — leave the diff for PR review.
````

### L1. RVOLE/OTE 256-vs-128 security-level over-provisioning undocumented `[supply-chain]` `[boundary]`

**Problem.** `RAW_SECURITY = KAPPA = lambda_c = 256` (`lib.rs:39-41`, `extension.rs:63`) while the curve
(secp256k1/p256) and hash (SHA-256) deliver ~128-bit computational security — the same over-provisioning ToB
flagged for SilentShard (λc=256 over 128-bit primitives). The parameterization is **internally consistent**
(the `208 = 128 + 80` split is a *statistical* KOS soundness budget, and 256 is the DKLs19 seed/correlation
width, not an asserted 256-bit computational floor), but **no doc states this** — a reader could misread 256
as a security claim.

**Fix approach.** One paragraph in `lib.rs` / `audit-context.md` clarifying that `KAPPA=256` is the seed/correlation
count, `STAT_SECURITY=80` is the statistical soundness, and computational security tracks the curve (~128-bit).
**Done:** the constants block carries the note; no number changes. (Adequacy of the choice stays paid-audit-reserved.)

### L2. Missing negative tests + no property-based testing `[validation]`

**Problem.** The leak-bearing checks are well covered, but two spec-mandated ban conditions have **no negative
test**: the γ_v check (`OtConsistencyCheckFailed`, `signing.rs:828-832` — only γ_u is tested) and the base-OT
`s≠0` invariant (`base.rs:80-83`). And there is **no `proptest`/property-based testing** anywhere — every
adversarial test is a single hand-crafted tamper. ToB's headline process recommendation is "a unit test for
*every* paper-specified check" + randomized negative testing.

**Fix approach.** Add the two missing negative tests; introduce `proptest` for malformed-message breadth
(empty/short/long vectors, identity points, out-of-range scalars/indices). **Done:** every leak-bearing ban
condition has a negative test; `proptest` exercises the deserialize/validate boundary.

### L3. ToB tooling absent from CI `[supply-chain]`

**Problem.** `cargo-llvm-cov` and `cargo-dylint` are not installed/wired (`cargo-audit` is, via `supply-chain.yml`).
ToB used coverage to find untested branches (the error/abort arms negative tests miss) and Dylint for Rust
lints. **Fix approach.** Add a `cargo llvm-cov` CI job (gate or report on the error/abort arms) and a `dylint`
run. **Done:** both run in CI; the coverage report flags any untested abort arm.

### L4. `zip` (not `zip_eq`) at the consistency fold `[validation]`

**Problem.** `extension.rs:361` uses `.zip()` (silent-truncation) in the COTe consistency fold. The two
vectors are equal-length by construction (KAPPA), so this is not exploitable, but ToB's code-quality
recommendation (the root mechanic of TOB-SILA-2) is to prefer `zip_eq`/`zip_longest` everywhere. **Fix:**
`zip` → `zip_eq`. **Done:** `grep` shows no bare `zip` on a wire-derived path.

## §4. Recommended work sequence

- **Sprint 1 — before the paid audit (robustness-changing):** H1 (chain-code/session-id agreement) and L2's
  γ_v + `s≠0` negative tests. These change what the auditor sees and close the one key-destruction-class gap.
- **Sprint 2 — pre-audit hardening:** M1 (const-time the three secret-bit branches), M2 (version-mismatch
  abort), L3 (coverage + dylint in CI).
- **Sprint 3 — polish:** L1 (document the security-level over-provisioning), L4 (`zip_eq`), proptest breadth.
- **Carry to the backend review:** TOB-SILA-6 (P2P nonce reuse → directional keys), -9 (replay → bind final
  sid into message-ID / unique `InstanceId`), -14 (drop-don't-abort on inauthentic message), and H1's
  transport trigger.
- **The paid audit must still cover regardless:** OT/VOLE multiplication soundness + selective-failure
  resistance; the SoftSpoken KOS+DKLs18+Roy22+FS combination (TOB-SILA-13, *Partially Resolved* even for
  SilentShard); the fast-refresh proactive-security argument; and *measured* side-channels.

## §5. PR review criteria

Each PR closing a finding: names the finding ID (H1/M1/…) **and** the TOB-SILA class; checks the
Done-definition items; for H1, records the negative test proving the *recoverable* abort fires before the
phase-2 ban; for M1, records the `grep` showing no secret-bit `if` remains on the three lines; keeps the
protocol math byte-identical to upstream (additive change only); runs `cargo test` + the `docs-citations`
lint and records output.

---

## Appendix A — TOB-SILA coverage matrix

| TOB-SILA | Class | Verdict | Evidence / note |
|---|---|---|---|
| 1 DKG committed-poly length | `[validation]` | **COVERED (N/A by design)** | no Feldman vector; one DLog proof/party + Lagrange-window consistency (`dkg.rs:417-459`) |
| 2 ZK-proof verification skippable | `[validation]` | **COVERED** | R=64 length gate before verify (`proofs.rs:378`); step5 demands a point per index |
| 3 malicious DKG panic | `[rust-safety]` | **COVERED** | trivial-PK/share guards (`dkg.rs:789-804`); no `feldman_verify` panic analogue |
| 4 proactive model unspecified | `[keygen]` | **COVERED** | model + zero-constant + zeroize documented (`refresh.rs:1-60,188,736`); formal proof reserved |
| 5 non-pairwise OTE sid | `[ssid]` | **COVERED** | pairwise `mul_sid` threads into PRG/chi/randomize (`signing.rs:351-359`→`extension.rs:266+`) |
| 6 P2P nonce reuse (HIGH) | `[boundary]` | **N/A-scope → backend** | messaging/AEAD is the backend (`libtss`), not this crate |
| 7 root chain-code agreement | `[validation]` | **GAP → H1** | committed-XOR binds each party to one value; cross-party agreement unverified (`dkg.rs:1093-1109`) |
| 8 late ssid → mutual ban (Med) | `[ssid]` `[abort]` | **GAP → H1** | divergence resolves to leak-bearing ban (`signing.rs:581`), not recoverable; L1 checks length only |
| 9 cross-session replay | `[ssid]` | **N/A-scope → backend** | message-ID/`InstanceId` is transport; core sid binding present |
| 10 DSG sid not tied to keygen | `[ssid]` | **COVERED** | signing sid binds keygen `session_id` + `chain_code` (`signing.rs:351-413`) |
| 11 domain separation | `[ssid]` | **partial** | (a) GAP — no early version-mismatch abort → M2; (b) COVERED — masking hashes sid-bound |
| 12 selective abort (HIGH) | `[abort]` | **COVERED** | H1: typed party-attributed ban, no panic (`signing.rs:575-597,783-834`; `ot.rs`/`multiplication.rs` kinds) |
| 13 sub-protocol combining | `[protocol]` | **COVERED (provenance)** | auditor-grade provenance (`extension.rs:1-37`); combined soundness reserved |
| 14 abort on inauthentic msg | `[validation]` | **N/A-scope → backend** | message auth is transport |
| 15 setup verifies threshold | `[validation]` | **COVERED** | M2 + `WrongCounterpartyCount` vs keyshare `t` (`signing.rs:272-281`) |
| Appendix D side-channel | `[const-time]` | **partial** | `field_mul` COVERED (M1); 3 residual secret-bit branches → M1-finding; no PPRF (N/A for `eval_pprf`) |
| Appendix F RVOLE | `[boundary]` | **partial** | typos N/A (uses DKLs19 Prot1 + DKLs23 §5.1); digest COVERED (length-delimited); 256-vs-128 → L1 |

## Appendix B — Codebase maturity rubric (ToB categories)

| Category | Rating | Justification |
|---|---|---|
| Arithmetic | **Strong** | `k256` scalar ops, validated `Parameters`, constant-time `field_mul` (M1) |
| Auditing | **N/A** | library provides no audit/logging surface (correct for a crypto core) |
| Authentication / Access | **N/A** | auth/access is the transport layer, out of this crate |
| Complexity management | **Satisfactory** | clear per-component modules; curve-generic; documented |
| Cryptography & key management | **Moderate** | strong primitives + H1/M1/M2/M3 hardening, but the SILA-7/8 agreement gap, the 256-vs-128 doc gap, and the 3 side-channel residuals |
| Documentation | **Satisfactory** | auditor-grade paper provenance + `audit-context`/`FORK`; minor: proactive cross-epoch subtlety + 256-vs-128 unflagged |
| Memory safety & error handling | **Satisfactory→Strong** | `#![forbid(unsafe_code)]`, no attacker-reachable panic (M6/L3), typed kind-aware aborts (H1) — better than SilentShard's *Moderate* |
| Testing & verification | **Moderate** | genuine adversarial tests for leak-bearing checks (better than SilentShard's positive-only) but γ_v/`s≠0` gaps, no property-based testing, no coverage tooling |

## Appendix C — Empirical spot-check

| Check | Method | Result |
|---|---|---|
| ToB tooling present | `command -v cargo-audit/llvm-cov/dylint` | `cargo-audit` ✅; `cargo-llvm-cov`/`dylint` ❌ → L3 |
| attacker-reachable panic | `grep expect/panic/unreachable` (non-test) on protocol paths | ✅ none (drivers + invariant-`expect` + M6-gated) |
| `re_key` custody gated | `grep compile_error`/`cfg` in `lib.rs`/`re_key.rs` | ✅ `compile_error!` on prod + wasm32 |
| `zip` on wire path | `grep zip` `dkls23-core/src` | one (const-time fold, equal-length) → L4 |
| negative tests | `grep 'fn test_.*(malformed|tampered|banned|trivial)'` | ✅ 7 files; **no `proptest`** → L2 |
| H1 ban is kind-aware | read `signing.rs:575-597,783-834` | ✅ `match error.kind`, party-attributed |
| chain-code agreement | read `dkg.rs:1093-1109`, `signing.rs:263-270` | ❌ cross-party agreement unverified → H1 |
| pairwise OTE sid | trace `mul_sid → ote_sid → chi/prg` | ✅ pairwise (`signing.rs:351-359`→`extension.rs:266+`) |

*This appendix is what keeps the review honest about being a self-audit, not an audit.*
