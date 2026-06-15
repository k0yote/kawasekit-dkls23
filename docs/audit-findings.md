# DKLs23 — Self-Audit Findings (`kawasekit-dkls23`)

CTO-class self-audit of the DKLs23 threshold-ECDSA core. Companion to the
context model in [`audit-context.md`](audit-context.md). Reviewer persona: external
cryptographer-and-Rust peer doing the rigorous pass *before* a paid audit is commissioned.

> **⏱ Historical baseline — point-in-time findings.** Recorded *during* the self-audit against the
> **pre-hardening** tree; the line numbers here are as-of that baseline. **The in-repo findings have since
> been implemented** (H1, M1–M4, M6, L1, L3, L4 across PRs #15–#25). For the finding→current-location map
> see [`audit-context.md`](audit-context.md) §1 "Second self-audit round" and `FORK.md`. This report is a
> historical record and is **not** drift-checked against current source (the living `audit-context.md` is
> — issue #27); read its line numbers as historical.

---

## §1. Executive Summary

> **The honest ceiling (read first).** This is a **self-audit**, not a third-party cryptographic
> audit. It raises the floor — catching catchable issues, enforcing the project's invariants, and
> checking the code against the DKLs23 paper — and it lowers the cost/surface of the eventual paid
> audit. It is **NOT a substitute for that audit and NEVER clears a mainnet / real-value gate.**
> Threshold-ECDSA bugs are precisely the class expert humans with specialized tooling have missed
> in *audited* libraries (TSSHOCK, BitForge, CVE-2025-66016/66017, Trail of Bits × Silence Labs
> DKLs). An LLM-driven review is reliable for known-vuln-class checks, invariant enforcement,
> paper-deviation, Rust/secret safety, and supply-chain — **not** for discovering novel
> cryptographic weaknesses, formal soundness, or measured side-channels.

**Verdict: `No value-gating issues found in self-audit — a third-party cryptographic audit remains MANDATORY before mainnet / real value.`**

This is *not* a clean bill of health. It means: walking the known DKLs/threshold-ECDSA failure classes
and the Rust-safety classes, I found **no Critical** (key-extraction / forgery / silent single-party
custody / share-loss) defect that the fork's self-audit hardening (M1/M2/M3/H1/C1/A4) left open. The
hardening is real and correctly placed. What remains is **one High** (the abort/error taxonomy is too
coarse for a 2-of-2 to handle aborts safely) plus pre-audit hardening (const-time, an incomplete
zeroization sweep, fast-refresh assurance, finishing/malleability contract, RC-crypto supply chain).
The paid audit must still cover the cryptographic core in full — especially the OT/VOLE multiplication,
the signing consistency relations, and the side-channel surface, which a self-audit cannot clear.

**Strengths (genuine):**
- **Fork delta verified clean against upstream `c9c407e` (0xCarbon v0.5.1 base).** Diffing the full delta
  (`git diff c9c407e..ddaa091`) shows the hardening is **purely additive**: every deletion in the seven
  changed `.rs` files is a `derive`/`let`/`&self`→`&mut self` line *replaced by its hardened form*
  (Zeroize, eager-wipe, or the M3-checked share). **No upstream validation, consistency check, or abort
  was removed or weakened.** The protocol math — `signing.rs`, `multiplication.rs`, `ot/extension.rs`,
  `zero_shares.rs`, `derivation.rs` — is **byte-identical to upstream** (see the Fork-delta section below).
- `#![forbid(unsafe_code)]` crate-wide; **zero `unsafe`**. The classic memory-safety class is closed by construction.
- The self-audit hardening is present and correctly located: **M1** identity rejection at every proof boundary (`proofs.rs:388/667`), **M2** `Parameters` re-validated on deserialize (`protocols.rs:117`), **M3** trivial-share rejection (`refresh.rs:700/1180`), **C1** trusted-dealer `re_key` cfg-gated out of production (verified: every call-site is in `#[cfg(test)]`), **A4** `compile_error!` guards + CI assertion of the bad build combos.
- **Verify-before-return**: `sign_phase4` recomputes and verifies the full ECDSA signature against `self.pk` before returning (`signing.rs:906`) — a forged/inconsistent aggregate cannot escape.
- **Constant-time comparisons** (`subtle::ct_eq`) on every secret-dependent equality: commitments, Fischlin hashes, OTE/mul consistency values (`commits.rs:43`, `proofs.rs:441/556`, `extension.rs:359`, `multiplication.rs:645`).
- The leak-bearing consistency checks (COTe, `verify_r`, γ_u/γ_v) all correctly map to `AbortKind::BanCounterparty`; DKG/refresh correctly use `recoverable` (no reusable OT state exists there). No *under*-banning found.
- Domain-separated, versioned, uniqueness-tested oracle tags; length-delimited `tagged_hash`.

**Value-gating themes:** none found in this crate. The closest is the **abort-taxonomy coarseness (H1)** —
the core is fail-safe (it *over*-bans), but the String-only error type forces an integrator into an
unsafe trade-off, one direction of which (suppress bans to avoid 2-of-2 lock-outs) reintroduces the
OT-reuse key-extraction risk. Fix the taxonomy before the paid audit so the auditor reviews the final shape.

### Fork-delta verification (vs upstream `0xCarbon` `c9c407e`, v0.5.1 base)

The checklist calls the fork delta *the highest-suspicion code in the whole review*. I diffed the full
delta against the upstream baseline and it comes back **clean and purely additive**:

- **No undocumented crypto-core change.** Exactly seven `.rs` files changed (`lib.rs`, `protocols.rs`,
  `dkg.rs`, `re_key.rs`, `refresh.rs`, `ot/base.rs`, `proofs.rs`) — the precise FORK.md list, nothing more.
- **No upstream check removed or weakened.** Every non-comment deletion is a `#[derive(...)]`, a `let`, an
  inline assignment, or a `&self` signature **replaced by its hardened version** (add `Zeroize`/
  `ZeroizeOnDrop`, wrap in `Zeroizing`, `&mut self` for eager old-`Party` wipe, or compute the
  M3-checked `refreshed_poly_point` before use). M1 (identity rejection) and C1 (`#[cfg]` gate) are pure additions.
- **Protocol math untouched.** `signing.rs`, `multiplication.rs`, `ot/extension.rs`, `zero_shares.rs`,
  `derivation.rs`, `commits.rs`, `hashes.rs` are **byte-identical to upstream** — the fork changes no OT/VOLE,
  signing-assembly, or wire-format logic. This matches FORK.md's claim and is now empirically confirmed.

**Finding attribution (where each finding actually lives):** because the fork doesn't touch the math, the
*majority of findings are inherited from upstream 0xCarbon code*, not fork-introduced:

| Finding | Lives in | Origin |
|---|---|---|
| H1 (abort taxonomy) | `signing.rs`, `ot.rs`/`multiplication.rs` error types | **upstream** (inherited) |
| M1 (`field_mul` const-time) | `ot/extension.rs` | **upstream** (inherited) |
| M2 (EncProof nonce zeroize) | `proofs.rs` | **fork** — incomplete H1 sweep (fork hardened DLog nonce, missed CP/Enc) |
| M3 (fast-refresh check/test) | `refresh.rs` | **upstream** algorithm; fork added M3/H1 but not a fast-refresh consistency check/test |
| M4 (low-S optional) | `signing.rs` | **upstream** (inherited) |
| M5 (RC crypto / yanked) | dependency tree | **fork-relevant** (pin policy) |
| M6 (`x_coord` panic) | `signing.rs` | **upstream** (inherited) |
| L1/L3/L4 | `signing.rs`/`dkg.rs`/`multiplication.rs` | **upstream** (inherited) |
| L2 (wasm RNG) | backend binary | **out of scope** (backend) |

Implication for audit scope: the fork delta is a small, reviewable, purely-additive hardening surface;
the paid audit's review of the **DKLs23 protocol math applies to the upstream 0xCarbon code**, where most
of these findings (H1, M1, M4, M6, L1/L3/L4) also live and are definitively resolved. **M2 is the one
finding squarely about the fork's own hardening being incomplete.**

---

## §2. Findings matrix

| ID | Severity | Class | Title | Est. effort | Value-gating |
|----|----------|-------|-------|-------------|--------------|
| H1 | 🟠 High | `[abort]` | Coarse error taxonomy forces unsafe ban decision (over-ban → 2-of-2 lock; under-ban → key extraction) | 1.5d | strongly rec. |
| M1 | 🟡 Medium | `[const-time]` | Hand-rolled `field_mul` branches on secret-derived bits (OTE consistency check) | 1–2d | strongly rec. |
| M2 | 🟡 Medium | `[secret-hygiene]` | Incomplete H1 sweep: EncProof/CP witness-bearing nonce not zeroized | 0.5d | rec. |
| M3 | 🟡 Medium | `[keygen]` | Fast-refresh has no in-protocol consistency check; fast-path M3 guard untested | 1d | rec. |
| M4 | 🟡 Medium | `[finishing]` | Low-S (EIP-2) normalization is optional; malleability contract unspecified | 0.5d | rec. |
| M5 | 🟡 Medium | `[supply-chain]` | Crypto stack on release-candidates; `crypto-bigint 0.7.1` yanked | 0.5d | rec. |
| M6 | 🟡 Medium | `[rust-safety]` | `sign_phase4` panics on malformed `x_coord` (low-level API DoS) | 0.5d | rec. |
| L1 | 🟢 Low | `[ssid]` | `mul_sid`/`zero_sid` non-canonical (adjacent variable-length fields, raw concat) | 0.5d | polish |
| L2 | 🟢 Low | `[nonce]` | wasm getrandom backend verification must be completed in the backend binary | 0.5d | polish |
| L3 | 🟢 Low | `[rust-safety]` | Fischlin PoW exhaustion panics instead of returning `Result` | 0.5d | polish |
| L4 | 🟢 Low | `[protocol]` | `public_gadget` agreement not asserted at runtime (fail-safe via `verify_r`) | 0.5d | polish |

**Effort:** High ≈ 1.5d · Medium ≈ 4–5d · Low ≈ 2d. **Before commissioning the paid audit:** close **H1**, **M1**,
**M2**, **M4** (taxonomy, const-time, zeroization sweep, finishing contract) — they will otherwise each generate
auditor findings and H1/M1 touch the security-critical OT path. The auditor will cover the OT/VOLE math,
side-channels, and protocol-soundness regardless of what the self-audit closes.

---

## §3. Per-finding detail + Claude Code prompts

### H1. Coarse error taxonomy forces an unsafe ban decision  `[abort]`

**Problem** — The signing layer raises `AbortKind::BanCounterparty` on *any* `Err` returned by the
multiplication, not only on a genuine consistency-check failure. At `signing.rs:563` (`mul_sender.run`)
and `signing.rs:759` (`mul_receiver.run_phase2`), the `Err` is mapped to `Abort::ban(...)`. But those
`Err`s come from two very different sources, indistinguishable at the call-site because `ErrorOT`
(`ot.rs:11`) and `ErrorMul` (`multiplication.rs:121`) carry only a `description: String`:
1. the **leak-bearing** COTe consistency check (`extension.rs:359–366`) and `verify_r` check
   (`multiplication.rs:645`) — these MUST ban (reused OT state leaked); and
2. benign **dimension/format** errors (`extension.rs:230–247`, `multiplication.rs:575–579`) — a
   malformed or version-skewed message, no leak.

**Impact** — The integrator (the 2-of-2 backend / `libtss`) receives `BanCounterparty` and cannot tell
the two apart. This creates a two-sided trap, *both directions value-relevant*:
- **Over-ban → availability/fund-lock.** Permanently excluding the *only* counterparty in a 2-of-2 on a
  transient/benign error makes the wallet unable to ever sign again — a fund-availability event.
- **Under-ban → key extraction.** An integrator who, to avoid false lock-outs, softens its handling of
  `BanCounterparty` (e.g. retries with the same party) re-opens exactly the OT-reuse key-extraction
  attack the ban exists to prevent (`protocols.rs:262–280`). Adversary model: malicious counterparty
  across repeated signing sessions.
The core itself is fail-safe (it over-bans), so this is not a Critical *in this crate* — but the taxonomy
makes correct integration impossible to do safely, and the auditor will flag it.

**Fix approach** — Give `ErrorMul`/`ErrorOT` a machine-readable kind, and ban only on the leak-bearing
kind. Recommended: add an enum discriminant (`ConsistencyFailure` vs `MalformedMessage` vs `OtError`)
to `ErrorMul`; in `signing.rs`, map `ConsistencyFailure` → `Abort::ban`, the rest → `Abort::recoverable`.
This preserves the mandated ban on the real leak while letting the backend treat benign errors as
retryable. (Option B — keep the String but parse it — is fragile; do not.)

**Done definition** —
- `ErrorMul` exposes a non-`String` kind; `grep -n "Abort::ban" signing.rs` shows ban *only* for the
  consistency-failure kind; dimension/format errors map to `recoverable`.
- A test drives a dimension-error message and asserts `AbortKind::Recoverable`; a tampered-`verify_r`
  message still asserts `AbortKind::BanCounterparty`.
- `cargo test -p dkls23-core` green.

**Claude Code prompt**
````
In kawasekit-dkls23 (DKLs23 threshold-ECDSA), the signing layer bans a counterparty on ANY
multiplication error, conflating the leak-bearing consistency-check failure (must ban) with benign
dimension/format errors (should be recoverable). ErrorOT (dkls23-core/src/utilities/ot.rs) and
ErrorMul (dkls23-core/src/utilities/multiplication.rs) carry only a String.

Task: introduce a machine-readable error kind so signing can ban selectively.
1. Add an enum kind to ErrorMul (e.g. ConsistencyFailure | MalformedMessage | OtError) and to ErrorOT
   (ConsistencyFailure | MalformedMessage), preserving the existing description String.
2. Set the kind at each construction site: the COTe check (extension.rs:359-366) and verify_r check
   (multiplication.rs:645-649) => ConsistencyFailure; the dimension checks (extension.rs:230-247,
   multiplication.rs:575-579) => MalformedMessage.
3. In signing.rs, at the two ban sites (~L563 mul_sender.run, ~L759 mul_receiver.run_phase2), map
   ConsistencyFailure => Abort::ban (unchanged), and MalformedMessage/OtError => Abort::recoverable.
   Do the same review for the dkg.rs / refresh.rs mul-init error mapping (they already use recoverable;
   keep them recoverable).
4. Add tests: a malformed-dimension message asserts AbortKind::Recoverable; a tampered verify_r still
   asserts AbortKind::BanCounterparty.
Run `cargo test -p dkls23-core`. Respect existing AbortReason variants. do not commit — leave the diff for PR review.
````

---

### M1. Hand-rolled `field_mul` branches on secret-derived bits  `[const-time]`

**Problem** — `field_mul` (GF(2²⁰⁸), `extension.rs:887–969`) multiplies via a right-to-left comb whose
inner step is data-dependent: `if (a[j] >> k) % 2 == 1 { c ^= shifted_b }` (`extension.rs:912`). In the
COTe consistency check, the first operand `a` is a slice of `q[i]` (`extension.rs:328–332`), and
`q[i] = correlation[i]·u[i] ⊕ extended_seeds[i]` (`extension.rs:289–291`) is derived from the **secret,
session-reused** OT `correlation` and `seeds`. So the multiply's branch count / memory-access pattern
depends on secret bits. The *comparison* of the check result is constant-time (`ct_eq`,
`extension.rs:359`), but the multiply that produces it is not.

**Impact** — A timing/microarchitectural side-channel on the reused OT correlation state. Over many
signing sessions an attacker able to measure `OTESender::run` timing could learn information about
`correlation`, which is exactly the long-lived secret the ban mechanism protects. Adversary model:
co-located or precise-timing attacker. **Honest limit:** I can flag the pattern but cannot *measure*
whether it is exploitable on the target hardware — that requires dudect-style testing and is squarely a
paid-audit / side-channel-lab item. I flag it because the checklist mandates flagging hand-rolled
variable-time paths on secret data, and this is one.

**Fix approach** — Make the comb constant-time: replace the `if bit` branch with a mask
(`let m = 0u64.wrapping_sub(bit); c[..] ^= b[..] & m`) so every iteration does the same work, or adopt a
constant-time GF(2^m) carry-less-multiply (e.g. via `clmul` where available, behind a portable fallback).
Re-verify the field self-test (`extension.rs:1042`) still passes.

**Done definition** —
- `extension.rs:912` no longer branches on operand bits; the comb uses a constant-time mask.
- `field_mul` self-test and all OTE tests pass: `cargo test -p dkls23-core ot::extension`.
- A comment records that constant-timeness here is best-effort and the paid audit must confirm by measurement.

**Claude Code prompt**
````
In kawasekit-dkls23, dkls23-core/src/utilities/ot/extension.rs, field_mul (GF(2^208), ~L887-969) uses a
data-dependent branch `if (a[j] >> k) % 2 == 1 { for i { c[j+i] ^= b[i] } }` (~L912). The operand `a` is
derived from the secret, session-reused OT correlation (q[i]), so this is a variable-time multiply on
secret data — a timing side-channel surface.

Task: make the comb multiply constant-time.
1. Replace the bit-branch with a mask: compute `let bit = (a[j] >> k) & 1; let m = 0u64.wrapping_sub(bit);`
   and XOR `b[i] & m` into c[j+i] unconditionally for every k (no early skip).
2. Keep the reduction step unchanged. Ensure no remaining secret-dependent branch in field_mul.
3. Add a code comment noting constant-timeness is best-effort and must be confirmed by measurement in the
   paid audit.
Run `cargo test -p dkls23-core` (esp. the field_mul self-test ~L1042 and OTE consistency tests).
do not commit — leave the diff for PR review.
````

---

### M2. Incomplete H1 sweep: EncProof/CP witness-bearing nonce not zeroized  `[secret-hygiene]`

**Problem** — The H1 hardening wrapped the DLog Schnorr nonces in `Zeroizing` (`proofs.rs:233`,
commit `3597d4c`) and `security.md` documents *that* nonce as the witness-bearing secret. But the
**Chaum-Pedersen / EncProof real-branch nonce** is equally witness-bearing and is **not** zeroized: in
`CPProof::prove_step1` (`proofs.rs:607–625`) the nonce `scalar_rand_commitment` and in `prove_step2` the
response `challenge_response = scalar_rand_commitment − challenge·scalar` (`proofs.rs:645`) are plain
stack `C::Scalar`s. Because `response = k − c·r`, the witness `r` (the base-OT receiver's secret) is
recoverable as `r = (k − response)/c` if the nonce `k` leaks. `EncProof::prove` (`proofs.rs:753–903`)
runs this on the real branch with the OT receiver's `r` as witness.

**Impact** — Same defense-in-depth class as the rest of H1: a residual secret in heap/stack/swap/core-dump.
Leaking the EncProof real nonce compromises the corresponding base-OT instance's receiver secret `r`.
This is not directly remotely exploitable; it is the exact memory-disclosure threat model H1 exists to
mitigate, and the sweep is incomplete. Self-consistency gap: H1/`security.md` claim the witness-bearing
nonce is zeroized; one witness-bearing nonce class is not.

**Fix approach** — Hold the CP/EncProof real nonce (and the simulator's transient scalars, which are not
witness-bearing but cheap to wipe) in `Zeroizing` for the duration of `EncProof::prove`, mirroring the
DLog treatment. Update `security.md` to state both nonce classes are covered.

**Done definition** —
- `grep -n "Zeroizing" proofs.rs` shows the CP/EncProof prove path wraps its nonce.
- `security.md` zeroization section names the CP/EncProof nonce.
- `cargo test -p dkls23-core proofs` green.

**Claude Code prompt**
````
In kawasekit-dkls23, dkls23-core/src/utilities/proofs.rs, the DLog prover wraps its Schnorr nonces in
Zeroizing (~L233) but the Chaum-Pedersen / EncProof real-branch nonce is left as a plain stack scalar.
In CPProof::prove_step1 (~L607) the nonce `scalar_rand_commitment` and the response in prove_step2 (~L645)
carry the witness `r` (response = k - c*r). EncProof::prove (~L753-903) runs this with the OT receiver
secret r.

Task: complete the H1 zeroization sweep for the CP/EncProof prover.
1. Hold the real-branch CP nonce in zeroize::Zeroizing for its lifetime inside EncProof::prove (and within
   CPProof::prove_step1/step2 where the nonce lives), mirroring DLogProof::prove.
2. Wipe the simulator's transient scalars too (cheap, defense-in-depth).
3. Update docs/security.md "Memory Safety" / zeroization section to state the CP/EncProof nonce is also
   covered, not only the DLog nonce.
Run `cargo test -p dkls23-core proofs`. do not commit — leave the diff for PR review.
````

---

### M3. Fast-refresh lacks an in-protocol consistency check; fast-path M3 untested  `[keygen]`

**Problem** — `refresh_phase4` (fast variant, `refresh.rs:1067–1147`) re-randomizes the existing OT
correlations in place via the Beaver-trick XOR, with **no consistency check** that the re-randomized
state is still a valid correlation, and it trusts (existence-checks only, `refresh.rs:1045/1053`) the
pre-existing correlations. A counterparty that corrupts its half of the re-randomization produces
inconsistent OT state; this is not detected during refresh — detection is deferred to the *next*
signing's `verify_r`/COTe check (→ ban). Separately, the fast-path **M3** trivial-share guard
(`refresh.rs:1171–1182`) has no dedicated test (only the full-refresh variant does, `refresh.rs:1416`).

**Impact** — No silent key leak (the next signing catches inconsistency and bans), but: (a) fast refresh
provides **no identifiable abort** for a party that corrupts the refresh — a liveness/attribution gap; and
(b) an untested M3 branch on a security-relevant guard is exactly where a future refactor could silently
regress. Adversary model: malicious counterparty during refresh.

**Fix approach** — (a) Add a test asserting the fast-path M3 branch rejects a degenerate result share.
(b) Consider whether DKLs23's proactive-refresh requires an in-refresh consistency check; if the design
intends "deferred to next signing", document that explicitly in `refresh.rs` and the security doc so the
auditor evaluates the deferral deliberately rather than discovering it. (c) Re-confirm the
re-randomization preserves the correlation with a round-trip test (refresh → sign succeeds; refresh with a
tampered pad → next sign bans).

**Done definition** —
- A `test_refresh_phase4_rejects_trivial_key_share` (fast) exists and passes.
- A test shows a tampered fast-refresh pad is caught at the next signing with `BanCounterparty`.
- `refresh.rs` documents the deferred-detection design (or adds the check).

**Claude Code prompt**
````
In kawasekit-dkls23, dkls23-core/src/protocols/refresh.rs, the fast refresh path (refresh_phase4,
~L1067-1147) re-randomizes OT correlations in place with no in-protocol consistency check, and its M3
trivial-share guard (~L1171-1182) is untested (only the full variant is, ~L1416).

Task:
1. Add `test_refresh_phase4_rejects_trivial_key_share` mirroring the full-variant test but for the fast
   path (feed correction_value = -poly_point; assert AbortKind::Recoverable + AbortReason::TrivialKeyShare).
2. Add a round-trip test: a fast refresh with a tampered re-randomization pad on one party leads the next
   signing to abort with AbortKind::BanCounterparty (confirming deferred detection).
3. Add a doc comment at the fast-refresh re-randomization block stating that consistency of the
   re-randomized OT state is verified at the next signing (deferred), so the design intent is explicit.
Run `cargo test -p dkls23-core refresh`. do not commit — leave the diff for PR review.
````

---

### M4. Low-S (EIP-2) normalization is optional; malleability contract unspecified  `[finishing]`

**Problem** — `sign_phase4` applies low-S only when the caller passes `normalize == true`
(`signing.rs:898`). The recovery id is a 2-bit value (y-parity | x-reduced, `signing.rs:945`),
documented as *not* EIP-155 `v`. For an EVM/Bitcoin co-signer, EIP-2 low-S is mandatory (high-S
signatures are rejected by Ethereum and are malleable); the decision is currently delegated entirely to
the caller with no enforced default at the boundary the wallet uses.

**Impact** — If the backend invokes `phase4` with `normalize == false` (or forgets it) for an EVM/BTC
key, it emits malleable / high-S signatures that downstream consumers reject or that enable txid
malleability. Not a key-extraction issue; a correctness/interop and malleability issue. Adversary model:
network malleator / non-compliant verifier.

**Fix approach** — Decide the contract at the curve-binding layer: for `secp256k1` (EVM/BTC) default to
`normalize == true`, or expose the signing entry such that low-S is the default and opting out is
explicit and documented. Verify the recovery id is recomputed *after* normalization (it is —
`signing.rs:918–945` runs post-normalize). Add a test that the emitted `s` is always low-S for the
secp256k1 path.

**Done definition** —
- The secp256k1 signing path produces low-S by default (test asserts `!s.is_high()`).
- The malleability contract is documented (which curves enforce low-S, who owns the decision).

**Claude Code prompt**
````
In kawasekit-dkls23, dkls23-core/src/protocols/signing.rs, low-S normalization in sign_phase4 (~L898) is
gated on a caller `normalize` flag. For secp256k1 (EVM/BTC) EIP-2 low-S is mandatory.

Task:
1. At the curve-binding / public signing surface used for secp256k1 (dkls23-secp256k1), ensure low-S is
   the default for that curve (either default normalize=true or enforce it), keeping opt-out explicit and
   documented for curves that don't need it.
2. Confirm recovery id is computed after normalization (it is, ~L918-945) and add a test asserting the
   emitted s is low-S (!s.is_high()) on the secp256k1 path.
3. Document the malleability contract in docs/security.md (which curves enforce low-S, and that the
   2-bit recovery_id is not EIP-155 v — the consumer derives v).
Run `cargo test`. do not commit — leave the diff for PR review.
````

---

### M5. Crypto stack on release-candidates; `crypto-bigint 0.7.1` yanked  `[supply-chain]`

**Problem** — `cargo audit` reports **0 advisories** but flags **`crypto-bigint 0.7.1` as yanked**, and
the entire crypto stack is on **release candidates**: `k256 0.14.0-rc.8`, `elliptic-curve 0.14.0-rc.29`,
`ecdsa 0.17.0-rc.16`, `p256 0.14.0-rc.8`. The fork's *standalone* `Cargo.lock` floated above the
backend's frozen set (FORK.md pins `rc.9`/`rc.32`); this is by design (fork CI floats; the backend lock
is authoritative). RC crypto has not had stable-release review.

**Impact** — (a) A yanked transitive dep is a supply-chain smell — the maintainers withdrew it. (b) RC
crypto can change API/behavior between candidates and is not the version a stable audit would normally
target. The paid audit must target the **exact frozen rc set** the backend ships, and any rc bump
re-opens audit scope. Adversary model: supply-chain / dependency-substitution; also plain
correctness-drift across rc bumps.

**Fix approach** — (a) In the **backend's authoritative `Cargo.lock`**, confirm no yanked crate is
referenced (the fork's floating lock referencing a yanked crate is acceptable per FORK.md, but verify the
shipped lock). (b) Keep `deny.toml`/`audit.toml` wired in CI (they are) and treat a *new* advisory against
the frozen rc set as release-blocking. (c) Document, in `FORK.md`/`security.md`, that the audit scope is
the exact frozen rc versions and that bumping them re-opens scope (FORK.md already says this — make the
yanked-crate check explicit in the runbook).

**Done definition** —
- Backend `Cargo.lock` verified free of yanked crates (`cargo audit` on the backend tree).
- CI continues to run `cargo audit` + `cargo deny` weekly (it does — `supply-chain.yml`).

**Claude Code prompt**
````
In kawasekit-dkls23, `cargo audit` flags crypto-bigint 0.7.1 as yanked, and the whole crypto stack is on
release candidates (k256 0.14.0-rc.x, elliptic-curve rc, ecdsa rc, p256 rc). Per FORK.md the fork's
standalone lock floats; the backend's lock is authoritative.

Task (documentation + CI hygiene, no crypto changes):
1. In FORK.md's runbook, add an explicit step: before a release, run `cargo audit` on the BACKEND tree and
   confirm no yanked crate is referenced in the backend's frozen Cargo.lock (the shipped set).
2. Confirm supply-chain.yml's weekly `cargo audit`/`cargo deny` covers the frozen rc tree and treats a new
   advisory as release-blocking; note this in docs/security.md.
3. Do NOT bump the rc pins (that re-opens audit scope per FORK.md).
do not commit — leave the diff for PR review.
````

---

### M6. `sign_phase4` panics on malformed `x_coord` (low-level API DoS)  `[rust-safety]`

**Problem** — `sign_phase4` calls `hex::decode_to_slice(x_coord, ...).expect("valid hex")`
(`signing.rs:937`) and `reduce_hex_bytes` → `.expect("valid hex")` (`signing.rs:976`) on the
caller-supplied `x_coord: &str`. Through the `SignSession` API this value is internally produced by
`phase3` (`hex::encode`, `signing.rs:834`) and is always well-formed; but `Party::sign_phase4` is a
public low-level entry that a caller (or a misbehaving orchestrator) can feed an arbitrary `x_coord`,
panicking the process.

**Impact** — A panic mid-protocol on attacker-influenced input — DoS, and a panic can leave the session
in an inconsistent state. Not key-extraction. Adversary model: a caller of the low-level API / a
coordinator that controls the `r`/`x_coord` passed to `phase4`. (The `verify_ecdsa_signature` path itself
parses hex via a `Result` (`signing.rs:994`), so the panic is specifically in the recovery-id branch.)

**Fix approach** — Make `x_coord` parsing return `Result`/`Abort` rather than `.expect`: add an
`AbortReason::InvalidXCoordinateHex` (the enum already has `InvalidXCoordinateHex` and `InvalidHex`!) and
return it on malformed input. Apply to both the recovery-id decode (`:937`) and `reduce_hex_bytes`
(`:976`).

**Done definition** —
- No `.expect("valid hex")` remains in `sign_phase4`/`reduce_hex_bytes`; malformed hex returns an `Abort`.
- A test feeds malformed `x_coord` to `sign_phase4` and asserts a recoverable `Abort`, not a panic.

**Claude Code prompt**
````
In kawasekit-dkls23, dkls23-core/src/protocols/signing.rs, sign_phase4 panics via .expect("valid hex") on
the caller-supplied x_coord (~L937 hex::decode_to_slice, ~L976 reduce_hex_bytes). The low-level
Party::sign_phase4 API can be fed arbitrary x_coord -> DoS panic.

Task:
1. Change reduce_hex_bytes (and the L937 decode) to return Result and propagate, OR have sign_phase4
   validate x_coord up front and return Err(Abort::recoverable(self.party_index,
   AbortReason::InvalidXCoordinateHex)) on malformed hex (the AbortReason variant already exists).
2. Add a test: sign_phase4 with a non-hex / wrong-length x_coord returns a recoverable Abort, not a panic.
Run `cargo test -p dkls23-core signing`. do not commit — leave the diff for PR review.
````

---

### L1. `mul_sid`/`zero_sid` non-canonical encoding  `[ssid]`

**Problem** — Session ids are built by raw `concat()` of fixed- and variable-length fields, e.g.
`zero_sid = "Zero shares protocol" ‖ session_id ‖ sign_id ‖ chain_code` (`signing.rs:395–401`) and the
`mul_sid` variants (`signing.rs:337–345/540–548`). `session_id` and `sign_id` are adjacent
**variable-length** `Vec<u8>`s with no length delimiter — unlike the rest of the codebase, which uses the
length-delimited `tagged_hash` (`hashes.rs:32`). **Impact:** in principle two `(session_id, sign_id)`
pairs could concatenate to the same byte string, colliding the ssid. In practice `session_id` is fixed
per key (set at DKG) and `chain_code` is fixed-length, so within a key the encoding is injective and
exploitability is low — but it is non-canonical and fragile.

**Fix** — Build `mul_sid`/`zero_sid` via the length-delimited `tagged_hash` (or length-prefix each
variable field) so the encoding is unambiguous regardless of field lengths. **Done:** ssid construction
is length-delimited; a test shows distinct `(session_id, sign_id)` inputs never collide.

---

### L2. wasm getrandom backend verification must be completed in the backend  `[nonce]`

**Problem** — This crate wires the wasm RNG correctly *at the crate level*: `Cargo.toml` enables
`getrandom` `wasm_js`, CI builds `wasm32-unknown-unknown` (`feature-guards.yml`), and `rng.rs:20` hands
out `rand::rng()` (ThreadRng, a CSPRNG). But the **high-value** `[nonce]` check — that the *shipped wasm
binary* routes `getrandom` to `crypto.getRandomValues` and that `ThreadRng` reseeds from it — can only be
verified in the **backend** wasm-bindgen build (`kawasekit-mpc-2p`, out of this repo's scope). With
getrandom 0.4 + `wasm_js`, a misconfiguration fails at compile/runtime (Err/panic) rather than silently
yielding predictable bytes, so the *key-recovery* risk is low; still, this is the single highest-stakes
RNG check and must be closed in the backend. **Fix/Done:** backend build sets the getrandom wasm backend
(feature and/or `--cfg getrandom_backend="wasm_js"` as the version requires) and a runtime smoke test
confirms entropy; record it in the backend's audit.

---

### L3. Fischlin PoW exhaustion panics instead of returning `Result`  `[rust-safety]`

**Problem** — `DLogProof::prove` exhaustion is surfaced via `.expect("Fischlin proof-of-work search
exhausted — RNG failure")` (`dkg.rs:350`, `base.rs:86`). This is astronomically unlikely (≈2⁻²⁵⁶ under a
working CSPRNG) and effectively signals RNG failure, but it panics mid-protocol rather than returning a
`Result`. **Fix:** propagate `ProofSearchExhausted` as an `Abort`/`Result` at these two call sites.
**Done:** no `.expect` on the prove path; exhaustion returns an error. (Low — only reachable under RNG failure.)

---

### L4. `public_gadget` agreement not asserted at runtime  `[protocol]`

**Problem** — The multiplication `public_gadget` is derived independently by sender and receiver from the
shared `nonce`+`session_id` (`multiplication.rs:177–186` vs `:435–444`) and never asserted equal at
runtime. A mismatch (e.g. nonce disagreement) yields wrong shares — but is caught by the `verify_r`
consistency check (→ ban), so the system is **fail-safe**. **Fix (optional):** none required for safety;
optionally add a debug assertion or a doc note that gadget agreement is enforced indirectly by `verify_r`.
**Done:** doc note added. (Low — fail-safe today.)

---

## §4. Recommended work sequence

**Sprint 1 — close before commissioning the paid audit (lowers its cost, removes certain findings):**
1. **H1** abort taxonomy — the error-kind refactor touches signing/dkg/refresh; do it first so M3/M6 tests build on the new kinds.
2. **M1** const-time `field_mul` — isolated to `extension.rs`; no dependency on H1.
3. **M2** EncProof/CP nonce zeroization — isolated to `proofs.rs`.
4. **M4** low-S finishing contract — isolated to the secp256k1 binding + a test.

**Sprint 2 — pre-audit hardening:**
5. **M6** `sign_phase4` panic → `Abort` (reuses the existing `InvalidXCoordinateHex` reason).
6. **M3** fast-refresh consistency tests + design doc.
7. **M5** supply-chain runbook step (backend yanked-crate check).

**Sprint 3 — polish:** L1 (canonical ssid), L3 (Fischlin `Result`), L4 (gadget doc). L2 is **not** closable
here — it is a backend task; track it in the backend's audit.

**What the paid audit must still cover regardless** (a self-audit cannot clear these):
- The OT/VOLE multiplication soundness and selective-failure resistance (the DKLs-specific class).
- The signing `u/v/γ` consistency relations vs the DKLs23 paper, round-by-round.
- **Measured** side-channel analysis (M1 is a flagged pattern, not a measured verdict).
- The fast-refresh proactive-security argument.
- The exact frozen **rc** crypto versions and the wasm RNG path in the shipped backend binary.
- The **upstream 0xCarbon code itself**, where most findings live (the fork-delta diff is done and clean —
  see §1 Fork-delta verification — but the auditor must still review the upstream OT/VOLE/signing math).

---

## §5. PR review criteria

For each PR closing a finding:
- [ ] The finding ID (H1/M1/…) is named in the PR title/description.
- [ ] Every **Done-definition** item for that finding is checked off in the PR.
- [ ] The empirical re-verification command (from the finding) was run and its **output pasted** into the PR.
- [ ] `cargo test -p dkls23-core`, `cargo clippy`, `cargo fmt --check` all green (paste output).
- [ ] For H1/M1/M3/M4: a **new test** encodes the behavior change (selective ban / const-time / fast-M3 / low-S).
- [ ] No new `unwrap()`/`expect()`/`panic!` on a protocol path; no secret added to a `Debug`/log/serialized surface.
- [ ] `cargo audit` + `cargo deny check` still clean (paste output).
- [ ] The PR does **not** claim the change makes the crate "audited" or "mainnet-ready" — the third-party audit gate remains.

---

## Appendix — Empirical spot-check

| Claim / check | Verification method | Result |
|---|---|---|
| No `unsafe` | `grep -rn unsafe src` | ✅ none (`#![forbid(unsafe_code)]`) |
| Dependency advisories | `cargo audit` | ✅ 0 advisories; ⚠️ `crypto-bigint 0.7.1` **yanked** → M5 |
| License/advisory bans | `cargo deny check advisories` | ✅ "advisories ok" (yanked noted) |
| Crypto stack stability | dep tree inspection | ⚠️ all **release-candidates** (k256 rc.8, elliptic-curve rc.29, ecdsa rc.16) → M5 |
| C1: trusted-dealer excluded from prod | `grep re_key` + cfg inspection | ✅ `re_key` is `#[cfg(any(test, feature="trusted-dealer-import"))]`; every call-site in `#[cfg(test)] mod tests` |
| A4: compile guards present | `grep compile_error! lib.rs` | ✅ L15 (`insecure-rng`), L23 (`trusted-dealer-import` on wasm32); CI asserts the 4 combos |
| M1 identity rejection | `grep identity proofs.rs` | ✅ DLog `:388`, CP/Enc `:667` |
| M2 Parameters validation | read `protocols.rs:117–122` | ✅ `try_from=ParametersRaw` re-imposes `1<t≤n` |
| M3 trivial-share + H1 old-Party wipe | `grep TrivialKeyShare\|self.zeroize refresh.rs` | ✅ `:700/1180`, `:736/1217` (fast-path M3 untested → M3 finding) |
| Signing ban distribution | `grep -c Abort::ban signing.rs` | ✅ 4 ban / 27 recoverable; all 4 on leak-bearing checks |
| DKG/refresh bans | `grep -c Abort::ban {dkg,refresh}.rs` | ✅ 0 / 0 (recoverable correct — no reusable OT state) |
| Verify-before-return | read `signing.rs:906` | ✅ full ECDSA verify before returning the signature |
| Constant-time compares | `grep -rl ct_eq` | ✅ commits, proofs, extension, multiplication |
| Commitment compare (doc drift) | `grep ct_eq commits.rs` vs `security.md:67` | ⚠️ code `ct_eq` (constant-time); doc says `==` — **stale doc, code safer** |
| Panic surfaces on protocol path | `awk` strip-tests + `grep unwrap\|expect\|panic` | ⚠️ `sign_phase4` hex `.expect` → M6; Fischlin `.expect` → L3; rest are length/index invariants |
| EncProof/CP nonce zeroized | `grep Zeroizing proofs.rs` | ❌ only DLog `states` (`:233`); CP/Enc nonce plain scalar → M2 |
| field_mul secret-bit branch | read `extension.rs:908–917` | ❌ `if (a[j]>>k)%2==1` on secret-derived `q` → M1 |
| wasm RNG wiring | `Cargo.toml` + `feature-guards.yml` | ◑ crate-level OK (`wasm_js`, CI builds wasm32); binary-level verify is backend (out of scope) → L2 |
| Fork delta vs upstream | `git -C ../DKLs23 diff c9c407e..ddaa091` | ✅ **clean & additive** — 7 `.rs` files (= FORK.md list), **no check removed/weakened**, every deletion is a derive/let/sig replaced by its hardened form |
| Fork touches protocol math? | `git diff --stat` on hot files | ✅ **no** — `signing.rs`/`multiplication.rs`/`ot/extension.rs`/`zero_shares.rs`/`derivation.rs` byte-identical to upstream |
| M1/C1 additive (not weakening) | `git diff … \| grep '^+'` | ✅ M1 identity-reject blocks and C1 `#[cfg]` gate are pure additions |
| Named breaks (TSSHOCK/BitForge/66016/66017) | family check | ✅ N/A — OT-based (no Paillier); Lindell17 abort-leak class checked → relates to H1 |

---

*Self-audit only. A third-party cryptographic audit of the frozen rc crypto + this fork delta remains a
standing pre-mainnet gate. Deep technical trace of the top clusters: see the next section / commit.*
