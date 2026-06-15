# DKLs23 — Audit Context (Global System Model)

> **Status:** Context-building artifact for a security audit of `kawasekit-dkls23`.
> **Mode:** This document is *pure architectural context* — deep understanding of how the
> system works, its invariants, trust boundaries, and where complexity concentrates. It
> contains **no vulnerability findings**; those live in [`audit-findings.md`](audit-findings.md).
>
> **Scope:** `dkls23-core` (curve-generic core) + the `dkls23-secp256k1` / `dkls23-secp256r1`
> bindings. Built bottom-up via per-function micro-analysis of all ~14.3k LOC.
>
> **Disclaimer:** This is a *self-audit context pass*, not a substitute for a paid third-party
> cryptographic audit. It does **not** clear a mainnet / real-value gate. The crate is
> `UNAUDITED` (see [`../FORK.md`](../FORK.md)); testnet / no-value only.
>
> **Refresh (2026-06-15, `dev`@`c3eadd3`):** this doc was first built on the *pre-hardening* tree. The
> second self-audit round has since merged (11 fix-PRs, #15–#25); the model below is re-grounded against
> current `dev`. The load-bearing change: the abort/ban decision is now driven by a **machine-readable
> error `kind`** (`OtErrorKind`/`MulErrorKind`), not by `Result` presence — see §3.7, §6, and the
> second-round delta in §1. Other corrected facts: `field_mul` is now constant-time (§3.2), low-S is the
> `SignSession` default (§3.7), the EncProof witness nonce is zeroized (§3.3/§7), and open-questions
> Q3/Q4 are closed (§9).

---

## 1. System at a glance

`kawasekit-dkls23` is a hardened fork of [0xCarbon/DKLs23](https://github.com/0xCarbon/DKLs23)
implementing the **DKLs23 Threshold ECDSA** protocol ([eprint 2023/765](https://eprint.iacr.org/2023/765.pdf)).
It computes ECDSA signatures across multiple parties holding key shares without ever
reconstructing the secret key. It backs the `kawasekit-mpc-2p` 2-of-2 co-signer.

- `#![forbid(unsafe_code)]` crate-wide.
- Curve-generic over the `DklsCurve` marker trait (`curve.rs`); instantiated for `k256::Secp256k1` and `p256::NistP256`.
- Crypto stack pinned to `k256` / `elliptic-curve` **0.14 release candidates** (deliberately frozen; see FORK.md).

```
                        PUBLIC API (lib.rs re-exports)
        DkgSession ───────── SignSession ───────── EcdsaSignature
            │ Option-sentinel    │ take()-sentinel       │ (r, s, 2-bit recid)
            ▼ state machine       ▼ state machine
   ┌─────────────────────────────────────────────────────────────┐
   │  dkg.rs(1906)   signing.rs(2440)   refresh.rs(2384)          │  PROTOCOLS
   │  derivation.rs(692, BIP-32)   re_key.rs(258, gated dealer)   │
   └─────────────────────────────────────────────────────────────┘
            │ consume ▼
   ┌─────────────────────────────────────────────────────────────┐
   │  multiplication.rs(996)  RVOLE/MtA   ── zero_shares.rs(213)  │  UTILITIES
   │  ot/extension.rs(1483)   COTe        ── proofs.rs(1275) ZK   │
   │  ot/base.rs(496)         endemic OT  ── commits/hashes/...   │
   └─────────────────────────────────────────────────────────────┘
```

**Protocol stack (paper mapping):**
Signing (Protocol 3.6) → Multiplication (Functionality 3.5, DKLs19 Protocol 1) → OT Extension
(KOS Fig.10 + SoftSpokenOT VOLE + DKLs18 transfer) → Base OT (Zhou et al. endemic OT).
DKG (DKLs19 Protocol 9.1) → Proofs (Schnorr/Fischlin, Chaum-Pedersen, EncProof).

### The fork delta (self-audit hardening over published 0.5.1)

| ID | What | Where |
|----|------|-------|
| **M1** | Reject identity points at proof-verifier boundaries | `proofs.rs:388` (DLog), `:667` (CP/Enc) |
| **M2** | Validate `Parameters` (`1 < t ≤ n`) on deserialize | `protocols.rs:117–122` |
| **M3** | Reject degenerate refreshed share `∈ {0,1}` | `refresh.rs:700` (full), `:1189` (fast) |
| **H1** | Zeroize secret structs + base-OT/Schnorr nonces; eager old-`Party` wipe on refresh | pervasive; `refresh.rs:736/1226`, `proofs.rs:233` |
| **C1** | Gate trusted-dealer `re_key` behind non-default feature | `protocols.rs:23`, `Cargo.toml:41` |
| **A4** | `compile_error!` guards: `insecure-rng` outside test; `trusted-dealer-import` on wasm32 | `lib.rs:14–25` |

> **⚠ Two colliding ID sets.** The table above is the fork's **first** self-audit (these IDs also appear in
> [`../FORK.md`](../FORK.md)). The **second** round (this audit; IDs from [`audit-findings.md`](audit-findings.md))
> reuses the letters H1 / M1 / M2 / M3 for *different* issues — do not conflate the two.

#### Second self-audit round (merged 2026-06; `audit-findings.md` IDs; verified against `dev`@`c3eadd3`)

| ID | Class | What | Where (current lines) |
|----|-------|------|------|
| **H1** | `[abort]` | Machine-readable error `kind` so signing bans **only** on a leak-bearing consistency failure | `ot.rs:17–49`, `multiplication.rs:126–173`, `signing.rs:580–596/788–804` |
| **M1** | `[OT]` | Constant-time GF(2²⁰⁸) `field_mul` comb (bit-mask, not a data-dependent branch) | `extension.rs:917–921` |
| **M2** | `[secret-hygiene]` | Zeroize the EncProof/CP witness-bearing commitment nonce | `proofs.rs:805/876` |
| **M3** | `[keygen]` | Fast-refresh trivial-share guard + deferred-detection round-trip tests | `refresh.rs:1449/1540` |
| **M4** | `[validation]` | `SignSession` finalizer always emits canonical low-S | `sign_session.rs:74/234` |
| **M5** | `[supply-chain]` | Yanked-crate / advisory runbook step (docs only) | `FORK.md`, `docs/security.md` |
| **M6** | `[rust-safety]` | Up-front `x_coord` hex validation in `sign_phase4` (typed abort, not `.expect`) | `signing.rs:938–946` |
| **L1** | `[ssid]` | Enforce canonical `ID_LEN`=32 `session_id`/`sign_id` at signing entry | `signing.rs:263–270` |
| **L3** | `[rust-safety]` | Document the Fischlin `.expect` as an RNG fail-stop (not attacker-reachable) | `dkg.rs:349`, `base.rs:85` |
| **L4** | `[OT]` | Document public-gadget agreement (a mismatch is caught downstream by `verify_r`) | `multiplication.rs:217/476` |

*Second-round items closed by docs/tests only (no protocol-math change): M5, L3, L4. **L2** (wasm `getrandom`
backend) is tracked in the `kawasekit-mpc-2p` repo — out of scope for `dkls23-core`. All protocol math is
byte-identical to upstream; the fork delta remains additive (guards, error tags, zeroization, tests).*

---

## 2. Foundational types (`protocols.rs`)

- **`PartyIndex(u8)`** — 1-based, rejects 0 at construction (`:62`) and on serde (`try_from="u8"`).
- **`Parameters{threshold, share_count}`** — validated `1 < t ≤ n` via `Parameters::new` and re-validated on deserialize through `ParametersRaw` (M2).
- **`Party<C>`** — the center of gravity. Fields: `parameters`, `party_index`, `session_id`, `poly_point`
  (secret share), `pk`, `zero_share`, `mul_senders`/`mul_receivers` (BTreeMaps holding the **reused OT
  correlations**), `derivation_data`, `address`. Manual `Zeroize` + `Drop` (`:174–198`): wipes all
  secrets; leaves `parameters`/`party_index`/`pk` (public).
- **`PublicKeyPackage<C>`** — group verifying key + per-party verifying shares + parameters.
- **`AbortKind`** — `Recoverable` | **`BanCounterparty(PartyIndex)`**. The ban variant is the central
  security mechanism (see §6). **`Abort{index, kind, reason}`** with `AbortReason` (`#[non_exhaustive]`,
  machine-readable). `Abort::recoverable` / `Abort::ban` constructors at `:484` / `:499`.

---

## 3. Module reference (verified facts + key line numbers)

### 3.1 Base OT — `utilities/ot/base.rs` (496)
Endemic OT (Zhou et al.). `OTSender{s, proof}` (`s` secret + zeroized, `proof` `#[zeroize(skip)]` public);
`OTReceiver{seed}` (zeroized). Roles **reverse** when driven by the extension. Two trust boundaries:
- Sender `run_phase2` (`:114–150`): verify receiver's `EncProof` **and** pin `h == enc_proof.base_h`
  **and** identity rejection — before computing pads `m0=(v·s)`, `m1=((v−h)·s)`.
- Receiver `run_phase2_step1` (`:267–284`): verify sender's `DLogProof` before releasing `z`.

Endemic property: both pads derived; receiver recovers exactly one via `z·r` (`:301`).
Invariants: `s≠0` (`:80–83`); `dlog(h)` unknown to both (hash-to-point, both sides identical construction).
*Open:* receiver's `r`/`vec_r` returned by value, not `Zeroizing` within base.rs.

### 3.2 OT Extension (COTe) — `utilities/ot/extension.rs` (1483)
KOS + SoftSpokenOT VOLE + DKLs18 transfer + Fiat-Shamir. Constants: `KAPPA=256`, `BATCH_SIZE=416`,
`OT_SECURITY=208`, `EXTENDED_BATCH_SIZE=624`, field GF(2²⁰⁸).
`OTESender{correlation:Vec<bool>, seeds}` / `OTEReceiver{seeds0, seeds1}` — **fully zeroized**, **persisted
in `Party` and reused every signing session** (forced-reuse, `OT_WIDTH=4`).

**THE consistency check** (`OTESender::run`, `:359–368`): constant-time GF(2²⁰⁸) fold over KAPPA columns;
mismatch → `ErrorOT::consistency("Receiver cheated in OTE")` (kind `OtErrorKind::ConsistencyFailure`) →
**ban trigger** (H1, 2nd round). Comparison is constant-time (`ct_eq` fold, `:359–362`); **`field_mul`
(`:888–974`) is now constant-time** — the comb uses a `0u64.wrapping_sub(bit)` mask (`:917–921`, M1, 2nd
round), not a data-dependent branch; pinned by `test_field_mul_identity` (`:1065`).
Session separation: `session_id` threaded into PRG (`:268`), chi (`:315/318`), randomize (`:421/429`).
`cut_and_transpose` (`:832`) ported from Coinbase kryptology.

### 3.3 ZK Proofs — `utilities/proofs.rs` (1275)
- **DLog / Fischlin** (R=64, L=4, T=32): `prove` holds 64 nonces in `Zeroizing<Vec>` (H1, `:233`).
  `verify` (`:374–460`): length gate (R=64), **M1 identity rejection** (`:387–390`, point + all commitments),
  distinctness (HashSet), Fischlin collision (`ct_eq`), 64 sigma checks. FS transcript binds
  sid/G/all-commitments/index/challenge/response but **not `proof.point` directly** (only via sigma eqn).
- **Chaum-Pedersen**: equality-of-DL. `verify` (`:663–678`): **M1 identity rejection** of `point_u/point_v/base_h`.
  `simulate` (`:688–720`) back-solves a verifying transcript for the OR-composition.
- **EncProof**: OR-composed CP + Fiat-Shamir. `verify` (`:909–959`): compatibility gate (`base_g==generator`),
  challenge-sum check (`:952`), both CP verifies. Bit-privacy via unconditional v-branches (`:776–787`).
**M2 (2nd round):** the EncProof/CP witness-bearing commitment nonce `real_scalar_commitment` is now held
in `Zeroizing` (`:805`, deref `&*` at `:876`), mirroring `DLogProof::prove`. *Open (residual):* the CP
*simulator* back-solve still uses bare transient scalars.

### 3.4 Multiplication (RVOLE/MtA) — `utilities/multiplication.rs` (996)
DKLs19 Protocol 1. `L=2`, `OT_WIDTH=4`. `MulSender{public_gadget, ote_sender}` / `MulReceiver{public_gadget,
ote_receiver}` — persisted in `Party`, reused every session. Correlation **I-RVOLE**:
`output_A[i] + output_B[i] == input[i]·b`.
**THE verify_r consistency check** (`run_phase2`, `:686` `ct_eq`) → **ban trigger** (`ErrorMul` carries
`MulErrorKind`; this raises `ConsistencyFailure`, `:687`). `chi_tilde/chi_hat`
derived by Fiat-Shamir from the receiver's transcript (`:348–359` sender ≡ `:571–582` receiver).
`gamma_sender` is **not** independently authenticated here — signing adds the γ_u/γ_v cross-check.
**L4 (2nd round, documented):** `public_gadget` equality across parties is **not asserted at runtime**;
`tau` is not authenticated by OTE — both are caught downstream by `verify_r`.

### 3.5 Zero Shares — `utilities/zero_shares.rs` (213)
Functionality 3.4. `SeedPair{lowest_index, index_counterparty, seed}`, `ZeroShare{seeds}` — zeroized.
**Sign rule** (`:79`, `:123–127`): `lowest_index = (index_party ≤ index_counterparty)`; **lower index
SUBTRACTS, higher ADDS** → pairwise cancel → **I-ZEROSHARE** `Σ ζ_i = 0`. Seeds XOR-combined (symmetric).
`zero_sid` composition (signing `:409–415`): `"Zero shares protocol" ‖ session_id ‖ sign_id ‖ chain_code`
— **party indices deliberately omitted** (they enter via the per-pair seed). Commit-then-reveal with
`verify_seed` → `ZeroShareDecommitFailed` (recoverable).

### 3.6 DKG — `protocols/dkg.rs` (1906)
DKLs19 Protocol 9.1: 4 phases + 5 steps. `step1` sample degree-`t−1` poly → `step2` Horner eval at all
indices → `step3` sum fragments into `poly_point`, `prove_commit` DLog of `P(i)` → `step5` decommit+verify,
**Lagrange-in-exponent** PK reconstruction (`:411–453`) with contiguous-window consistency. `phase4`
trivial-PK (`pk ∉ {identity, generator}`) + trivial-share (`poly_point ∉ {0,1}`) guards, then assembles
`Party`. Chain code = **committed XOR** of all parties' aux codes (`:1075–1110`, unbiasable).
**All DKG aborts are `recoverable`** (`Abort::ban` count = **0**) — a failed mul-init produces no reusable
OT state, so the ban discipline does not apply yet (explicit comment `:1020–1021`).

### 3.7 Signing — `protocols/signing.rs` (2440) — the linchpin
DKLs23 Protocol 3.6, 4 phases. Nonce `k` and inversion mask `φ` sampled (`:329–330`); `R_i = k·G` committed.
The **deferred-inversion trick**: `k⁻¹` is never computed on a secret — `s = Σw/Σu = k⁻¹(H(m)+sk·r)`
materializes only on public aggregated scalars (`:948`), then independently re-verified
(`verify_ecdsa_signature`, `:959`). Recovery id = 2-bit (y-parity | x-reduced) (`:999`) — **not**
EIP-155 `v`. Two 2nd-round entry guards: **L1** — `session_id`/`sign_id` must be `ID_LEN`=32 at
`sign_phase1` entry (`:263–270` → `MalformedSessionId`, recoverable); **M6** — `x_coord` hex re-validated
up front in `sign_phase4` (`:938–946` → `InvalidXCoordinateHex`, recoverable), placed **after** the
zero-denominator check (`:923`). Low-s: `Party::sign_phase4` keeps the `normalize` flag, but
`SignSession::phase4` **always** requests canonical low-S (M4; asserted `!s.is_high()`, `sign_session.rs:234`).

**Complete ban-vs-recoverable map** (verified: **4 ban, 31 recoverable**). The two mul bans are now
**kind-aware** — they `match error.kind` and ban only on `ConsistencyFailure`, downgrading
`MalformedMessage` to recoverable (H1, 2nd round):

| Kind | Line | Trigger | Reason |
|------|------|---------|--------|
| **BAN** | `:581` | `mul_sender.run` Err with `kind==ConsistencyFailure` (phase 2) | `MultiplicationVerificationFailed` |
| **BAN** | `:789` | `mul_receiver.run_phase2` Err `ConsistencyFailure` — the leak-bearing `verify_r` (phase 3) | `MultiplicationVerificationFailed` |
| **BAN** | `:817` | `R_j·chi ≠ d_u·G + gamma_u` (phase 3) | `GammaUInconsistency` |
| **BAN** | `:829` | `pk_j·chi ≠ d_v·G + gamma_v` (phase 3) | `OtConsistencyCheckFailed` |
| recoverable | `:589/:797` | mul Err with `kind==MalformedMessage` (phases 2/3) | `MultiplicationVerificationFailed` |
| recoverable | `:373` | `mul_receiver.run_phase1` Err — no leak-bearing check has run yet | `MultiplicationVerificationFailed` |
| recoverable | `:266` | `session_id`/`sign_id` length ≠ `ID_LEN` (L1) | `MalformedSessionId` |
| recoverable | `:941` | `x_coord` not valid field-length hex (M6) | `InvalidXCoordinateHex` |
| recoverable | many | party-set / routing / commitment / signature-verify failures | various |

### 3.8 Refresh — `protocols/refresh.rs` (2384)
Two variants. **Full** re-runs DKG-shaped setup with a **zero-constant correction polynomial** (`:188`) →
`pk` preserved, enforced by requiring the correction's reconstructed pk == identity (`:411`). **Fast**
re-randomizes existing OT correlations **in place** via the Beaver-trick XOR with `TAG_REFRESH_FAST_*`
oracles (`:1071–1156`) — no base OT; trusts (does not re-verify) the pre-existing correlations.
Both: **M3** trivial-share guard (`:700/1189`), **H1** eager `self.zeroize()` on success only (`:736/1226`).
**All refresh aborts `recoverable`** (`Abort::ban` count = **0**): full rebuilds fresh OT; fast has no
fallible mul-init (only `MissingMulState`; the XOR is infallible). The fast-path M3 guard and the
**deferred-detection** property — a corrupted fast-refresh correlation is caught (*banned*) at the next
signing's `verify_r` — are now pinned by tests (`refresh.rs:1449/1540`, 2nd round).

### 3.9 Derivation — `protocols/derivation.rs` (692)
BIP-32 **non-hardened only** (no party holds the full key). `child_tweak` (`:105–147`): HMAC-SHA512 keyed on
chain code, data = compressed pk ‖ child index; IL≥n edge case detected via reduce-roundtrip equality
(`:129`). `derive_child` adds the **public** tweak to both share (`poly_point + tweak`) and group key
(`pk + tweak·G`) — **I-DERIVE**. `PublicKeyPackage::derive_child` mirrors the shift on every verifying share.
The derived signing transcript is differentiated **only** because `chain_code` is hashed into
`mul_sid`/`zero_sid`. *Open:* `derive_child` rejects `new_pk == identity` but not `new_poly_point == 0`.

### 3.10 Re-key (trusted dealer) — `protocols/re_key.rs` (258)
**Single-custody** keygen: one host holds the whole secret, then Shamir-shares it locally (no comms).
`#[cfg(any(test, feature="trusted-dealer-import"))]` (C1) — off by default; `compile_error!` on wasm32.
Full secret held in `Zeroizing` (`:63`); Shamir polynomial (constant term = secret) in `Zeroizing<Vec>`
(`:72`). Fabricates all OT correlations centrally for every ordered pair (`:134–199`).
**Provisioning-only, never a service capability** (FORK.md hard rule).

### 3.11 Sessions & framing — `dkg_session.rs` (478), `sign_session.rs` (277), `messages.rs` (378)
State machines encoded by `Option` field presence (no explicit enum). DKG uses `as_ref()`+guard+manual
zeroize; SIGN uses `take()` (guard+consume fused); both terminal phases consume `self` by value.
Illegal transitions → `PhaseCalledOutOfOrder` (recoverable). **The session wrappers do NOT touch the
`messages.rs` framing** — they accept already-typed, already-deserialized structs; wire decode
(1-byte tag + 4-byte BE len + length-capped bincode, `find_in_stream`) happens in the sibling framing
layer that the out-of-scope `libtss` orchestration invokes. `EcdsaSignature{r:[u8;32], s:[u8;32],
recovery_id:u8}` is a public value type, no zeroize (signature is public).

---

## 4. State & invariant catalog (line-anchored)

**Correctness**
- **I-KEYGEN** — group key = Lagrange-in-exponent of fragments; every contiguous `t`-window must agree (`dkg.rs:411–453` → `PolynomialInconsistency`); `verifying_share[i] == poly_point_i·G`.
- **I-RVOLE** — `output_A + output_B == input·b` (`multiplication.rs:875`).
- **I-ZEROSHARE** — `Σ ζ_i == 0` over the signer set (`zero_shares.rs:79,123–127`).
- **I-SIG** — `s = Σw/Σu = k⁻¹(H(m)+sk·r)`; inversion deferred to public scalars (`signing.rs:948`); re-verified (`:959`).
- **I-DERIVE** — same public `tweak` added to every share shifts `sk→sk+tweak`, `pk→pk+tweak·G` (`derivation.rs:172–174,349–353`).
- **I-REFRESH** — correction polynomial has constant term 0 → `pk` preserved; correction-pk == identity enforced (`refresh.rs:411/896`).

**Security/hardening** — M1 (`proofs.rs:388/667`), M2 (`protocols.rs:117–122`), M3 (`refresh.rs:700/1189`),
H1 (pervasive + `refresh.rs:736/1226`, `proofs.rs:233`), C1 (`protocols.rs:23`), session separation
(`session_id` in every oracle).

---

## 5. Workflow reconstruction

- **DKG** — sample poly → exchange evals → `prove_commit` → decommit+verify, Lagrange-in-exponent +
  consistency, XOR chain code, bootstrap OT/zero-share/mul → `Party`. *All recoverable.*
- **Signing** — validate set → sample `k`,`φ`, commit `R_i`, mul-receiver start → Lagrange `λ`,
  `sk_i = poly_point·λ + ζ`, mul-sender run → verify decommits, mul-receiver finish (**leak-bearing**),
  γ_u/γ_v checks, aggregate `R`,`pk`, broadcast `u,w` → `s = Σw/Σu`, low-s, **verify-before-return**.
  *The only 4 ban sites.*
- **Refresh** — full (DKG-shaped, zero-constant correction) | fast (in-place OT re-randomization). Both
  preserve `pk`, apply M3, eager-zeroize old `Party`.
- **Derivation** — public tweak forks a new `Party` reusing OT/zero-share state; chain code differentiates
  the derived transcript.

---

## 6. Trust boundary & abort/ban model

**Actors:** local honest party; counterparties (malicious for every received message); orchestrator/`libtss`
(trusted to route + wire-decode); caller `address_fn` (sees only public `pk`).

**The `BanCounterparty` mechanism:** OT correlations are *reused*, so a counterparty failing a leak-bearing
check has probed reusable secret state; continuing enables gradual key extraction → MUST permanently ban.
Verified distribution: **signing = 4 bans; DKG = 0; refresh = 0.**

**Resolved in the 2nd round (was a flagged structural fact):** the ban formerly discriminated by `Result`
*presence* only — any `Err` banned. H1 gave `ErrorOT`/`ErrorMul` a machine-readable `kind`
(`OtErrorKind`/`MulErrorKind` ∈ {`ConsistencyFailure`, `MalformedMessage`}); signing now `match`es on it
(`signing.rs:580–596/788–804`) and bans **only** on `ConsistencyFailure`. The two layers carry *inverted*
`::new` defaults — `ErrorMul::new`→`ConsistencyFailure` (ban-safe), `ErrorOT::new`→`MalformedMessage` —
reconciled by `ErrorMul::from_ot` propagating the OT kind 1:1. The two leak-bearing roots: mul `verify_r`
(`multiplication.rs:687`) and the COTe consistency fold (`extension.rs:365`). A malformed-*dimension*
message is now **recoverable**, not a ban.

---

## 7. Zeroization map (H1)

**Covered (persistent secret structs, `ZeroizeOnDrop`):** `Party` (manual), `OTESender`/`OTEReceiver`,
`OTSender.s`/`OTReceiver.seed`, `MulSender`/`MulReceiver`/`MulDataToKeepReceiver`, `ZeroShare`/`SeedPair`,
`DerivData` (pk skipped), all DKG/refresh init carriers (public routing/proof fields `#[zeroize(skip)]`),
signing `UniqueKeep`/`KeepPhase` intermediates (public points skipped), DLog nonces **+ the EncProof/CP
witness commitment nonce** (`Zeroizing`, M2), re_key secret + polynomial (`Zeroizing`).

**Not covered (transient stack locals — neutral observations):** base-OT `vec_r`/`bits`; OTE
`extended_seeds1`/`q`/`v0`/`v1`/`transposed_q`; mul `a_tilde`/`z_tilde`; signing bare `Scalar` locals
(`u,v,w,s,d_u,d_v,…`); DKG `secret_polynomial`; the CP *simulator*'s bare transient scalars. Some depend on whether
`k256`/`p256` `Scalar` `Drop` scrubs (`DefaultIsZeroes`).

---

## 8. Fragility clusters (where the audit should focus)

Ranked by concentration of subtle invariants × attacker reachability:

1. **OTE consistency check + forced-reuse** (`extension.rs:359–368`) — sole gate protecting reused
   correlations; constant-time compare **and** (after M1) constant-time `field_mul`; the ban it raises is
   now kind-tagged (H1); session-separation rests on unique caller `session_id`.
2. **Signing u/v/γ consistency + signature assembly** (`signing.rs:777–838,907–1001`) — deferred-inversion
   algebra, the two γ relations binding mul outputs to committed points, recovery-id derivation.
3. **Fast-refresh OT re-randomization** (`refresh.rs:1071–1156`) — in-place bit/seed mutation with
   index-order swap; trusts pre-existing correlations (deferred-detection at next-sign `verify_r`, now tested — M3).
4. **EncProof OR-composition + endemic base OT** (`proofs.rs:753–959`, `base.rs:114–150`) — bit-privacy,
   FS challenge-sum binding, `h==base_h` pin.
5. **DKG Lagrange-in-exponent + chain-code XOR** (`dkg.rs:411–453,1075–1110`).
6. **Public-gadget agreement** (`multiplication.rs:221–230,480–489`) — derived identically both sides,
   **never asserted equal at runtime** (documented L4; a mismatch fails `verify_r` downstream).

---

## 9. Open questions / "need-to-inspect" register

1. **Transient secret zeroization scope** — which stack locals matter; depends on `k256`/`p256` `Scalar` `Drop`. *(EncProof witness nonce now `Zeroizing` — M2.)*
2. **DLog FS** doesn't bind `proof.point` directly — cross-ref Zhou et al. Fig. 27.
3. ~~**`x_coord` panic surface** in `sign_phase4`~~ — **resolved (M6):** `x_coord` is validated up front (`:941`) and the residual `.expect` runs only on the validated value; the original panic was already gated by `verify_ecdsa_signature`.
4. **M3 semantics** — rejects *result* `∈{0,1}`, not *correction==0*. **Fast-path now tested** (M3, 2nd round): guard `refresh.rs:1449`; deferred-detection round trip `:1540`.
5. **`mul_sid`/`zero_sid` are raw `concat()`**, not length-delimited — but `session_id`/`sign_id` are now length-pinned to `ID_LEN` (L1), so the variable-length fields can't collide (`chain_code` is fixed `[u8;32]`).
6. **Serde exposure of secrets** — whether any path persists `Party`/`OTESender`/`ZeroShare` outside the
   zeroized region; whether `OTSender` deserialize re-checks `proof.point == s·G`.
7. **Doc/code drift** — `security.md:67` understates hardening (says `==`, code uses `ct_eq`);
   `DkgSession.proof_commitment` written but never read.

---

## 10. Verification log (confirmed against source)

| Claim | Method | Result |
|-------|--------|--------|
| Signing ban sites | `grep Abort::ban signing.rs` | 4 (`:581/789/817/829`) ✓ |
| Signing recoverable | `grep -c Abort::recoverable` | 31 ✓ |
| DKG / refresh bans | `grep -c Abort::ban` | 0 / 0 ✓ |
| Ban is kind-aware (H1) | read `signing.rs:580–596/788–804` | `match error.kind` ✓ |
| Error `kind` machinery (H1) | read `ot.rs:17–49`, `multiplication.rs:126–173` | `OtErrorKind`/`MulErrorKind` + `from_ot` 1:1 ✓ |
| `field_mul` constant-time (M1) | read `extension.rs:917–921` | `0u64.wrapping_sub(bit)` mask, no data branch ✓ |
| EncProof nonce zeroized (M2) | `grep Zeroizing proofs.rs` | `:805` (deref `:876`) ✓ |
| SignSession low-S default (M4) | read `sign_session.rs:74/234` | always `!s.is_high()` ✓ |
| M6 x_coord guard | `grep InvalidXCoordinateHex signing.rs` | `:941` (after `ZeroDenominator` `:926`) ✓ |
| L1 ssid length | `grep MalformedSessionId signing.rs` | `:266` (`ID_LEN`=32) ✓ |
| M3 trivial-share + H1 zeroize | `grep TrivialKeyShare\|self.zeroize` | `:700/1189`, `:736/1226` ✓ |
| M3 fast-path tested | `grep 'fn test' refresh.rs` | `:1449`, `:1540` ✓ |
| M1 identity rejection (1st round) | `grep identity proofs.rs` | `:388` (DLog), `:667` (CP/Enc) ✓ |
| `ct_eq` usage breadth | `grep -rl ct_eq` | commits, proofs, extension, multiplication ✓ |

---

*Generated during the context-building phase. Vulnerability findings: see [`audit-findings.md`](audit-findings.md).*
