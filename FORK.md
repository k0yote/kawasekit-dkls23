# FORK.md — kawasekit-dkls23

`kawasekit-dkls23` is kawasekit's maintained fork of **[0xCarbon/DKLs23](https://github.com/0xCarbon/DKLs23)**,
the DKLs23 threshold-ECDSA implementation that backs the `kawasekit-mpc-2p` 2-of-2 co-signer.

It exists for one reason: the **running** mpc-2p backend must carry the pre-paid-audit **self-audit hardening**
(secret zeroization, identity-point rejection, `Parameters` validation, gated trusted-dealer `re_key`), which the
**published** `dkls23-{core,secp256k1} 0.5.1` on crates.io does **not** have. The backend therefore depends on
this fork by an exact git SHA, not on the crates.io release.

## Pinned upstream base

|  |  |
|---|---|
| Upstream | `0xCarbon/DKLs23` |
| Base version | `dkls23-core` / `dkls23-secp256k1` **v0.5.1** (the crates.io release line) |
| Base commit | `c9c407e` — "Merge pull request #90 from 0xCarbon/dev" (2026-04-09) |
| Fork branch | `dev` |
| Fork HEAD (pinned by the backend) | `4ec716bc479b351e5822d7f21f0e6d0d86d96173` |

The backend pins this exact SHA in **two** places — they MUST match, otherwise two copies of
`dkls23-secp256k1` (crates.io vs git) would make the `Abort` types incompatible:

- `kawasekit-mpc-2p/crypto-core/Cargo.toml` → `dkls23-secp256k1 = { git = "…/kawasekit-dkls23.git", rev = "4ec716bc…" }`
- `kawasekit-mpc-2p/Cargo.toml` (dev-dep) → same git + rev.

> The 0.5.1 line the fork is cut from already carries upstream's own `rand 0.10.1` maintenance bump
> (`6fe0259`, merge `a0ac4d0`); those are upstream commits, not part of the kawasekit delta.

## The delta (what this fork changes vs the published 0.5.1)

Nine commits, `4398d25..4ec716b` on `dev`, plus the A4 build-safety guards below. All are **defensive
hardening from the crate self-audit** (`docs/security.md` and the mpc-2p `docs/SELF-AUDIT.md`); none change the
wire format or the protocol math, so this **first round** is a **drop-in source swap** for the published 0.5.1
(same crate name + version `0.5.1`).

> **Heads-up on finding IDs.** A later **second self-audit round** (recorded in `docs/audit-findings.md`) reuses
> the letters **M1/M2/M3/H1** for *different* findings than the first-round table below — read the two as
> **separate sets**. See [Second self-audit round](#second-self-audit-round) for the
> four fixes it landed, one of which (**M4**, low-S) is a **breaking API change**, so the fork as a whole is no
> longer a pure drop-in.

| File | Self-audit finding | One-line rationale |
|---|---|---|
| `dkls23-core/src/utilities/proofs.rs` | **M1** + **M2** | Reject identity points at the proof-verifier boundary; validate `Parameters` on deserialize. |
| `dkls23-core/src/protocols.rs` | M1/M2 support | Shared validation surface used by the boundary checks above. |
| `dkls23-core/src/utilities/ot/base.rs` | **H1 (part 1)** | Zeroize the base-OT secret/seed + Schnorr nonces after use. |
| `dkls23-core/src/protocols/dkg.rs` | **H1 (part 2)** | Zeroize key-init carriers in DKG. |
| `dkls23-core/src/protocols/refresh.rs` | **H1 / M3** | Zeroize the old `Party` on refresh; reject a trivially-refreshed (unchanged) key share. |
| `dkls23-core/src/protocols/re_key.rs` | **C1** | Gate single-custody trusted-dealer `re_key` behind a non-default feature; zeroize its trusted-dealer locals. |
| `dkls23-core/Cargo.toml` | C1 | Declare the `trusted-dealer-import` (gated `re_key`) feature, default-off. |
| `dkls23-core/src/lib.rs` | **A4** (kawasekit M6-3a) | `compile_error!` guards: `insecure-rng` forbidden outside `cfg(test)`; `trusted-dealer-import` forbidden on `wasm32`. |
| `docs/security.md` | — | Records the self-audit hardening. |
| `.github/…` | — | CI hygiene: spelling dictionary; drop the deprecated upstream audit/unmaintained workflows (replaced by `supply-chain.yml` + `feature-guards.yml`). |

### A4 — locked-out feature combinations

`dkls23-core/src/lib.rs` carries `compile_error!` guards (belt-and-suspenders over the existing `#[cfg(...)]`
gating), and `.github/workflows/feature-guards.yml` asserts them in CI:

| Build | Result | Why |
|---|---|---|
| `--features insecure-rng` (non-test) | **must fail** | `insecure-rng` weakens the CSPRNG; it is test-only. |
| `--target wasm32 --features trusted-dealer-import` | **must fail** | The wasm32 **agent** is a distributed 2-of-2 party; single-custody `re_key` import would be a custody violation. |
| `--features trusted-dealer-import` (native) | **must succeed** | A deliberate **native** import flow is a documented, legitimate use (`re_key.rs`). |
| default (native + wasm32) | **must succeed** | The normal builds. |

> **Design note (A4 scoping):** the `trusted-dealer-import` guard is scoped to `wasm32`, not "outside test",
> because the fork documents a legitimate native import use. The custody risk is specifically the **agent**
> (the wasm32 party), so the guard targets that build and leaves native import available. `insecure-rng` is
> truly test-only, so its guard is "outside `cfg(test)`".

> **Hard rule — `trusted-dealer-import` is provisioning-only, never a service capability.** The native
> `trusted-dealer-import` (single-custody `re_key`) exists for a one-time **provisioning / import** path
> ONLY. The production owner-backend **service** build MUST NEVER enable it — the running backend must never
> reconstitute a full key. This is the non-custodial invariant: import is a one-time provisioning step, not a
> standing service capability. The `wasm32` guard above stops the agent; this rule binds the **native service**
> build by policy (the guard can't distinguish a service binary from a provisioning tool on native).
> **TODO (when the import flow is implemented):** give it its own feature-guarded binary, separate from the
> backend service binary, so the service binary can never link the import code path. This rule also belongs in
> the deploy runbook (Track D — note it here, do not build Track D now).

## Second self-audit round

A second, independent CTO-class self-audit (recorded in `docs/audit-findings.md`, with a deep-dive in
`docs/audit-deepdive-signing.md`) walked the OT/VOLE, signing, refresh, and Rust/secret-safety classes and
verified the **first-round delta is clean and additive vs upstream `c9c407e`** (no upstream check weakened; the
protocol math is byte-identical). It produced **four pre-paid-audit fixes**, all landed as reviewed PRs on `dev`.

> Its finding IDs **collide by letter** with the first-round table above — they are a **separate set**. In
> particular this round's **M2** *completes* the first round's **H1** zeroization sweep, and this round's **M1**
> is unrelated to the first round's identity-rejection **M1**.

| Finding (2nd round) | What | Files | PR | Drop-in? |
|---|---|---|---|---|
| **H1** `[abort]` | Ban a counterparty **only** on the leak-bearing consistency failure (`verify_r`/COTe), not on benign dimension/format errors. `ErrorMul`/`ErrorOT` gain a machine-readable kind. | `protocols/signing.rs`, `utilities/multiplication.rs`, `utilities/ot.rs`, `utilities/ot/extension.rs` | #15 | yes |
| **M1** `[const-time]` | Make the GF(2²⁰⁸) `field_mul` comb constant-time (drop the secret-dependent branch in the OTE check). | `utilities/ot/extension.rs` | #18 | yes |
| **M2** `[secret-hygiene]` | Zeroize the EncProof/Chaum-Pedersen witness-bearing nonce — **completes the first round's H1 sweep**. | `utilities/proofs.rs` | #16 | yes |
| **M4** `[finishing]` | `SignSession::phase4` always emits canonical **low-S** (EIP-2); no knob to emit malleable high-S. | `protocols/sign_session.rs` | #17 | **NO — breaking** |

> **⚠️ M4 is a breaking API change**, so this round is **not** a pure drop-in (unlike round one):
> `SignSession::phase4(received, normalize)` → `SignSession::phase4(received)`. The low-level
> `Party::sign_phase4(.., normalize)` is **unchanged** (it remains the explicit opt-out). **Action for the
> backend:** when bumping the pinned `rev` past this round, **drop the `normalize` argument** from the
> `SignSession::phase4` call site (behavior becomes always-low-S). See the rebase process below.

Still-open findings from this round (not yet landed; tracked in issue #13): **M3** (fast-refresh consistency
test), **M5** (supply-chain runbook + yanked-crate check), **M6** (`sign_phase4` hex panic), **L1–L4** (polish).

## ToB-methodology review round

A third pass walked all 15 TOB-SILA classes (Trail of Bits' Silent Shard methodology) against the core —
recorded in `docs/audit-tob-methodology-review.md`, tracked as GitHub issues `[ToB-H1..L4]`. It confirmed the
fork had **already converged on ToB's two High findings** (selective-abort = 2nd-round H1; setup-threshold =
M2) and surfaced **one genuinely new gap** plus pre-audit hardening.

> Finding IDs **collide by letter** with both earlier rounds — a **third separate set** (`[ToB-*]`, the
> GitHub issues). This round's **H1** is unrelated to the first/second-round H1s.

| Finding (ToB round) | What | Files | PR | Drop-in? |
|---|---|---|---|---|
| **H1** `[ssid]` `[abort]` | Cross-party **agreement** on the assembled DKG root (`chain_code`) + session ids was unverified in-core (DKG *binds* each aux chain code but never cross-verifies the *assembled* root; `session_id` enters the keyshare unchecked) → two honest parties left with divergent-but-valid views would **ban each other** at the leak-bearing phase-2 COTe check (key-destruction). Fix: `sign_phase1` broadcasts a Fiat-Shamir echo `H(session_id ‖ sign_id ‖ chain_code)`; `sign_phase2` constant-time cross-checks it **before** any leak-bearing mul → `RootAgreementMismatch` (recoverable + identifiable). | `protocols/signing.rs`, `protocols.rs`, `utilities/oracle_tags.rs` | #38 | yes |
| **M1** `[const-time]` | Three residual secret-choice-bit branches beyond `field_mul` (TOB appendix D): `t_b` (OTE), the gadget-fold `b`, and the `verify_u` entry. Fix: compute both branches and `Choice`-select (`subtle::ConditionallySelectable`) instead of `if bit { … }` — no secret-dependent branch; behaviour unchanged. Measured-timing verdict stays paid-audit-reserved. | `utilities/ot/extension.rs`, `utilities/multiplication.rs` | #40 | yes |
| **M2** `[ssid]` | No runtime protocol-version handshake (TOB-SILA-11a): a version mismatch surfaced only as an opaque later consistency/proof failure (or a ban). Fix: a crate `PROTOCOL_VERSION` stamped into the signing phase-1 broadcast and checked in `sign_phase2` **before** any leak-bearing step → `ProtocolVersionMismatch` (recoverable, identifiable). Defense-in-depth; not key-affecting. | `lib.rs`, `protocols/signing.rs`, `protocols.rs` | #41 | yes |
| **L1** `[supply-chain]` | Document that `KAPPA=256` is the OT-correlation width, not a security claim; computational security tracks the curve (~128-bit). Doc-only, no number changes. | `lib.rs`, `docs/audit-context.md` | #42 | yes |
| **L2** `[validation]` | Add the missing γ_v-ban and base-OT `s≠0` negative tests; introduce `proptest` on the input-validation surface (PartyIndex/Parameters/hex). Tests + `proptest` dev-dep only. | `protocols/signing.rs`, `utilities/ot/base.rs`, `protocols.rs` | #42 | yes |
| **L3** `[supply-chain]` | Wire two of ToB's tools into CI: a `cargo llvm-cov` coverage job (report + lcov artifact) and an advisory `cargo dylint` job (ToB general lints, `continue-on-error`). CI/tooling only; no crate change. | `.github/workflows/coverage-lint.yml`, `Cargo.toml` | #43 | yes |
| **L4** `[validation]` | `zip` → `itertools::zip_eq` at the COTe consistency fold (length-safe; never panics — both vectors are KAPPA by construction). Adds the `itertools` dep. | `utilities/ot/extension.rs` | #42 | yes |

> **Scope (honesty):** the in-core echo closes the **honest-divergence** case (a passive relay delivering
> different-but-each-valid views). A **malicious** equivocator that forges a matching echo while signing under
> a different root still bans at phase 2 — full equivocation resistance is the authenticated-broadcast /
> transport layer's responsibility (TOB-SILA-6/9/14, carried to the backend `kawasekit-mpc-2p`).

All ToB-methodology findings (H1, M1, M2, L1–L4) are now resolved (PRs #38, #40–#43). The OT/VOLE
multiplication soundness and all *measured* side-channel work stay **reserved for the paid audit**, and the
transport-layer classes (TOB-SILA-6/9/14) are carried to the backend `kawasekit-mpc-2p`.

**Follow-up (PR #44):** the ToB-M2 protocol-version check is **extended to DKG** — `PROTOCOL_VERSION` is
stamped into `BroadcastDerivationPhase2to4` and checked in `dkg::phase4` so a cross-version *keygen* aborts
early (`ProtocolVersionMismatch`). Cross-party root agreement (H1) stays **delegated to the signing-side
echo** (no DKG round added — see the H1/M2 notes in `docs/audit-tob-methodology-review.md`).

## Frozen release-candidate crypto versions

DKLs23 is built on the `k256` / `elliptic-curve` **0.14 release-candidate** line. There is **no stable `k256`
0.14** — stable `k256` is `0.13`, a different API the DKLs23 code is not written against. So the crypto is, and
remains until upstream ships a stable 0.14, **version-scoped to exact release candidates**:

- The backend pins `k256 = "=0.14.0-rc.9"` and `elliptic-curve = "=0.14.0-rc.32"` (exact `=` pins in
  `kawasekit-mpc-2p/crypto-core/Cargo.toml`); the committed `Cargo.lock` is the authoritative freeze.
- **One unified resolution for what ships.** The fork is consumed *as the backend's git dependency*. In that
  build the backend's `=` pins drive a single resolution across the whole tree — including the fork's DKLs
  crates — so the running co-signer has exactly **one** `k256 0.14` (`rc.9`) and **one** `elliptic-curve 0.14`
  (`rc.32`). That backend `Cargo.lock` is the audit target. The fork's *standalone* `Cargo.lock` (used only by
  the fork's own CI, in isolation) floats on the same rc line and is **not** what ships.
- **The freeze is load-bearing — the rc line is actively churning.** A bare `cargo update` on a fresh tree now
  pulls `elliptic-curve 0.14.0-rc.33` (published after the freeze; an exact `rc.32` resolve already fails a
  `rustcrypto-ff` constraint). The `=` pins + the committed lock are the only thing holding the audited versions.
- **Decision — which lock is authoritative: the BACKEND's.** We do **not** commit-freeze the fork's standalone
  `Cargo.lock`; the fork's own CI is allowed to float to a newer rc (e.g. `rc.33`). The single authoritative
  frozen set is the **backend's committed `Cargo.lock`** (`k256 0.14.0-rc.9` / `elliptic-curve 0.14.0-rc.32`) —
  that is what ships and what the T2 audit targets. The fork CI's role is supply-chain signal
  (advisories/licenses/sources) across the rc line, **not** to define the shipped crypto versions. If a fork-CI
  rc differs from the backend's frozen set, the **backend's** set wins by definition.
- **Audit scope:** the mandatory third-party crypto audit is scoped to *the backend's frozen rc versions* +
  this fork delta. Bumping any backend rc pin re-opens that scope. Do **not** `cargo update` the crypto crates
  in the backend.

## Upstream-advisory / rebase process

1. Watch `0xCarbon/DKLs23` (releases + `dev`) and the [RustSec advisory-db] for anything touching the dep
   tree. `cargo audit` and `cargo deny check` are wired into `supply-chain.yml` (incl. a weekly schedule) to
   catch newly-published advisories against the frozen rc tree.
2. To take an upstream fix: rebase the kawasekit delta onto the new upstream tag on a topic branch; resolve
   conflicts only in the touched files; keep the delta minimal (no new behavior).
3. Re-run the full fork CI (`backend-ci`, `clippy`, `fmt-check`, **`supply-chain`**, **`feature-guards`**, **`docs-citations`**).
   - **Doc citations (#27):** the audit docs are line-anchored; `docs-citations.yml` snapshots every cited
     source line into `docs/audit-citations.lock` and fails when a cited line's content drifts. After a rebase
     that shifts source lines — or any intentional re-grounding of `docs/audit-context.md` — re-verify the
     affected citations, then re-bless the lock: `python3 tools/check_doc_citations.py --update`.
4. Bump the pinned `rev` in **both** backend `Cargo.toml`s + refresh the backend `Cargo.lock`; re-run the
   backend 4-point + the M6-3a gates + the e2e; update this file's HEAD + base rows.
   - **If the bump crosses the second self-audit round (PRs #15–#18):** drop the `normalize` argument from the
     backend's `SignSession::phase4(received, normalize)` call(s) — the only source change that round requires
     of the backend (the result is now always low-S). See [Second self-audit round](#second-self-audit-round).
   - **Supply chain (2nd-round M5):** after refreshing the backend `Cargo.lock`, run `cargo audit` and
     `cargo deny check` on the **backend** tree and confirm its frozen lock carries **no yanked crate** and no
     new advisory. The fork's *standalone* lock is allowed to float — `deny.toml` sets `yanked = "warn"` for the
     frozen-tree `crypto-bigint 0.7.1`, surfaced not failed — but the **backend's authoritative lock is what
     ships**, so a yanked crate or a new advisory **there** is release-blocking. A new advisory against the
     frozen rc tree needs no code change to become relevant, which is why `supply-chain.yml` also runs weekly.
5. Land as a reviewed PR — the backend pin bump and the fork HEAD move in the **same** cycle.

## Status

UNAUDITED. The fork carries the **self-audit** hardening only; the mandatory **third-party** crypto audit is a
standing pre-mainnet gate (it does **not** clear by self-audit). Testnet / no-value only.

[RustSec advisory-db]: https://github.com/RustSec/advisory-db
