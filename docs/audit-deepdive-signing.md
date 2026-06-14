# Deep Dive — Signing Consistency, Signature Assembly & the Error→Ban Dataflow

> Companion technical trace for [`audit-findings.md`](audit-findings.md) finding **H1** and the
> signing fragility cluster in [`audit-context.md`](audit-context.md) §8.2. Pure technical analysis;
> all line numbers are `dkls23-core/src/protocols/signing.rs` unless noted. This deepens *one* cluster —
> it does not replace the per-module context model.

This is the path that actually produces an ECDSA signature and the path where the OT-reuse
key-extraction risk is contained. Understanding it precisely is what justifies H1's severity.

---

## 1. The deferred-inversion identity (why `u`, `v`, `w` exist)

ECDSA needs `s = k⁻¹·(H(m) + sk·r)`. In a threshold setting `k` and `sk` are *secret-shared* — you
cannot invert a shared `k` directly. DKLs23's trick: introduce a per-party **inversion mask** `φ_i`,
multiply through by `φ_total = Σφ_i`, and let the inversion fall out of a *division of two public
aggregated scalars*. The code realizes exactly this.

Per party `i`: `instance_key k_i`, `inversion_mask φ_i`, `key_share sk_i = poly_point·λ_i + ζ_i`
(with `Σζ_i = 0`, so `Σ sk_i = sk`), and `instance_point R_i = k_i·G`. For each counterparty `j` the
pairwise multiplication yields sender outputs `c_u, c_v` (party in sender role, input `[k_i, sk_i]`) and
receiver outputs `d_u, d_v` (party in receiver role), satisfying the RVOLE relation
`c + d = (sender input)·χ` where `χ` is the receiver's random factor (`current_kept.chi`).

**The assembled scalars** (`signing.rs:831–838`):
```
u = k_i·(φ_i + Σ_j ψ_j) + Σ_j (c_u + d_u)          // L831
v = sk_i·(φ_i + Σ_j ψ_j) + Σ_j (c_v + d_v)         // L832
w = H(m)·φ_i + v·r                                  // L838  (r = reduce(R.x))
```
where `ψ_j = φ_j − χ_j` (`signing.rs:583`) and `first_sum_u_v = φ_i + Σ_j ψ_j` (`:805` accumulates `ψ_j`
onto the `φ_i` seed). Summed across all parties, the cross-terms telescope (this is the DKLs23 algebra;
the test cross-checks it against an independent ECDSA at `signing.rs:1411–1422`):
```
Σ u_i = k_total · φ_total
Σ v_i = sk    · φ_total
Σ w_i = H(m)·φ_total + (Σ v_i)·r = φ_total·(H(m) + sk·r)
```
**Phase 4 division** (`signing.rs:878–894`):
```
s = (Σ w_i) / (Σ u_i)
  = φ_total·(H(m)+sk·r) / (k_total·φ_total)
  = k_total⁻¹·(H(m) + sk·r)                          ← the ECDSA s, with r = (k_total·G).x
```
**The key safety property:** `k_total⁻¹` is *never computed on a secret*. It emerges from a division of
`Σw` by `Σu`, both of which are public broadcast scalars (`Broadcast3to4{u, w}`, `:840`). The mask
`φ_total` multiplies both sums and cancels in the quotient, and it is precisely what hides `k_total`
(an observer only ever sees `k_total·φ_total = Σu`, never `k_total`). This is why there is **no
threshold inversion sub-protocol** and no nonce ever leaves a party.

---

## 2. The two γ consistency checks — what they bind, and why failure ⇒ ban

Between computing the multiplication and trusting its outputs, phase 3 runs two checks
(`signing.rs:777` and `:790`). They are the malicious-security crux of signing.

**γ_u check** (`signing.rs:777`):
```rust
if (message.instance_point * current_kept.chi) != ((generator * d_u) + message.gamma_u) {
    return Err(Abort::ban(..., AbortReason::GammaUInconsistency { counterparty }));
}
```
With `message.instance_point = R_j = k_j·G`, `message.gamma_u = c_u·G` (j's sender output point, set in
phase 2 `:580`), and `χ = current_kept.chi`, this checks (in the exponent):
```
k_j·χ·G  ==  (d_u + c_u)·G      ⟺      c_u + d_u  ==  k_j·χ
```
i.e. *the multiplication output `(c_u, d_u)` is consistent with the nonce `k_j` that `j` **committed** to
in `R_j`.* A malicious `j` who fed a different `k_j′ ≠ k_j` into the multiplication than the one behind
its committed `R_j` produces `c_u + d_u = k_j′·χ ≠ k_j·χ` and fails here.

**γ_v check** (`signing.rs:790`): identical structure with `sk_j` / `pk_j = sk_j·G`:
```
sk_j·χ  ==  c_v + d_v
```
binding the multiplication's `v`-instance output to `j`'s committed verification share `pk_j`. (Note the
documented paper-deviation at `:786–789`: the implementers use `pk_j` where the paper writes
`Lagrange(P,j,0)·P(j)`, justified against the alt-`gamma_v` computation on p.21 — a deliberate, commented
deviation a paid auditor should confirm against the paper.)

**Why a failure must ban, not retry.** `R_j` and `pk_j` were commitment-bound in phase 1 (`commit_point`,
`:328`), decommitted in phase 2 (`:606`), and verified in phase 3 (`verify_commitment_point`, `:719`). So
a γ mismatch is unambiguous: `j` used inconsistent values between its commitment and the multiplication —
and the multiplication runs on the **persistent, session-reused** OT correlations (`Party.mul_*`). A
counterparty probing with inconsistent inputs is exactly the OT-reuse leakage the ban exists to stop
(`protocols.rs:262–280`). These two ban sites (`:779`, `:791`) carry **dedicated, unambiguous reasons**
(`GammaUInconsistency`, `OtConsistencyCheckFailed`) — they are *correctly* always-ban. **They are not the
H1 problem.**

---

## 3. The error→ban dataflow — where H1 actually lives (precise trace)

The two ban sites that *do* conflate are the multiplication-`Err` sites. Trace the receiver side
(`signing.rs:752–767`):
```rust
let mul_result = mul_receiver.run_phase2(&mul_sid, &current_kept.mul_keep, &message.mul_transmit);
match mul_result {
    Err(error) => {
        return Err(Abort::ban(                                       // ← L759: ALWAYS ban
            self.party_index, counterparty,
            AbortReason::MultiplicationVerificationFailed {
                counterparty, detail: error.description.clone(),     // ← only a String survives
            }));
    }
    Ok(d_values) => { d_u = d_values[0]; d_v = d_values[1]; }
}
```
`run_phase2` returns `Result<_, ErrorMul>`, and `ErrorMul` (`multiplication.rs:121`) carries **only**
`description: String`. Its `Err` has three distinct origins with *opposite* required handling:

```
mul_receiver.run_phase2  (multiplication.rs:569)
   │
   ├── dimension guard            multiplication.rs:575–579   → ErrorMul("…incorrect dimensions")     ──┐ BENIGN
   ├── OTE phase-2 (dim/format)   extension.rs:742–751        → ErrorMul(wraps ErrorOT)               ──┤ (should be
   │                                                                                                    │  recoverable)
   └── verify_r consistency check multiplication.rs:645–649   → ErrorMul("…Consistency check failed!") ── LEAK-BEARING
                                   (constant-time ct_eq)                                                   (MUST ban)
        │
        ▼  all three collapse to one String, then →  Abort::ban  (signing.rs:759)
```
The sender side is symmetric (`signing.rs:556→563`): `mul_sender.run` (`multiplication.rs:214`) returns
`Err` from either the **COTe consistency check** (`extension.rs:359–366`, leak-bearing, must ban) **or**
dimension guards (`extension.rs:230–247`, benign) — both → `Abort::ban` at `:563`.

**So:** of the four signing ban sites, **two are clean** (γ_u/γ_v, dedicated reasons) and **two are
overloaded** (`:563`, `:759` — leak-bearing *and* benign collapsed into one `BanCounterparty`). That is
the exact surface of H1. The integrator cannot recover the distinction because the error type discarded
it three layers down.

**Why this is High, both directions:**
- *Over-ban → 2-of-2 fund-lock.* A benign dimension/format error (version skew, transport corruption,
  a bug) permanently excludes the only counterparty → the wallet can never sign → fund-availability event.
- *Under-ban → key extraction.* An integrator who softens `BanCounterparty` handling to avoid the
  lock-outs (e.g. retries with the same party) re-opens the OT-reuse key-extraction attack across
  sessions — the precise failure the ban exists to prevent.

The fix (H1) is to give `ErrorMul`/`ErrorOT` a machine-readable kind and ban *only* on
`ConsistencyFailure`, mapping dimension/format to `recoverable` — which is already how DKG/refresh treat
their mul-init errors (they have no reusable state to leak; `dkg.rs`/`refresh.rs` use `recoverable`
throughout, verified: 0 `Abort::ban`).

---

## 4. The verify-before-return backstop, and why it is *not* a substitute for §3

Phase 4 independently recomputes and verifies the ECDSA signature before returning it
(`signing.rs:905`, `verify_ecdsa_signature` at `:988–1031`):
```
R' = (G·H(m)·s⁻¹) + (pk·r·s⁻¹)        // :1018, rejects identity :1020
accept ⟺ reduce(R'.x) == r            // :1030 ; r,s parsed canonical (from_repr, reject ≥ n) :994/998 ; reject zero :1004
```
This is a full, independent ECDSA check — a forged or inconsistent aggregate cannot be returned
(`SignatureVerificationFailed`, recoverable, `:907`). It is a genuine strength.

**But it guards a different property than the γ-checks + ban.** Verify-before-return ensures *output
integrity* (no invalid signature escapes). The γ-checks + correct ban ensure *long-term key secrecy*
(no key-extraction via repeated OT-reuse probing). They are complementary, not redundant: an attacker who
only wants to *leak key bits over many sessions* does not care that the final signature fails to verify —
the leak happens during the multiplication, before assembly. **This is exactly why H1 matters even though
verify-before-return exists:** the backstop catches bad *outputs*, not the slow OT-state *leak*; only the
correctly-targeted ban does that.

---

## 5. Const-time & panic surface on the signing path (scoped)

- **Point comparisons in the γ-checks** (`:777`, `:790`) use `!=` on `AffinePoint`, not `ct_eq`. The
  operands derive from secret `χ`/`d_u`/`d_v`, but the only thing the comparison reveals is the
  (public) check-failed bit that becomes a ban. Timing of the point `==` (curve-crate `PartialEq`) leaks
  at most *which coordinate byte differs* on a failing check — already-public information. Low concern;
  noted because the operands are secret-derived and the comparison is not the project's usual `ct_eq`.
- **Scalar arithmetic** (`u,v,w,s`, the reduces, `s.invert()`) is `k256`/`p256` `Scalar` ops — constant
  time per those crates. The **non-constant-time concern on this path is one layer down**: the OTE
  `field_mul` (M1), invoked via the multiplication, branches on secret-derived correlation bits.
- **Ordering-dependent panic:** `s.invert().unwrap()` (`:923`) is safe *only because*
  `verify_ecdsa_signature` (`:905`, which rejects `s == 0` at `:1004`) ran first. A future reorder that
  moved the rec-id computation before the verify would make this panic reachable. Worth a guard comment.
- **`x_coord` hex panic** (`:937`, and `reduce_hex_bytes` `:976`) — finding **M6**: `.expect("valid hex")`
  on the caller-supplied `x_coord` panics the low-level `Party::sign_phase4` API on malformed input. The
  `SignSession` path is internally safe (`x_coord` is produced by `hex::encode` at `:834`); the
  low-level API is the exposure.
- **Low-S is optional** (`:898`, `if normalize && s.is_high()`) and `verify_ecdsa_signature` accepts
  high-S — so the crate can emit a *verifying but malleable* high-S signature when `normalize == false`
  (finding **M4**).

---

## 6. Summary — what this cluster establishes

| Property | Mechanism | Verdict |
|---|---|---|
| Nonce never inverted as a secret | deferred inversion `s = Σw/Σu`, `φ_total` mask cancels (`:831–894`) | ✅ correct & elegant |
| Mul output bound to committed nonce/share | γ_u/γ_v checks (`:777/790`), commitment-decommit (`:328/606/719`) | ✅ present, dedicated ban reasons |
| Output integrity | verify-before-return (`:905`) | ✅ strong backstop |
| Long-term key secrecy under OT reuse | ban on leak-bearing mul failure | ⚠️ **correct ban present but conflated with benign errors → H1** |
| Const-time on signing scalars | `k256`/`p256` ops | ✅ (point `!=` in γ-checks noted) |
| Const-time on the mul substrate | OTE `field_mul` | ⚠️ secret-bit branch → **M1** (one layer down) |
| Malleability | low-S optional | ⚠️ **M4** |
| Panic safety | mostly invariant-`expect`; `x_coord` exposed | ⚠️ **M6** (low-level API) |

The signing algebra and the malicious-security checks are **present and correctly placed**. The residual
risk on this path is not a missing check — it is that the *error taxonomy* (H1) prevents an integrator
from acting on the ban safely, plus the const-time (M1) and finishing (M4) hardening items. None is a
key-extraction defect *in this crate*; H1 is the one that, mis-integrated, could become one — which is why
it leads the findings and why the paid audit must review the final taxonomy and the DKLs23 algebra
round-by-round against the paper.
