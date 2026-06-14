# Security Considerations

This document describes security properties, assumptions, and known limitations
of the DKLs23 implementation.

## Cryptographic Assumptions

The protocol's security relies on:
- **Hardness of ECDLP** on secp256k1
- **Random oracle model** (SHA-256 and SHA3-256 are used as instantiations)
- **Secure authenticated channels** between all parties

## OT Correlation Reuse

The DKLs23 protocol reuses base OT correlations (`OTESender` / `OTEReceiver`)
across multiple signing sessions for efficiency. This design is secure under
honest execution, but if a counterparty cheats during the COTe consistency check
or the multiplication verification step, information about the reused OT state
leaks.

**Mandatory response**: When a multiplication or consistency check fails, the
abort carries `AbortKind::BanCounterparty(index)`. The application MUST
permanently exclude the identified party from all future signing and refresh
sessions. Failure to do so enables gradual key extraction across sessions.

See Section 3.2 of the paper for the formal security argument.

## Fiat-Shamir Transcript Binding

Session IDs for the multiplication protocol and zero-share protocol include:
- Protocol domain separator
- Both party indices
- DKG session ID
- Signing session ID
- BIP-32 chain code (binds to the derived key path)

This prevents cross-session and cross-derivation transcript reuse.

## Memory Safety

- `#![forbid(unsafe_code)]` is enforced crate-wide.
- All types holding secret material implement `Zeroize` and `ZeroizeOnDrop`:
  - `OTESender`, `OTEReceiver` (OT correlations)
  - `OTSender`, `OTReceiver` (base-OT sender secret `s` / receiver seed)
  - `MulSender`, `MulReceiver`, `MulDataToKeepReceiver` (multiplication state)
  - `ZeroShare`, `SeedPair` (shared seeds)
  - `DerivData` (derived key share and chain code)
  - `KeepPhase1to2`, `KeepPhase2to3` (signing intermediates)
  - `UniqueKeep1to2`, `UniqueKeep2to3` (signing intermediates)
  - DKG init carriers: `KeepInitMulPhase3to4`, `TransmitInitMulPhase3to4`
    (base-OT/COTe bootstrap state), `KeepInitZeroSharePhase2to3`,
    `KeepInitZeroSharePhase3to4`, `TransmitInitZeroSharePhase3to4` (zero-share PRF seeds)
  - Refresh carriers: `KeepRefreshPhase2to3`, `KeepRefreshPhase3to4`,
    `TransmitRefreshPhase3to4` (refresh PRF seeds)
  - `Party` (manual `Zeroize` + `Drop` implementation)
- The non-interactive ZK proof objects (`DLogProof`, `InteractiveDLogProof`,
  `CPProof`, `EncProof`) and the public routing field `parties: PartiesMessage`
  carried by the init carriers above are **broadcast values** — they hold no secret
  material and are `#[zeroize(skip)]`ped where they appear inside a zeroizing struct.
  The witness-bearing secrets are the per-round proof **nonces**, which never enter a
  proof object: the Schnorr nonce is held in `Zeroizing` inside `DLogProof::prove`, and the
  Chaum-Pedersen real-branch nonce (witness-bearing in the `EncProof` OR-proof, since the
  witness is recoverable from it) is held in `Zeroizing` inside `EncProof::prove` — both
  wiped on return. (The fake-branch challenge is a public proof field, so it is not wiped.)

## Side-Channel Resistance

- Scalar arithmetic is delegated to `k256`, which uses constant-time operations
  from the `subtle` crate.
- Hash comparisons in the commitment scheme (`commits.rs`) use standard `==` on
  `[u8; 32]`. This is a potential timing side-channel, though exploitation
  requires an attacker who can both supply malicious messages AND measure
  sub-microsecond timing differences.

## Deterministic RNG (`insecure-rng` feature)

The `insecure-rng` feature is scoped to `cfg(test)` only. Even if the feature
flag is enabled in a production build, the secure `ThreadRng` is always returned.
This makes it impossible to accidentally ship deterministic randomness.

## Signature finishing (low-S / malleability)

ECDSA signatures are malleable: `(r, s)` and `(r, n - s)` both verify. The high-level
**`SignSession::phase4`** always emits the canonical **low-S** form (EIP-2 / BIP-62) and exposes no
knob to disable it — this is the recommended signing path. The low-level
`Party::sign_phase4(…, normalize)` keeps an explicit `normalize` flag for advanced callers who
genuinely need an un-normalized `s`; passing `false` there yields a malleable high-S signature, so
EVM / Bitcoin signers must not do so.

The `recovery_id` carried by `EcdsaSignature` is a 2-bit value (bit 0 = `R.y` parity, bit 1 =
`R.x >= n`), **not** the EIP-155 `v`; the consumer derives `v` from it. It is computed *after* low-S
normalization, so it stays consistent with the emitted `s`.

## Known Limitations

1. **No hardened BIP-32 derivation**: Only non-hardened derivation is supported
   because no party holds the full secret key.
2. **No proactive security refresh schedule**: The refresh protocol exists but
   the crate does not enforce periodic refresh. Applications should implement
   their own refresh schedule.
3. **u8 party indices**: Party counts are limited to 255 by the `u8` type.
