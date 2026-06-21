# dkls23-core

> Part of [**kawasekit-dkls23**](../README.md), a hardened fork of [0xCarbon/DKLs23](https://github.com/0xCarbon/DKLs23).
> **UNAUDITED — testnet / no-value only.** Not published to crates.io; consumed by git rev. See [FORK.md](../FORK.md) and [SECURITY.md](../SECURITY.md).

Curve-generic core implementation of the [DKLs23](https://eprint.iacr.org/2023/765.pdf) Threshold ECDSA protocol.

This crate provides the cryptographic primitives and protocol logic for:

- **Distributed Key Generation (DKG)** — generate key shares without a trusted dealer
- **Threshold Signing** — produce ECDSA signatures with a subset of parties
- **Key Refresh** — rotate key shares without changing the public key
- **BIP-32 Derivation** — derive child keys from a master key share

## Usage

This is the curve-generic core — most users should depend on a curve-specific crate instead:

- [`dkls23-secp256k1`](../dkls23-secp256k1/) — for Ethereum, Bitcoin, Cosmos, TRON
- [`dkls23-secp256r1`](../dkls23-secp256r1/) — for NEO3, Sui

Use `dkls23-core` directly only if you need to implement a custom curve via the `DklsCurve` trait.

```toml
[dependencies]
dkls23-core = { git = "https://github.com/k0yote/kawasekit-dkls23", rev = "<commit-sha>" }
```

## API Levels

- **High-level:** `DkgSession` and `SignSession` manage protocol state automatically
- **Low-level:** `phase1`–`phase4` functions and keep-state types for advanced resumable/stateless orchestration

Session orchestration, transport, and resumable flows are the responsibility of the consuming application and are out of scope for this crate.

## License

Licensed under either of [Apache License 2.0](../LICENSE-APACHE) or [MIT](../LICENSE-MIT) at your option.
