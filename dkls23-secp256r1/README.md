# dkls23-secp256r1

> Part of [**kawasekit-dkls23**](../README.md), a hardened fork of [0xCarbon/DKLs23](https://github.com/0xCarbon/DKLs23).
> **UNAUDITED — testnet / no-value only.** Not published to crates.io; consumed by git rev. See [FORK.md](../FORK.md) and [SECURITY.md](../SECURITY.md).

[DKLs23](https://eprint.iacr.org/2023/765.pdf) Threshold ECDSA for the **secp256r1 (NIST P-256)** curve, with address derivation for multiple blockchains.

Built on [`dkls23-core`](../dkls23-core/) — provides concrete type aliases and chain-specific address computation.

## Supported Chains

| Chain | Function | Address Format |
|-------|----------|----------------|
| NEO3 | `compute_neo3_address` | Base58Check (`N...`) |
| Sui | `compute_sui_address` | Hex (`0x...`) |

## Usage

```toml
[dependencies]
dkls23-secp256r1 = { git = "https://github.com/k0yote/kawasekit-dkls23", rev = "<commit-sha>" }
```

## Features

- `serde` (default) — serialization support for key shares and protocol messages
- `insecure-rng` — deterministic RNG for testing (never use in production)

## Protocol Overview

- **Distributed Key Generation (DKG)** — generate key shares without a trusted dealer
- **Threshold Signing** — produce ECDSA signatures with a subset of parties
- **Key Refresh** — rotate key shares without changing the public key
- **BIP-32 Derivation** — derive child keys from a master key share

Session orchestration, transport, and resumable flows are the responsibility of the consuming application and are out of scope for this crate.

## License

Licensed under either of [Apache License 2.0](../LICENSE-APACHE) or [MIT](../LICENSE-MIT) at your option.
