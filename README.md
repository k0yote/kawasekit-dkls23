<div align="center">
  <p>
    <a href="https://github.com/k0yote/kawasekit-dkls23/actions/workflows/coverage-lint.yml">
      <img src="https://github.com/k0yote/kawasekit-dkls23/actions/workflows/coverage-lint.yml/badge.svg?branch=dev" alt="CI status">
    </a>
  </p>
</div>

# kawasekit-dkls23

> **⚠️ UNAUDITED — testnet / no-value only.** This is kawasekit's **hardened fork** of
> [0xCarbon/DKLs23](https://github.com/0xCarbon/DKLs23), carrying pre-paid-audit **self-audit
> hardening only**. A third-party cryptographic audit is a standing pre-mainnet gate that a
> self-audit **does not clear**. Do **not** use this with real value. See [FORK.md](FORK.md)
> and [SECURITY.md](SECURITY.md).

## Overview

An implementation of the [DKLs23 threshold-ECDSA protocol](https://eprint.iacr.org/2023/765.pdf):
ECDSA signatures computed across multiple parties, each holding a key share, without ever
reconstructing the secret key in one place.

`kawasekit-dkls23` is a fork of 0xCarbon's implementation, hardened ahead of a paid audit. The
protocol math is **byte-identical to upstream `v0.5.1`** (`c9c407e`); the delta is purely additive
defensive hardening. Pinned base, per-finding delta, and rebase process are in [FORK.md](FORK.md).

## How it's consumed

This fork is **not published to crates.io** — it keeps the upstream crate names and is consumed by
pinning an exact git commit:

```toml
[dependencies]
dkls23-secp256k1 = { git = "https://github.com/k0yote/kawasekit-dkls23", rev = "<commit-sha>" }
# or dkls23-secp256r1 / dkls23-core
```

> The crates.io `dkls23-*` packages are **upstream 0xCarbon's** releases and do **not** carry this
> fork's hardening. Pin this repo by git rev to get the hardened code.

## Crates

| Crate | Description |
|-------|-------------|
| [`dkls23-core`](dkls23-core/) | Curve-generic core protocol |
| [`dkls23-secp256k1`](dkls23-secp256k1/) | secp256k1 — Ethereum, Bitcoin, Cosmos, TRON |
| [`dkls23-secp256r1`](dkls23-secp256r1/) | NIST P-256 — NEO3, Sui |

## Orchestration & transport

This is the cryptographic core only. Session orchestration, transport, and message authentication
are the responsibility of the consuming application and are **out of scope** for this repository.

## Building & testing

```bash
git clone https://github.com/k0yote/kawasekit-dkls23
cd kawasekit-dkls23
cargo test
```

## Security

- **Reporting:** use GitHub's private vulnerability reporting (repository **Security → Report a
  vulnerability**). See [SECURITY.md](SECURITY.md).
- **Audit status & ceiling:** [SECURITY.md](SECURITY.md), [FORK.md](FORK.md), and the artifacts under
  [`docs/`](docs/). Open findings: issue [#13](https://github.com/k0yote/kawasekit-dkls23/issues/13).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Participation is governed by our
[Code of Conduct](CODE_OF_CONDUCT.md).

## License & attribution

Forked from [0xCarbon/DKLs23](https://github.com/0xCarbon/DKLs23) (original authors credited there).
Licensed under either [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT) at your option.
