# Security Policy

## Introduction
Thank you for helping us keep our project secure. This document outlines our security policy and provides instructions for reporting vulnerabilities.

## Self-audit status (kawasekit fork)
This is `kawasekit-dkls23`, kawasekit's hardened fork of 0xCarbon/DKLs23 — see [FORK.md](FORK.md). It is
**UNAUDITED**: it carries self-audit hardening only, and a third-party cryptographic audit is a standing
pre-mainnet gate that **does not clear by self-audit**. Testnet / no-value only.

A CTO-class self-audit pass has been completed. **Verdict:** no value-gating issues found in the
self-audit; a third-party cryptographic audit remains **MANDATORY** before mainnet / real value. Artifacts:
- [`docs/audit-context.md`](docs/audit-context.md) — system model, invariants, trust boundaries, fragility clusters
- [`docs/audit-findings.md`](docs/audit-findings.md) — findings (severity, fixes, empirical verification)
- [`docs/audit-deepdive-signing.md`](docs/audit-deepdive-signing.md) — signing consistency + error→ban dataflow deep dive

Open findings are tracked in issue [#13](https://github.com/k0yote/kawasekit-dkls23/issues/13)
(filter by the [`audit`](https://github.com/k0yote/kawasekit-dkls23/issues?q=is%3Aissue+label%3Aaudit) label).

## Reporting a Vulnerability
If you discover a security vulnerability, please report it to us in a responsible manner. To report a vulnerability, please email us at [fabio@bealore.com]. Include the following details in your report:
- A description of the vulnerability
- Steps to reproduce the vulnerability
- Any potential impact of the vulnerability

## Expected Response Time
We will acknowledge your report within 48 hours and provide a detailed response within 5 business days, including an evaluation of the vulnerability and an expected resolution date.

## Responsible Disclosure
We ask that you do not disclose the vulnerability publicly until we have had a chance to address it. We believe in responsible disclosure and will work with you to ensure that vulnerabilities are fixed promptly.

## Acknowledgments
Thank you for helping us keep our project secure!
