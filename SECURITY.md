# Security policy

qUSB is v1 and unaudited. Nobody independent has reviewed the code yet. Don't store more than you can afford to lose, and read [THREAT-MODEL.md](THREAT-MODEL.md) for what it does and does not protect.

## Report a vulnerability

Please report anything that could lose funds or expose keys privately, not in a public issue.

1. Use GitHub private vulnerability reporting: on [github.com/prfagit/qusb](https://github.com/prfagit/qusb), open the **Security** tab and choose **Report a vulnerability**.
2. If that is not available to you, message [@prfa](https://x.com/prfa) on X and ask for a private channel. Don't put the details in a public post.

Include what you found, how to reproduce it, and which version, commit or program hash you looked at. Non-sensitive bugs can go in a normal GitHub issue.

## In scope

- The on-chain `qvault` program (`programs/qvault`), program ID `CnfS7soDNtZaJgshcU38tvDuK2zZZwFPAedRUdRmdwZ2`.
- The WOTS implementation (`crates/qusb-wots`).
- Key derivation, the keystore, sealed backups and the withdraw message (`crates/qusb-core`).
- The `qusb` CLI (`crates/qusb-cli`).
- The release pipeline and the stick scripts (`.github/workflows`, `scripts/`): anything that would let a tampered binary pass verification.

## Known limits, not vulnerabilities

These are documented in [THREAT-MODEL.md](THREAT-MODEL.md):

- The program is upgradeable until it is finalised, and the upgrade authority is a normal Ed25519 key.
- A published withdrawal signature can be replayed if the same vault is funded again.
- The classic lane is quantum-exposed.
- A compromised signing machine sees the keys.

A new way to exploit any of these is still worth a report.

## Out of scope

- The $qUSB token and its market.
- Third-party wallets, RPC providers and exchanges.
- Attacks that need the 24 words, the passphrase, or physical coercion.
