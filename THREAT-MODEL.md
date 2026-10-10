# qUSB threat model — v1

What qUSB defends against, what it doesn't, and what you have to do yourself. The protocol details are in [SPEC.md](SPEC.md).

**Status: v1, unaudited.** Don't store more than you can afford to lose until there's an independent audit.

## What it protects

| Threat | Protection |
|---|---|
| A quantum computer running Shor against your on-chain public key | Vault funds sit behind WOTS (hash-based, SHA-256). There is no elliptic curve to break. Grover leaves about 2^112 work. |
| Someone finds or steals the stick | `vault.qv` is XChaCha20-Poly1305 under an Argon2id key (64 MiB, t=3). Without the passphrase they get ciphertext. |
| Malware on the online machine | Signing happens offline. The `.qsig` is bound to one vault, recipient, refund address and amount, so the broadcaster can't redirect funds. |
| A vendor disappearing or going bad | There's no chip, firmware or company. Any USB stick, open code, reproducible from 24 words. |
| A lost stick | Everything re-derives from the 24 words. Sealed backups use ML-KEM-768 + X25519. |

## What it does not protect

- **The classic lane.** The Ed25519 fee/SPL key (Phantom-compatible) is quantum-exposed, like every Solana wallet today. Keep only fee money there.
- **A compromised signing machine.** Keys are decrypted in RAM while signing. If the offline machine runs malware, it can see them. Use a machine you trust, ideally offline.
- **Your 24 words.** Anyone with them has everything. Write them down offline and keep them away from cameras and the cloud.
- **A weak passphrase.** Argon2id slows guessing; it can't save `password1`.
- **Reusing a one-time key.** Each vault key signs exactly once, and the CLI moves change to the next vault. Signing twice from the same vault with different messages leaks enough to forge. Don't hand-edit the keystore or restore an old copy and sign again.
- **Bugs.** The qvault program and CLI are v1 and unaudited. Read the code; the tests are in `crates/` and `programs/qvault`.
- **Wrench attacks, coercion, or you sending to the wrong address.**

## Program trust

- The qvault program checks the WOTS signature on-chain and has one instruction (Withdraw). There is no admin key over vault funds.
- The program's upgrade authority can change the code. Check the authority on-chain before you trust a deployment.
- Program ID `CnfS7soDNtZaJgshcU38tvDuK2zZZwFPAedRUdRmdwZ2`, upgrade authority `FFQJa621tNkbVFgL83PXRjiRpffdGdHLbMXmt43MJw27`.

## Report a problem

Open a GitHub issue for non-sensitive bugs. For anything that could lose funds, contact [@prfa](https://x.com/prfa) privately first.
