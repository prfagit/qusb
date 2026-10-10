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
- **Reusing a one-time key.** Each vault key signs exactly once, and the CLI moves change to the next vault. Signing twice from the same vault with different messages leaks enough to make forgery practical. Don't hand-edit the keystore or restore an old copy and sign again.
- **Restoring from the 24 words without a rescan.** The words bring back the keys, not the record of which vaults have already signed. After a restore, let qusb rescan the chain for vaults that were already spent before you sign anything. Signing from a vault that has signed before is the reuse case above. A rescan trusts the RPC node's history: qusb refuses a node that does not keep full history, but a node that lies outright cannot be detected, so use an RPC you trust for a restore.
- **Funding a vault you have already spent from (replay).** The qvault program keeps no state, so a withdrawal signature that has been published stays valid. If SOL ever lands in that vault again, anyone can submit the old signature again: the signed amount goes to the original recipient and the rest to the original refund vault, and a replayed sweep sends everything to the original recipient. The funds can't be redirected to the attacker, but they move without you. This also holds for a sweep that was broadcast while the vault was empty. **The rule: use each vault address once, and never fund a vault you have already spent from.** Don't give out an old vault address as a standing deposit address; take a fresh one from `qusb receive` each time.
- **The program's upgrade authority.** See "Program trust" below.
- **Third-party code.** `ml-kem` 0.2.x (sealed backups) and `pinocchio` 0.11.x (the on-chain program) are pre-1.0 and have not had an independent security review that we know of.
- **Bugs.** The qvault program and CLI are v1 and unaudited. Read the code; the tests are in `crates/` and `programs/qvault`.
- **Wrench attacks, coercion, or you sending to the wrong address.**

## Program trust

- The qvault program checks the WOTS signature on-chain and has one instruction (Withdraw). There is no admin key over vault funds: no instruction lets anyone move a vault's SOL without that vault's signature.
- **The program is upgradeable.** Whoever holds the upgrade authority can replace the code, and new code could send later withdrawals somewhere else. Funds in vaults are only as safe as that key until the program is finalised.
- The upgrade authority is `FFQJa621tNkbVFgL83PXRjiRpffdGdHLbMXmt43MJw27`. It is a normal Ed25519 key, so it is itself quantum-exposed: the post-quantum protection of the vaults does not cover the key that can change the program.
- The plan is to finalise the program (remove the upgrade authority) once v1 is trusted. After that nobody can change it, including to fix a bug.
- Program ID `CnfS7soDNtZaJgshcU38tvDuK2zZZwFPAedRUdRmdwZ2`. The deployed bytes have sha256 `5581547af0d5d03e43de1f4605f25914d92dcb8989f070470a70f212a3a4d4ea`. Check both the hash and the authority yourself before you trust a deployment: the recipe is in the [README](README.md#verify-the-on-chain-program).

## Report a problem

See [SECURITY.md](SECURITY.md). Open a GitHub issue for non-sensitive bugs. For anything that could lose funds, report it privately first.
