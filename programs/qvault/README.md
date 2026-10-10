# qvault

Solana program (pinocchio, ~17 KB `.so`) for qUSB vaults, SPEC.md §3. One instruction, `Withdraw` (tag 0): rebuilds the signed message from the account keys, recovers the WOTS pk_hash with `qusb_wots::recover_pk_hash` (sol_sha256 syscall), requires the vault to be the `[b"qvault", pk_hash]` PDA, then sweeps or splits the vault to recipient and refund via signed system transfers.

Program id: `CnfS7soDNtZaJgshcU38tvDuK2zZZwFPAedRUdRmdwZ2` (keypair stays in `~/.config/qusb/`, never in the repo).

Note: the signed message is 127 bytes (23 + 3x32 + 8); SPEC.md's "119" omits the amount.

## Build and test

```
cargo-build-sbf                                    # -> ../../target/deploy/qvault.so
CARGO_TARGET_DIR=$PWD/target-qvault cargo test -- --nocapture
```

Tests (litesvm 0.11, loads the built `.so`): partial withdraw + refund, `u64::MAX` sweep, wrong message / tampered sig, wrong vault, recipient == vault, tx size.

## Measured

- Legacy tx with SetComputeUnitLimit(1_400_000) + SetComputeUnitPrice: 1204 bytes (limit 1232).
- Compute units: 760,599 for a partial withdraw (two transfers) with refund.
