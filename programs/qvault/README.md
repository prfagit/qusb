# qvault

Solana program (pinocchio, ~17 KB `.so`) for qUSB vaults, SPEC.md §3. One instruction, `Withdraw` (tag 0): rebuilds the signed message from the account keys, recovers the WOTS pk_hash with `qusb_wots::recover_pk_hash` (sol_sha256 syscall), requires the vault to be the `[b"qvault", pk_hash]` PDA, then sweeps or splits the vault to recipient and refund via signed system transfers.

Program id: `CnfS7soDNtZaJgshcU38tvDuK2zZZwFPAedRUdRmdwZ2`. The program is upgradeable; the upgrade authority is `FFQJa621tNkbVFgL83PXRjiRpffdGdHLbMXmt43MJw27` (see THREAT-MODEL.md, "Program trust"). No key lives in the repo.

The signed message is 127 bytes (23 domain + 3x32 keys + 8 amount), as in SPEC.md §3. A comment in `src/lib.rs` still mentions an older SPEC figure of 119; the source is left untouched so the deployed bytes stay reproducible.

## Build and test

Run from the repo root. The tests load the built `.so`, so build first (Agave v4.0.2 toolchain, as CI pins):

```sh
cargo build-sbf --manifest-path programs/qvault/Cargo.toml   # -> target/deploy/qvault.so
shasum -a 256 target/deploy/qvault.so                        # 5581547af0d5d03e43de1f4605f25914d92dcb8989f070470a70f212a3a4d4ea
cargo test -p qvault -- --nocapture
```

The hash is the one deployed on mainnet. The root README ("Verify the on-chain program") shows how to compare it with the chain.

Tests (`tests/withdraw.rs`, litesvm 0.11, loading the built `.so`):

- partial withdraw with refund, `u64::MAX` sweep, amount exactly equal to the balance, transaction size
- rejected: wrong message, tampered signature, wrong vault, tampered refund, recipient == vault, vault == refund, recipient == refund, amount over balance, both rent failures, bad length, bad tag, wrong account count, wrong system program, read-only vault
- known limits, asserted so they can't change silently: a published signature replays if the vault is funded again, and a sweep of an empty vault succeeds
- a compute-unit ceiling over 40 withdrawals
- signing through `qusb-core` (the code the CLI ships) and verifying in the program
- a pinned known-answer vector for the signature, computed independently from SPEC.md §2

## Measured

- Legacy tx with SetComputeUnitLimit(1_400_000) + SetComputeUnitPrice: 1204 bytes (limit 1232). About 28 bytes are spare, so a tip or memo instruction does not fit.
- Compute units: about 610k to 960k per withdrawal over 40 measured, mean near 780k. Cost is about 197 CU per hash step, and the number of steps depends on the message digest, so two withdrawals of the same kind can differ by hundreds of thousands of CU. A sweep and a partial send differ by only about 1.3k CU.
- The 1.4M limit covers about 7,080 hash steps. The theoretical maximum is 7,395, so a digest in that last sliver would not fit; the largest seen in the 40 measured was 4,845 and a typical one is near 3,900. Simulate before sending, as SPEC.md §3 requires, so a signature that can't land is never published.
