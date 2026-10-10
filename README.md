<p align="center"><img src="brand/logo.png" width="160" alt="qUSB"></p>

# qUSB

A quantum-proof cold wallet you make from any USB stick.

No chip, no vendor, no firmware. The stick holds an encrypted keystore and the `qusb` binaries. Your SOL sits in **qvaults**: Solana addresses guarded by Winternitz one-time signatures (hash-based, SHA-256) and checked on-chain by the `qvault` program. There's no elliptic curve, so Shor's algorithm has nothing to break.

> **v1, unaudited.** Don't store more than you can afford to lose. Read [THREAT-MODEL.md](THREAT-MODEL.md) first.
>
> **The on-chain program is still upgradeable.** It has no admin key over vault funds, but whoever holds its upgrade authority (`FFQJa621tNkbVFgL83PXRjiRpffdGdHLbMXmt43MJw27`) could deploy new code that redirects later withdrawals. That authority is a normal Ed25519 key, so it is itself quantum-exposed. The plan is to finalise the program (remove the authority) once v1 is trusted. Until then you are trusting that key. See [Verify the on-chain program](#verify-the-on-chain-program).

## How it works

```
any USB stick ──▶ qusb init ──▶ 24 words + passphrase, keystore encrypted on the stick
                  qusb receive ─▶ a fresh vault address (send SOL from any wallet)
   offline:       qusb sign ───▶ .qsig (one vault, one recipient, one amount)
   online:        qusb broadcast ▶ qvault verifies the WOTS signature on-chain, SOL moves
```

- **Keys** are decrypted only in RAM while signing, then zeroized. The keystore is Argon2id (64 MiB, t=3) + XChaCha20-Poly1305.
- **Each vault key signs exactly once.** On a partial send the change moves to the next vault automatically.
- **Each vault address is used once.** Never send SOL to a vault you have already spent from: the old signature is public and still works. [THREAT-MODEL.md](THREAT-MODEL.md) explains why.
- **Recovery:** everything re-derives from the 24 words. Sealed backups to a second stick use ML-KEM-768 + X25519.
- **Classic lane:** a normal Ed25519 key (`m/44'/501'/0'/0'`, the same one Phantom derives) pays fees and holds SPL tokens. It's quantum-exposed and the CLI labels it that way.

## Numbers

| | |
|---|---|
| WOTS signature | 840 bytes (N=28, W=256, 30 chains) |
| Withdraw transaction | 1204 bytes (limit 1232). About 28 bytes are spare, so a tip or memo instruction does not fit. |
| Compute | about 610k to 960k CU per withdrawal, mean near 780k (40 measured). It depends on the message digest, not on the kind of send: a sweep and a partial send differ by about 1.3k CU. |
| Program | ~17 KB, one instruction, no admin key over vault funds, upgradeable (see the note above) |
| qvault program ID | `CnfS7soDNtZaJgshcU38tvDuK2zZZwFPAedRUdRmdwZ2` |

## Repo

| Path | What |
|---|---|
| `crates/qusb-wots` | WOTS, `no_std`, shared by the signer and the on-chain program |
| `crates/qusb-core` | mnemonic, key derivation, keystore, seal, withdraw message |
| `crates/qusb-cli` | the `qusb` binary |
| `programs/qvault` | the Solana program (pinocchio) |
| `scripts/make-stick.sh` | verify a release and put it on a stick |
| `scripts/verify-release.sh` | check release files against `SHA256SUMS` and their build provenance |
| `stick/START-HERE.txt` | the readme that ships on every stick |
| [SPEC.md](SPEC.md) | the protocol; if the code disagrees with it, the code is wrong |

## Build and test

```sh
cargo test --workspace --exclude qvault

# The program tests load the built .so, so build it first.
# Needs the Agave toolchain (CI pins v4.0.2):
#   sh -c "$(curl -sSfL https://release.anza.xyz/v4.0.2/install)"
cargo build-sbf --manifest-path programs/qvault/Cargo.toml   # -> target/deploy/qvault.so
cargo test -p qvault
```

## Verify the on-chain program

You don't have to take the deployed program on trust. Dump it from mainnet and hash it:

```sh
solana program dump CnfS7soDNtZaJgshcU38tvDuK2zZZwFPAedRUdRmdwZ2 qvault.so -u mainnet-beta
shasum -a 256 qvault.so        # or: sha256sum qvault.so
# expected: 5581547af0d5d03e43de1f4605f25914d92dcb8989f070470a70f212a3a4d4ea
```

Then rebuild the same bytes from this source:

```sh
sh -c "$(curl -sSfL https://release.anza.xyz/v4.0.2/install)"   # Agave v4.0.2: cargo-build-sbf 4.0.0, platform-tools v1.53 (rustc 1.89.0)
cargo build-sbf --manifest-path programs/qvault/Cargo.toml
shasum -a 256 target/deploy/qvault.so                           # same hash as above
```

The build uses the committed `Cargo.lock`. CI does the same build on every push, fails if the hash is not the one above, and uploads the built `qvault.so` as a workflow artifact.

Check who can change the program:

```sh
solana program show CnfS7soDNtZaJgshcU38tvDuK2zZZwFPAedRUdRmdwZ2 -u mainnet-beta
# Authority: FFQJa621tNkbVFgL83PXRjiRpffdGdHLbMXmt43MJw27
```

If the hash you dump ever differs from the one in this README, the program was upgraded: stop and find out why before you sign anything. Once the program is finalised, `Authority` will read `none`.

## Make a stick

macOS and Linux:

```sh
scripts/make-stick.sh /Volumes/MYSTICK v0.1.1
```

The script downloads the release into a temporary directory, checks every file against `SHA256SUMS`, and copies to the stick only after that passes. If the [GitHub CLI](https://cli.github.com) is installed and logged in, it also checks the build provenance with `gh attestation verify`; if not, its last lines say that provenance was not checked. It refuses anything that isn't a removable volume.

To check a release you downloaded by hand: `scripts/verify-release.sh <dir>`.

Windows (PowerShell):

```powershell
$tag = "v0.1.1"; $stick = "E:\"     # your stick's drive letter
$base = "https://github.com/prfagit/qusb/releases/download/$tag"
$tmp = Join-Path $env:TEMP "qusb-$tag"
New-Item -ItemType Directory -Force $tmp | Out-Null
foreach ($f in "qusb-stick.zip", "SHA256SUMS") { Invoke-WebRequest "$base/$f" -OutFile "$tmp\$f" }
Expand-Archive "$tmp\qusb-stick.zip" "$tmp\stick" -Force

# every binary in the zip must match the published SHA256SUMS
$sums = @{}
Get-Content "$tmp\SHA256SUMS" | ForEach-Object { $h, $n = $_ -split '\s+\*?', 2; $sums[$n] = $h }
$bins = Get-ChildItem "$tmp\stick\bin\qusb-*"
if ($bins.Count -ne 5) { throw "expected 5 binaries, found $($bins.Count)" }
foreach ($b in $bins) {
  if ((Get-FileHash $b.FullName -Algorithm SHA256).Hash.ToLower() -ne $sums[$b.Name]) { throw "checksum mismatch: $($b.Name)" }
}

# optional, needs the GitHub CLI: check the build provenance of both downloads
gh attestation verify "$tmp\SHA256SUMS" --repo prfagit/qusb
gh attestation verify "$tmp\qusb-stick.zip" --repo prfagit/qusb

# only if everything above passed
Copy-Item "$tmp\stick\*" $stick -Recurse -Force
```

The binaries are not code-signed, so the operating system may warn about them:

- **macOS Gatekeeper:** a binary that came through a browser is quarantined. Verify it first, then clear the flag with `xattr -d com.apple.quarantine <STICK>/bin/qusb-macos-*`.
- **Windows SmartScreen:** it may block the first run. Verify the checksum first, then choose "More info" and "Run anyway", or run `Unblock-File <STICK>\bin\qusb-windows-x64.exe`.

Then follow `START-HERE.txt` on the stick.

<!-- commands:start (the CLI command list lives here; update it when commands change) -->
| Command | What it does |
|---|---|
| `qusb verify` | check the binaries on the stick against `bin/SHA256SUMS` |
| `qusb init` | create the keystore; `--restore` rebuilds it from the 24 words and rescans the chain |
| `qusb receive` | show the next unused vault address |
| `qusb status` | list vaults and balances, no passphrase needed |
| `qusb sign` | sign a withdrawal offline and write a `.qsig` file |
| `qusb broadcast <file> --payer <stick or keypair.json>` | check a `.qsig`, show where the money goes, then send it |
| `qusb send` | sign and broadcast in one go on an online machine |
| `qusb rescan` | read the chain to find spent and funded vaults; run it after any restore |

`sign`, `send` and `broadcast` show a summary and wait for a typed yes (`--yes` skips it for scripts). `qusb --help` lists the rest: `classic`, `seal`, `seal-key`, `unseal`, `wipe-check`.
<!-- commands:end -->

## Dependencies

The hash-based parts (WOTS, SHA-256) are small and in this repo. Two dependencies deserve a plain warning: [`ml-kem`](https://crates.io/crates/ml-kem) 0.2.x (sealed backups) and [`pinocchio`](https://crates.io/crates/pinocchio) 0.11.x (the on-chain program) are both pre-1.0 and have not had an independent security review that we know of. CI runs `cargo deny` against the RustSec advisory database ([deny.toml](deny.toml)).

## Funding

No VC, no sales, no paid marketing. qUSB is funded by $qUSB (`9NDY4jY5gqcNfDrZsKujtnuvH12pPG5FUGS5QmwZpump`). The creator fees pay the dev and the team to build it. The token gives no claim on anything, and the code stays open source whatever happens.

## Security

qUSB is v1 and unaudited. How to report a problem, and what is in scope, is in [SECURITY.md](SECURITY.md). Anything that could lose funds: report it privately, not in a public issue.

## License

MIT or Apache-2.0, at your option.

Built by [prfa](https://x.com/prfa) · [qusb.app](https://qusb.app)
