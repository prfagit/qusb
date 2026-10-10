# qUSB protocol spec — v1

This is the source of truth. If code disagrees with this file, the code is wrong.

## 0. What qUSB is

A post-quantum cold wallet you make from **any** USB stick. No chip, no vendor, no firmware.

- The stick holds an encrypted keystore plus portable `qusb` binaries for each OS.
- The keystore is decrypted only in RAM, by the commands that need it (§5), and qusb never writes a secret to the host disk. The secret buffers qusb owns are zeroized when dropped (§5).
- Funds sit in **qvaults**: Solana addresses guarded by Winternitz one-time signatures (WOTS). WOTS is hash-based and has no elliptic-curve math for Shor's algorithm to break.
- A **classic lane** (a normal Ed25519 Solana key at `m/44'/501'/0'/0'`, the same key Phantom derives) pays fees and holds SPL tokens. It is quantum-exposed, and the CLI labels it that way.

## 1. Primitives

| Use | Algorithm |
|---|---|
| Mnemonic | BIP39, 24 words (256-bit entropy). Seed = BIP39 PBKDF2 with an empty BIP39 passphrase → 64 bytes. |
| Classic key | SLIP-0010 ed25519, path `m/44'/501'/0'/0'` (Phantom/Solflare compatible) |
| Keystore KDF | Argon2id, m = 65536 KiB, t = 3, p = 1, 16-byte salt, 32-byte output |
| Keystore AEAD | XChaCha20-Poly1305, 24-byte nonce |
| Sealed backups | Hybrid KEM: ML-KEM-768 (FIPS 203) + X25519, combined key = SHA-256("qUSB/seal/v1" ‖ ss_mlkem ‖ ss_x25519 ‖ ct_mlkem ‖ eph_x25519_pub), then XChaCha20-Poly1305 |
| Vault signatures | WOTS, §2 |

All symmetric pieces are 256-bit and stay ≥128-bit under Grover. The asymmetric pieces are hash-based (WOTS) or lattice-hybrid (seal).

## 2. WOTS (crate `qusb-wots`, `no_std`, shared by the CLI and the on-chain program)

Constants:
- `N = 28`: chain element size in bytes. Every hash is SHA-256 truncated to its first 28 bytes.
- `W = 256`: one chain per message byte, positions 0..=255.
- `L1 = 28`: message digits. `L2 = 2`: checksum digits. `L = 30`: total chains.
- Signature size = 30 × 28 = **840 bytes**.

Definitions (`‖` is concatenation, `u8(i)` is a single byte):

```
H_N(x)          = SHA256(x)[0..28]
step(i, j, x)   = H_N( "qW" ‖ u8(i) ‖ u8(j) ‖ x )        // chain i, position j -> j+1
chain(i, x, a, b) = apply step(i, j, ·) for j = a .. b-1   // a <= b <= 255

digest(msg)     = H_N( "qUSB/wots/msg/v1" ‖ msg )         // 28 digits d[0..28]
checksum        = Σ_{k<28} (255 - d[k])                    // max 7140, fits u16
digits          = d[0..28] ‖ u16_be(checksum)              // 30 digits

sk_i            = H_N( "qUSB/wots/sk/v1" ‖ wots_seed(32) ‖ u8(i) )   i in 0..30
pk_i            = chain(i, sk_i, 0, 255)
sig_i           = chain(i, sk_i, 0, digits[i])
recover_i       = chain(i, sig_i, digits[i], 255)          // must equal pk_i

pk_hash         = SHA256( "qUSB/wots/pk/v1" ‖ pk_0 ‖ … ‖ pk_29 )     // full 32 bytes
```

API (Rust):
```rust
pub const N: usize = 28; pub const L: usize = 30; pub const SIG_LEN: usize = 840;
pub type Sig = [[u8; N]; L];
pub fn digits(msg: &[u8]) -> [u8; L];
pub fn recover_pk_hash(sig: &Sig, msg: &[u8]) -> [u8; 32];   // no_std, used on-chain
#[cfg(feature = "std")] pub struct Keypair { … }             // from_seed([u8;32]), pk_hash(), sign(msg) -> Sig
```
The hash backend is pluggable through a `Hasher` trait. Off-chain it uses `sha2`; on-chain it uses the `sol_sha256` syscall.

**One-time rule:** a WOTS key signs exactly once. Two signatures over different messages let an attacker forge others. The keystore records every used index together with what it signed, and refuses to sign anything else from it (§4, §5).

## 3. qvault (Solana program `programs/qvault`)

- A vault address is a PDA: `seeds = [b"qvault", pk_hash]` under the qvault program id.
- The vault is a system-owned account with no data. Anyone can fund it with a plain SOL transfer from any wallet or exchange. There is no `open` instruction.
- The program has a single instruction, **Withdraw** (tag `0`).

Instruction data, 849 bytes:
```
[0]        tag = 0
[1..841]   sig: 30 × 28 bytes
[841..849] amount: u64 LE   (u64::MAX = sweep everything to the recipient)
```
Accounts:
```
0 payer      the transaction's fee payer. The program does not read this account or check that it signed: any key can broadcast
1 vault      writable           (PDA being spent)
2 recipient  writable
3 refund     writable           (where the remainder goes; normally the next vault of the same keystore)
4 system_program
```
Signed message, 127 bytes:
```
msg = "qUSB/qvault/withdraw/v1" (23 bytes) ‖ vault(32) ‖ recipient(32) ‖ refund(32) ‖ amount u64 LE (8)
```
Program logic:
1. Parse the data and check its length is exactly 849.
2. `pk_hash = recover_pk_hash(sig, msg)`, rebuilding msg from the account keys and the amount.
3. `(expected, bump) = find_program_address([b"qvault", pk_hash])`. If `vault != expected`, return `InvalidSeeds`.
4. Require `vault != recipient`, `vault != refund` and `recipient != refund`.
5. Let `bal = vault.lamports`. If `amount == u64::MAX`, then `send = bal` and `rest = 0`. Otherwise require `amount <= bal`, and set `send = amount`, `rest = bal - amount`.
6. Transfer from the vault through a system-program CPI signed with seeds `[b"qvault", pk_hash, [bump]]`: `send` to the recipient, then `rest` (if > 0) to the refund account.
7. The vault ends at 0 lamports, so the runtime garbage-collects it. The program keeps no state: nothing on chain records that this key has signed.

**Replay.** A broadcast signature is public, and it stays valid. If SOL lands in a used vault again, anyone can submit the same instruction again. It moves the new balance by the same rule: `amount` to the same recipient and the rest to the same refund address (everything to the recipient for `max`; it fails while the balance is below `amount`). The sender of the replay cannot change where the funds go, but the owner cannot stop it and cannot sign anything else from that vault: the only exit the owner controls is to broadcast the original `.qsig` again. The rule that follows: **never fund a used vault.** `receive` shows the lowest vault that has never signed, and keeps showing that same address until the vault is spent; after that it never shows it again. The CLI refuses a used vault as a recipient, and `status` warns when a used vault holds a balance.

Rent: the runtime rejects the transaction if the recipient or the refund account would end above 0 and under the rent-exempt minimum (890,880 lamports for an account with no data). So a `rest` under the minimum to an empty refund account fails, and so does a `send` under the minimum to a recipient that does not exist yet. Broadcasters must **simulate before sending**, so a failing signature is never published. When the CLI can see the balance and `rest` would be under the minimum, it signs the exact balance (§5).

Transaction budget (legacy message): 1 signature, accounts = payer, vault, recipient, refund, system, ComputeBudget, qvault. With a `SetComputeUnitLimit(1_400_000)` and a `SetComputeUnitPrice` instruction, the serialized transaction is about 1200 bytes, under the 1232-byte limit. Measured compute: about 7,980 CU plus 196.6 CU per chain step the verifier walks. The number of steps depends on the message digest, so a withdrawal costs between about 658k and 962k CU, 780k on average, inside the 1.4M limit. A sweep and a partial send differ by about 1.3k CU. A test must assert the serialized size.

Offline property: the WOTS signature does not cover a blockhash. A `.qsig` produced on an air-gapped machine stays valid forever (which is also why a used vault must never be funded again, see Replay). Any online machine can wrap it with a fee payer and a fresh blockhash. No durable nonce is needed.

## 4. Stick layout

```
<STICK>/                       any FAT32/exFAT/ext4 USB
  START-HERE.txt
  bin/  qusb-macos-arm64  qusb-macos-x64  qusb-linux-x64  qusb-linux-arm64  qusb-windows-x64.exe  SHA256SUMS
  qusb/
    vault.qv                   encrypted keystore (JSON, below)
    public.json                watch-only cache, no secrets
    sigs/                      vault<index>.qsig outputs
```

`vault.qv` (JSON):
```json
{ "qusb": 1,
  "kdf": { "alg": "argon2id", "m_kib": 65536, "t": 3, "p": 1, "salt": "<b64>" },
  "aead": { "alg": "xchacha20poly1305", "nonce": "<b64>" },
  "ct": "<b64>" }
```
The AEAD associated data is the canonical string `qusb:1:argon2id:65536:3:1`.
The plaintext is JSON:
```json
{ "mnemonic": "24 words", "created": 1760000000, "label": "my stick",
  "next_vault": 2, "used": [0],
  "spends": [ { "vault": 0, "recipient": "<b58>", "refund": "<b58>", "amount": "1500000000" | "max" } ],
  "assumed_used_below": 0 }
```
- `used`: vault indices whose key must sign nothing new.
- `spends`: what each used vault signed, when known: written at signing time, or rebuilt from the chain by `rescan` (§5).
- `assumed_used_below`: N after an offline restore with `--next-vault N`, which marks vaults below N used with no evidence; `rescan` sets it back to 0.
- `spends` and `assumed_used_below` were added after v0.1.0. A keystore without them is read as it is (empty and 0), and a v0.1.0 binary that opens a newer keystore still sees `used`. When a v0.1.0 binary saves a newer keystore it drops both fields. That fails safe: every used vault stays used, and with the record gone, writing the same `.qsig` again is refused.

A reader rejects KDF parameters above m = 1,048,576 KiB, t = 64 or p = 16 before it allocates or hashes: the outer file is not authenticated until the AEAD check.

Every re-encryption uses a fresh salt and nonce. Writes are atomic: write `vault.qv.tmp`, fsync, rename, then fsync the directory (Unix, best effort: some FAT/exFAT drivers cannot). The same write is used for `.qsig` files. If `vault.qv.tmp` is found at unlock, a write was cut short: when it decrypts under the passphrase it is complete and newer than `vault.qv` (it may record a spend the old file lacks), so it is moved into place; when it does not decrypt and `vault.qv` does, it is removed.

`public.json`:
```json
{ "qusb": 1, "label": "my stick", "classic": "<base58>", "program": "<qvault program id>",
  "vaults": [ { "index": 0, "address": "<base58>", "pk_hash": "<hex>", "state": "fresh|used" } ],
  "seal_pub": "<b64 ml-kem-768 ek ‖ x25519 pub>" }
```

Derivation (everything recovers from the 24 words):
```
wots_seed(k)   = HMAC-SHA512(key="qUSB/wots/v1", seed64 ‖ u32_be(k))[0..32]
seal_mlkem_d_z = HMAC-SHA512(key="qUSB/seal/mlkem/v1", seed64)       // 64 bytes = d‖z for ML-KEM-768 KeyGen_internal
seal_x25519    = HMAC-SHA512(key="qUSB/seal/x25519/v1", seed64)[0..32]
```

`.qsig` (JSON; it holds no secret and is bound to one vault, recipient, refund and amount, so it is safe to carry around. It is not single-use on chain: see Replay, §3):
```json
{ "qusb": 1, "kind": "qvault-withdraw", "program": "<id>", "vault": "<b58>", "vault_index": 0,
  "recipient": "<b58>", "refund": "<b58>", "amount": "1500000000" | "max", "sig": "<b64 840 bytes>" }
```

## 5. CLI (`qusb`)

```
qusb verify                         check bin/SHA256SUMS against the files beside the binary; needs no keystore
qusb init <stick> [--label L]       new keystore (shows 24 words once, quizzes 3)
qusb init <stick> --restore [--next-vault N] [--rpc URL]   restore from words, see Restore below
qusb status [--rpc URL]             classic address, vaults, balances (watch-only, no passphrase)
qusb receive                        next fresh vault address + terminal QR, classic address for fees
qusb sign --vault I --to ADDR --amount SOL|max             offline → qusb/sigs/vaultI.qsig, marks I used
qusb broadcast FILE.qsig --payer KEYPAIR.json|stick [--rpc URL] [--priority-fee MICROLAMPORTS]
qusb send --vault I --to ADDR --amount SOL|max [--payer KEYPAIR.json|stick] [--rpc URL] [--priority-fee MICROLAMPORTS]
                                    sign + broadcast in one go (online machine); the payer defaults to stick
qusb rescan [--rpc URL]             rebuild the used-vault record from the chain, see Restore below
qusb classic send --to ADDR --amount SOL [--rpc URL]       classic lane (SOL only), labelled quantum-exposed
qusb seal --to SEAL_PUB --out FILE  encrypt this stick's mnemonic to another stick's seal key (inheritance/backup)
qusb seal-key                       this stick's seal key and its fingerprint
qusb unseal FILE                    decrypt a sealed backup with this stick
qusb wipe-check                     print what is on the host that touched qusb (should be nothing)
```
Global flags: `--stick PATH` and `--yes`.

The stick is auto-detected by walking up from the binary's location to find `qusb/vault.qv` (or a leftover `qusb/vault.qv.tmp`, §4). `--stick` overrides this. `verify` reads `SHA256SUMS` from the binary's own directory, so it works before `init`; it exits non-zero if any listed file is missing or differs.

**Confirmations.** `sign`, `send`, `broadcast`, `classic send` and `seal` print what they are about to do and wait for a typed `yes`. `--yes` skips that. For a withdrawal the summary is: vault, recipient, refund, amount, and, when a transaction will be sent, the fee payer and the maximum fee. `seal` shows the fingerprint of the recipient seal key (the first 10 bytes of the SHA-256 of the decoded key, in hex) to compare with `qusb seal-key` on the receiving stick. A maximum fee above 0.01 SOL is asked about even with `--yes`.

**Signing rules** (`sign` and `send` share one path):
1. The vault index must be below 1,000,000 and below `next_vault + 20`. That is the window a restore scans (below), so every index that can sign is one a rescan reads.
2. The recipient must not be the vault itself, and must not be a used vault of this keystore.
3. Refund = the lowest vault index `r >= max(next_vault, I + 1)` that is not used and whose address is not the recipient. So sending to your own `receive` address moves the refund one vault further. `next_vault` becomes `r + 1`. There is no flag to choose the refund.
4. Amount. With the balance in view (`send`): the rent-exempt minimum is read from the RPC node, and `send` refuses if the answer is 0 or more than twice the known 890,880 lamports, because that number decides how much is signed; an empty vault is refused; `max`, and any amount that would leave a remainder under the rent-exempt minimum, are signed as the exact balance seen, and the summary says so; an amount above the balance is refused. An exact amount is preferred to `max` because of replay (§3): a replayed `max` takes whatever the vault holds then. Offline (`sign`) the amount is signed as typed, with a warning that the balance is unknown.
5. `send` also checks, before the key is spent, that the fee payer can be read and can pay the maximum fee, and that the recipient would not end under the rent-exempt minimum.
6. Order: record `{vault, recipient, refund, amount}` in the keystore and save it; then sign; then write the `.qsig` (atomic write, §4). Nothing that can fail for another reason sits between the save and the write.
7. A used vault signs nothing new. Asking again for the recipient and amount on record writes the same `.qsig` again (signing is deterministic, so no second signature exists). Anything else is refused, and the error names what was signed. A used vault with no record (marked by v0.1.0 or by an offline restore) is refused outright.
8. If `sigs/vault<k>.qsig` already exists for a vault the keystore calls unused (an older copy of `vault.qv` was put back over a newer one), nothing new is signed and the error says to broadcast that file. The one exception is a request with the file's own recipient, refund and amount, which signs to the same bytes.

**Broadcasting.** `broadcast` treats the `.qsig` as untrusted input. It requires version 1, kind `qvault-withdraw`, and `program` equal to the built-in qvault program id; vault, recipient and refund must differ; and the WOTS signature, checked locally over the message rebuilt from the file's fields (§3), must recover the vault address. Only then does it show the summary and ask. `--payer` has no default: `stick` decrypts the keystore on this machine to reach the classic key and says so; a keypair file keeps the stick out of it. The transaction is simulated first. Its signature is computed locally and printed before it is sent. Busy-endpoint replies (HTTP 429, 502, 503, 504) are retried, and polling errors while waiting do not end the wait. If the send call fails or no confirmation is seen in about 90 seconds, the result is reported as status unknown with that signature to check, never as a failure. When `send` fails after signing, the error ends with the path of the saved `.qsig` and the `qusb broadcast` command that retries it.

Fees: the priority fee is charged on the requested compute limit, so the maximum fee is `5000 + ceil(1_400_000 × price / 1_000_000)` lamports. It is shown in SOL before sending.

**Restore and rescan.** The 24 words do not say which vault keys have signed, so a restored keystore must learn that before it hands out or signs from any vault.
- `rescan` first calls `getFirstAvailableBlock` and refuses unless the answer is at or below slot 455,074,608, the first slot the qvault program existed on mainnet. A node that has dropped older blocks answers "no history" for a spent vault, which reads exactly like a vault that never signed. The refusal says to use a node with full history or to restore with `--next-vault`.
- It then walks vault indices from 0. For each address it pages `getSignaturesForAddress` until a page comes back empty, and reads each transaction until it finds a spend. A vault is **used** iff a transaction contains a qvault Withdraw instruction (top level or inner) with that address in the vault position (account 1) and either the transaction succeeded, or the instruction's signature verifies locally. Deposits and change sent to a vault do not count.
- The walk stops after 20 indices in a row with no history, and never before `next_vault`. `next_vault` becomes one past the highest index with any history, so funded vaults at higher indices appear in `status` and can be spent.
- When the spend can be rebuilt and verified from the instruction, it is recorded in `spends`, so the keystore can write that same `.qsig` again.
- The keystore changes only after the whole walk succeeded. Any RPC error stops the scan with nothing saved.
- `init --restore` runs the same walk before it creates the keystore. If the RPC cannot be reached it refuses, unless `--next-vault N` is given (N from 1 to 1000; 0 would claim that nothing was ever used): then vaults `0..N` are marked used, `assumed_used_below = N`, and the user is told to run `qusb rescan` online. That rescan unlocks the vaults below N that the chain shows unspent and that have no spend record. Before it saves, it lists them and waits for a typed `yes`, which `--yes` does not skip.
- Limits: a rescan trusts the RPC node's history. The first-block check catches a node that has pruned it; a node that claims full history and leaves transactions out cannot be detected, so a restore needs an RPC you trust. A rescan also cannot see a `.qsig` that was signed and never broadcast: if a copy exists, broadcast it; otherwise empty that vault with one `send --amount max` and never fund it again. The CLI prints what it found and says both.

**Secrets in memory.** The keystore is decrypted in RAM by every command except `status`, `verify` and `wipe-check`; `broadcast` decrypts it only with `--payer stick`. Passphrase input is a tty prompt with no echo (`rpassword`), never argv or env. A build made with the cargo feature `test-hooks` also accepts them from the environment; release binaries are built without it. The passphrase, the mnemonic (including the parsed BIP39 form), the BIP39 seed, the derived WOTS, classic and seal keys, the Argon2 output, the decrypted keystore plaintext and a fee payer keypair file are zeroized on drop. Not covered: short-lived stack copies the compiler makes, copies inside the JSON, terminal and OS layers, and anything the OS swaps to disk. The 24 words (`init`) and unsealed text (`unseal`) are shown on the terminal's alternate screen, which is wiped together with the scrollback afterwards. Text printed from files nobody authenticated (`public.json`, unsealed content) has its control characters removed.

`status` reads `public.json`, which is not authenticated. `receive` therefore derives the address from the unlocked keystore. `status` always shows balances when the RPC answers, and warns about every used vault that holds a balance (§3, Replay). `receive` and `init` print: use each address once; never send to an address you have already spent from. Every command that writes the keystore reminds the user to eject the stick safely.

## 6. Token-funded development (non-protocol, for the site/README)

- `$qUSB` trades on pump.fun (CA `9NDY4jY5gqcNfDrZsKujtnuvH12pPG5FUGS5QmwZpump`). The creator fee pays the dev and the team to build qUSB.
- No VC, no sales team, no paid marketing. The token gives no claim on anything, and the code stays MIT/Apache-2.0 whatever the token does.
