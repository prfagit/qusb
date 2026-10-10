# qUSB protocol spec — v1

This is the source of truth. If code disagrees with this file, the code is wrong.

## 0. What qUSB is

A post-quantum cold wallet you make from **any** USB stick. No chip, no vendor, no firmware.

- The stick holds an encrypted keystore plus portable `qusb` binaries for each OS.
- Keys are decrypted only in RAM, only while signing, and are zeroized afterwards. They never touch the host disk.
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

**One-time rule:** a WOTS key signs exactly once. Two signatures over different messages let an attacker forge others. The keystore records every used index and refuses to sign twice (§4).

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
0 payer      signer, writable   (classic fee payer; any key)
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
7. The vault ends at 0 lamports, so the runtime garbage-collects it and the one-time key is retired in the same transaction.

Rent: if 0 < `rest` < the rent-exempt minimum, the runtime rejects the transaction. Broadcasters must **simulate before sending**, so a failing signature is never published. The CLI picks `amount = u64::MAX` whenever `rest` would be under rent.

Transaction budget (legacy message): 1 signature, accounts = payer, vault, recipient, refund, system, ComputeBudget, qvault. With a `SetComputeUnitLimit(1_400_000)` and a `SetComputeUnitPrice` instruction, the serialized transaction is about 1200 bytes, under the 1232-byte limit. Measured compute: about 708k CU for a sweep and 859k CU for a partial send, inside the 1.4M limit. A test must assert the serialized size.

Offline property: the WOTS signature does not cover a blockhash. A `.qsig` produced on an air-gapped machine stays valid forever. Any online machine can wrap it with a fee payer and a fresh blockhash. No durable nonce is needed.

## 4. Stick layout

```
<STICK>/                       any FAT32/exFAT/ext4 USB
  START-HERE.txt
  bin/  qusb-macos-arm64  qusb-macos-x64  qusb-linux-x64  qusb-linux-arm64  qusb-windows-x64.exe  SHA256SUMS
  qusb/
    vault.qv                   encrypted keystore (JSON, below)
    public.json                watch-only cache, no secrets
    sigs/                      *.qsig outputs
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
  "next_vault": 1, "used": [0] }
```
Every re-encryption uses a fresh nonce. Writes are atomic: write `vault.qv.tmp`, fsync, then rename.

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

`.qsig` (JSON, safe to carry around because it is single-use and bound to a recipient):
```json
{ "qusb": 1, "kind": "qvault-withdraw", "program": "<id>", "vault": "<b58>", "vault_index": 0,
  "recipient": "<b58>", "refund": "<b58>", "amount": "1500000000" | "max", "sig": "<b64 840 bytes>" }
```

## 5. CLI (`qusb`)

```
qusb init <stick> [--restore]       new keystore (shows 24 words once, quizzes 3), or restore from words
qusb status [--stick P] [--rpc URL] classic address, vaults, balances (watch-only, no passphrase)
qusb receive                        next fresh vault address + terminal QR
qusb sign --vault I --to ADDR --amount SOL|max [--refund-auto]   offline → qusb/sigs/*.qsig, marks I used, derives I+1 as refund
qusb broadcast FILE.qsig [--payer KEYPAIR.json|stick] [--rpc URL] [--priority-fee MICROLAMPORTS]
qusb send ...                       sign + broadcast in one go (online machine)
qusb classic send --to ADDR --amount SOL [--mint MINT]   classic lane (SPL/SOL), labelled quantum-exposed
qusb seal --to SEAL_PUB --out FILE  encrypt this stick's mnemonic to another stick's seal key (inheritance/backup)
qusb unseal FILE                    decrypt a sealed backup with this stick
qusb verify                         check bin/SHA256SUMS against the binaries on the stick
qusb wipe-check                     print what is on the host that touched qusb (should be nothing)
```
The stick is auto-detected by walking up from the binary's location to find `qusb/vault.qv`. `--stick` overrides this.
Passphrase input: tty with no echo (`rpassword`), never argv or env. Every secret buffer is `Zeroizing`.

## 6. Token-funded development (non-protocol, for the site/README)

- `$qUSB` trades on pump.fun (CA `9NDY4jY5gqcNfDrZsKujtnuvH12pPG5FUGS5QmwZpump`). The creator fee pays the dev and the team to build qUSB.
- No VC, no sales team, no paid marketing. The token gives no claim on anything, and the code stays MIT/Apache-2.0 whatever the token does.
