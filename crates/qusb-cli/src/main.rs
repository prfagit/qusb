mod rpc;
mod tx;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use qusb_core::{b58, derive, keystore, mnemonic, public, seal, stick, withdraw};
use rpc::Rpc;
use serde_json::Value;
use std::{
    fs,
    io::{IsTerminal, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

type R<T> = Result<T, Box<dyn std::error::Error>>;

const DEFAULT_RPC: &str = "https://api.mainnet-beta.solana.com";
const RENT_ZERO_DATA: u64 = 890_880;
/// The slot of the one transaction that created the qvault program account on mainnet: the first
/// slot the program existed, so no vault was spent before it. Not "last deployed in slot", which an
/// upgrade would move.
const QVAULT_FIRST_SLOT: u64 = 455_074_608;
const LANE: &str = "classic lane: quantum-exposed";
/// A fee ceiling above this (0.01 SOL) is asked about even with --yes: it is almost always a typo.
const HIGH_FEE: u64 = 10_000_000;
/// ponytail: an offline restore derives and lists every vault below N on each keystore write, so N
/// is capped. Cache the derived addresses if anyone ever needs more.
const MAX_ASSUMED: u32 = 1000;
const EJECT: &str =
    "The stick was written to. Eject it safely before you unplug it, or this change can be lost.";
const USE_ONCE: &str =
    "Use each address once. Never send to an address you have already spent from.";

#[derive(Parser)]
#[command(
    name = "qusb",
    version,
    about = "qUSB: quantum-safe one-time SOL vaults on a USB stick"
)]
struct Cli {
    /// Stick root or its qusb/ directory (default: auto-detect from the binary, then the current directory)
    #[arg(long, global = true)]
    stick: Option<PathBuf>,
    /// Answer yes to the confirmation prompts
    #[arg(long, global = true)]
    yes: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(clap::Args)]
struct Net {
    /// JSON-RPC endpoint (also env QUSB_RPC)
    #[arg(long, env = "QUSB_RPC", default_value = DEFAULT_RPC)]
    rpc: String,
    /// Priority fee in micro-lamports per compute unit
    #[arg(long, default_value_t = 0)]
    priority_fee: u64,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new keystore on the stick, or restore one from 24 words
    Init {
        /// Stick root (or use --stick)
        path: Option<PathBuf>,
        /// Restore from 24 words: reads the chain to find spent vaults, or takes --next-vault offline
        #[arg(long)]
        restore: bool,
        #[arg(long, default_value = "qusb stick")]
        label: String,
        /// Offline restore: lock every vault below N until `qusb rescan`. N must be above every vault index you ever used (1 or more)
        #[arg(long, requires = "restore", value_name = "N")]
        next_vault: Option<u32>,
        #[arg(long, env = "QUSB_RPC", default_value = DEFAULT_RPC)]
        rpc: String,
    },
    /// Classic address, vaults and balances (watch-only, no passphrase)
    Status {
        #[arg(long, env = "QUSB_RPC", default_value = DEFAULT_RPC)]
        rpc: String,
    },
    /// Show the next fresh vault address and a QR code
    Receive,
    /// Sign a withdrawal offline and write a .qsig file
    Sign {
        #[arg(long)]
        vault: u32,
        #[arg(long)]
        to: String,
        /// SOL amount, e.g. 1.5, or "max"
        #[arg(long)]
        amount: String,
    },
    /// Check a .qsig, wrap it in a transaction, simulate, then send
    Broadcast {
        file: PathBuf,
        /// Fee payer: a solana-keygen keypair JSON, or `stick` to decrypt the keystore here and use its classic key
        #[arg(long, value_name = "FILE|stick")]
        payer: String,
        #[command(flatten)]
        net: Net,
    },
    /// Sign and broadcast in one go (online machine)
    Send {
        #[arg(long)]
        vault: u32,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: String,
        /// Fee payer: a solana-keygen keypair JSON, or `stick` for the stick's classic key
        #[arg(long, value_name = "FILE|stick", default_value = "stick")]
        payer: String,
        #[command(flatten)]
        net: Net,
    },
    /// Read the chain to find spent and funded vaults, and bring the keystore up to date (online)
    Rescan {
        #[arg(long, env = "QUSB_RPC", default_value = DEFAULT_RPC)]
        rpc: String,
    },
    /// Classic lane (quantum-exposed)
    Classic {
        #[command(subcommand)]
        cmd: ClassicCmd,
    },
    /// Encrypt this stick's mnemonic to another stick's seal key
    Seal {
        #[arg(long)]
        to: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Show this stick's seal key and its fingerprint
    SealKey,
    /// Decrypt a sealed backup with this stick
    Unseal { file: PathBuf },
    /// Check bin/SHA256SUMS against the files on the stick
    Verify,
    /// List host traces qusb could have left
    WipeCheck,
}

#[derive(Subcommand)]
enum ClassicCmd {
    Send {
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: String,
        #[arg(long)]
        mint: Option<String>,
        #[command(flatten)]
        net: Net,
    },
}

fn main() {
    if let Err(e) = run(Cli::parse()) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

// ---------- helpers ----------

fn prompt(msg: &str) -> R<Zeroizing<String>> {
    // Test hook: exists only in builds made with `--features test-hooks`, never in a release binary.
    #[cfg(feature = "test-hooks")]
    if let Ok(p) = std::env::var("QUSB_TEST_PASS") {
        return Ok(Zeroizing::new(p));
    }
    Ok(Zeroizing::new(rpassword::prompt_password(msg)?))
}

/// Waits for a typed "yes". `skip` is --yes.
fn confirm(skip: bool, what: &str) -> R<()> {
    if skip {
        return Ok(());
    }
    eprint!("{what}\nType yes to continue: ");
    let mut l = String::new();
    std::io::stdin().read_line(&mut l)?;
    if l.trim() == "yes" {
        Ok(())
    } else {
        Err("cancelled, nothing was done".into())
    }
}

/// Printable form of text that comes from a file nobody authenticated: no terminal escapes.
fn plain(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// The alternate screen, for secrets. Dropping it wipes that screen and the scrollback, so the
/// words do not stay in the terminal history.
struct Private(bool);
impl Private {
    fn enter() -> Self {
        let on = std::io::stdout().is_terminal();
        if on {
            print!("\x1b[?1049h\x1b[2J\x1b[H");
        }
        Private(on)
    }
    fn clear(&self) {
        if self.0 {
            print!("\x1b[2J\x1b[3J\x1b[H");
        }
    }
}
impl Drop for Private {
    fn drop(&mut self) {
        if self.0 {
            print!("\x1b[2J\x1b[3J\x1b[H\x1b[?1049l\x1b[3J");
            let _ = std::io::stdout().flush();
        }
    }
}

fn qusb_dir_of(p: &Path) -> PathBuf {
    if p.file_name().is_some_and(|n| n == "qusb") {
        p.to_path_buf()
    } else {
        p.join("qusb")
    }
}

fn stick_dir(opt: &Option<PathBuf>) -> R<PathBuf> {
    // vault.qv.tmp on its own is a keystore whose last write was cut short; `keystore::unlock` finishes it.
    if let Some(p) = opt {
        let d = qusb_dir_of(p);
        return if d.join("vault.qv").is_file() || d.join("vault.qv.tmp").is_file() {
            Ok(d)
        } else {
            Err(format!("no qusb/vault.qv under {}", p.display()).into())
        };
    }
    let find = |d: &Path| stick::find(d).or_else(|| stick::find_file(d, "vault.qv.tmp"));
    let exe = std::env::current_exe().ok().and_then(|e| find(e.parent()?));
    exe.or_else(|| find(&std::env::current_dir().ok()?))
        .ok_or_else(|| "no stick found; run from the stick or pass --stick PATH".into())
}

/// Decimal SOL to lamports with no floating point. "max" is u64::MAX.
fn parse_amount(s: &str) -> R<u64> {
    if s == "max" {
        return Ok(u64::MAX);
    }
    let (i, f) = s.split_once('.').unwrap_or((s, ""));
    let digits = |x: &str| x.bytes().all(|b| b.is_ascii_digit());
    if i.is_empty() && f.is_empty() || !digits(i) || !digits(f) || f.len() > 9 {
        return Err(format!("bad amount '{s}': use SOL with at most 9 decimals, or max").into());
    }
    let whole: u64 = if i.is_empty() { 0 } else { i.parse()? };
    let frac: u64 = if f.is_empty() {
        0
    } else {
        format!("{f:0<9}").parse()?
    };
    let l = whole
        .checked_mul(1_000_000_000)
        .and_then(|w| w.checked_add(frac))
        .ok_or("amount too large")?;
    if l == u64::MAX {
        return Err("amount too large".into());
    }
    Ok(l)
}

fn sol(l: u64) -> String {
    format!("{}.{:09}", l / 1_000_000_000, l % 1_000_000_000)
}

/// A .qsig amount ("max" or lamports) as typed on the command line and as shown to the user.
fn amount_arg(a: &str) -> String {
    match a.parse() {
        Ok(l) => sol(l),
        Err(_) => a.into(),
    }
}

/// The amount to sign, and a line for the summary when it is not what was typed. Online, the exact
/// observed balance is signed where v0.1.0 signed `max`: a `max` signature, replayed, takes
/// whatever the vault holds later, an exact one only ever moves that amount.
/// Rent rule (SPEC §3): a remainder of 0 < rest < rent-exempt minimum would fail, so that sweeps.
fn plan_amount(amount: u64, balance: Option<u64>, rent: u64) -> R<(u64, Option<String>)> {
    if amount == 0 {
        return Err("the amount must be more than zero".into());
    }
    let Some(b) = balance else {
        let note = if amount == u64::MAX {
            "This signs `max`: whatever the vault holds when it is broadcast goes to the recipient."
                .into()
        } else {
            format!("The balance is unknown offline. If this would leave the vault with less than {} SOL, the broadcast fails and the key is still spent: use --amount max to send everything.", sol(rent))
        };
        return Ok((amount, Some(note)));
    };
    if b == 0 {
        return Err("this vault holds nothing; signing would spend its one-time key for no reason. Nothing was signed".into());
    }
    if amount == u64::MAX {
        return Ok((
            b,
            Some("`max` is signed as the exact balance seen now.".into()),
        ));
    }
    if amount > b {
        return Err(format!("vault holds {} SOL, less than {}", sol(b), sol(amount)).into());
    }
    if b != amount && b - amount < rent {
        return Ok((b, Some(format!("You asked for {} SOL. The {} SOL left over would be under the rent-exempt minimum and the network would reject it, so this sends the whole vault.", sol(amount), sol(b - amount)))));
    }
    Ok((amount, None))
}

/// The rent-exempt minimum decides how much `send` signs (the sweep in `plan_amount`), and it comes
/// from the RPC node, so an answer far from the known value is refused, not trusted.
fn plausible_rent(rent: u64) -> R<u64> {
    if rent == 0 || rent > 2 * RENT_ZERO_DATA {
        return Err(format!("this RPC node reports a rent-exempt minimum of {} SOL, where {} SOL is expected. That number decides how much is signed, so nothing was signed. Use another RPC node, or `qusb sign` offline and then `qusb broadcast`", sol(rent), sol(RENT_ZERO_DATA)).into());
    }
    Ok(rent)
}

/// The network takes a fee only from a payer that is then left with the rent-exempt minimum, with
/// exactly nothing, or that was under the minimum already.
fn payer_ok(bal: u64, fee: u64, rent: u64) -> bool {
    bal >= fee && (bal - fee >= rent || bal == fee || bal < rent)
}

fn read_keypair(p: &Path) -> R<SigningKey> {
    let raw = Zeroizing::new(
        fs::read(p).map_err(|e| format!("cannot read fee payer keypair {}: {e}", p.display()))?,
    );
    let v: Zeroizing<Vec<u8>> = Zeroizing::new(serde_json::from_slice(&raw)?);
    if v.len() != 64 {
        return Err("keypair file must hold 64 bytes".into());
    }
    let k = SigningKey::from_bytes(v[..32].try_into().unwrap());
    if k.verifying_key().as_bytes() != &v[32..] {
        return Err("keypair file is inconsistent".into());
    }
    Ok(k)
}

fn seed_of(s: &keystore::Secrets) -> Zeroizing<[u8; 64]> {
    mnemonic::seed64(&s.mnemonic)
}

fn addr(a: &str) -> R<[u8; 32]> {
    Ok(b58::dec32(a.trim())?)
}

fn unlock(dir: &Path) -> R<(keystore::Secrets, Zeroizing<String>)> {
    let cut_short = dir.join("vault.qv.tmp").is_file();
    let pass = prompt("Passphrase: ")?;
    let s = keystore::unlock(dir, &pass)?;
    if cut_short {
        eprintln!("note: the last write to this stick was cut short (unplugged early?). The keystore has been recovered. {EJECT}");
    }
    Ok((s, pass))
}

/// The one gate in front of a vault key, shared by `sign` and `send`: the amount rules, then
/// `withdraw::plan` (refund choice, recipient rules, one signature per key).
fn prepare(
    s: &keystore::Secrets,
    k: u32,
    to: &[u8; 32],
    typed: u64,
    balance: Option<u64>,
    rent: u64,
) -> R<(withdraw::Plan, Option<String>)> {
    // A used vault can only repeat what it signed, whatever it holds now.
    let (amount, note) = if s.used.contains(&k) {
        (typed, None)
    } else {
        plan_amount(typed, balance, rent)?
    };
    match withdraw::plan(s, k, to, amount) {
        Ok(p) if p.refund_index.is_none() => Ok((p, Some(format!("Vault {k} already signed exactly this. The same .qsig is written again; nothing new is signed.")))),
        Ok(p) => Ok((p, note)),
        Err(qusb_core::Error::SignedOther(x)) => Err(format!(
            "vault {k} already signed {} to {} (refund {}). A vault key signs once, so nothing else can ever be signed from this vault. To write that same .qsig again:\n  qusb sign --vault {k} --to {} --amount {}",
            show_amount(&x.amount), x.recipient, x.refund, x.recipient, amount_arg(&x.amount)
        ).into()),
        Err(e @ qusb_core::Error::AlreadyUsed(_)) => Err(format!("{e}. If this stick was restored offline, run `qusb rescan` online: it unlocks the vaults the chain shows as unspent").into()),
        Err(e) => Err(e.into()),
    }
}

fn show_amount(a: &str) -> String {
    match a.parse() {
        Ok(l) => format!("{} SOL", sol(l)),
        Err(_) => "everything in the vault at broadcast time (max)".into(),
    }
}

/// The last question before a vault key is spent, or its .qsig written again.
fn confirm_spend(yes: bool, k: u32, plan: &withdraw::Plan) -> R<()> {
    let what = match plan.refund_index {
        Some(_) => {
            format!("This spends the one-time key of vault {k}: it can never sign anything else.")
        }
        None => format!("Vault {k} signed this before. The same file is written again."),
    };
    confirm(yes, &what)
}

/// What is about to be signed or sent. `payer` is the fee payer address and the most it can be charged.
fn summary(title: &str, vault: &str, sp: &keystore::Spend, payer: Option<(&str, u64)>) {
    println!("{title}");
    println!("  vault        {vault}");
    println!("  recipient    {}", sp.recipient);
    println!("  refund       {}", sp.refund);
    println!("  amount       {}", show_amount(&sp.amount));
    if let Some((p, fee)) = payer {
        println!("  fee payer    {p}");
        println!("  maximum fee  {} SOL", sol(fee));
    }
}

/// The fee ceiling for `micro` micro-lamports per compute unit, asked about when it is large.
fn fee_ceiling(micro: u64) -> R<u64> {
    let fee = tx::max_fee(micro);
    if fee > HIGH_FEE {
        confirm(
            false,
            &format!(
                "--priority-fee {micro} lets this transaction cost up to {} SOL in fees.",
                sol(fee)
            ),
        )?;
    }
    Ok(fee)
}

/// The one path that spends a vault key. Order matters (SPEC §3, one-time keys): everything that
/// can fail without the key runs first, then the spend is saved, then signed, then the .qsig written.
/// If the last step is lost, running the same command again writes the same .qsig.
fn sign_core(
    dir: &Path,
    s: &mut keystore::Secrets,
    pass: &str,
    plan: withdraw::Plan,
) -> R<(withdraw::QSig, PathBuf)> {
    let sp = plan.spend;
    let (to, refund) = (addr(&sp.recipient)?, addr(&sp.refund)?);
    let amount = withdraw::parse_amount(&sp.amount)?;
    let sigs = dir.join("sigs");
    fs::create_dir_all(&sigs)?;
    let name = sigs.join(format!("vault{}.qsig", sp.vault));
    if let Some(r) = plan.refund_index {
        // A .qsig on the stick for a vault this keystore calls unused: the keystore is behind (an
        // older copy of vault.qv put back). Only the same withdrawal, which signs to the same bytes,
        // may go on.
        let same = |q: withdraw::QSig| {
            (q.vault_index, &q.recipient, &q.refund, &q.amount)
                == (sp.vault, &sp.recipient, &sp.refund, &sp.amount)
        };
        if name.exists()
            && !fs::read(&name).is_ok_and(|b| serde_json::from_slice(&b).is_ok_and(same))
        {
            return Err(format!("{} already exists: vault {} has signed before, but this keystore has no record of it (was an older copy of vault.qv put back?). A vault key signs once, so nothing new was signed. Broadcast the existing file:\n  qusb broadcast {} --payer <keypair.json|stick>", name.display(), sp.vault, name.display()).into());
        }
        keystore::mark_used(s, sp.clone())?;
        s.next_vault = s.next_vault.max(r + 1);
        keystore::save(dir, s, pass)?;
    }
    let q = withdraw::sign(&seed_of(s), sp.vault, &to, &refund, amount);
    let json = serde_json::to_string_pretty(&q)?;
    if let Err(e) = keystore::atomic_write(&name, json.as_bytes()) {
        eprintln!("could not write {}: {e}\n{json}", name.display());
        return Err("the signature is printed above: save it now, or run the same command again to write the file".into());
    }
    if let Err(e) = public::write(dir, &public::build(s)) {
        eprintln!("warning: could not update public.json ({e}); `qusb status` may be out of date");
    }
    Ok((q, name))
}

/// Simulates, prints the signature, sends, then waits. The signature is known before anything is
/// sent, so an unclear ending can always be looked up instead of retried blind.
fn submit(rpc: &Rpc, payer: &SigningKey, ixs: &[tx::Ix]) -> R<()> {
    let pk = payer.verifying_key().to_bytes();
    let msg = tx::message(pk, rpc.blockhash()?, ixs);
    let raw = tx::sign(payer, &msg)?;
    let b64 = B64.encode(&raw);
    rpc.simulate(&b64).map_err(|e| {
        let e = e.to_string();
        if e.contains("InsufficientFundsForRent") {
            format!("{e}\nAn account would end under the rent-exempt minimum ({} SOL). A new recipient must receive at least that much. If the vault balance changed after signing, the difference goes to the refund address, which must not end under that minimum either: send that much to the refund address and broadcast again.", sol(RENT_ZERO_DATA))
        } else {
            e
        }
    })?;
    let sig = b58::enc(&raw[1..65]);
    println!("simulation ok\nsignature {sig}\nsending");
    let unknown = |why: String| -> Box<dyn std::error::Error> {
        format!("status unknown ({why}). The transaction may still land: check this signature before retrying\n  {sig}").into()
    };
    rpc.send(&b64).map_err(|e| unknown(e.to_string()))?;
    if !rpc.confirm(&sig)? {
        return Err(unknown("sent, but not seen confirmed".into()));
    }
    println!("confirmed");
    Ok(())
}

/// Nothing reaches the fee payer's signature without `withdraw::check`.
fn submit_qsig(rpc: &Rpc, payer: &SigningKey, q: &withdraw::QSig, micro: u64) -> R<()> {
    let c = withdraw::check(q)?;
    let pk = payer.verifying_key().to_bytes();
    let ixs = tx::withdraw_ixs(pk, c.vault, c.recipient, c.refund, c.ix_data, micro);
    submit(rpc, payer, &ixs)
}

/// If `tx` holds a qvault Withdraw (top level or inner) naming `vault` as the vault account:
/// Some(what it signed), or Some(None) when the transaction succeeded but cannot be rebuilt.
/// A failed transaction counts too when its signature verifies: that key has signed.
fn spent_by(tx: &Value, k: u32, vault: &str) -> Option<Option<keystore::Spend>> {
    let list = |v: &Value| v.as_array().cloned().unwrap_or_default();
    let (msg, meta) = (&tx["transaction"]["message"], &tx["meta"]);
    let mut keys = list(&msg["accountKeys"]);
    keys.extend(list(&meta["loadedAddresses"]["writable"]));
    keys.extend(list(&meta["loadedAddresses"]["readonly"]));
    let key = |i: &Value| keys.get(i.as_u64()? as usize)?.as_str();
    let mut ixs = list(&msg["instructions"]);
    for inner in list(&meta["innerInstructions"]) {
        ixs.extend(list(&inner["instructions"]));
    }
    let mut unverified = false;
    for ix in &ixs {
        let acc = list(&ix["accounts"]);
        if key(&ix["programIdIndex"]) != Some(derive::QVAULT_PROGRAM_ID)
            || acc.get(1).and_then(key) != Some(vault)
        {
            continue;
        }
        let q = (|| {
            let data = b58::dec(ix["data"].as_str()?).ok()?;
            withdraw::from_ix(k, vault, key(acc.get(2)?)?, key(acc.get(3)?)?, &data)
        })();
        if let Some(q) = q.filter(|q| withdraw::check(q).is_ok()) {
            return Some(Some(keystore::Spend {
                vault: k,
                recipient: q.recipient,
                refund: q.refund,
                amount: q.amount,
            }));
        }
        unverified |= meta["err"].is_null();
    }
    unverified.then_some(None)
}

/// Brings `s` in line with the chain (SPEC §5, rescan). Walks vaults from 0 until SCAN_GAP in a row
/// have no history. A vault is used iff a transaction spends it; deposits and change do not count.
/// `s` changes only after the whole walk succeeded: half a scan must never pass for a full one.
/// Returns the report, and the vaults an offline restore had locked that this unlocks.
fn rescan(rpc: &Rpc, s: &mut keystore::Secrets) -> R<(String, Vec<u32>)> {
    // A node that has dropped old blocks answers "no history" for a vault that was spent, which
    // reads exactly like a vault that never signed. Only a node that reaches back to the program's
    // first slot can say "never spent".
    let first = rpc.first_available_block()?;
    if first > QVAULT_FIRST_SLOT {
        return Err(format!("this RPC node does not keep full history (its oldest block is slot {first}, and vaults could be spent from slot {QVAULT_FIRST_SLOT} on), so it cannot show which vaults were spent. Use an RPC node that keeps full history, or restore offline with `qusb init <stick> --restore --next-vault N`. Nothing was changed").into());
    }
    let seed = seed_of(s);
    let known = s.next_vault.max(s.used.iter().max().map_or(0, |m| m + 1));
    let (mut spent, mut top, mut empty, mut i) = (vec![], None, 0, 0u32);
    while (empty < keystore::SCAN_GAP || i < known) && i < keystore::MAX_VAULT {
        let vault = b58::enc(&derive::vault(&seed, i));
        let mut page = rpc.signatures(&vault, None)?;
        if page.is_empty() {
            empty += 1;
        } else {
            (empty, top) = (0, Some(i));
        }
        // ponytail: one getTransaction per signature until a spend turns up. A vault address spammed
        // with dust transfers makes this slow; batch the requests if that ever happens.
        'vault: while let Some(last) = page.last().cloned() {
            for sig in &page {
                if let Some(rec) = spent_by(&rpc.transaction(sig)?, i, &vault) {
                    spent.push((i, rec));
                    break 'vault;
                }
            }
            // Until an empty page: a node may return fewer than it was asked for.
            page = rpc.signatures(&vault, Some(&last))?;
        }
        i += 1;
    }

    // Vaults an offline restore locked on a guess are unlocked if the chain shows no spend. Anything
    // this keystore itself signed, or that was used with no such guess, stays used.
    let assumed = std::mem::take(&mut s.assumed_used_below);
    let chain: Vec<u32> = spent.iter().map(|(k, _)| *k).collect();
    let spends = &s.spends;
    let keep = |u: &u32| *u >= assumed || chain.contains(u) || spends.iter().any(|x| x.vault == *u);
    let unlocked: Vec<u32> = s.used.iter().copied().filter(|u| !keep(u)).collect();
    s.used.retain(keep);
    for (k, rec) in spent {
        if !s.used.contains(&k) {
            s.used.push(k);
        }
        match (rec, s.spends.iter().find(|x| x.vault == k)) {
            (Some(rec), None) => s.spends.push(rec),
            (Some(rec), Some(have)) if *have != rec => eprintln!("warning: vault {k} signed {} to {} on chain, but this stick recorded a different withdrawal. Two signatures from one vault key exist, so that key is no longer safe: never fund vault {k} again.", show_amount(&rec.amount), rec.recipient),
            _ => {}
        }
    }
    s.used.sort_unstable();
    if let Some(t) = top {
        s.next_vault = s.next_vault.max(t + 1);
    }
    let report = format!(
        "Scanned vaults 0 to {}. Spent on chain: {}. Highest vault with any history: {}. Next fresh vault: {}.\nIf you know you used more vaults than that, this RPC node is missing history: do not sign, and rescan with another node.",
        i - 1,
        if chain.is_empty() { "none".into() } else { format!("{chain:?}") },
        top.map_or("none".into(), |t| t.to_string()),
        keystore::next_fresh(s)
    );
    Ok((report, unlocked))
}

// ---------- commands ----------

fn run(cli: Cli) -> R<()> {
    match cli.cmd {
        Cmd::Init {
            path,
            restore,
            label,
            next_vault,
            rpc,
        } => init(path.or(cli.stick), restore, label, next_vault, rpc),
        Cmd::Status { rpc } => {
            let info = public::read(&stick_dir(&cli.stick)?)?;
            let mut addrs = vec![info.classic.clone()];
            addrs.extend(info.vaults.iter().map(|v| v.address.clone()));
            let bal = Rpc::new(rpc).balances(&addrs).ok();
            let show = |i: usize| match &bal {
                Some(b) => format!("{} SOL", sol(b[i])),
                None => "balance unavailable (offline?)".into(),
            };
            println!("{}", plain(&info.label));
            println!("Watch-only view from public.json, which is not authenticated: use `qusb receive` for an address to fund.");
            println!("classic  {}  {}", plain(&info.classic), show(0));
            for (i, v) in info.vaults.iter().enumerate() {
                println!(
                    "vault {} {}  {}  {}",
                    v.index,
                    plain(&v.state),
                    plain(&v.address),
                    show(i + 1)
                );
            }
            for (i, v) in info.vaults.iter().enumerate() {
                let held = bal.as_ref().map_or(0, |b| b[i + 1]);
                if v.state == "used" && held > 0 {
                    println!("warning: vault {} has been spent from and holds {} SOL. Anyone can replay its old signature, which sends these funds to the old recipient and refund addresses. The only way out that you control is to broadcast the original .qsig again (qusb/sigs/vault{}.qsig). Never fund a used vault.", v.index, sol(held), v.index);
                }
            }
            Ok(())
        }
        Cmd::Receive => {
            // The address comes from the keystore, not from public.json: that file is not
            // authenticated, and whoever can edit it could put their own address here.
            let (s, _) = unlock(&stick_dir(&cli.stick)?)?;
            let (seed, k) = (seed_of(&s), keystore::next_fresh(&s));
            let vault = b58::enc(&derive::vault(&seed, k));
            println!("Vault {k}: {vault}");
            let qr = qrcode::QrCode::new(vault.as_bytes())?
                .render::<qrcode::render::unicode::Dense1x2>()
                .quiet_zone(true)
                .build();
            println!("{qr}");
            println!("{USE_ONCE}");
            println!(
                "Fees are paid from the classic address ({LANE}): {}",
                b58::enc(derive::classic_keypair(&seed).verifying_key().as_bytes())
            );
            Ok(())
        }
        Cmd::Sign { vault, to, amount } => {
            let dir = stick_dir(&cli.stick)?;
            let to = addr(&to)?;
            let typed = parse_amount(&amount)?;
            let (mut s, pass) = unlock(&dir)?;
            let (plan, note) = prepare(&s, vault, &to, typed, None, RENT_ZERO_DATA)?;
            let v = b58::enc(&derive::vault(&seed_of(&s), vault));
            summary("Withdrawal to sign", &v, &plan.spend, None);
            note.iter().for_each(|n| println!("{n}"));
            confirm_spend(cli.yes, vault, &plan)?;
            let (q, p) = sign_core(&dir, &mut s, &pass, plan)?;
            println!(
                "Signed vault {vault}, amount {}. Wrote {}",
                q.amount,
                p.display()
            );
            println!("Vault {vault} is marked used. Carry the file to an online machine and run: qusb broadcast <file> --payer <keypair.json|stick>");
            println!("{EJECT}");
            Ok(())
        }
        Cmd::Broadcast { file, payer, net } => {
            let q: withdraw::QSig = serde_json::from_slice(&fs::read(&file)?)?;
            // A .qsig is a file from anywhere. Before the fee payer signs around it: it must name the
            // built-in program and carry a signature that verifies for exactly what it says.
            withdraw::check(&q)?;
            let key = if payer == "stick" {
                eprintln!("warning: --payer stick decrypts the keystore on this machine to reach the classic key. On a machine you do not fully trust, pay from a separate keypair file instead.");
                derive::classic_keypair(&seed_of(&unlock(&stick_dir(&cli.stick)?)?.0))
            } else {
                read_keypair(Path::new(&payer))?
            };
            let sp = keystore::Spend {
                vault: q.vault_index,
                recipient: q.recipient.clone(),
                refund: q.refund.clone(),
                amount: q.amount.clone(),
            };
            let pk = b58::enc(key.verifying_key().as_bytes());
            let fee = fee_ceiling(net.priority_fee)?;
            summary("Withdrawal to broadcast", &q.vault, &sp, Some((&pk, fee)));
            confirm(cli.yes, "The signature checks out for exactly this.")?;
            submit_qsig(&Rpc::new(net.rpc), &key, &q, net.priority_fee)
        }
        Cmd::Send {
            vault,
            to,
            amount,
            payer,
            net,
        } => {
            let dir = stick_dir(&cli.stick)?;
            let rpc = Rpc::new(net.rpc);
            let to = addr(&to)?;
            let typed = parse_amount(&amount)?;
            let (mut s, pass) = unlock(&dir)?;
            // Everything that can fail is settled before the vault key is spent: the fee payer is
            // loaded and funded, the balances are read, the recipient can take the amount.
            let key = if payer == "stick" {
                derive::classic_keypair(&seed_of(&s))
            } else {
                read_keypair(Path::new(&payer))?
            };
            let pk = b58::enc(key.verifying_key().as_bytes());
            let v = b58::enc(&derive::vault(&seed_of(&s), vault));
            let bal = rpc.balances(&[v.clone(), b58::enc(&to), pk.clone()])?;
            let rent = plausible_rent(rpc.min_rent_zero_data().unwrap_or(RENT_ZERO_DATA))?;
            let (plan, note) = prepare(&s, vault, &to, typed, Some(bal[0]), rent)?;
            let fee = tx::max_fee(net.priority_fee);
            if !payer_ok(bal[2], fee, rent) {
                return Err(format!("fee payer {pk} holds {} SOL. It must cover a fee of up to {} SOL and still hold the rent-exempt minimum of {} SOL. Fund it first. Nothing was signed", sol(bal[2]), sol(fee), sol(rent)).into());
            }
            if let Ok(n) = plan.spend.amount.parse::<u64>() {
                if bal[1].saturating_add(n) < rent {
                    return Err(format!("the recipient would hold {} SOL, under the rent-exempt minimum of {} SOL, and the network rejects that. Send more, or to an address that already holds SOL. Nothing was signed", sol(bal[1] + n), sol(rent)).into());
                }
            }
            summary(
                "Withdrawal to sign and send",
                &v,
                &plan.spend,
                Some((&pk, fee)),
            );
            note.iter().for_each(|n| println!("{n}"));
            fee_ceiling(net.priority_fee)?;
            confirm_spend(cli.yes, vault, &plan)?;
            let (q, p) = sign_core(&dir, &mut s, &pass, plan)?;
            drop(s);
            println!(
                "Signed vault {vault}, amount {}. Wrote {}",
                q.amount,
                p.display()
            );
            println!("{EJECT}");
            submit_qsig(&rpc, &key, &q, net.priority_fee).map_err(|e| {
                format!("{e}\nThe signed withdrawal is saved in {} and stays valid. Once the cause is fixed, retry with:\n  qusb broadcast {} --payer {payer}", p.display(), p.display()).into()
            })
        }
        Cmd::Rescan { rpc } => {
            let dir = stick_dir(&cli.stick)?;
            let (mut s, pass) = unlock(&dir)?;
            let (report, unlocked) = rescan(&Rpc::new(rpc), &mut s)?;
            println!("{report}");
            if !unlocked.is_empty() {
                // Never skipped by --yes: this is the one step that lets a locked vault key sign again.
                confirm(false, &format!("Vaults {unlocked:?} were locked as used by the offline restore. This RPC node shows no withdrawal from them, so they become spendable again. That is wrong if the node hides history, or if you signed a .qsig from one of them that was never broadcast, and a second signature from one vault key can let anyone take what that vault holds. Continue only if you trust this RPC node and never signed from these vaults."))?;
            }
            keystore::save(&dir, &s, &pass)?;
            public::write(&dir, &public::build(&s))?;
            println!("Saved.\n{EJECT}");
            Ok(())
        }
        Cmd::Classic {
            cmd:
                ClassicCmd::Send {
                    to,
                    amount,
                    mint,
                    net,
                },
        } => {
            if mint.is_some() {
                return Err("SPL token transfers are not supported yet; nothing was sent".into());
            }
            println!("{LANE}");
            let lamports = parse_amount(&amount)?;
            if lamports == u64::MAX {
                return Err("classic send needs an exact SOL amount".into());
            }
            let to_key = addr(&to)?;
            confirm(
                cli.yes,
                &format!(
                    "Send {} SOL from the classic address to {}.",
                    sol(lamports),
                    to.trim()
                ),
            )?;
            let (s, _) = unlock(&stick_dir(&cli.stick)?)?;
            let key = derive::classic_keypair(&seed_of(&s));
            drop(s);
            submit(
                &Rpc::new(net.rpc),
                &key,
                &tx::transfer_ixs(key.verifying_key().to_bytes(), to_key, lamports),
            )
        }
        Cmd::Seal { to, out } => {
            let to = seal::decode_pub(&to)?;
            println!("Recipient seal key fingerprint: {}", seal::fingerprint(&to));
            confirm(cli.yes, "Whoever holds that seal key's stick can read this stick's 24 words. Compare the fingerprint with `qusb seal-key` on the receiving stick first.")?;
            let (s, _) = unlock(&stick_dir(&cli.stick)?)?;
            fs::write(&out, B64.encode(seal::seal(&to, s.mnemonic.as_bytes())?))?;
            println!("Sealed backup written to {}", out.display());
            Ok(())
        }
        Cmd::SealKey => {
            let (s, _) = unlock(&stick_dir(&cli.stick)?)?;
            let (p, _) = seal::seal_keys(&seed_of(&s));
            println!("{}", seal::encode_pub(&p));
            println!("Fingerprint: {}", seal::fingerprint(&p));
            Ok(())
        }
        Cmd::Unseal { file } => {
            let blob = B64.decode(fs::read_to_string(file)?.trim())?;
            let (s, _) = unlock(&stick_dir(&cli.stick)?)?;
            let (_, sk) = seal::seal_keys(&seed_of(&s));
            let pt = seal::unseal(&sk, &blob)?;
            // The text is whatever the sender sealed: print it without its control characters.
            let text = Zeroizing::new(plain(&String::from_utf8_lossy(&pt)));
            let screen = Private::enter();
            println!("Sealed words (keep private):\n{}", *text);
            if screen.0 {
                println!("\nPress Enter to clear the screen.");
                std::io::stdin().read_line(&mut String::new())?;
            }
            Ok(())
        }
        Cmd::Verify => verify(cli.stick.as_deref()),
        Cmd::WipeCheck => {
            println!("qusb writes only to the stick (qusb/ and its sigs/). It writes nothing to the host by design.");
            let tmp = std::env::temp_dir();
            let hits: Vec<_> = fs::read_dir(&tmp)?
                .flatten()
                .filter(|e| e.file_name().to_string_lossy().starts_with("qusb"))
                .collect();
            if hits.is_empty() {
                println!("{}: no qusb files", tmp.display());
            }
            for h in hits {
                println!("found {}", h.path().display());
            }
            println!("Shell history may hold lines with 'qusb' (commands, never passphrases). Clear them if you want no trace.");
            Ok(())
        }
    }
}

fn init(
    path: Option<PathBuf>,
    restore: bool,
    label: String,
    next_vault: Option<u32>,
    rpc: String,
) -> R<()> {
    let dir = qusb_dir_of(&path.ok_or("give the stick path: qusb init <stick>")?);
    if dir.join("vault.qv").exists() {
        return Err("this stick already has a keystore".into());
    }
    if dir.join("vault.qv.tmp").exists() {
        return Err("this stick has a keystore whose last write was cut short (qusb/vault.qv.tmp). Run `qusb receive` with its passphrase to recover it, or delete that file if init never finished".into());
    }
    let mut s = keystore::Secrets {
        created: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
        label,
        ..Default::default()
    };
    if restore {
        #[cfg(feature = "test-hooks")]
        let w = std::env::var("QUSB_TEST_WORDS")
            .map(Zeroizing::new)
            .or_else(|_| prompt("24 words: "));
        #[cfg(not(feature = "test-hooks"))]
        let w = prompt("24 words: ");
        s.mnemonic = Zeroizing::new(w?.split_whitespace().collect::<Vec<_>>().join(" "));
        mnemonic::validate(&s.mnemonic)?;
        // The words do not say which vault keys have signed. A restore must know before it hands
        // out or signs from any vault: from the chain, or from a bound the user gives.
        match next_vault {
            Some(0) => return Err("--next-vault 0 would say that no vault was ever used, which is the one thing an offline restore cannot know. Give a number above every vault index you ever used (1 or more), or restore online without --next-vault. Nothing was written".into()),
            Some(n) if n > MAX_ASSUMED => {
                return Err(format!(
                    "--next-vault can be at most {MAX_ASSUMED}; restore online instead"
                )
                .into())
            }
            Some(n) => {
                s.used = (0..n).collect();
                (s.assumed_used_below, s.next_vault) = (n, n);
                println!("Every vault below index {n} is locked as used ({n} in all). Run `qusb rescan` on an online machine to find their balances and unlock the ones that never signed.");
            }
            None => {
                println!("Reading vault history from {rpc}");
                let (report, _) = rescan(&Rpc::new(rpc), &mut s).map_err(|e| format!("could not read vault history: {e}\nA restore must learn which vaults were already spent before it can hand one out. Go online and try again, or restore offline with --next-vault N, where N is above every vault index you ever used. Nothing was written"))?;
                println!("{report}");
            }
        }
        println!("If you ever signed a .qsig that was never broadcast, the chain cannot show it. If you still have a copy of that .qsig, broadcast it. Otherwise empty that vault with a single `qusb send --amount max` and never fund it again.");
    } else {
        s.mnemonic = mnemonic::generate();
        show_and_quiz(&s.mnemonic)?;
    }
    let pass = loop {
        let a = prompt("New passphrase (8+ characters): ")?;
        if a.chars().count() < 8 {
            eprintln!("too short");
            continue;
        }
        if *a != *prompt("Repeat passphrase: ")? {
            eprintln!("did not match");
            continue;
        }
        break a;
    };
    keystore::create(&dir, &s, &pass)?;
    public::write(&dir, &public::build(&s))?;
    fs::create_dir_all(dir.join("sigs"))?;
    println!("Keystore created in {}", dir.display());
    let k = keystore::next_fresh(&s);
    println!("Vault {k}: {}", b58::enc(&derive::vault(&seed_of(&s), k)));
    println!("{USE_ONCE}\n{EJECT}");
    Ok(())
}

fn show_and_quiz(w: &str) -> R<()> {
    #[cfg(feature = "test-hooks")]
    if std::env::var("QUSB_TEST_PASS").is_ok() {
        return Ok(());
    }
    use rand_core::{OsRng, RngCore};
    let list: Vec<&str> = w.split(' ').collect();
    let screen = Private::enter();
    println!("Your 24 recovery words. Write them on paper. They are shown once.\n");
    for (i, x) in list.iter().enumerate() {
        println!("{:>2}. {x}", i + 1);
    }
    println!("\nPress Enter when written down.");
    std::io::stdin().read_line(&mut String::new())?;
    screen.clear();
    let mut picks: Vec<usize> = vec![];
    while picks.len() < 3 {
        let p = (OsRng.next_u32() % 24) as usize;
        if !picks.contains(&p) {
            picks.push(p);
        }
    }
    picks.sort();
    for p in picks {
        loop {
            println!("Enter word number {}:", p + 1);
            let mut l = Zeroizing::new(String::new());
            if std::io::stdin().read_line(&mut l)? == 0 {
                return Err("input closed before the words were confirmed".into());
            }
            if l.trim() == list[p] {
                break;
            }
            eprintln!("That is not it. Check your paper.");
        }
    }
    Ok(())
}

/// Works before `init`: the sums sit beside the binary in bin/, so no keystore is needed to find them.
fn verify(stick: Option<&Path>) -> R<()> {
    use sha2::{Digest, Sha256};
    let bin = match stick {
        Some(p) => qusb_dir_of(p).parent().ok_or("bad stick path")?.join("bin"),
        None => std::env::current_exe()?
            .parent()
            .ok_or("cannot locate the binary")?
            .to_path_buf(),
    };
    let sums = fs::read_to_string(bin.join("SHA256SUMS"))
        .map_err(|e| format!("cannot read {}: {e}", bin.join("SHA256SUMS").display()))?;
    let (mut bad, mut ok) = (0, 0);
    for line in sums.lines().filter(|l| !l.trim().is_empty()) {
        let (h, name) = line
            .split_once(char::is_whitespace)
            .ok_or("bad SHA256SUMS line")?;
        let name = name.trim().trim_start_matches('*');
        match fs::read(bin.join(name)) {
            Ok(b) if hex::encode(Sha256::digest(&b)) == h => {
                ok += 1;
                println!("ok       {name}");
            }
            Ok(_) => {
                bad += 1;
                println!("MISMATCH {name}");
            }
            Err(_) => {
                bad += 1;
                println!("MISSING  {name}");
            }
        }
    }
    if bad > 0 || ok == 0 {
        return Err(format!(
            "{bad} file(s) missing or not matching SHA256SUMS, {ok} verified in {}",
            bin.display()
        )
        .into());
    }
    println!("{ok} file(s) verified");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::{BufRead, Read};

    const ART: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    fn secrets() -> keystore::Secrets {
        keystore::Secrets {
            mnemonic: Zeroizing::new(ART.into()),
            ..Default::default()
        }
    }

    #[test]
    fn amounts() {
        assert_eq!(parse_amount("1.5").unwrap(), 1_500_000_000);
        assert_eq!(parse_amount("0.000000001").unwrap(), 1);
        assert_eq!(parse_amount("2").unwrap(), 2_000_000_000);
        assert_eq!(parse_amount("max").unwrap(), u64::MAX);
        for bad in [
            "1.0000000001",
            "",
            ".",
            "-1",
            "1e3",
            "1.5.2",
            "99999999999999999999",
        ] {
            assert!(parse_amount(bad).is_err(), "{bad}");
        }
        // What the "sign it again" hint prints must parse back to the recorded amount.
        assert_eq!(
            parse_amount(&amount_arg("1500000000")).unwrap(),
            1_500_000_000
        );
        assert_eq!(amount_arg("max"), "max");
    }

    #[test]
    fn rent_rule() {
        let amt = |a, b| plan_amount(a, b, RENT_ZERO_DATA).map(|x| x.0).ok();
        // Remainder under rent: the exact balance is signed, never `max`.
        assert_eq!(amt(900_000, Some(1_000_000)), Some(1_000_000));
        assert_eq!(amt(u64::MAX, Some(1_000_000)), Some(1_000_000));
        assert_eq!(amt(1_000_000, Some(1_000_000)), Some(1_000_000));
        assert_eq!(amt(100_000, Some(1_000_000)), Some(100_000));
        assert_eq!(amt(2_000_000, Some(1_000_000)), None);
        let pay = |b| payer_ok(b, 5000, RENT_ZERO_DATA);
        assert!(pay(RENT_ZERO_DATA + 5000) && pay(5000) && pay(6000));
        assert!(!pay(4999) && !pay(RENT_ZERO_DATA + 4999) && !pay(0));
        // A node cannot talk `send` into sweeping a vault by reporting a huge rent.
        assert!(plausible_rent(RENT_ZERO_DATA).is_ok() && plausible_rent(1).is_ok());
        assert!(plausible_rent(0).is_err() && plausible_rent(99_500_000_000).is_err());
        // An empty vault, or a zero amount, would spend the key for nothing.
        assert_eq!(amt(u64::MAX, Some(0)), None);
        assert_eq!(amt(0, Some(1_000_000)), None);
        assert_eq!(amt(0, None), None);
        // Offline the amount is signed as typed, with a note.
        assert_eq!(amt(u64::MAX, None), Some(u64::MAX));
        assert_eq!(amt(5, None), Some(5));
        assert!(plan_amount(5, None, RENT_ZERO_DATA).unwrap().1.is_some());
        assert!(plan_amount(900_000, Some(1_000_000), RENT_ZERO_DATA)
            .unwrap()
            .1
            .is_some());
    }

    #[test]
    fn sign_again_is_identical_or_refused() {
        let d = std::env::temp_dir().join(format!("qusb-cli-sign-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        let fast = keystore::KdfParams {
            m_kib: 8,
            t: 1,
            p: 1,
        };
        keystore::create_with(&d, &secrets(), "pw", &fast).unwrap();
        let unsigned = fs::read(d.join("vault.qv")).unwrap();
        let mut s = keystore::unlock(&d, "pw").unwrap();
        let (to, seed) = ([7u8; 32], mnemonic::seed64(ART));

        // Vault 0 to its own address is refused with the key untouched.
        assert!(prepare(&s, 0, &derive::vault(&seed, 0), 5, None, 1).is_err());
        let (plan, _) = prepare(&s, 0, &to, 5, None, 1).unwrap();
        let (q, file) = sign_core(&d, &mut s, "pw", plan).unwrap();
        assert!(withdraw::check(&q).is_ok());
        assert_eq!(q.refund, b58::enc(&derive::vault(&seed, 1)));
        let first = fs::read(&file).unwrap();
        assert_eq!(public::read(&d).unwrap().vaults[0].state, "used");

        // From disk, as a later run sees it: the spend is on record, the same request gives the
        // same bytes, and any other request is refused.
        let mut s = keystore::unlock(&d, "pw").unwrap();
        assert_eq!((s.used.clone(), s.next_vault), (vec![0], 2));
        fs::remove_file(&file).unwrap();
        let (plan, note) = prepare(&s, 0, &to, 5, Some(0), 1).unwrap();
        assert!(plan.refund_index.is_none() && note.is_some());
        let (_, again) = sign_core(&d, &mut s, "pw", plan).unwrap();
        assert_eq!(
            (again, fs::read(&file).unwrap()),
            (file.clone(), first.clone())
        );
        let other = prepare(&s, 0, &[9; 32], 5, None, 1)
            .unwrap_err()
            .to_string();
        assert!(
            other.contains("qusb sign --vault 0 --to") && other.contains("--amount 0.000000005")
        );
        assert!(prepare(&s, 0, &to, 6, None, 1).is_err());
        assert_eq!(keystore::unlock(&d, "pw").unwrap().used, vec![0]);

        // An older vault.qv copied back knows nothing of that signature. The .qsig on the stick
        // does: anything else is refused and the file is left alone, the same request is the same bytes.
        fs::write(d.join("vault.qv"), unsigned).unwrap();
        let mut s = keystore::unlock(&d, "pw").unwrap();
        let (plan, _) = prepare(&s, 0, &[9; 32], 5, None, 1).unwrap();
        let e = sign_core(&d, &mut s, "pw", plan).unwrap_err().to_string();
        assert!(e.contains("qusb broadcast"), "{e}");
        assert_eq!((fs::read(&file).unwrap(), s.used.len()), (first.clone(), 0));
        let (plan, _) = prepare(&s, 0, &to, 5, None, 1).unwrap();
        sign_core(&d, &mut s, "pw", plan).unwrap();
        assert_eq!((fs::read(&file).unwrap(), s.used.clone()), (first, vec![0]));
    }

    /// A JSON-RPC server for one test: every request is answered with `f(method, params)`.
    fn fake_rpc(f: impl Fn(&str, &Value) -> Value + Send + 'static) -> Rpc {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        std::thread::spawn(move || {
            for c in l.incoming() {
                let mut c = c.unwrap();
                let mut r = std::io::BufReader::new(c.try_clone().unwrap());
                let (mut len, mut line) = (0, String::new());
                while r.read_line(&mut line).unwrap() > 2 {
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap();
                    }
                    line.clear();
                }
                let mut body = vec![0; len];
                r.read_exact(&mut body).unwrap();
                let req: Value = serde_json::from_slice(&body).unwrap();
                let result = f(req["method"].as_str().unwrap(), &req["params"]);
                let out = json!({"jsonrpc": "2.0", "id": 1, "result": result}).to_string();
                write!(c, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{out}", out.len()).unwrap();
            }
        });
        Rpc::new(url)
    }

    /// getTransaction reply for a withdraw built from `q`.
    fn chain_tx(q: &withdraw::QSig, err: Value) -> Value {
        json!({
            "meta": {"err": err, "innerInstructions": [], "loadedAddresses": {"writable": [], "readonly": []}},
            "transaction": {"message": {
                "accountKeys": [b58::enc(&[5; 32]), q.vault, q.recipient, q.refund, b58::enc(&tx::SYSTEM), b58::enc(&tx::compute_budget()), q.program],
                "instructions": [
                    {"programIdIndex": 5, "accounts": [], "data": "3DdGGhkhJbjm"},
                    {"programIdIndex": 6, "accounts": [0, 1, 2, 3, 4], "data": b58::enc(&withdraw::ix_data(q).unwrap())},
                ],
            }},
        })
    }

    #[test]
    fn rescan_restores_what_the_chain_knows() {
        let seed = mnemonic::seed64(ART);
        let v = |k| derive::vault(&seed, k);
        let a = |k| b58::enc(&v(k));
        // On chain: vault 0 was spent with change to vault 1; vault 2 signed a withdrawal that
        // failed; vault 3 was named by a failed transaction with a made-up signature; vault 5 holds
        // a deposit. Everything else has no history.
        let spend0 = withdraw::sign(&seed, 0, &[7; 32], &v(1), 1_500_000_000);
        let spend2 = withdraw::sign(&seed, 2, &[7; 32], &v(4), u64::MAX);
        let mut junk = withdraw::sign(&seed, 3, &[7; 32], &v(4), 5);
        junk.amount = "6".into();
        let txs = json!({
            "s0": chain_tx(&spend0, Value::Null),
            "s2": chain_tx(&spend2, json!({"InstructionError": [2, "Custom"]})),
            "s3": chain_tx(&junk, json!({"InstructionError": [2, "InvalidSeeds"]})),
            "dep": {"meta": {"err": null}, "transaction": {"message": {"accountKeys": [b58::enc(&[5; 32]), a(5), b58::enc(&tx::SYSTEM)], "instructions": [{"programIdIndex": 2, "accounts": [0, 1], "data": "3Bxs4h24hBtQy9rw"}]}}},
        });
        let history =
            json!({ a(0): ["s0"], a(1): ["s0"], a(2): ["s2"], a(3): ["s3"], a(5): ["dep"] });
        let chain = move || {
            let (txs, history) = (txs.clone(), history.clone());
            fake_rpc(move |method, p| match method {
                "getFirstAvailableBlock" => json!(0),
                "getSignaturesForAddress" if !p[1]["before"].is_null() => json!([]),
                "getSignaturesForAddress" => history[p[0].as_str().unwrap()]
                    .as_array()
                    .map(|l| l.iter().map(|s| json!({"signature": s})).collect())
                    .unwrap_or(json!([])),
                "getTransaction" => txs[p[0].as_str().unwrap()].clone(),
                m => panic!("unexpected {m}"),
            })
        };

        // Online restore: the keystore starts empty, as `init --restore` builds it.
        let mut s = secrets();
        rescan(&chain(), &mut s).unwrap();
        assert_eq!(s.used, vec![0, 2]);
        assert_eq!(s.next_vault, 6);
        assert_eq!(keystore::next_fresh(&s), 6);
        assert_eq!(s.spends.len(), 2);
        assert_eq!(
            (s.spends[0].vault, s.spends[0].amount.as_str()),
            (0, "1500000000")
        );
        // Vault 0 can only repeat what the chain shows it signed.
        let again = withdraw::plan(&s, 0, &[7; 32], 1_500_000_000).unwrap();
        assert_eq!((again.refund_index, again.spend.refund), (None, a(1)));
        assert!(withdraw::plan(&s, 0, &[9; 32], 5).is_err());
        assert!(withdraw::plan(&s, 2, &[9; 32], 5).is_err());
        // Funded and never-spent vaults are listed and spendable; change and deposits did not mark them.
        for k in [1, 3, 5] {
            assert_eq!(
                withdraw::plan(&s, k, &[9; 32], 5).unwrap().refund_index,
                Some(6)
            );
        }
        let info = public::build(&s);
        assert_eq!(info.vaults.len(), 7);
        assert_eq!(info.vaults[5].state, "fresh");

        // Offline restore with --next-vault 4, then a rescan: the guesses the chain does not back
        // are unlocked, the real spends stay.
        let mut s = secrets();
        (s.used, s.assumed_used_below, s.next_vault) = (vec![0, 1, 2, 3], 4, 4);
        assert!(withdraw::plan(&s, 1, &[9; 32], 5).is_err());
        assert_eq!(rescan(&chain(), &mut s).unwrap().1, vec![1, 3]);
        assert_eq!(
            (s.used.clone(), s.assumed_used_below, s.next_vault),
            (vec![0, 2], 0, 6)
        );

        // A vault this keystore marked used itself stays used even though the chain is silent.
        let mut s = secrets();
        (s.used, s.next_vault) = (vec![1], 2);
        rescan(&chain(), &mut s).unwrap();
        assert_eq!(s.used, vec![0, 1, 2]);

        // No chain, no change: a restore cannot quietly start from zero.
        let mut s = secrets();
        (s.used, s.assumed_used_below, s.next_vault) = (vec![0], 1, 1);
        assert!(rescan(&Rpc::new("http://127.0.0.1:1".into()), &mut s).is_err());
        assert_eq!(
            (s.used, s.assumed_used_below, s.next_vault),
            (vec![0], 1, 1)
        );
    }

    #[test]
    fn rescan_refuses_a_node_without_full_history() {
        // Such a node answers "no history" for every vault, spent or not. `first` is what it
        // reports as its oldest slot; null is a node that will not say.
        let node = |first: Value| {
            fake_rpc(move |method, _| match method {
                "getFirstAvailableBlock" => first.clone(),
                "getSignaturesForAddress" => json!([]),
                m => panic!("unexpected {m}"),
            })
        };
        for first in [json!(QVAULT_FIRST_SLOT + 1), Value::Null] {
            // Online restore: the keystore starts empty, and must not be handed out as "nothing spent".
            let mut s = secrets();
            assert!(rescan(&node(first.clone()), &mut s).is_err());
            // Offline restore with --next-vault 3, then rescan: the locks stay.
            (s.used, s.assumed_used_below, s.next_vault) = (vec![0, 1, 2], 3, 3);
            assert!(rescan(&node(first), &mut s).is_err());
            assert_eq!(
                (s.used, s.assumed_used_below, s.next_vault),
                (vec![0, 1, 2], 3, 3)
            );
        }
        let e = rescan(&node(json!(QVAULT_FIRST_SLOT + 1)), &mut secrets()).unwrap_err();
        assert!(e.to_string().contains("does not keep full history"));
        // The same answers from a node that reaches back far enough are believed.
        let (_, unlocked) = rescan(&node(json!(QVAULT_FIRST_SLOT)), &mut secrets()).unwrap();
        assert!(unlocked.is_empty());
    }

    #[test]
    fn rescan_reaches_every_index_that_can_sign() {
        let seed = mnemonic::seed64(ART);
        // The furthest vault a fresh stick signs from is the last one a restore looks at.
        let edge = keystore::SCAN_GAP - 1;
        assert!(withdraw::plan(&secrets(), edge + 1, &[7; 32], 5).is_err());
        let plan = withdraw::plan(&secrets(), edge, &[7; 32], 5).unwrap();
        let refund = addr(&plan.spend.refund).unwrap();
        let spend = withdraw::sign(&seed, edge, &[7; 32], &refund, 5);
        let (vault, txs) = (
            spend.vault.clone(),
            json!({"s": chain_tx(&spend, Value::Null)}),
        );
        // A node that returns two signatures a page: two deposits, then the older spend.
        let rpc = fake_rpc(move |method, p| {
            match method {
            "getFirstAvailableBlock" => json!(0),
            "getSignaturesForAddress" if p[0] == vault.as_str() => {
                let all = ["dep1", "dep2", "s"];
                let from = p[1]["before"]
                    .as_str()
                    .map_or(0, |b| all.iter().position(|x| *x == b).unwrap() + 1);
                all[from..].iter().take(2).map(|s| json!({"signature": s})).collect()
            }
            "getSignaturesForAddress" => json!([]),
            "getTransaction" => txs.get(p[0].as_str().unwrap()).cloned().unwrap_or(
                json!({"meta": {"err": null}, "transaction": {"message": {"accountKeys": [], "instructions": []}}}),
            ),
            m => panic!("unexpected {m}"),
        }
        });
        let mut s = secrets();
        rescan(&rpc, &mut s).unwrap();
        assert_eq!((s.used, s.next_vault), (vec![edge], edge + 1));
    }
}
