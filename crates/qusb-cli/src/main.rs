mod rpc;
mod tx;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use qusb_core::{b58, derive, keystore, mnemonic, public, seal, stick, withdraw};
use rpc::Rpc;
use std::{
    fs,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

type R<T> = Result<T, Box<dyn std::error::Error>>;

const DEFAULT_RPC: &str = "https://api.mainnet-beta.solana.com";
const RENT_ZERO_DATA: u64 = 890_880;
const LANE: &str = "classic lane: quantum-exposed";

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
        #[arg(long)]
        restore: bool,
        #[arg(long, default_value = "qusb stick")]
        label: String,
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
    /// Wrap a .qsig in a transaction, simulate, then send
    Broadcast {
        file: PathBuf,
        /// solana-keygen keypair JSON for the fee payer (default: the stick's classic key)
        #[arg(long)]
        payer: Option<PathBuf>,
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
        /// solana-keygen keypair JSON for the fee payer (default: the stick's classic key)
        #[arg(long)]
        payer: Option<PathBuf>,
        #[command(flatten)]
        net: Net,
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
    // Test hook, debug builds only: never compiled into release binaries.
    #[cfg(debug_assertions)]
    if let Ok(p) = std::env::var("QUSB_TEST_PASS") {
        let _ = msg;
        return Ok(Zeroizing::new(p));
    }
    Ok(Zeroizing::new(rpassword::prompt_password(msg)?))
}

fn qusb_dir_of(p: &Path) -> PathBuf {
    if p.file_name().is_some_and(|n| n == "qusb") {
        p.to_path_buf()
    } else {
        p.join("qusb")
    }
}

fn stick_dir(opt: &Option<PathBuf>) -> R<PathBuf> {
    if let Some(p) = opt {
        let d = qusb_dir_of(p);
        return if d.join("vault.qv").is_file() {
            Ok(d)
        } else {
            Err(format!("no qusb/vault.qv under {}", p.display()).into())
        };
    }
    let exe = std::env::current_exe()
        .ok()
        .and_then(|e| stick::find(e.parent()?));
    exe.or_else(|| stick::find(&std::env::current_dir().ok()?))
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

/// Rent rule (SPEC §3): leaving 0 < rest < rent-exempt minimum would fail, so sweep instead.
fn plan_amount(amount: u64, balance: Option<u64>, rent: u64) -> R<u64> {
    match balance {
        None if amount != u64::MAX => {
            eprintln!("warning: balance unknown offline; if the vault would be left under {} SOL the broadcast will fail. Use --amount max to sweep.", sol(rent));
            Ok(amount)
        }
        Some(b) if amount != u64::MAX => {
            if amount > b {
                return Err(
                    format!("vault holds {} SOL, less than {}", sol(b), sol(amount)).into(),
                );
            }
            if b - amount < rent {
                eprintln!("note: remainder would be under the rent minimum, so this sweeps the whole vault ({} SOL).", sol(b));
                return Ok(u64::MAX);
            }
            Ok(amount)
        }
        _ => Ok(amount),
    }
}

fn read_keypair(p: &Path) -> R<SigningKey> {
    let v: Vec<u8> = serde_json::from_slice(&fs::read(p)?)?;
    let b: [u8; 64] = v
        .try_into()
        .map_err(|_| "keypair file must hold 64 bytes")?;
    let k = SigningKey::from_bytes(b[..32].try_into().unwrap());
    if k.verifying_key().as_bytes() != &b[32..] {
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
    let pass = prompt("Passphrase: ")?;
    Ok((keystore::unlock(dir, &pass)?, pass))
}

/// mark_used, save, then sign, then write the .qsig (order matters: SPEC §3 one-time keys).
fn sign_core(
    dir: &Path,
    s: &mut keystore::Secrets,
    pass: &str,
    k: u32,
    to: &[u8; 32],
    amount: u64,
) -> R<(withdraw::QSig, PathBuf)> {
    keystore::mark_used(s, k)?;
    let refund_idx = s.next_vault.max(k + 1);
    s.next_vault = refund_idx + 1;
    keystore::save(dir, s, pass)?;
    public::write(dir, &public::build(s))?;
    let seed = seed_of(s);
    let refund = derive::vault_address(
        &derive::vault_pk_hash(&seed, refund_idx),
        &derive::program_id(),
    );
    let q = withdraw::sign(&seed, k, to, &refund, amount);
    let json = serde_json::to_string_pretty(&q)?;
    let sigs = dir.join("sigs");
    let name = sigs.join(format!(
        "vault{k}-{}.qsig",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs()
    ));
    if let Err(e) = fs::create_dir_all(&sigs).and_then(|_| fs::write(&name, &json)) {
        // The key is already spent; never lose the signature.
        eprintln!("could not write {}: {e}\n{json}", name.display());
        return Err("signature printed above; save it now".into());
    }
    Ok((q, name))
}

fn submit(rpc: &Rpc, payer: &SigningKey, ixs: &[tx::Ix]) -> R<()> {
    let pk = payer.verifying_key().to_bytes();
    let msg = tx::message(pk, rpc.blockhash()?, ixs);
    let raw = tx::sign(payer, &msg)?;
    let b64 = B64.encode(&raw);
    rpc.simulate(&b64)?;
    println!("simulation ok, sending");
    let sig = rpc.send(&b64)?;
    println!("signature {sig}");
    println!(
        "{}",
        if rpc.confirm(&sig)? {
            "confirmed"
        } else {
            "not confirmed yet; check the signature on an explorer"
        }
    );
    Ok(())
}

fn broadcast_qsig(rpc: &Rpc, payer: &SigningKey, q: &withdraw::QSig, fee: u64) -> R<()> {
    let ixs = tx::withdraw_ixs(
        payer.verifying_key().to_bytes(),
        addr(&q.vault)?,
        addr(&q.recipient)?,
        addr(&q.refund)?,
        addr(&q.program)?,
        withdraw::ix_data(q)?,
        fee,
    );
    submit(rpc, payer, &ixs)
}

fn online_amount(rpc: &Rpc, dir: &Path, k: u32, amount: &str) -> R<u64> {
    let amt = parse_amount(amount)?;
    let info = public::read(dir)?;
    let v = info
        .vaults
        .iter()
        .find(|v| v.index == k)
        .ok_or("unknown vault index")?;
    let rent = rpc.min_rent_zero_data().unwrap_or(RENT_ZERO_DATA);
    plan_amount(amt, Some(rpc.balance(&v.address)?), rent)
}

// ---------- commands ----------

fn run(cli: Cli) -> R<()> {
    match cli.cmd {
        Cmd::Init {
            path,
            restore,
            label,
        } => init(path.or(cli.stick), restore, label),
        Cmd::Status { rpc } => {
            let info = public::read(&stick_dir(&cli.stick)?)?;
            let rpc = Rpc::new(rpc);
            let mut online = true;
            let mut bal = |a: &str| match online.then(|| rpc.balance(a)) {
                Some(Ok(b)) => format!("{} SOL", sol(b)),
                Some(Err(_)) => {
                    online = false;
                    "balance unavailable (offline?)".into()
                }
                None => "balance unavailable (offline?)".into(),
            };
            println!("{}", info.label);
            println!("classic  {}  {}", info.classic, bal(&info.classic));
            for v in &info.vaults {
                println!(
                    "vault {} {}  {}  {}",
                    v.index,
                    v.state,
                    v.address,
                    if v.state == "used" {
                        String::new()
                    } else {
                        bal(&v.address)
                    }
                );
            }
            Ok(())
        }
        Cmd::Receive => {
            let info = public::read(&stick_dir(&cli.stick)?)?;
            let v = info
                .vaults
                .iter()
                .rev()
                .find(|v| v.state == "fresh")
                .ok_or("no fresh vault")?;
            println!("Vault {}: {}", v.index, v.address);
            let qr = qrcode::QrCode::new(v.address.as_bytes())?
                .render::<qrcode::render::unicode::Dense1x2>()
                .quiet_zone(true)
                .build();
            println!("{qr}");
            Ok(())
        }
        Cmd::Sign { vault, to, amount } => {
            let dir = stick_dir(&cli.stick)?;
            let to = addr(&to)?;
            let amt = plan_amount(parse_amount(&amount)?, None, RENT_ZERO_DATA)?;
            let (mut s, pass) = unlock(&dir)?;
            let (q, p) = sign_core(&dir, &mut s, &pass, vault, &to, amt)?;
            println!(
                "Signed vault {vault}, amount {}. Wrote {}",
                q.amount,
                p.display()
            );
            println!(
                "Vault {vault} is now marked used. Broadcast the file from any online machine."
            );
            Ok(())
        }
        Cmd::Broadcast { file, payer, net } => {
            let q: withdraw::QSig = serde_json::from_slice(&fs::read(&file)?)?;
            let key = match payer {
                Some(p) => read_keypair(&p)?,
                None => derive::classic_keypair(&seed_of(&unlock(&stick_dir(&cli.stick)?)?.0)),
            };
            broadcast_qsig(&Rpc::new(net.rpc), &key, &q, net.priority_fee)
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
            let amt = online_amount(&rpc, &dir, vault, &amount)?;
            let (mut s, pass) = unlock(&dir)?;
            let (q, p) = sign_core(&dir, &mut s, &pass, vault, &to, amt)?;
            println!(
                "Signed vault {vault}, amount {}. Wrote {}",
                q.amount,
                p.display()
            );
            let key = match payer {
                Some(p) => read_keypair(&p)?,
                None => derive::classic_keypair(&seed_of(&s)),
            };
            drop(s);
            broadcast_qsig(&rpc, &key, &q, net.priority_fee)
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
                println!("SPL: soon");
                return Ok(());
            }
            println!("{LANE}");
            let lamports = parse_amount(&amount)?;
            if lamports == u64::MAX {
                return Err("classic send needs an exact SOL amount".into());
            }
            let to = addr(&to)?;
            let (s, _) = unlock(&stick_dir(&cli.stick)?)?;
            let key = derive::classic_keypair(&seed_of(&s));
            drop(s);
            submit(
                &Rpc::new(net.rpc),
                &key,
                &tx::transfer_ixs(key.verifying_key().to_bytes(), to, lamports),
            )
        }
        Cmd::Seal { to, out } => {
            let to = seal::decode_pub(&to)?;
            let (s, _) = unlock(&stick_dir(&cli.stick)?)?;
            fs::write(&out, B64.encode(seal::seal(&to, s.mnemonic.as_bytes())?))?;
            println!("Sealed backup written to {}", out.display());
            Ok(())
        }
        Cmd::Unseal { file } => {
            let blob = B64.decode(fs::read_to_string(file)?.trim())?;
            let (s, _) = unlock(&stick_dir(&cli.stick)?)?;
            let (_, sk) = seal::seal_keys(&seed_of(&s));
            let pt = seal::unseal(&sk, &blob)?;
            println!(
                "Sealed words (keep private):\n{}",
                String::from_utf8_lossy(&pt)
            );
            Ok(())
        }
        Cmd::Verify => verify(&stick_dir(&cli.stick)?),
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

fn init(path: Option<PathBuf>, restore: bool, label: String) -> R<()> {
    let dir = qusb_dir_of(&path.ok_or("give the stick path: qusb init <stick>")?);
    if dir.join("vault.qv").exists() {
        return Err("this stick already has a keystore".into());
    }
    let words = if restore {
        #[cfg(debug_assertions)]
        let w = std::env::var("QUSB_TEST_WORDS")
            .map(Zeroizing::new)
            .or_else(|_| prompt("24 words: "));
        #[cfg(not(debug_assertions))]
        let w = prompt("24 words: ");
        let w = Zeroizing::new(w?.split_whitespace().collect::<Vec<_>>().join(" "));
        mnemonic::validate(&w)?;
        println!("Restored. Vault history is not recovered: do not sign from a vault index that was spent before.");
        w
    } else {
        let w = mnemonic::generate();
        show_and_quiz(&w)?;
        w
    };
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
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let s = keystore::Secrets {
        mnemonic: words,
        created: now,
        label,
        next_vault: 0,
        used: vec![],
    };
    keystore::create(&dir, &s, &pass)?;
    let info = public::build(&s);
    public::write(&dir, &info)?;
    fs::create_dir_all(dir.join("sigs"))?;
    println!("Keystore created in {}", dir.display());
    println!("Vault 0: {}", info.vaults[0].address);
    Ok(())
}

fn show_and_quiz(w: &str) -> R<()> {
    #[cfg(debug_assertions)]
    if std::env::var("QUSB_TEST_PASS").is_ok() {
        return Ok(());
    }
    use rand_core::{OsRng, RngCore};
    use std::io::IsTerminal;
    let list: Vec<&str> = w.split(' ').collect();
    println!("Your 24 recovery words. Write them on paper. They are shown once.\n");
    for (i, x) in list.iter().enumerate() {
        println!("{:>2}. {x}", i + 1);
    }
    println!("\nPress Enter when written down.");
    std::io::stdin().read_line(&mut String::new())?;
    if std::io::stdin().is_terminal() {
        print!("\x1b[2J\x1b[H");
    }
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
            let mut l = String::new();
            std::io::stdin().read_line(&mut l)?;
            if l.trim() == list[p] {
                break;
            }
            eprintln!("That is not it. Check your paper.");
        }
    }
    Ok(())
}

fn verify(dir: &Path) -> R<()> {
    use sha2::{Digest, Sha256};
    let bin = dir.parent().ok_or("bad stick path")?.join("bin");
    let sums = fs::read_to_string(bin.join("SHA256SUMS"))?;
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
            Err(_) => println!("missing  {name}"),
        }
    }
    if bad > 0 {
        return Err(format!("{bad} file(s) do not match SHA256SUMS").into());
    }
    println!("{ok} file(s) verified");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
    }

    #[test]
    fn rent_rule() {
        assert_eq!(
            plan_amount(900_000, Some(1_000_000), RENT_ZERO_DATA).unwrap(),
            u64::MAX
        );
        assert_eq!(
            plan_amount(100_000, Some(1_000_000), RENT_ZERO_DATA).unwrap(),
            100_000
        );
        assert!(plan_amount(2_000_000, Some(1_000_000), RENT_ZERO_DATA).is_err());
    }
}
