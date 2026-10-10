//! Hand-serialized legacy Solana transactions (no solana-sdk).
use ed25519_dalek::{Signer, SigningKey};
use qusb_core::b58;

pub const MAX_TX: usize = 1232;
pub const SYSTEM: [u8; 32] = [0; 32];
pub const CU_LIMIT: u32 = 1_400_000;
/// Lamports per signature; every transaction here has one.
pub const BASE_FEE: u64 = 5000;

/// The most a withdraw transaction can cost its fee payer. The priority fee is charged on the
/// compute unit limit, not on the units used.
pub fn max_fee(micro_price: u64) -> u64 {
    let prio = (CU_LIMIT as u128 * micro_price as u128).div_ceil(1_000_000);
    u64::try_from(prio)
        .unwrap_or(u64::MAX)
        .saturating_add(BASE_FEE)
}

pub fn compute_budget() -> [u8; 32] {
    b58::dec32("ComputeBudget111111111111111111111111111111").unwrap()
}

pub struct Meta {
    pub key: [u8; 32],
    pub signer: bool,
    pub writable: bool,
}
pub struct Ix {
    pub program: [u8; 32],
    pub accounts: Vec<Meta>,
    pub data: Vec<u8>,
}

fn m(key: [u8; 32], signer: bool, writable: bool) -> Meta {
    Meta {
        key,
        signer,
        writable,
    }
}

fn compact(out: &mut Vec<u8>, n: usize) {
    let mut n = n as u16;
    loop {
        let b = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(b);
            return;
        }
        out.push(b | 0x80);
    }
}

/// Compute-budget instructions (limit, then price) followed by the qvault Withdraw. The program is
/// always the built-in qvault id: a .qsig never chooses what the fee payer's signature runs.
pub fn withdraw_ixs(
    payer: [u8; 32],
    vault: [u8; 32],
    recipient: [u8; 32],
    refund: [u8; 32],
    data: Vec<u8>,
    micro_price: u64,
) -> Vec<Ix> {
    let mut v = vec![budget(2, &CU_LIMIT.to_le_bytes())];
    v.push(budget(3, &micro_price.to_le_bytes()));
    v.push(Ix {
        program: qusb_core::derive::program_id(),
        accounts: vec![
            m(payer, true, true),
            m(vault, false, true),
            m(recipient, false, true),
            m(refund, false, true),
            m(SYSTEM, false, false),
        ],
        data,
    });
    v
}
fn budget(tag: u8, arg: &[u8]) -> Ix {
    Ix {
        program: compute_budget(),
        accounts: vec![],
        data: [&[tag][..], arg].concat(),
    }
}

pub fn transfer_ixs(payer: [u8; 32], to: [u8; 32], lamports: u64) -> Vec<Ix> {
    let mut data = 2u32.to_le_bytes().to_vec();
    data.extend_from_slice(&lamports.to_le_bytes());
    vec![Ix {
        program: SYSTEM,
        accounts: vec![m(payer, true, true), m(to, false, true)],
        data,
    }]
}

/// Account order: payer first, then writable signers, readonly signers, writable others, readonly others.
/// Within a class, accounts appear in first-use order (instruction accounts, then program ids).
pub fn message(payer: [u8; 32], blockhash: [u8; 32], ixs: &[Ix]) -> Vec<u8> {
    let mut keys: Vec<Meta> = vec![m(payer, true, true)];
    let mut add = |k: [u8; 32], s: bool, w: bool| match keys.iter_mut().find(|x| x.key == k) {
        Some(x) => {
            x.signer |= s;
            x.writable |= w;
        }
        None => keys.push(m(k, s, w)),
    };
    for ix in ixs {
        for a in &ix.accounts {
            add(a.key, a.signer, a.writable);
        }
    }
    for ix in ixs {
        add(ix.program, false, false);
    }
    let class = |x: &Meta| match (x.signer, x.writable) {
        (true, true) => 0,
        (true, false) => 1,
        (false, true) => 2,
        _ => 3,
    };
    keys.sort_by_key(class); // stable
    let n = |c| keys.iter().filter(|x| class(x) == c).count() as u8;
    let mut out = vec![n(0) + n(1), n(1), n(3)];
    compact(&mut out, keys.len());
    for k in &keys {
        out.extend_from_slice(&k.key);
    }
    out.extend_from_slice(&blockhash);
    let idx = |k: &[u8; 32]| keys.iter().position(|x| &x.key == k).unwrap() as u8;
    compact(&mut out, ixs.len());
    for ix in ixs {
        out.push(idx(&ix.program));
        compact(&mut out, ix.accounts.len());
        out.extend(ix.accounts.iter().map(|a| idx(&a.key)));
        compact(&mut out, ix.data.len());
        out.extend_from_slice(&ix.data);
    }
    out
}

/// Signs the message with `payer` (the fee payer, sole signer) and serializes the transaction.
pub fn sign(payer: &SigningKey, msg: &[u8]) -> Result<Vec<u8>, String> {
    let mut tx = vec![1u8];
    tx.extend_from_slice(&payer.sign(msg).to_bytes());
    tx.extend_from_slice(msg);
    if tx.len() > MAX_TX {
        return Err(format!(
            "transaction is {} bytes, over the {MAX_TX} limit",
            tx.len()
        ));
    }
    Ok(tx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn withdraw_tx_layout() {
        let payer = SigningKey::from_bytes(&[7; 32]);
        let pk = payer.verifying_key().to_bytes();
        let (vault, rec, refund) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        let prog = qusb_core::derive::program_id();
        let ixs = withdraw_ixs(pk, vault, rec, refund, vec![0u8; 849], 1000);
        let msg = message(pk, [9; 32], &ixs);
        let tx = sign(&payer, &msg).unwrap();
        assert!(tx.len() <= MAX_TX, "{}", tx.len());
        assert_eq!(tx[0], 1);
        let msg = &tx[65..];
        assert_eq!(&msg[..3], &[1, 0, 3]);
        assert_eq!(msg[3], 7);
        let keys: Vec<&[u8]> = (0..7).map(|i| &msg[4 + 32 * i..36 + 32 * i]).collect();
        let want = [
            &pk,
            &vault,
            &rec,
            &refund,
            &SYSTEM,
            &compute_budget(),
            &prog,
        ];
        for (k, w) in keys.iter().zip(want) {
            assert_eq!(*k, &w[..]);
        }
        assert_eq!(&msg[4 + 224..4 + 256], &[9u8; 32]); // blockhash
        let rest = &msg[4 + 256..];
        assert_eq!(rest[0], 3); // three instructions
        assert_eq!(&rest[1..9], &[5, 0, 5, 2, 0xc0, 0x5c, 0x15, 0]); // limit ix: program 5, no accounts, [2, 1_400_000 LE]
    }

    #[test]
    fn fee_ceiling() {
        assert_eq!(max_fee(0), 5000);
        assert_eq!(max_fee(1), 5002); // 1.4 lamports, rounded up
        assert_eq!(max_fee(1_000_000), 1_405_000);
        assert_eq!(max_fee(u64::MAX), u64::MAX);
    }
}
