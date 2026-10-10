//! Loads the SBF build (`cargo-build-sbf` first) into litesvm.
use litesvm::LiteSVM;
use qusb_wots::{sig_to_bytes, Keypair as Wots};
use solana_address::Address;
use solana_compute_budget_interface::ComputeBudgetInstruction as Budget;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_system_interface::program::ID as SYSTEM;
use solana_transaction::Transaction;

const SOL: u64 = 1_000_000_000;
const PROGRAM: Address = Address::new_from_array(qvault::ID.to_bytes());

fn vault_of(w: &Wots) -> Address {
    Address::find_program_address(&[b"qvault", &w.pk_hash()], &PROGRAM).0
}

fn msg(vault: &Address, to: &Address, refund: &Address, amount: u64) -> Vec<u8> {
    [
        &b"qUSB/qvault/withdraw/v1"[..],
        vault.as_ref(),
        to.as_ref(),
        refund.as_ref(),
        &amount.to_le_bytes(),
    ]
    .concat()
}

struct Env {
    svm: LiteSVM,
    payer: Keypair,
}

fn env() -> Env {
    let mut svm = LiteSVM::new();
    let so = concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/deploy/qvault.so");
    svm.add_program_from_file(PROGRAM, so)
        .expect("build the .so first: cargo-build-sbf");
    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 10 * SOL).unwrap();
    Env { svm, payer }
}

fn fund(e: &mut Env, vault: &Address, lamports: u64) {
    e.svm.airdrop(vault, lamports).unwrap();
}

fn tx(
    e: &Env,
    sig: &[u8],
    vault: &Address,
    to: &Address,
    refund: &Address,
    amount: u64,
) -> Transaction {
    let mut data = vec![0u8];
    data.extend_from_slice(sig);
    data.extend_from_slice(&amount.to_le_bytes());
    let ix = Instruction::new_with_bytes(
        PROGRAM,
        &data,
        vec![
            AccountMeta::new(e.payer.pubkey(), true),
            AccountMeta::new(*vault, false),
            AccountMeta::new(*to, false),
            AccountMeta::new(*refund, false),
            AccountMeta::new_readonly(SYSTEM, false),
        ],
    );
    let m = Message::new(
        &[
            Budget::set_compute_unit_limit(1_400_000),
            Budget::set_compute_unit_price(1),
            ix,
        ],
        Some(&e.payer.pubkey()),
    );
    Transaction::new(&[&e.payer], m, e.svm.latest_blockhash())
}

/// Signs honestly for (vault, to, refund, amount).
fn signed(e: &Env, w: &Wots, to: &Address, refund: &Address, amount: u64) -> Transaction {
    let v = vault_of(w);
    let sig = sig_to_bytes(&w.sign(&msg(&v, to, refund, amount)));
    tx(e, &sig, &v, to, refund, amount)
}

fn err(e: &mut Env, t: Transaction) -> String {
    format!("{:?}", e.svm.send_transaction(t).unwrap_err().err)
}

fn addrs() -> (Address, Address) {
    (Keypair::new().pubkey(), Keypair::new().pubkey())
}

#[test]
fn partial_withdraw_with_refund() {
    let mut e = env();
    let w = Wots::from_seed(&[1; 32]);
    let next = vault_of(&Wots::from_seed(&[2; 32]));
    let (to, _) = addrs();
    let v = vault_of(&w);
    fund(&mut e, &v, 5 * SOL);
    let t = signed(&e, &w, &to, &next, SOL);
    let size = bincode::serialize(&t).unwrap().len();
    let meta = e.svm.send_transaction(t).expect("withdraw");
    println!("TX_SIZE={size} CU={}", meta.compute_units_consumed);
    assert!(size <= 1232, "tx size {size}");
    assert_eq!(e.svm.get_balance(&to), Some(SOL));
    assert_eq!(e.svm.get_balance(&next), Some(4 * SOL));
    assert!(e.svm.get_account(&v).is_none());
}

#[test]
fn sweep_max() {
    let mut e = env();
    let w = Wots::from_seed(&[3; 32]);
    let (to, refund) = addrs();
    let v = vault_of(&w);
    fund(&mut e, &v, 3 * SOL);
    e.svm
        .send_transaction(signed(&e, &w, &to, &refund, u64::MAX))
        .expect("sweep");
    assert_eq!(e.svm.get_balance(&to), Some(3 * SOL));
    assert!(e.svm.get_balance(&refund).is_none());
    assert!(e.svm.get_account(&v).is_none());
}

#[test]
fn wrong_message_or_tampered_sig_fails() {
    let mut e = env();
    let w = Wots::from_seed(&[4; 32]);
    let (to, refund) = addrs();
    let v = vault_of(&w);
    fund(&mut e, &v, 3 * SOL);
    // signed for 1 SOL, submitted for 2 SOL
    let sig = sig_to_bytes(&w.sign(&msg(&v, &to, &refund, SOL)));
    let t = tx(&e, &sig, &v, &to, &refund, 2 * SOL);
    assert!(err(&mut e, t).contains("InvalidSeeds"));
    // signed for another recipient
    let (other, _) = addrs();
    let t = tx(&e, &sig, &v, &other, &refund, SOL);
    assert!(err(&mut e, t).contains("InvalidSeeds"));
    // tampered signature
    let mut bad = sig;
    bad[100] ^= 1;
    let t = tx(&e, &bad, &v, &to, &refund, SOL);
    assert!(err(&mut e, t).contains("InvalidSeeds"));
    assert_eq!(e.svm.get_balance(&v), Some(3 * SOL));
}

#[test]
fn wrong_vault_fails() {
    let mut e = env();
    let w = Wots::from_seed(&[5; 32]);
    let other = vault_of(&Wots::from_seed(&[6; 32]));
    let (to, refund) = addrs();
    fund(&mut e, &other, 3 * SOL);
    // valid signature of key 5 over a message naming key 6's vault
    let sig = sig_to_bytes(&w.sign(&msg(&other, &to, &refund, SOL)));
    let t = tx(&e, &sig, &other, &to, &refund, SOL);
    assert!(err(&mut e, t).contains("InvalidSeeds"));
    assert_eq!(e.svm.get_balance(&other), Some(3 * SOL));
}

#[test]
fn recipient_equals_vault_fails() {
    let mut e = env();
    let w = Wots::from_seed(&[7; 32]);
    let v = vault_of(&w);
    let (refund, _) = addrs();
    fund(&mut e, &v, 3 * SOL);
    let t = signed(&e, &w, &v, &refund, SOL);
    assert!(err(&mut e, t).contains("InvalidArgument"));
    assert_eq!(e.svm.get_balance(&v), Some(3 * SOL));
}
