//! Loads the SBF build (`cargo-build-sbf` first) into litesvm.
use litesvm::LiteSVM;
use qusb_wots::{digits, recover_pk_hash, sig_to_bytes, Hasher, Keypair as Wots, Sha2};
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

fn metas(payer: &Address, vault: &Address, to: &Address, refund: &Address) -> Vec<AccountMeta> {
    vec![
        AccountMeta::new(*payer, true),
        AccountMeta::new(*vault, false),
        AccountMeta::new(*to, false),
        AccountMeta::new(*refund, false),
        AccountMeta::new_readonly(SYSTEM, false),
    ]
}

fn ix_data(sig: &[u8], amount: u64) -> Vec<u8> {
    let mut data = vec![0u8];
    data.extend_from_slice(sig);
    data.extend_from_slice(&amount.to_le_bytes());
    data
}

/// Raw form: any fee payer, any instruction data, any account list.
fn tx_with(e: &Env, payer: &Keypair, data: &[u8], metas: Vec<AccountMeta>) -> Transaction {
    let m = Message::new(
        &[
            Budget::set_compute_unit_limit(1_400_000),
            Budget::set_compute_unit_price(1),
            Instruction::new_with_bytes(PROGRAM, data, metas),
        ],
        Some(&payer.pubkey()),
    );
    Transaction::new(&[payer], m, e.svm.latest_blockhash())
}

fn tx(
    e: &Env,
    sig: &[u8],
    vault: &Address,
    to: &Address,
    refund: &Address,
    amount: u64,
) -> Transaction {
    let m = metas(&e.payer.pubkey(), vault, to, refund);
    tx_with(e, &e.payer, &ix_data(sig, amount), m)
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

#[test]
fn refund_tampering_fails() {
    let mut e = env();
    let w = Wots::from_seed(&[8; 32]);
    let (to, refund) = addrs();
    let (thief, _) = addrs();
    let v = vault_of(&w);
    fund(&mut e, &v, 3 * SOL);
    let sig = sig_to_bytes(&w.sign(&msg(&v, &to, &refund, SOL)));
    let t = tx(&e, &sig, &v, &to, &thief, SOL);
    assert!(err(&mut e, t).contains("InvalidSeeds"));
    assert_eq!(e.svm.get_balance(&v), Some(3 * SOL));
}

#[test]
fn aliased_accounts_fail() {
    let mut e = env();
    let w = Wots::from_seed(&[9; 32]);
    let (to, _) = addrs();
    let v = vault_of(&w);
    fund(&mut e, &v, 3 * SOL);
    // vault == refund
    let t = signed(&e, &w, &to, &v, SOL);
    assert!(err(&mut e, t).contains("InvalidArgument"));
    // recipient == refund, partial and sweep
    for amount in [SOL, u64::MAX] {
        let t = signed(&e, &w, &to, &to, amount);
        assert!(err(&mut e, t).contains("InvalidArgument"));
    }
    assert_eq!(e.svm.get_balance(&v), Some(3 * SOL));
}

#[test]
fn insufficient_funds_fails() {
    let mut e = env();
    let w = Wots::from_seed(&[10; 32]);
    let (to, refund) = addrs();
    let v = vault_of(&w);
    fund(&mut e, &v, 3 * SOL);
    let t = signed(&e, &w, &to, &refund, 3 * SOL + 1);
    assert!(err(&mut e, t).contains("InsufficientFunds"));
    assert_eq!(e.svm.get_balance(&v), Some(3 * SOL));
}

#[test]
fn amount_equal_to_balance_empties_vault() {
    let mut e = env();
    let w = Wots::from_seed(&[11; 32]);
    let (to, refund) = addrs();
    let v = vault_of(&w);
    fund(&mut e, &v, 2 * SOL);
    e.svm
        .send_transaction(signed(&e, &w, &to, &refund, 2 * SOL))
        .expect("exact balance");
    assert_eq!(e.svm.get_balance(&to), Some(2 * SOL));
    assert!(e.svm.get_account(&refund).is_none());
    assert!(e.svm.get_account(&v).is_none());
}

/// SPEC §3 "Rent": the runtime rejects a transfer that leaves a new account under the rent minimum.
#[test]
fn rent_failures() {
    let mut e = env();
    let w = Wots::from_seed(&[12; 32]);
    let (to, refund) = addrs();
    let v = vault_of(&w);
    fund(&mut e, &v, 3 * SOL);
    // remainder to a fresh refund account is under rent
    let t = signed(&e, &w, &to, &refund, 3 * SOL - 1000);
    assert!(err(&mut e, t).contains("InsufficientFundsForRent"));
    // amount to a fresh recipient is under rent
    let t = signed(&e, &w, &to, &refund, 1000);
    assert!(err(&mut e, t).contains("InsufficientFundsForRent"));
    assert_eq!(e.svm.get_balance(&v), Some(3 * SOL));
}

#[test]
fn bad_length_and_bad_tag_fail() {
    let mut e = env();
    let w = Wots::from_seed(&[13; 32]);
    let (to, refund) = addrs();
    let v = vault_of(&w);
    fund(&mut e, &v, 3 * SOL);
    let good = ix_data(&sig_to_bytes(&w.sign(&msg(&v, &to, &refund, SOL))), SOL);
    let short = good[..good.len() - 1].to_vec();
    let long = [&good[..], &[0]].concat();
    let mut tag = good.clone();
    tag[0] = 1;
    for data in [short, long, tag, vec![]] {
        let m = metas(&e.payer.pubkey(), &v, &to, &refund);
        let t = tx_with(&e, &e.payer, &data, m);
        assert!(err(&mut e, t).contains("InvalidInstructionData"));
    }
    assert_eq!(e.svm.get_balance(&v), Some(3 * SOL));
}

#[test]
fn wrong_accounts_fail() {
    let mut e = env();
    let w = Wots::from_seed(&[14; 32]);
    let (to, refund) = addrs();
    let (extra, _) = addrs();
    let v = vault_of(&w);
    let p = e.payer.pubkey();
    fund(&mut e, &v, 3 * SOL);
    let data = ix_data(&sig_to_bytes(&w.sign(&msg(&v, &to, &refund, SOL))), SOL);

    // one account too many, one too few
    let mut six = metas(&p, &v, &to, &refund);
    six.push(AccountMeta::new_readonly(extra, false));
    let mut four = metas(&p, &v, &to, &refund);
    four.pop();
    for m in [six, four] {
        let t = tx_with(&e, &e.payer, &data, m);
        assert!(err(&mut e, t).contains("NotEnoughAccountKeys"));
    }
    // something else in the system program slot
    let mut m = metas(&p, &v, &to, &refund);
    m[4] = AccountMeta::new_readonly(extra, false);
    let t = tx_with(&e, &e.payer, &data, m);
    assert!(err(&mut e, t).contains("MissingAccount"));
    // vault passed read-only
    let mut m = metas(&p, &v, &to, &refund);
    m[1] = AccountMeta::new_readonly(v, false);
    let t = tx_with(&e, &e.payer, &data, m);
    assert!(err(&mut e, t).contains("PrivilegeEscalation"));
    assert_eq!(e.svm.get_balance(&v), Some(3 * SOL));
}

/// Known limit, not a feature: the program keeps no state, so a published signature
/// works again if the same vault is ever funded again. The money still goes only where
/// the owner signed, but it moves without the owner. THREAT-MODEL.md: use each vault once.
#[test]
fn replay_succeeds_if_a_spent_vault_is_funded_again() {
    let mut e = env();
    let stranger = Keypair::new();
    e.svm.airdrop(&stranger.pubkey(), SOL).unwrap();

    // partial: 1 SOL to the recipient, the rest to the next vault
    let w = Wots::from_seed(&[15; 32]);
    let next = vault_of(&Wots::from_seed(&[16; 32]));
    let (to, _) = addrs();
    let v = vault_of(&w);
    fund(&mut e, &v, 5 * SOL);
    let data = ix_data(&sig_to_bytes(&w.sign(&msg(&v, &to, &next, SOL))), SOL);
    let m = metas(&e.payer.pubkey(), &v, &to, &next);
    e.svm
        .send_transaction(tx_with(&e, &e.payer, &data, m))
        .expect("first");
    fund(&mut e, &v, 10 * SOL);
    e.svm.expire_blockhash();
    let m = metas(&stranger.pubkey(), &v, &to, &next);
    e.svm
        .send_transaction(tx_with(&e, &stranger, &data, m))
        .expect("replay by a stranger");
    assert_eq!(e.svm.get_balance(&to), Some(2 * SOL));
    assert_eq!(e.svm.get_balance(&next), Some(13 * SOL));
    assert!(e.svm.get_account(&v).is_none());

    // sweep: a replay sends everything to the original recipient
    let w = Wots::from_seed(&[17; 32]);
    let (to, refund) = addrs();
    let v = vault_of(&w);
    fund(&mut e, &v, 3 * SOL);
    let sig = sig_to_bytes(&w.sign(&msg(&v, &to, &refund, u64::MAX)));
    let data = ix_data(&sig, u64::MAX);
    let m = metas(&e.payer.pubkey(), &v, &to, &refund);
    e.svm
        .send_transaction(tx_with(&e, &e.payer, &data, m))
        .expect("sweep");
    fund(&mut e, &v, 7 * SOL);
    e.svm.expire_blockhash();
    let m = metas(&stranger.pubkey(), &v, &to, &refund);
    e.svm
        .send_transaction(tx_with(&e, &stranger, &data, m))
        .expect("sweep replay");
    assert_eq!(e.svm.get_balance(&to), Some(10 * SOL));
    assert!(e.svm.get_account(&refund).is_none());
}

/// A sweep of a vault that holds nothing succeeds and moves nothing. The signature is
/// then public, so that vault must not be funded afterwards (see the replay test).
#[test]
fn empty_vault_sweep_succeeds_and_moves_nothing() {
    let mut e = env();
    let w = Wots::from_seed(&[18; 32]);
    let (to, refund) = addrs();
    e.svm
        .send_transaction(signed(&e, &w, &to, &refund, u64::MAX))
        .expect("empty sweep");
    assert!(e.svm.get_account(&to).is_none());
    assert!(e.svm.get_account(&refund).is_none());
}

/// Cost is about 197 CU per hash step and the step count depends on the message digest,
/// so compute varies per withdrawal. Fixed inputs keep this run reproducible.
#[test]
fn compute_units_stay_under_the_ceiling() {
    let mut e = env();
    let (mut lo, mut hi, mut sum, mut worst_steps) = (u64::MAX, 0, 0, 0);
    for k in 0..40u8 {
        let w = Wots::from_seed(&[100 + k; 32]);
        let v = vault_of(&w);
        let to = Address::new_from_array([k + 1; 32]);
        let refund = Address::new_from_array([k + 101; 32]);
        fund(&mut e, &v, 5 * SOL);
        let amount = if k % 2 == 0 { u64::MAX } else { SOL };
        let steps: u32 = digits::<Sha2>(&msg(&v, &to, &refund, amount))
            .iter()
            .map(|&d| 255 - d as u32)
            .sum();
        let t = signed(&e, &w, &to, &refund, amount);
        assert!(bincode::serialize(&t).unwrap().len() <= 1232);
        let cu = e
            .svm
            .send_transaction(t)
            .expect("withdraw")
            .compute_units_consumed;
        (lo, hi, sum) = (lo.min(cu), hi.max(cu), sum + cu);
        worst_steps = worst_steps.max(steps);
    }
    println!(
        "CU min={lo} max={hi} mean={} worst_steps={worst_steps}",
        sum / 40
    );
    assert!(
        hi < 1_100_000,
        "compute {hi} is too close to the 1.4M limit"
    );
}

/// Signs through qusb-core (what the CLI ships) instead of the hand-built message above,
/// so signer and on-chain verifier are checked against each other.
#[test]
fn core_signer_matches_program() {
    use qusb_core::{b58, derive, withdraw};
    let program = derive::program_id();
    assert_eq!(program, PROGRAM.to_bytes());
    let mut e = env();
    let seed = [9u8; 64];
    for (index, amount) in [(0u32, u64::MAX), (1, SOL)] {
        let (to, _) = addrs();
        let refund = derive::vault_address(&derive::vault_pk_hash(&seed, index + 1), &program);
        let q = withdraw::sign(&seed, index, &to.to_bytes(), &refund, amount);
        let refund = Address::new_from_array(refund);
        let v = Address::new_from_array(b58::dec32(&q.vault).unwrap());
        // core's hand-rolled PDA and message agree with solana's and with this file's
        let pk_hash = derive::vault_pk_hash(&seed, index);
        assert_eq!(
            v,
            Address::find_program_address(&[b"qvault", &pk_hash], &PROGRAM).0
        );
        assert_eq!(
            withdraw::message(&v.to_bytes(), &to.to_bytes(), &refund.to_bytes(), amount),
            msg(&v, &to, &refund, amount)
        );
        fund(&mut e, &v, 3 * SOL);
        let m = metas(&e.payer.pubkey(), &v, &to, &refund);
        let t = tx_with(&e, &e.payer, &withdraw::ix_data(&q).unwrap(), m);
        e.svm.send_transaction(t).expect("core-signed withdraw");
        let sent = if amount == u64::MAX { 3 * SOL } else { amount };
        assert_eq!(e.svm.get_balance(&to), Some(sent));
        assert!(e.svm.get_account(&v).is_none());
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Pinned vector, computed independently from SPEC.md §2 (a few lines of Python with
/// hashlib): seed = bytes 0..31, message = domain ‖ 0x11*32 ‖ 0x22*32 ‖ 0x33*32 ‖ 1 SOL LE.
/// Any change to the WOTS or message format breaks this before it reaches a vault.
#[test]
fn known_answer_vector() {
    let seed: [u8; 32] = core::array::from_fn(|i| i as u8);
    let w = Wots::from_seed(&seed);
    let m = msg(
        &Address::new_from_array([0x11; 32]),
        &Address::new_from_array([0x22; 32]),
        &Address::new_from_array([0x33; 32]),
        SOL,
    );
    assert_eq!(m.len(), 127);
    assert_eq!(
        hex(&w.pk_hash()),
        "3953e4852bb38a00ce6fa8cef823306291c5bb53fe9934d689ad8a9a65a11893"
    );
    let sig = w.sign(&m);
    let bytes = sig_to_bytes(&sig);
    assert_eq!(bytes.len(), 840);
    assert_eq!(
        hex(&bytes[..28]),
        "fe254f99061c41cf7c81d63d785ffd22fdf9b3c4855b1006533aa5f0"
    );
    assert_eq!(
        hex(&qvault::SolHasher::hashv(&[&bytes[..]])),
        "6e2342ae3421ae56fe7b552c0897a6755758cae32ed7550f480c41beec9395dc"
    );
    // the program's own hasher recovers the same key
    assert_eq!(recover_pk_hash::<qvault::SolHasher>(&sig, &m), w.pk_hash());
}
