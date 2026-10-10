use qusb_core::{derive::*, keystore::*, *};
use zeroize::Zeroizing;

const ART: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
const FAST: KdfParams = KdfParams {
    m_kib: 8,
    t: 1,
    p: 1,
};

fn tmp(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("qusb-core-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}
fn secrets() -> Secrets {
    Secrets {
        mnemonic: Zeroizing::new(ART.into()),
        created: 1,
        label: "t".into(),
        next_vault: 1,
        used: vec![0],
        ..Default::default()
    }
}
fn spend(vault: u32, amount: &str) -> Spend {
    Spend {
        vault,
        recipient: b58::enc(&[7; 32]),
        refund: b58::enc(&[8; 32]),
        amount: amount.into(),
    }
}
fn sha(s: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(s))
}

#[test]
fn classic_address_matches_reference() {
    // Reference: `solana-keygen pubkey 'prompt:?key=0/0'` (solana-cli 4.0.2, m/44'/501'/0'/0') with the
    // 24-word "abandon x23 art" phrase. The same tool gives HAgk14Jp...Kpqk for the 12-word "about"
    // phrase, the well-known Phantom address, so path and curve handling are the Phantom ones.
    let seed = mnemonic::seed64(ART);
    let pk = derive::classic_keypair(&seed).verifying_key();
    assert_eq!(
        b58::enc(pk.as_bytes()),
        "3Cy3YNTFywCmxoxt8n7UH6hg6dLo5uACowX3CFceaSnx"
    );
    let seed12 = mnemonic::seed64("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
    let pk12 = derive::classic_keypair(&seed12).verifying_key();
    assert_eq!(
        b58::enc(pk12.as_bytes()),
        "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk"
    );
}

#[test]
fn vault_address_matches_solana_cli() {
    // `solana find-program-derived-address CnfS7s... string:qvault hex:<01 x32>`
    let a = vault_address(&[1u8; 32], &program_id());
    assert_eq!(b58::enc(&a), "21QPdQ1epB1ceqyDJhJDLQGJpB1JkT9mDhGrNDTcGByp");
}

#[test]
fn keystore_roundtrip_wrong_pass_and_used() {
    let d = tmp("ks");
    create_with(&d, &secrets(), "pw", &FAST).unwrap();
    assert!(matches!(
        create_with(&d, &secrets(), "pw", &FAST),
        Err(Error::Exists)
    ));
    let mut s = unlock(&d, "pw").unwrap();
    assert_eq!(&**s.mnemonic, ART);
    assert_eq!(s.used, vec![0]);
    assert!(matches!(unlock(&d, "nope"), Err(Error::Decrypt)));
    let before = std::fs::read(d.join("vault.qv")).unwrap();
    mark_used(&mut s, spend(1, "max")).unwrap();
    assert!(matches!(
        mark_used(&mut s, spend(1, "max")),
        Err(Error::AlreadyUsed(1))
    ));
    save(&d, &s, "pw").unwrap();
    assert_ne!(before, std::fs::read(d.join("vault.qv")).unwrap());
    let s = unlock(&d, "pw").unwrap();
    assert_eq!(s.used, vec![0, 1]);
    assert_eq!(s.spends, vec![spend(1, "max")]);
    assert!(!d.join("vault.qv.tmp").exists());

    // Interrupted write. A complete leftover is the newer state and wins, with or without vault.qv.
    let (main, left) = (d.join("vault.qv"), d.join("vault.qv.tmp"));
    std::fs::write(&left, &before).unwrap(); // `before` is a whole keystore with used == [0]
    assert_eq!(unlock(&d, "pw").unwrap().used, vec![0]);
    assert!(main.exists() && !left.exists());
    std::fs::rename(&main, &left).unwrap();
    assert_eq!(stick::find(&d), None);
    assert!(matches!(unlock(&d, "nope"), Err(Error::Decrypt)));
    assert!(left.exists());
    assert_eq!(unlock(&d, "pw").unwrap().used, vec![0]);
    assert!(main.exists() && !left.exists());
    // A partial leftover is dropped, but only once the passphrase has opened vault.qv.
    std::fs::write(&left, &before[..before.len() / 2]).unwrap();
    assert!(unlock(&d, "nope").is_err());
    assert!(left.exists());
    assert_eq!(unlock(&d, "pw").unwrap().used, vec![0]);
    assert!(!left.exists());
    let root = tmp("stick");
    std::fs::create_dir_all(root.join("bin")).unwrap();
    assert_eq!(stick::find(&root.join("bin")), None);
    create_with(&root.join("qusb"), &secrets(), "pw", &FAST).unwrap();
    assert_eq!(stick::find(&root.join("bin")), Some(root.join("qusb")));
}

#[test]
fn public_info_roundtrip() {
    let d = tmp("pub");
    let p = public::build(&secrets());
    assert_eq!(p.vaults.len(), 2);
    assert_eq!(p.vaults[0].state, "used");
    assert_eq!(p.vaults[1].state, "fresh");
    public::write(&d, &p).unwrap();
    assert_eq!(public::read(&d).unwrap(), p);
    assert!(seal::decode_pub(&p.seal_pub).is_ok());
}

#[test]
fn withdraw_sign_verifies() {
    let seed = mnemonic::seed64(ART);
    let (rcp, rf) = ([7u8; 32], [8u8; 32]);
    let q = withdraw::sign(&seed, 3, &rcp, &rf, 1_500_000_000);
    let vault = b58::dec32(&q.vault).unwrap();
    let msg = withdraw::message(&vault, &rcp, &rf, 1_500_000_000);
    assert_eq!(msg.len(), 127); // SPEC §3 (corrected from 119)
    let d = withdraw::ix_data(&q).unwrap();
    assert_eq!(d.len(), 849);
    let sig = qusb_wots::sig_from_bytes(&d[1..841]).unwrap();
    let pk = vault_pk_hash(&seed, 3);
    assert!(qusb_wots::verify(&pk, &sig, &msg));
    assert_eq!(vault, vault_address(&pk, &program_id()));
    assert_eq!(withdraw::sign(&seed, 3, &rcp, &rf, u64::MAX).amount, "max");
}

#[test]
fn seal_roundtrip_and_tamper() {
    let seed = mnemonic::seed64(&mnemonic::generate());
    let (p, s) = seal::seal_keys(&seed);
    let p2 = seal::decode_pub(&seal::encode_pub(&p)).unwrap();
    assert_eq!(p, p2);
    let blob = seal::seal(&p2, b"twenty four words").unwrap();
    assert_eq!(&**seal::unseal(&s, &blob).unwrap(), b"twenty four words");
    for i in [0, 40, 1100, 1130, blob.len() - 1] {
        let mut t = blob.clone();
        t[i] ^= 1;
        assert!(seal::unseal(&s, &t).is_err(), "tamper at {i}");
    }
}

// Fixed points for the "abandon x23 art" phrase. If any of these move, every existing stick derives
// different vaults, seal keys or signatures: that is a fund-losing change, not a refactor.
const VAULT0: &str = "FR9k9ooKADXGjyESAkpcVegBs6Y1YDU9E6mYYHNG7Y1y";
const VAULT1: &str = "pzmpmt9WYuVvHkMNHSB2qEHiH2C7kiUeAD5jEivnyn5";
const VAULT2: &str = "3xQyLvzdBrgZQmtKfDaQHLz2VuM4EgZECfbDxLXoARBZ";

#[test]
fn known_answers() {
    let seed = mnemonic::seed64(ART);
    assert_eq!(
        hex::encode(vault_pk_hash(&seed, 0)),
        "9a77585db6f641730c1b2325d37b5c294673795e5bf64d18dac37bd366cda8af"
    );
    for (k, want) in [VAULT0, VAULT1, VAULT2].iter().enumerate() {
        assert_eq!(b58::enc(&derive::vault(&seed, k as u32)), *want);
    }
    assert_eq!(
        sha(&seal::encode_pub(&seal::seal_keys(&seed).0)),
        "bef4cced81ce1c509b28ba1430af73791c55b54798ae113e95381905d37996ce"
    );
    assert_eq!(
        sha(&withdraw::sign(&seed, 0, &[7; 32], &[8; 32], 1_500_000_000).sig),
        "0e022a660ddc8d95e99859c74c44d54e3bc18a2bf52e3d932574831387c7d666"
    );
}

/// vault.qv written by the v0.1.0 binary: passphrase "pw", next_vault 2, used [0], no spend records.
const V010: &str = r#"{"qusb":1,"kdf":{"alg":"argon2id","m_kib":8,"t":1,"p":1,"salt":"6bdP0gU6vqWuXNRWv5l2eg=="},"aead":{"alg":"xchacha20poly1305","nonce":"0ePqSs32egNLs7Q6/OClrmqbh7rOwZEh"},"ct":"h6G2GUe/e+TtdQiuiB7hzRcfwkJj2gdt5z9L6ZqlE1c6J0jaXcFZo1yk7JIWg8k0Dv3POk48zgXEI0biFobz9cP6110vOy5CpVDqxMQuNmkmTYeaEG9AkDfdSwruvpGDsCPcxMbXAwZv9f758Zeinw8t292cCxZODP80LH/NF8gBO2DJ9vAWdRT0x/7XRKRv135/R9qQPBR7s832xaNcV4J1JsMZVokAklI4z8OmHzzoEJTkB8bHE4cxsgcUUB6nF/7xwqOX0dctmPcgbZjfOCBH+qgOnfWaSBlcV5svcyVu8H2tRbtNMza+AJAmllQT0HLq4lL8zgfwSBgaFHHCrsqMiUHJO+MR9m8qeEkD6atnwL1Q7SRs5g=="}"#;

#[test]
fn reads_v010_keystore_and_bounds_kdf() {
    let d = tmp("v010");
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("vault.qv"), V010).unwrap();
    let mut s = unlock(&d, "pw").unwrap();
    assert_eq!(&**s.mnemonic, ART);
    assert_eq!((s.next_vault, &s.used, s.spends.len()), (2, &vec![0], 0));
    // Vault 0 signed something this keystore never recorded: it must stay shut.
    assert!(matches!(
        withdraw::plan(&s, 0, &[7; 32], u64::MAX),
        Err(Error::AlreadyUsed(0))
    ));
    // Still usable and still readable after a save in the new format.
    let p = withdraw::plan(&s, 1, &[7; 32], u64::MAX).unwrap();
    mark_used(&mut s, p.spend.clone()).unwrap();
    save(&d, &s, "pw").unwrap();
    assert_eq!(unlock(&d, "pw").unwrap().spends, vec![p.spend]);

    // KDF parameters are read before anything authenticates the file.
    for (from, to) in [
        (r#""m_kib":8"#, r#""m_kib":4294967295"#),
        (r#""t":1"#, r#""t":4294967295"#),
        (r#""p":1"#, r#""p":4294967295"#),
    ] {
        std::fs::write(d.join("vault.qv"), V010.replace(from, to)).unwrap();
        let t = std::time::Instant::now();
        assert!(matches!(unlock(&d, "pw"), Err(Error::Format(_))), "{to}");
        assert!(t.elapsed().as_secs() < 2, "{to}");
    }
}

#[test]
fn refund_selection_and_refusals() {
    let seed = mnemonic::seed64(ART);
    let v = |k| derive::vault(&seed, k);
    let mut s = secrets(); // vault 0 used, next_vault 1
    s.next_vault = 2; // as after a spend from 0 with change in 1: `receive` now shows vault 2

    // Plain case: refund is the next unused vault.
    let p = withdraw::plan(&s, 1, &[7; 32], 5).unwrap();
    assert_eq!(p.refund_index, Some(2));
    assert_eq!(p.spend.refund, VAULT2);
    assert_eq!((p.spend.vault, p.spend.amount.as_str()), (1, "5"));

    // Sending to your own receive address: recipient == would-be refund, so the refund moves on.
    let p = withdraw::plan(&s, 1, &v(2), u64::MAX).unwrap();
    assert_eq!(p.refund_index, Some(3));
    assert_eq!(p.spend.recipient, VAULT2);
    assert_eq!(p.spend.refund, b58::enc(&v(3)));
    let q = withdraw::sign(&seed, 1, &v(2), &v(3), u64::MAX);
    assert!(withdraw::check(&q).is_ok());

    // A used index is never chosen as the refund.
    s.used.push(2);
    assert_eq!(
        withdraw::plan(&s, 1, &[7; 32], 5).unwrap().refund_index,
        Some(3)
    );

    // recipient == vault, and recipient == a vault that has already signed.
    for to in [v(1), v(0), v(2)] {
        assert!(matches!(
            withdraw::plan(&s, 1, &to, 5),
            Err(Error::Refused(_))
        ));
    }

    // Index bounds: no overflow, no walk to the end of u32.
    // The last index a restore's scan reaches is next_vault + SCAN_GAP - 1: one past it never signs.
    for k in [s.next_vault + SCAN_GAP, MAX_VAULT, u32::MAX] {
        assert!(
            matches!(withdraw::plan(&s, k, &[7; 32], 5), Err(Error::Refused(_))),
            "{k}"
        );
    }
    assert!(withdraw::plan(&s, s.next_vault + SCAN_GAP - 1, &[7; 32], 5).is_ok());
    s.next_vault = u32::MAX;
    assert!(matches!(
        withdraw::plan(&s, 1, &[7; 32], 5),
        Err(Error::Refused(_))
    ));
    assert_eq!(next_fresh(&secrets()), 1);
}

#[test]
fn resign_used_vault() {
    let seed = mnemonic::seed64(ART);
    let mut s = secrets();
    let first = withdraw::plan(&s, 1, &[7; 32], 5).unwrap();
    mark_used(&mut s, first.spend.clone()).unwrap();
    s.next_vault = 3;
    let refund = b58::dec32(&first.spend.refund).unwrap();
    let q1 = withdraw::sign(&seed, 1, &[7; 32], &refund, 5);

    // Same recipient and amount: the recorded spend comes back with its original refund, even though
    // next_vault has moved, and signing it again gives a byte-identical .qsig.
    let again = withdraw::plan(&s, 1, &[7; 32], 5).unwrap();
    assert_eq!((again.refund_index, &again.spend), (None, &first.spend));
    let refund2 = b58::dec32(&again.spend.refund).unwrap();
    let q2 = withdraw::sign(&seed, 1, &[7; 32], &refund2, 5);
    assert_eq!(q1, q2);

    // Anything else would be a second signature from a one-time key.
    for (to, amount) in [([9u8; 32], 5), ([7; 32], 6), ([7; 32], u64::MAX)] {
        match withdraw::plan(&s, 1, &to, amount) {
            Err(Error::SignedOther(x)) => assert_eq!(x, first.spend),
            other => panic!("{other:?}"),
        }
    }
}

#[test]
fn check_rejects_foreign_and_tampered_qsig() {
    let seed = mnemonic::seed64(ART);
    let (to, refund) = ([7u8; 32], derive::vault(&seed, 1));
    let good = withdraw::sign(&seed, 0, &to, &refund, 1_500_000_000);
    let c = withdraw::check(&good).unwrap();
    assert_eq!(b58::enc(&c.vault), VAULT0);
    assert_eq!(
        (c.recipient, c.refund, c.amount),
        (to, refund, 1_500_000_000)
    );
    assert_eq!(c.ix_data, withdraw::ix_data(&good).unwrap());
    let back = withdraw::from_ix(0, &good.vault, &good.recipient, &good.refund, &c.ix_data);
    assert_eq!(back, Some(good.clone()));
    assert_eq!(withdraw::from_ix(0, "", "", "", &c.ix_data[1..]), None);

    let bad = |f: &dyn Fn(&mut withdraw::QSig)| {
        let mut q = good.clone();
        f(&mut q);
        withdraw::check(&q).is_err()
    };
    // A program that is not qvault (here: the system program) could do anything with the fee payer.
    assert!(bad(&|q| q.program = b58::enc(&[0; 32])));
    assert!(bad(&|q| q.recipient = b58::enc(&[9; 32])));
    assert!(bad(&|q| q.refund = b58::enc(&[9; 32])));
    assert!(bad(&|q| q.vault = VAULT1.into()));
    assert!(bad(&|q| q.amount = "max".into()));
    assert!(bad(&|q| q.amount = "1500000001".into()));
    assert!(bad(&|q| q.qusb = 2));
    assert!(bad(&|q| q.kind = "other".into()));
    assert!(bad(&|q| {
        use base64::{engine::general_purpose::STANDARD as B64, Engine};
        let mut sig = B64.decode(&q.sig).unwrap();
        sig[100] ^= 1;
        q.sig = B64.encode(sig);
    }));
    assert!(bad(&|q| q.sig = "AAAA".into()));
    // Validly signed, but the program rejects recipient == refund forever.
    assert!(withdraw::check(&withdraw::sign(&seed, 0, &to, &to, 5)).is_err());
}
