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
    }
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
    mark_used(&mut s, 1).unwrap();
    assert!(matches!(mark_used(&mut s, 1), Err(Error::AlreadyUsed(1))));
    save(&d, &s, "pw").unwrap();
    assert_ne!(before, std::fs::read(d.join("vault.qv")).unwrap());
    assert_eq!(unlock(&d, "pw").unwrap().used, vec![0, 1]);
    assert!(!d.join("vault.qv.tmp").exists());
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
