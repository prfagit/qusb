//! qUSB core: mnemonic, derivation, keystore, public cache, withdraw signing, sealed backups.
//! Paths passed to `keystore::*`, `public::*` are the `qusb/` directory that holds `vault.qv`.

use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid mnemonic: {0}")]
    Mnemonic(String),
    #[error("wrong passphrase or corrupted data")]
    Decrypt,
    #[error("vault index {0} was already used")]
    AlreadyUsed(u32),
    #[error("keystore already exists")]
    Exists,
    #[error("bad format: {0}")]
    Format(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}
pub type Result<T> = std::result::Result<T, Error>;

fn fmt_err(e: impl std::fmt::Display) -> Error {
    Error::Format(e.to_string())
}

pub mod b58 {
    pub fn enc(b: &[u8]) -> String {
        bs58::encode(b).into_string()
    }
    pub fn dec32(s: &str) -> crate::Result<[u8; 32]> {
        let v = bs58::decode(s).into_vec().map_err(crate::fmt_err)?;
        v.try_into()
            .map_err(|_| crate::fmt_err("expected 32 bytes"))
    }
}

fn rand_bytes<const N: usize>() -> [u8; N] {
    use rand_core::{OsRng, RngCore};
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

fn hmac512(key: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; 64]> {
    use hmac::{Hmac, Mac};
    let mut m = Hmac::<sha2::Sha512>::new_from_slice(key).unwrap();
    for p in parts {
        m.update(p);
    }
    Zeroizing::new(m.finalize().into_bytes().into())
}

pub mod mnemonic {
    use super::*;
    pub fn generate() -> Zeroizing<String> {
        let ent = Zeroizing::new(rand_bytes::<32>());
        Zeroizing::new(bip39::Mnemonic::from_entropy(&*ent).unwrap().to_string())
    }
    pub fn validate(words: &str) -> Result<()> {
        bip39::Mnemonic::parse_normalized(words)
            .map(|_| ())
            .map_err(|e| Error::Mnemonic(e.to_string()))
    }
    /// Panics on an invalid mnemonic; call `validate` first.
    pub fn seed64(words: &str) -> Zeroizing<[u8; 64]> {
        Zeroizing::new(
            bip39::Mnemonic::parse_normalized(words)
                .expect("validated mnemonic")
                .to_seed(""),
        )
    }
}

pub mod derive {
    use super::*;
    use sha2::{Digest, Sha256};
    pub const QVAULT_PROGRAM_ID: &str = "CnfS7soDNtZaJgshcU38tvDuK2zZZwFPAedRUdRmdwZ2";

    /// SLIP-0010 ed25519, m/44'/501'/0'/0'.
    pub fn classic_keypair(seed64: &[u8; 64]) -> ed25519_dalek::SigningKey {
        let mut i = hmac512(b"ed25519 seed", &[seed64]);
        for idx in [44u32, 501, 0, 0] {
            i = hmac512(
                &i[32..],
                &[&[0], &i[..32], &(idx | 0x8000_0000).to_be_bytes()],
            );
        }
        ed25519_dalek::SigningKey::from_bytes(i[..32].try_into().unwrap())
    }

    pub fn wots_seed(seed64: &[u8; 64], k: u32) -> Zeroizing<[u8; 32]> {
        let h = hmac512(b"qUSB/wots/v1", &[seed64, &k.to_be_bytes()]);
        Zeroizing::new(h[..32].try_into().unwrap())
    }

    pub fn vault_pk_hash(seed64: &[u8; 64], k: u32) -> [u8; 32] {
        qusb_wots::Keypair::from_seed(&wots_seed(seed64, k)).pk_hash()
    }

    /// PDA [b"qvault", pk_hash] under `program` (Solana find_program_address).
    pub fn vault_address(pk_hash: &[u8; 32], program: &[u8; 32]) -> [u8; 32] {
        for bump in (0..=255u8).rev() {
            let mut h = Sha256::new();
            for p in [
                &b"qvault"[..],
                pk_hash,
                &[bump],
                program,
                b"ProgramDerivedAddress",
            ] {
                h.update(p);
            }
            let out: [u8; 32] = h.finalize().into();
            if curve25519_dalek::edwards::CompressedEdwardsY(out)
                .decompress()
                .is_none()
            {
                return out;
            }
        }
        unreachable!("no valid bump")
    }

    pub fn program_id() -> [u8; 32] {
        b58::dec32(QVAULT_PROGRAM_ID).unwrap()
    }
}

pub mod keystore {
    use super::*;
    use argon2::{Algorithm, Argon2, Params, Version};
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use chacha20poly1305::{
        aead::{Aead, KeyInit, Payload},
        XChaCha20Poly1305, XNonce,
    };
    use serde::{Deserialize, Serialize};
    use std::{fs, io::Write, path::Path};

    #[derive(Serialize, Deserialize)]
    pub struct Secrets {
        pub mnemonic: Zeroizing<String>,
        pub created: u64,
        pub label: String,
        pub next_vault: u32,
        pub used: Vec<u32>,
    }

    /// Argon2id params. `Default` is the SPEC §1 value; lower only in tests.
    #[derive(Clone, Copy)]
    pub struct KdfParams {
        pub m_kib: u32,
        pub t: u32,
        pub p: u32,
    }
    impl Default for KdfParams {
        fn default() -> Self {
            KdfParams {
                m_kib: 65536,
                t: 3,
                p: 1,
            }
        }
    }

    #[derive(Serialize, Deserialize)]
    struct Kdf {
        alg: String,
        m_kib: u32,
        t: u32,
        p: u32,
        salt: String,
    }
    #[derive(Serialize, Deserialize)]
    struct AeadInfo {
        alg: String,
        nonce: String,
    }
    #[derive(Serialize, Deserialize)]
    struct File {
        qusb: u32,
        kdf: Kdf,
        aead: AeadInfo,
        ct: String,
    }

    fn aad(m: u32, t: u32, p: u32) -> String {
        format!("qusb:1:argon2id:{m}:{t}:{p}")
    }
    fn path(dir: &Path) -> std::path::PathBuf {
        dir.join("vault.qv")
    }

    pub(crate) fn atomic_write(p: &Path, data: &[u8]) -> Result<()> {
        let mut name = p.file_name().unwrap().to_os_string();
        name.push(".tmp");
        let tmp = p.with_file_name(name);
        let mut f = fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, p)?;
        Ok(())
    }

    fn key(pass: &str, k: &KdfParams, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        let params = Params::new(k.m_kib, k.t, k.p, Some(32)).map_err(fmt_err)?;
        let mut out = Zeroizing::new([0u8; 32]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(pass.as_bytes(), salt, &mut *out)
            .map_err(fmt_err)?;
        Ok(out)
    }

    fn write(dir: &Path, s: &Secrets, pass: &str, k: &KdfParams) -> Result<()> {
        let salt = rand_bytes::<16>();
        let nonce = rand_bytes::<24>();
        let pt = Zeroizing::new(serde_json::to_vec(s).map_err(fmt_err)?);
        let kk = key(pass, k, &salt)?;
        let ct = XChaCha20Poly1305::new((&*kk).into())
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &pt,
                    aad: aad(k.m_kib, k.t, k.p).as_bytes(),
                },
            )
            .map_err(|_| Error::Decrypt)?;
        let f = File {
            qusb: 1,
            kdf: Kdf {
                alg: "argon2id".into(),
                m_kib: k.m_kib,
                t: k.t,
                p: k.p,
                salt: B64.encode(salt),
            },
            aead: AeadInfo {
                alg: "xchacha20poly1305".into(),
                nonce: B64.encode(nonce),
            },
            ct: B64.encode(ct),
        };
        fs::create_dir_all(dir)?;
        atomic_write(&path(dir), &serde_json::to_vec_pretty(&f).map_err(fmt_err)?)
    }

    fn read_file(dir: &Path) -> Result<File> {
        let f: File = serde_json::from_slice(&fs::read(path(dir))?).map_err(fmt_err)?;
        if f.qusb != 1 || f.kdf.alg != "argon2id" || f.aead.alg != "xchacha20poly1305" {
            return Err(fmt_err("unsupported keystore"));
        }
        Ok(f)
    }

    /// Fails with `Exists` if vault.qv is already there.
    pub fn create(dir: &Path, s: &Secrets, pass: &str) -> Result<()> {
        create_with(dir, s, pass, &KdfParams::default())
    }
    pub fn create_with(dir: &Path, s: &Secrets, pass: &str, k: &KdfParams) -> Result<()> {
        if path(dir).exists() {
            return Err(Error::Exists);
        }
        write(dir, s, pass, k)
    }

    pub fn unlock(dir: &Path, pass: &str) -> Result<Secrets> {
        let f = read_file(dir)?;
        let salt = B64.decode(&f.kdf.salt).map_err(fmt_err)?;
        let nonce = B64.decode(&f.aead.nonce).map_err(fmt_err)?;
        let ct = B64.decode(&f.ct).map_err(fmt_err)?;
        if nonce.len() != 24 {
            return Err(fmt_err("bad nonce"));
        }
        let k = KdfParams {
            m_kib: f.kdf.m_kib,
            t: f.kdf.t,
            p: f.kdf.p,
        };
        let kk = key(pass, &k, &salt)?;
        let pt = XChaCha20Poly1305::new((&*kk).into())
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ct,
                    aad: aad(k.m_kib, k.t, k.p).as_bytes(),
                },
            )
            .map_err(|_| Error::Decrypt)?;
        let pt = Zeroizing::new(pt);
        serde_json::from_slice(&pt).map_err(fmt_err)
    }

    /// Re-encrypts with fresh salt+nonce, keeping the KDF params of the existing file (SPEC defaults if none).
    pub fn save(dir: &Path, s: &Secrets, pass: &str) -> Result<()> {
        let k = read_file(dir)
            .map(|f| KdfParams {
                m_kib: f.kdf.m_kib,
                t: f.kdf.t,
                p: f.kdf.p,
            })
            .unwrap_or_default();
        write(dir, s, pass, &k)
    }

    /// In-memory; caller must `save` BEFORE signing. Err(AlreadyUsed) if `k` is already recorded.
    pub fn mark_used(s: &mut Secrets, k: u32) -> Result<()> {
        if s.used.contains(&k) {
            return Err(Error::AlreadyUsed(k));
        }
        s.used.push(k);
        Ok(())
    }
}

pub mod public {
    use super::*;
    use serde::{Deserialize, Serialize};
    use std::path::Path;

    #[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
    pub struct VaultInfo {
        pub index: u32,
        pub address: String,
        pub pk_hash: String,
        pub state: String,
    }
    #[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
    pub struct PublicInfo {
        pub qusb: u32,
        pub label: String,
        pub classic: String,
        pub program: String,
        pub vaults: Vec<VaultInfo>,
        pub seal_pub: String,
    }

    /// Lists vaults 0..=max(next_vault, last used + 1); `used` ones are marked used, the rest fresh.
    pub fn build(s: &keystore::Secrets) -> PublicInfo {
        let seed = mnemonic::seed64(&s.mnemonic);
        let prog = derive::program_id();
        let n = s.next_vault.max(s.used.iter().max().map_or(0, |m| m + 1)) + 1;
        let vaults = (0..n)
            .map(|i| {
                let pk = derive::vault_pk_hash(&seed, i);
                VaultInfo {
                    index: i,
                    address: b58::enc(&derive::vault_address(&pk, &prog)),
                    pk_hash: hex::encode(pk),
                    state: if s.used.contains(&i) { "used" } else { "fresh" }.into(),
                }
            })
            .collect();
        PublicInfo {
            qusb: 1,
            label: s.label.clone(),
            classic: b58::enc(derive::classic_keypair(&seed).verifying_key().as_bytes()),
            program: derive::QVAULT_PROGRAM_ID.into(),
            vaults,
            seal_pub: seal::encode_pub(&seal::seal_keys(&seed).0),
        }
    }

    pub fn write(dir: &Path, p: &PublicInfo) -> Result<()> {
        std::fs::create_dir_all(dir)?;
        keystore::atomic_write(
            &dir.join("public.json"),
            &serde_json::to_vec_pretty(p).map_err(fmt_err)?,
        )
    }
    pub fn read(dir: &Path) -> Result<PublicInfo> {
        serde_json::from_slice(&std::fs::read(dir.join("public.json"))?).map_err(fmt_err)
    }
}

pub mod withdraw {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use serde::{Deserialize, Serialize};

    /// SPEC §3 signed message, 127 bytes.
    pub fn message(
        vault: &[u8; 32],
        recipient: &[u8; 32],
        refund: &[u8; 32],
        amount: u64,
    ) -> Vec<u8> {
        let mut m = b"qUSB/qvault/withdraw/v1".to_vec();
        for p in [&vault[..], recipient, refund, &amount.to_le_bytes()] {
            m.extend_from_slice(p);
        }
        m
    }

    #[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
    pub struct QSig {
        pub qusb: u32,
        pub kind: String,
        pub program: String,
        pub vault: String,
        pub vault_index: u32,
        pub recipient: String,
        pub refund: String,
        /// decimal lamports or "max"
        pub amount: String,
        /// base64, 840 bytes
        pub sig: String,
    }

    impl QSig {
        pub fn amount_u64(&self) -> Result<u64> {
            if self.amount == "max" {
                Ok(u64::MAX)
            } else {
                self.amount.parse().map_err(fmt_err)
            }
        }
    }

    /// Does NOT touch the keystore: the caller must `mark_used` + `save` first. `amount == u64::MAX` means "max".
    pub fn sign(
        seed64: &[u8; 64],
        vault_index: u32,
        recipient: &[u8; 32],
        refund: &[u8; 32],
        amount: u64,
    ) -> QSig {
        let kp = qusb_wots::Keypair::from_seed(&derive::wots_seed(seed64, vault_index));
        let vault = derive::vault_address(&kp.pk_hash(), &derive::program_id());
        let sig = kp.sign(&message(&vault, recipient, refund, amount));
        QSig {
            qusb: 1,
            kind: "qvault-withdraw".into(),
            program: derive::QVAULT_PROGRAM_ID.into(),
            vault: b58::enc(&vault),
            vault_index,
            recipient: b58::enc(recipient),
            refund: b58::enc(refund),
            amount: if amount == u64::MAX {
                "max".into()
            } else {
                amount.to_string()
            },
            sig: B64.encode(qusb_wots::sig_to_bytes(&sig)),
        }
    }

    /// 849-byte instruction data: tag 0 | sig 840 | amount u64 LE.
    pub fn ix_data(q: &QSig) -> Result<Vec<u8>> {
        let sig = B64.decode(&q.sig).map_err(fmt_err)?;
        if sig.len() != qusb_wots::SIG_LEN {
            return Err(fmt_err("bad sig length"));
        }
        let mut d = vec![0u8];
        d.extend_from_slice(&sig);
        d.extend_from_slice(&q.amount_u64()?.to_le_bytes());
        Ok(d)
    }
}

pub mod seal {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        XChaCha20Poly1305, XNonce,
    };
    use ml_kem::{
        kem::{Decapsulate, Encapsulate},
        EncodedSizeUser, KemCore, MlKem768,
    };
    use sha2::{Digest, Sha256};

    const EK: usize = 1184;
    const CT: usize = 1088;

    #[derive(Clone, Debug, PartialEq)]
    pub struct SealPub {
        pub mlkem: Vec<u8>,
        pub x25519: [u8; 32],
    }

    #[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
    pub struct SealSecret {
        d_z: [u8; 64],
        x: [u8; 32],
    }

    type Dk = <MlKem768 as KemCore>::DecapsulationKey;
    type Ek = <MlKem768 as KemCore>::EncapsulationKey;

    fn mlkem_keys(d_z: &[u8; 64]) -> (Dk, Ek) {
        let d: [u8; 32] = d_z[..32].try_into().unwrap();
        let z: [u8; 32] = d_z[32..].try_into().unwrap();
        MlKem768::generate_deterministic((&d).into(), (&z).into())
    }

    pub fn seal_keys(seed64: &[u8; 64]) -> (SealPub, SealSecret) {
        let d_z: [u8; 64] = *hmac512(b"qUSB/seal/mlkem/v1", &[seed64]);
        let x: [u8; 32] = hmac512(b"qUSB/seal/x25519/v1", &[seed64])[..32]
            .try_into()
            .unwrap();
        let (_, ek) = mlkem_keys(&d_z);
        let xpub = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(x));
        (
            SealPub {
                mlkem: ek.as_bytes().to_vec(),
                x25519: xpub.to_bytes(),
            },
            SealSecret { d_z, x },
        )
    }

    /// base64 of ml-kem ek (1184) ‖ x25519 pub (32).
    pub fn encode_pub(p: &SealPub) -> String {
        B64.encode([&p.mlkem[..], &p.x25519].concat())
    }
    pub fn decode_pub(s: &str) -> Result<SealPub> {
        let b = B64.decode(s.trim()).map_err(fmt_err)?;
        if b.len() != EK + 32 {
            return Err(fmt_err("bad seal pub length"));
        }
        Ok(SealPub {
            mlkem: b[..EK].to_vec(),
            x25519: b[EK..].try_into().unwrap(),
        })
    }

    fn combine(ss_m: &[u8], ss_x: &[u8], ct: &[u8], eph: &[u8]) -> Zeroizing<[u8; 32]> {
        let mut h = Sha256::new();
        for p in [&b"qUSB/seal/v1"[..], ss_m, ss_x, ct, eph] {
            h.update(p);
        }
        Zeroizing::new(h.finalize().into())
    }

    /// Blob = eph_x25519_pub(32) ‖ ct_mlkem(1088) ‖ nonce(24) ‖ aead ciphertext.
    pub fn seal(to: &SealPub, plaintext: &[u8]) -> Result<Vec<u8>> {
        use rand_core::OsRng;
        let ek_enc = ml_kem::Encoded::<Ek>::try_from(&to.mlkem[..])
            .map_err(|_| fmt_err("bad ml-kem key"))?;
        let ek = Ek::from_bytes(&ek_enc);
        let (ct, ss_m) = ek
            .encapsulate(&mut OsRng)
            .map_err(|_| fmt_err("encapsulate"))?;
        let eph = x25519_dalek::EphemeralSecret::random_from_rng(OsRng);
        let eph_pub = x25519_dalek::PublicKey::from(&eph);
        let ss_x = eph.diffie_hellman(&x25519_dalek::PublicKey::from(to.x25519));
        let k = combine(&ss_m, ss_x.as_bytes(), &ct, eph_pub.as_bytes());
        let nonce = rand_bytes::<24>();
        let enc = XChaCha20Poly1305::new((&*k).into())
            .encrypt(XNonce::from_slice(&nonce), plaintext)
            .map_err(|_| Error::Decrypt)?;
        Ok([&eph_pub.to_bytes()[..], &ct, &nonce, &enc].concat())
    }

    pub fn unseal(sk: &SealSecret, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if blob.len() < 32 + CT + 24 + 16 {
            return Err(fmt_err("sealed blob too short"));
        }
        let (eph, rest) = blob.split_at(32);
        let (ct, rest) = rest.split_at(CT);
        let (nonce, enc) = rest.split_at(24);
        let (dk, _) = mlkem_keys(&sk.d_z);
        let ct_arr = ml_kem::Ciphertext::<MlKem768>::try_from(ct).map_err(|_| Error::Decrypt)?;
        let ss_m = dk.decapsulate(&ct_arr).map_err(|_| Error::Decrypt)?;
        let ss_x = x25519_dalek::StaticSecret::from(sk.x).diffie_hellman(
            &x25519_dalek::PublicKey::from(<[u8; 32]>::try_from(eph).unwrap()),
        );
        let k = combine(&ss_m, ss_x.as_bytes(), ct, eph);
        XChaCha20Poly1305::new((&*k).into())
            .decrypt(XNonce::from_slice(nonce), enc)
            .map(Zeroizing::new)
            .map_err(|_| Error::Decrypt)
    }
}

pub mod stick {
    use std::path::{Path, PathBuf};
    /// Walks up from `start` looking for `<dir>/qusb/vault.qv`; returns the `qusb/` directory.
    pub fn find(start: &Path) -> Option<PathBuf> {
        start
            .ancestors()
            .map(|d| d.join("qusb"))
            .find(|d| d.join("vault.qv").is_file())
    }
}
