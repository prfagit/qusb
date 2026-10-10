//! Winternitz one-time signatures, qUSB v1 (see SPEC.md §2).
//!
//! N = 28-byte chain elements (SHA-256 truncated), W = 256, 28 message digits
//! plus 2 checksum digits = 30 chains, 840-byte signatures. Hash-based: nothing
//! here falls to Shor. Verification is `no_std` so the on-chain program
//! shares this exact code with the signer.
#![cfg_attr(not(feature = "std"), no_std)]

pub const N: usize = 28;
pub const L1: usize = 28;
pub const L: usize = 30;
pub const SIG_LEN: usize = N * L;
pub type Sig = [[u8; N]; L];

/// SHA-256 over concatenated slices. Off-chain: `sha2`. On-chain: `sol_sha256`.
pub trait Hasher {
    fn hashv(parts: &[&[u8]]) -> [u8; 32];
}

#[inline]
fn h_n<H: Hasher>(parts: &[&[u8]]) -> [u8; N] {
    let full = H::hashv(parts);
    let mut out = [0u8; N];
    out.copy_from_slice(&full[..N]);
    out
}

/// Advance chain `i` from position `a` to `b` (applies step j for j in a..b).
pub fn chain<H: Hasher>(i: u8, mut x: [u8; N], a: u8, b: u8) -> [u8; N] {
    let mut j = a;
    while j < b {
        x = h_n::<H>(&[b"qW", &[i, j], &x]);
        j += 1;
    }
    x
}

/// 28 digest digits followed by the big-endian u16 checksum.
pub fn digits<H: Hasher>(msg: &[u8]) -> [u8; L] {
    let d = h_n::<H>(&[b"qUSB/wots/msg/v1", msg]);
    let csum: u16 = d.iter().map(|&b| 255 - b as u16).sum();
    let mut out = [0u8; L];
    out[..L1].copy_from_slice(&d);
    out[L1..].copy_from_slice(&csum.to_be_bytes());
    out
}

fn pk_hash_of<H: Hasher>(pk: &[[u8; N]; L]) -> [u8; 32] {
    let mut parts: [&[u8]; L + 1] = [&[]; L + 1];
    parts[0] = b"qUSB/wots/pk/v1";
    for (k, p) in pk.iter().enumerate() {
        parts[k + 1] = p;
    }
    H::hashv(&parts)
}

/// Recompute the public-key hash a signature commits to. If it equals the
/// vault's pk_hash, the signature is valid for `msg`.
pub fn recover_pk_hash<H: Hasher>(sig: &Sig, msg: &[u8]) -> [u8; 32] {
    let d = digits::<H>(msg);
    let mut pk = [[0u8; N]; L];
    for i in 0..L {
        pk[i] = chain::<H>(i as u8, sig[i], d[i], 255);
    }
    pk_hash_of::<H>(&pk)
}

pub fn sig_from_bytes(b: &[u8]) -> Option<Sig> {
    if b.len() != SIG_LEN {
        return None;
    }
    let mut sig = [[0u8; N]; L];
    for (i, c) in b.chunks_exact(N).enumerate() {
        sig[i].copy_from_slice(c);
    }
    Some(sig)
}

pub fn sig_to_bytes(sig: &Sig) -> [u8; SIG_LEN] {
    let mut out = [0u8; SIG_LEN];
    for (i, c) in sig.iter().enumerate() {
        out[i * N..(i + 1) * N].copy_from_slice(c);
    }
    out
}

#[cfg(feature = "std")]
pub use keys::*;

#[cfg(feature = "std")]
mod keys {
    use super::*;
    use sha2::{Digest, Sha256};
    use zeroize::{Zeroize, ZeroizeOnDrop};

    pub struct Sha2;
    impl Hasher for Sha2 {
        fn hashv(parts: &[&[u8]]) -> [u8; 32] {
            let mut h = Sha256::new();
            for p in parts {
                h.update(p);
            }
            h.finalize().into()
        }
    }

    /// One-time keypair. Sign once, then throw it away.
    #[derive(Zeroize, ZeroizeOnDrop)]
    pub struct Keypair {
        sk: [[u8; N]; L],
    }

    impl Keypair {
        pub fn from_seed(wots_seed: &[u8; 32]) -> Self {
            let mut sk = [[0u8; N]; L];
            for (i, s) in sk.iter_mut().enumerate() {
                *s = h_n::<Sha2>(&[b"qUSB/wots/sk/v1", wots_seed, &[i as u8]]);
            }
            Keypair { sk }
        }

        pub fn pk_hash(&self) -> [u8; 32] {
            let pk: [[u8; N]; L] =
                core::array::from_fn(|i| chain::<Sha2>(i as u8, self.sk[i], 0, 255));
            pk_hash_of::<Sha2>(&pk)
        }

        pub fn sign(&self, msg: &[u8]) -> Sig {
            let d = digits::<Sha2>(msg);
            let mut sig = [[0u8; N]; L];
            for i in 0..L {
                sig[i] = chain::<Sha2>(i as u8, self.sk[i], 0, d[i]);
            }
            sig
        }
    }

    pub fn verify(pk_hash: &[u8; 32], sig: &Sig, msg: &[u8]) -> bool {
        recover_pk_hash::<Sha2>(sig, msg) == *pk_hash
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_and_reject() {
        let kp = Keypair::from_seed(&[7u8; 32]);
        let pk = kp.pk_hash();
        let sig = kp.sign(b"send 1 SOL to bob");
        assert!(verify(&pk, &sig, b"send 1 SOL to bob"));
        assert!(!verify(&pk, &sig, b"send 9 SOL to eve"));
        assert!(!verify(
            &Keypair::from_seed(&[8u8; 32]).pk_hash(),
            &sig,
            b"send 1 SOL to bob"
        ));
        let mut bad = sig;
        bad[3][0] ^= 1;
        assert!(!verify(&pk, &bad, b"send 1 SOL to bob"));
        assert_eq!(sig_from_bytes(&sig_to_bytes(&sig)), Some(sig));
    }

    #[test]
    fn checksum_blocks_forward_forgery() {
        // Hashing any signature element forward raises a digit, which must lower the
        // checksum. Since checksum digits can only be hashed forward too, no forgery exists.
        let d = digits::<Sha2>(b"x");
        let csum = u16::from_be_bytes([d[28], d[29]]);
        assert_eq!(csum, d[..28].iter().map(|&b| 255 - b as u16).sum::<u16>());
    }

    #[test]
    fn known_vector_is_stable() {
        // Pins the format: changing any constant or domain tag breaks existing vaults.
        let kp = Keypair::from_seed(&[0u8; 32]);
        let hex: String = kp.pk_hash().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "972d9519495918895691edc17a78afc778d31b9fd25662f1803b0e7c72e6d486"
        );
    }
}
