//! qvault: single-instruction Winternitz-guarded SOL vault (SPEC.md §3).
use pinocchio::{
    cpi::{Seed, Signer},
    entrypoint,
    error::ProgramError,
    AccountView, Address, ProgramResult,
};
use pinocchio_system::instructions::Transfer;
use qusb_wots::{recover_pk_hash, sig_from_bytes, Hasher, SIG_LEN};

/// CnfS7soDNtZaJgshcU38tvDuK2zZZwFPAedRUdRmdwZ2
pub const ID: Address = Address::new_from_array([
    0xaf, 0x23, 0x26, 0x26, 0x14, 0xa4, 0x89, 0x17, 0x9b, 0xf5, 0x57, 0x94, 0x78, 0x49, 0xb4, 0x28,
    0xbe, 0xdb, 0xfd, 0xd3, 0x6c, 0x81, 0xec, 0x72, 0x49, 0x76, 0x85, 0xdb, 0xd6, 0x79, 0x18, 0xb9,
]);

const DOMAIN: &[u8] = b"qUSB/qvault/withdraw/v1";
const DATA_LEN: usize = 1 + SIG_LEN + 8;
/// 23 domain + 3 * 32 keys + 8 amount. (SPEC.md says 119; that omits the amount.)
const MSG_LEN: usize = 23 + 96 + 8;

/// sol_sha256 on-chain; solana-sha256-hasher uses sha2 off-chain.
pub struct SolHasher;
impl Hasher for SolHasher {
    fn hashv(parts: &[&[u8]]) -> [u8; 32] {
        solana_sha256_hasher::hashv(parts).to_bytes()
    }
}

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let [_payer, vault, recipient, refund, _system] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if data.len() != DATA_LEN || data[0] != 0 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let sig = sig_from_bytes(&data[1..1 + SIG_LEN]).ok_or(ProgramError::InvalidInstructionData)?;
    let amount_le = &data[1 + SIG_LEN..];
    let amount = u64::from_le_bytes(amount_le.try_into().unwrap());

    let mut msg = [0u8; MSG_LEN];
    msg[..23].copy_from_slice(DOMAIN);
    msg[23..55].copy_from_slice(vault.address().as_array());
    msg[55..87].copy_from_slice(recipient.address().as_array());
    msg[87..119].copy_from_slice(refund.address().as_array());
    msg[119..].copy_from_slice(amount_le);

    let pk_hash = recover_pk_hash::<SolHasher>(&sig, &msg);
    let (expected, bump) = Address::find_program_address(&[b"qvault", &pk_hash], program_id);
    if vault.address() != &expected {
        return Err(ProgramError::InvalidSeeds);
    }
    let (v, r, f) = (vault.address(), recipient.address(), refund.address());
    if v == r || v == f || r == f {
        return Err(ProgramError::InvalidArgument);
    }

    let bal = vault.lamports();
    let (send, rest) = if amount == u64::MAX {
        (bal, 0)
    } else if amount <= bal {
        (amount, bal - amount)
    } else {
        return Err(ProgramError::InsufficientFunds);
    };

    let bump = [bump];
    let seeds = [
        Seed::from(b"qvault"),
        Seed::from(&pk_hash),
        Seed::from(&bump),
    ];
    let signer = [Signer::from(&seeds)];
    Transfer {
        from: vault,
        to: recipient,
        lamports: send,
    }
    .invoke_signed(&signer)?;
    if rest > 0 {
        Transfer {
            from: vault,
            to: refund,
            lamports: rest,
        }
        .invoke_signed(&signer)?;
    }
    Ok(())
}
