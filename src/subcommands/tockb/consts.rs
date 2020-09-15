use ckb_hash::blake2b_256;
use lazy_static::lazy_static;

pub const SCRIPT_CONFIG_FILE: &'static str = "scripts.toml";

pub const TOCKB_TYPESCRIPT: &[u8] = include_bytes!("../../../../build/release/toCKB-typescript");
pub const TOCKB_LOCKSCRIPT: &[u8] = include_bytes!("../../../../build/release/toCKB-lockscript");

lazy_static! {
    pub static ref TOCKB_TYPESCRIPT_HASH: [u8; 32] = blake2b_256(TOCKB_TYPESCRIPT);
    pub static ref TOCKB_LOCKSCRIPT_HASH: [u8; 32] = blake2b_256(TOCKB_LOCKSCRIPT);
}
