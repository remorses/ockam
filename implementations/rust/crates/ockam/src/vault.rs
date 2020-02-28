use std::ptr;

use cfg_if::cfg_if;
use thiserror::Error;

pub type VaultResult<T> = Result<T, VaultError>;

cfg_if! {
    if #[cfg(feature = "term_encoding")] {
        use rustler;
        use rustler::NifUnitEnum;
    }
}

#[allow(non_camel_case_types)]
#[derive(Error, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum VaultError {
    #[error("< Invalid parameter specified")]
    INVALID_PARAM,
    #[error("Invalid configuration specified")]
    INVALID_CFG,
    #[error("Invalid size specified")]
    INVALID_SIZE,
    #[error("Function has not yet been implemented")]
    UNIMPLEMENTED,
    #[error("Insufficent space for a memory allocation")]
    MEM_INSUFFICIENT,
    #[error("The specified buffer is not a managed buffer")]
    MEM_INVALID_PTR,
    #[error("The requested memory size is not available")]
    MEM_UNAVAIL,
    #[error("Vault needs to be initialized")]
    VAULT_UNINITIALIZED,
    #[error("Vault is already initialized")]
    VAULT_ALREADY_INIT,
    #[error("Specified size is invalid for the call")]
    VAULT_SIZE_MISMATCH,
    #[error("Supplied keysize is invalid for call")]
    VAULT_INVALID_KEY_SIZE,
    #[error("Supplied buffer is null")]
    VAULT_INVALID_BUFFER,
    #[error("Supplied buffer size is invalid for call")]
    VAULT_INVALID_BUFFER_SIZE,
    #[error("TPM failed to initialize")]
    VAULT_TPM_INIT_FAIL,
    #[error("Random number generator failure")]
    VAULT_TPM_RAND_FAIL,
    #[error("Key failure in vault")]
    VAULT_TPM_KEY_FAIL,
    #[error("ECDH failed to complete successfully")]
    VAULT_TPM_ECDH_FAIL,
    #[error("SHA256 unable to complete")]
    VAULT_TPM_SHA256_FAIL,
    #[error("HKDF failed to complete successfully")]
    VAULT_TPM_HKDF_FAIL,
    #[error("AES failed to complete successfully")]
    VAULT_TPM_AES_GCM_FAIL,
    #[error("Hardware identification failed")]
    VAULT_TPM_ID_FAIL,
    #[error("Specified hardware is not the expected hardware")]
    VAULT_TPM_ID_INVALID,
    #[error("The hardware configuration is unlocked")]
    VAULT_TPM_UNLOCKED,
    #[error("The specified interface is not supported")]
    VAULT_TPM_UNSUPPORTED_IFACE,
    #[error("AES GCM tag invalid for decryption")]
    VAULT_TPM_AES_GCM_DECRYPT_INVALID,
    #[error("Host software library failed to initialize")]
    VAULT_HOST_INIT_FAIL,
    #[error("Random number failed to generate on host")]
    VAULT_HOST_RAND_FAIL,
    #[error("Key failure in software")]
    VAULT_HOST_KEY_FAIL,
    #[error("ECDH failed to complete successfully")]
    VAULT_HOST_ECDH_FAIL,
    #[error("SHA256 failed to complete sucessfully")]
    VAULT_HOST_SHA256_FAIL,
    #[error("HKDF failed to complete successfully")]
    VAULT_HOST_HKDF_FAIL,
    #[error("AES failed to complete successfully")]
    VAULT_HOST_AES_FAIL,
}
impl VaultError {
    fn wrap<F>(fun: F) -> VaultResult<()>
    where
        F: Fn() -> ockam_vault_sys::OCKAM_ERR,
    {
        use ockam_vault_sys::OCKAM_ERR::*;

        let err = match fun() {
            OCKAM_ERR_NONE => return Ok(()),
            OCKAM_ERR_INVALID_PARAM => Self::INVALID_PARAM,
            OCKAM_ERR_INVALID_CFG => Self::INVALID_CFG,
            OCKAM_ERR_INVALID_SIZE => Self::INVALID_SIZE,
            OCKAM_ERR_UNIMPLEMENTED => Self::UNIMPLEMENTED,
            OCKAM_ERR_MEM_INSUFFICIENT => Self::MEM_INSUFFICIENT,
            OCKAM_ERR_MEM_INVALID_PTR => Self::MEM_INVALID_PTR,
            OCKAM_ERR_MEM_UNAVAIL => Self::MEM_UNAVAIL,
            OCKAM_ERR_VAULT_UNINITIALIZED => Self::VAULT_UNINITIALIZED,
            OCKAM_ERR_VAULT_ALREADY_INIT => Self::VAULT_ALREADY_INIT,
            OCKAM_ERR_VAULT_SIZE_MISMATCH => Self::VAULT_SIZE_MISMATCH,
            OCKAM_ERR_VAULT_INVALID_KEY_SIZE => Self::VAULT_INVALID_KEY_SIZE,
            OCKAM_ERR_VAULT_INVALID_BUFFER => Self::VAULT_INVALID_BUFFER,
            OCKAM_ERR_VAULT_INVALID_BUFFER_SIZE => Self::VAULT_INVALID_BUFFER_SIZE,
            OCKAM_ERR_VAULT_TPM_INIT_FAIL => Self::VAULT_TPM_INIT_FAIL,
            OCKAM_ERR_VAULT_TPM_RAND_FAIL => Self::VAULT_TPM_RAND_FAIL,
            OCKAM_ERR_VAULT_TPM_KEY_FAIL => Self::VAULT_TPM_KEY_FAIL,
            OCKAM_ERR_VAULT_TPM_ECDH_FAIL => Self::VAULT_TPM_ECDH_FAIL,
            OCKAM_ERR_VAULT_TPM_SHA256_FAIL => Self::VAULT_TPM_SHA256_FAIL,
            OCKAM_ERR_VAULT_TPM_HKDF_FAIL => Self::VAULT_TPM_HKDF_FAIL,
            OCKAM_ERR_VAULT_TPM_AES_GCM_FAIL => Self::VAULT_TPM_AES_GCM_FAIL,
            OCKAM_ERR_VAULT_TPM_ID_FAIL => Self::VAULT_TPM_ID_FAIL,
            OCKAM_ERR_VAULT_TPM_ID_INVALID => Self::VAULT_TPM_ID_INVALID,
            OCKAM_ERR_VAULT_TPM_UNLOCKED => Self::VAULT_TPM_UNLOCKED,
            OCKAM_ERR_VAULT_TPM_UNSUPPORTED_IFACE => Self::VAULT_TPM_UNSUPPORTED_IFACE,
            OCKAM_ERR_VAULT_TPM_AES_GCM_DECRYPT_INVALID => Self::VAULT_TPM_AES_GCM_DECRYPT_INVALID,
            OCKAM_ERR_VAULT_HOST_INIT_FAIL => Self::VAULT_HOST_INIT_FAIL,
            OCKAM_ERR_VAULT_HOST_RAND_FAIL => Self::VAULT_HOST_RAND_FAIL,
            OCKAM_ERR_VAULT_HOST_KEY_FAIL => Self::VAULT_HOST_KEY_FAIL,
            OCKAM_ERR_VAULT_HOST_ECDH_FAIL => Self::VAULT_HOST_ECDH_FAIL,
            OCKAM_ERR_VAULT_HOST_SHA256_FAIL => Self::VAULT_HOST_SHA256_FAIL,
            OCKAM_ERR_VAULT_HOST_HKDF_FAIL => Self::VAULT_HOST_HKDF_FAIL,
            OCKAM_ERR_VAULT_HOST_AES_FAIL => Self::VAULT_HOST_AES_FAIL,
        };
        Err(err)
    }
}

#[cfg(feature = "term_encoding")]
rustler::atoms! {
    invalid_param,
    invalid_cfg,
    invalid_size,
    unimplemented,
    mem_insufficient,
    mem_invalid_ptr,
    mem_unavail,
    vault_uninitialized,
    vault_already_init,
    vault_size_mismatch,
    vault_invalid_key_size,
    vault_invalid_buffer,
    vault_invalid_buffer_size,
    vault_tpm_init_fail,
    vault_tpm_rand_fail,
    vault_tpm_key_fail,
    vault_tpm_ecdh_fail,
    vault_tpm_sha256_fail,
    vault_tpm_hkdf_fail,
    vault_tpm_aes_gcm_fail,
    vault_tpm_id_fail,
    vault_tpm_id_invalid,
    vault_tpm_unlocked,
    vault_tpm_unsupported_iface,
    vault_tpm_aes_gcm_decrypt_invalid,
    vault_host_init_fail,
    vault_host_rand_fail,
    vault_host_key_fail,
    vault_host_ecdh_fail,
    vault_host_sha256_fail,
    vault_host_hkdf_fail,
    vault_host_aes_fail
}

#[cfg(feature = "term_encoding")]
impl rustler::Encoder for VaultError {
    fn encode<'c>(&self, env: rustler::Env<'c>) -> rustler::Term<'c> {
        use rustler::Atom;
        let string = self.to_string();
        let atom = Atom::try_from_bytes(env, string.as_bytes())
            .unwrap()
            .unwrap();
        atom.to_term(env)
    }
}

/// Support key types in Ockam Vault
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "term_encoding", derive(NifUnitEnum))]
pub enum KeyType {
    Static = 0,
    Ephemeral,
}
impl From<ockam_vault_sys::OCKAM_VAULT_KEY_e> for KeyType {
    fn from(value: ockam_vault_sys::OCKAM_VAULT_KEY_e) -> Self {
        use ockam_vault_sys::OCKAM_VAULT_KEY_e::*;
        match value {
            OCKAM_VAULT_KEY_STATIC => Self::Static,
            OCKAM_VAULT_KEY_EPHEMERAL => Self::Ephemeral,
            _ => unreachable!(),
        }
    }
}
impl Into<ockam_vault_sys::OCKAM_VAULT_KEY_e> for KeyType {
    fn into(self) -> ockam_vault_sys::OCKAM_VAULT_KEY_e {
        use ockam_vault_sys::OCKAM_VAULT_KEY_e::*;
        match self {
            Self::Static => OCKAM_VAULT_KEY_STATIC,
            Self::Ephemeral => OCKAM_VAULT_KEY_EPHEMERAL,
        }
    }
}

/// Specifies the mode of operation for AES GCM
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum AesGcmMode {
    Encrypt = 0,
    Decrypt,
}
impl From<ockam_vault_sys::OCKAM_VAULT_AES_GCM_MODE_e> for AesGcmMode {
    fn from(value: ockam_vault_sys::OCKAM_VAULT_AES_GCM_MODE_e) -> Self {
        use ockam_vault_sys::OCKAM_VAULT_AES_GCM_MODE_e::*;
        match value {
            OCKAM_VAULT_AES_GCM_MODE_ENCRYPT => Self::Encrypt,
            OCKAM_VAULT_AES_GCM_MODE_DECRYPT => Self::Decrypt,
        }
    }
}
impl Into<ockam_vault_sys::OCKAM_VAULT_AES_GCM_MODE_e> for AesGcmMode {
    fn into(self) -> ockam_vault_sys::OCKAM_VAULT_AES_GCM_MODE_e {
        use ockam_vault_sys::OCKAM_VAULT_AES_GCM_MODE_e::*;
        match self {
            Self::Encrypt => OCKAM_VAULT_AES_GCM_MODE_ENCRYPT,
            Self::Decrypt => OCKAM_VAULT_AES_GCM_MODE_DECRYPT,
        }
    }
}

/// The elliptic curve vault will support
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "term_encoding", derive(NifUnitEnum))]
pub enum Curve {
    /// NIST P-256/SECP256R1
    P256 = 0,
    Curve25519,
}
impl From<ockam_vault_sys::OCKAM_VAULT_EC_e> for Curve {
    fn from(value: ockam_vault_sys::OCKAM_VAULT_EC_e) -> Self {
        use ockam_vault_sys::OCKAM_VAULT_EC_e::*;
        match value {
            OCKAM_VAULT_EC_P256 => Self::P256,
            OCKAM_VAULT_EC_CURVE25519 => Self::Curve25519,
        }
    }
}
impl Into<ockam_vault_sys::OCKAM_VAULT_EC_e> for Curve {
    fn into(self) -> ockam_vault_sys::OCKAM_VAULT_EC_e {
        use ockam_vault_sys::OCKAM_VAULT_EC_e::*;
        match self {
            Self::P256 => OCKAM_VAULT_EC_P256,
            Self::Curve25519 => OCKAM_VAULT_EC_CURVE25519,
        }
    }
}

use once_cell::sync::OnceCell;

static VAULT_CONFIG: OnceCell<Box<dyn VaultConfig>> = OnceCell::new();

pub trait VaultConfig: Send + Sync {
    unsafe fn as_vault_config(&self) -> ockam_vault_sys::OCKAM_VAULT_CFG_s;
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Config<T, H> {
    tpm: Option<T>,
    host: Option<H>,
    curve: Curve,
}
impl<T, H> Config<T, H> {
    pub fn new(tpm: Option<T>, host: Option<H>, curve: Curve) -> Self {
        Self { tpm, host, curve }
    }
}
impl<T, H> VaultConfig for Config<T, H> {
    unsafe fn as_vault_config(&self) -> ockam_vault_sys::OCKAM_VAULT_CFG_s {
        use ockam_vault_sys::OCKAM_VAULT_CFG_s;
        OCKAM_VAULT_CFG_s {
            p_tpm: self
                .tpm
                .as_ref()
                .map(|t| t as *const _ as *mut _)
                .unwrap_or_else(|| ptr::null_mut()),
            p_host: self
                .host
                .as_ref()
                .map(|h| h as *const _ as *mut _)
                .unwrap_or_else(|| ptr::null_mut()),
            ec: self.curve.into(),
        }
    }
}
unsafe impl<T, H> Send for Config<T, H> {}
unsafe impl<T, H> Sync for Config<T, H> {}

/// Initialize the vault using the provided configuration.
///
/// Expected to be called only once globally.
pub fn init(config: Box<dyn VaultConfig>) -> VaultResult<()> {
    VAULT_CONFIG
        .set(config)
        .map_err(|_| VaultError::VAULT_ALREADY_INIT)?;
    let raw_config = VAULT_CONFIG
        .get()
        .map(|c| unsafe { c.as_vault_config() })
        .unwrap();
    let config_ptr = &raw_config as *const _ as *mut _;
    VaultError::wrap(|| unsafe { ockam_vault_sys::ockam_vault_init(config_ptr) })
}

/// Writes random bytes to the given slice
///
/// Returns `Ok` if successful, `Err(reason)` otherwise
///
/// It is recommended to use the `rand` module rather than use this directly
pub fn random(bytes: &mut [u8]) -> VaultResult<()> {
    let ptr = bytes.as_mut_ptr();
    let len = bytes.len() as u32;
    VaultError::wrap(|| unsafe { ockam_vault_sys::ockam_vault_random(ptr, len) })
}

/// Generate an ECC keypair
pub fn key_gen(key_type: KeyType) -> VaultResult<()> {
    VaultError::wrap(|| unsafe { ockam_vault_sys::ockam_vault_key_gen(key_type.into()) })
}

/// Get a public key from the vault for the given type
pub fn get_public_key(key_type: KeyType) -> VaultResult<Vec<u8>> {
    let mut buffer = Vec::with_capacity(32);
    get_public_key_with_buffer(key_type, buffer.as_mut_slice())?;
    Ok(buffer)
}

/// Get a public key from the vault for the given type, using the provided buffer
pub fn get_public_key_with_buffer(key_type: KeyType, buffer: &mut [u8]) -> VaultResult<()> {
    let ptr = buffer.as_mut_ptr();
    let len = buffer.len() as u32;
    VaultError::wrap(|| unsafe {
        ockam_vault_sys::ockam_vault_key_get_pub(key_type.into(), ptr, len)
    })
}

/// Write a private key to the Ockam Vault. Should typically be used for testing only.
pub fn write_public_key(key_type: KeyType, privkey: &[u8]) -> VaultResult<()> {
    let ptr = privkey.as_ptr() as *mut _;
    let len = privkey.len() as u32;
    VaultError::wrap(|| unsafe {
        ockam_vault_sys::ockam_vault_key_write(key_type.into(), ptr, len)
    })
}

/// Perform ECDH using the specified key
///
/// Returns the pre-master secret key
///
/// - `key_type`: The key type to use
/// - `pubkey`: The public key to use
pub fn ecdh(key_type: KeyType, pubkey: &[u8]) -> VaultResult<Vec<u8>> {
    let mut buffer = Vec::with_capacity(32);
    ecdh_with_buffer(key_type, pubkey, buffer.as_mut_slice())?;
    Ok(buffer)
}

/// Same as `ecdh`, but takes an output buffer to write to
pub fn ecdh_with_buffer(key_type: KeyType, pubkey: &[u8], buffer: &mut [u8]) -> VaultResult<()> {
    let ptr = pubkey.as_ptr() as *mut _;
    let len = pubkey.len() as u32;
    let pmk_ptr = buffer.as_mut_ptr();
    let pmk_len = buffer.len() as u32;
    VaultError::wrap(|| unsafe {
        ockam_vault_sys::ockam_vault_ecdh(key_type.into(), ptr, len, pmk_ptr, pmk_len)
    })
}

/// Perform a SHA256 operation on the message passed in.
pub fn sha256(bytes: &[u8]) -> VaultResult<Vec<u8>> {
    let ptr = bytes.as_ptr() as *mut _;
    let len = bytes.len() as u16;

    let mut hash = Vec::with_capacity(32);
    let hash_ptr = hash.as_mut_ptr();
    let hash_len = hash.len() as u8;
    VaultError::wrap(|| unsafe {
        ockam_vault_sys::ockam_vault_sha256(ptr, len, hash_ptr, hash_len)
    })?;
    Ok(hash)
}

/// Perform HKDF operation on the input key material and optional salt and info.
pub fn hkdf(salt: &[u8], key: &[u8], info: Option<&[u8]>) -> VaultResult<Vec<u8>> {
    let mut buffer = Vec::with_capacity(32);
    hkdf_with_buffer(salt, key, info, buffer.as_mut_slice())?;
    Ok(buffer)
}

/// Same as `hkdf`, but takes an output buffer to write to
pub fn hkdf_with_buffer(
    salt: &[u8],
    key: &[u8],
    info: Option<&[u8]>,
    buffer: &mut [u8],
) -> VaultResult<()> {
    let result_ptr = buffer.as_mut_ptr();
    let result_len = buffer.len() as u32;
    let salt_ptr = salt.as_ptr();
    let salt_len = salt.len() as u32;
    let key_ptr = key.as_ptr();
    let key_len = key.len() as u32;
    let info_ptr = info.map(|b| b.as_ptr()).unwrap_or_else(|| ptr::null());
    let info_len = info.map(|b| b.len() as u32).unwrap_or_default();
    VaultError::wrap(|| unsafe {
        ockam_vault_sys::ockam_vault_hkdf(
            salt_ptr as *mut _,
            salt_len,
            key_ptr as *mut _,
            key_len,
            info_ptr as *mut _,
            info_len,
            result_ptr,
            result_len,
        )
    })
}

/// AES GCM function for encrypt. Depending on underlying implementation, Vault may support
/// 128, 192 and/or 256 variants.
pub fn aes_gcm_encrypt(
    input: &[u8],
    key: &[u8],
    iv: &[u8],
    additional_data: Option<&[u8]>,
    tag: &[u8],
) -> VaultResult<Vec<u8>> {
    let mut buffer = Vec::with_capacity(input.len());
    aes_gcm_with_buffer(
        AesGcmMode::Encrypt,
        input,
        key,
        iv,
        additional_data,
        tag,
        buffer.as_mut_slice(),
    )?;
    Ok(buffer)
}

/// Same as `aes_gcm_encrypt`, but takes a buffer to write the output to
#[inline]
pub fn aes_gcm_encrypt_with_buffer(
    input: &[u8],
    key: &[u8],
    iv: &[u8],
    additional_data: Option<&[u8]>,
    tag: &[u8],
    buffer: &mut [u8],
) -> VaultResult<()> {
    aes_gcm_with_buffer(
        AesGcmMode::Encrypt,
        input,
        key,
        iv,
        additional_data,
        tag,
        buffer,
    )
}

/// AES GCM function for decrypt. Depending on underlying implementation, Vault may support
/// 128, 192 and/or 256 variants.
pub fn aes_gcm_decrypt(
    input: &[u8],
    key: &[u8],
    iv: &[u8],
    additional_data: Option<&[u8]>,
    tag: &[u8],
) -> VaultResult<Vec<u8>> {
    let mut buffer = Vec::with_capacity(input.len());
    aes_gcm_with_buffer(
        AesGcmMode::Decrypt,
        input,
        key,
        iv,
        additional_data,
        tag,
        buffer.as_mut_slice(),
    )?;
    Ok(buffer)
}

/// Same as `aes_gcm_decrypt`, but takes a buffer to write the output to
#[inline]
pub fn aes_gcm_decrypt_with_buffer(
    input: &[u8],
    key: &[u8],
    iv: &[u8],
    additional_data: Option<&[u8]>,
    tag: &[u8],
    buffer: &mut [u8],
) -> VaultResult<()> {
    aes_gcm_with_buffer(
        AesGcmMode::Decrypt,
        input,
        key,
        iv,
        additional_data,
        tag,
        buffer,
    )
}

fn aes_gcm_with_buffer(
    mode: AesGcmMode,
    input: &[u8],
    key: &[u8],
    iv: &[u8],
    additional_data: Option<&[u8]>,
    tag: &[u8],
    buffer: &mut [u8],
) -> VaultResult<()> {
    let input_ptr = input.as_ptr();
    let input_len = input.len() as u32;
    let key_ptr = key.as_ptr();
    let key_len = key.len() as u32;
    let iv_ptr = iv.as_ptr();
    let iv_len = iv.len() as u32;
    let data_ptr = additional_data
        .map(|b| b.as_ptr())
        .unwrap_or_else(|| ptr::null());
    let data_len = additional_data.map(|b| b.len() as u32).unwrap_or_default();
    let tag_ptr = tag.as_ptr();
    let tag_len = tag.len() as u32;
    let output_ptr = buffer.as_mut_ptr();
    let output_len = buffer.len() as u32;
    VaultError::wrap(|| unsafe {
        ockam_vault_sys::ockam_vault_aes_gcm(
            mode.into(),
            key_ptr as *mut _,
            key_len,
            iv_ptr as *mut _,
            iv_len,
            data_ptr as *mut _,
            data_len,
            tag_ptr as *mut _,
            tag_len,
            input_ptr as *mut _,
            input_len,
            output_ptr,
            output_len,
        )
    })
}
