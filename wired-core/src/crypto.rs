use thiserror::Error;

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("system random generation failed")]
    Random,
    #[error("decryption failed")]
    Decrypt,
}

pub fn random_salt() -> Result<[u8; SALT_LEN], CryptoError> {
    let mut salt = [0u8; SALT_LEN];
    fill_random(&mut salt)?;
    Ok(salt)
}

pub fn random_nonce() -> Result<[u8; NONCE_LEN], CryptoError> {
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce)?;
    Ok(nonce)
}

pub fn derive_key(key: &[u8], salt: &[u8; SALT_LEN]) -> [u8; 32] {
    hash32(&[b"wired-transport key v1", salt, key])
}

pub fn mapping_seed(key: &[u8], salt: &[u8; SALT_LEN]) -> [u8; 32] {
    hash32(&[b"wired-transport pixel-map v1", salt, key])
}

#[cfg(not(target_arch = "wasm32"))]
pub fn encrypt(
    plaintext: &[u8],
    key: &[u8],
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>, CryptoError> {
    use ring::aead;

    let raw_key = derive_key(key, salt);
    let unbound = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &raw_key)
        .map_err(|_| CryptoError::Decrypt)?;
    let sealing_key = aead::LessSafeKey::new(unbound);
    let nonce = aead::Nonce::assume_unique_for_key(*nonce);
    let mut in_out = plaintext.to_vec();

    sealing_key
        .seal_in_place_append_tag(nonce, aead::Aad::from(b"wired-transport-v1"), &mut in_out)
        .map_err(|_| CryptoError::Decrypt)?;

    Ok(in_out)
}

#[cfg(not(target_arch = "wasm32"))]
pub fn decrypt(
    ciphertext: &[u8],
    key: &[u8],
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>, CryptoError> {
    use ring::aead;

    let raw_key = derive_key(key, salt);
    let unbound = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &raw_key)
        .map_err(|_| CryptoError::Decrypt)?;
    let opening_key = aead::LessSafeKey::new(unbound);
    let nonce = aead::Nonce::assume_unique_for_key(*nonce);
    let mut in_out = ciphertext.to_vec();
    let plain = opening_key
        .open_in_place(nonce, aead::Aad::from(b"wired-transport-v1"), &mut in_out)
        .map_err(|_| CryptoError::Decrypt)?;

    Ok(plain.to_vec())
}

#[cfg(target_arch = "wasm32")]
pub fn encrypt(
    plaintext: &[u8],
    key: &[u8],
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>, CryptoError> {
    use chacha20poly1305::aead::{AeadInPlace, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};

    let raw_key = derive_key(key, salt);
    let cipher = ChaCha20Poly1305::new_from_slice(&raw_key).map_err(|_| CryptoError::Decrypt)?;
    let nonce = Nonce::from_slice(nonce);
    let mut in_out = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(nonce, b"wired-transport-v1", &mut in_out)
        .map_err(|_| CryptoError::Decrypt)?;
    in_out.extend_from_slice(&tag);
    Ok(in_out)
}

#[cfg(target_arch = "wasm32")]
pub fn decrypt(
    ciphertext: &[u8],
    key: &[u8],
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>, CryptoError> {
    use chacha20poly1305::aead::{AeadInPlace, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce, Tag};

    if ciphertext.len() < 16 {
        return Err(CryptoError::Decrypt);
    }

    let raw_key = derive_key(key, salt);
    let cipher = ChaCha20Poly1305::new_from_slice(&raw_key).map_err(|_| CryptoError::Decrypt)?;
    let nonce = Nonce::from_slice(nonce);
    let (body, tag) = ciphertext.split_at(ciphertext.len() - 16);
    let mut in_out = body.to_vec();
    cipher
        .decrypt_in_place_detached(
            nonce,
            b"wired-transport-v1",
            &mut in_out,
            Tag::from_slice(tag),
        )
        .map_err(|_| CryptoError::Decrypt)?;
    Ok(in_out)
}

pub fn digest16(parts: &[&[u8]]) -> [u8; 16] {
    let digest = hash32(parts);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

#[cfg(not(target_arch = "wasm32"))]
fn fill_random(out: &mut [u8]) -> Result<(), CryptoError> {
    use ring::rand;

    let rng = rand::SystemRandom::new();
    rand::SecureRandom::fill(&rng, out).map_err(|_| CryptoError::Random)
}

#[cfg(target_arch = "wasm32")]
fn fill_random(out: &mut [u8]) -> Result<(), CryptoError> {
    getrandom::getrandom(out).map_err(|_| CryptoError::Random)
}

#[cfg(not(target_arch = "wasm32"))]
fn hash32(parts: &[&[u8]]) -> [u8; 32] {
    use ring::digest;

    let mut ctx = digest::Context::new(&digest::SHA256);
    for part in parts {
        ctx.update(part);
    }
    let digest = ctx.finish();
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

#[cfg(target_arch = "wasm32")]
fn hash32(parts: &[&[u8]]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}
