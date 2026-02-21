use anyhow::{Context, Result};
use argon2::{password_hash::SaltString, Argon2, Params, PasswordHasher};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::RngCore;
use zeroize::ZeroizeOnDrop;

/// 32-byte encryption key derived from the master key via Argon2id.
#[derive(ZeroizeOnDrop)]
pub struct EncryptionKey([u8; 32]);

impl EncryptionKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Derive a 32-byte encryption key from `master_key` and `salt` using Argon2id.
/// The salt should be stored persistently (sirr.salt) and reused across restarts.
pub fn derive_key(master_key: &str, salt: &[u8; 32]) -> Result<EncryptionKey> {
    // Encode salt as base64 for argon2 SaltString
    let salt_b64 = base64_encode(salt);
    let salt_string = SaltString::from_b64(&salt_b64)
        .map_err(|e| anyhow::anyhow!("invalid salt for argon2: {e}"))?;

    let params = Params::new(
        65536, // m_cost: 64 MiB
        3,     // t_cost: 3 iterations
        1,     // p_cost: 1 lane
        Some(32),
    )
    .map_err(|e| anyhow::anyhow!("argon2 params: {e}"))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let hash = argon2
        .hash_password(master_key.as_bytes(), &salt_string)
        .map_err(|e| anyhow::anyhow!("argon2 hash: {e}"))?;

    let binding = hash.hash.context("no hash output")?;
    let hash_bytes = binding.as_bytes();

    let mut key = [0u8; 32];
    key.copy_from_slice(&hash_bytes[..32]);

    Ok(EncryptionKey(key))
}

/// Encrypt `plaintext` with `key`, returning `(ciphertext, nonce)`.
pub fn encrypt(key: &EncryptionKey, plaintext: &[u8]) -> Result<(Vec<u8>, [u8; 12])> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("encrypt: {e}"))?;

    Ok((ciphertext, nonce_bytes))
}

/// Decrypt `ciphertext` with `key` and `nonce`, returning plaintext.
pub fn decrypt(key: &EncryptionKey, ciphertext: &[u8], nonce_bytes: &[u8; 12]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
    let nonce = Nonce::from(*nonce_bytes);

    let plaintext = cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("decrypt: {e}"))?;

    Ok(plaintext)
}

/// Generate a fresh 32-byte random salt.
pub fn generate_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    OsRng.fill_bytes(&mut salt);
    salt
}

fn base64_encode(input: &[u8]) -> String {
    // argon2 SaltString requires URL-safe base64 without padding, max 64 chars.
    // We use a simple table rather than pulling in base64 crate.
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(TABLE[(n & 0x3f) as usize] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let salt = generate_salt();
        let key = derive_key("test-master-key", &salt).unwrap();
        let plaintext = b"hello, sirr!";
        let (ct, nonce) = encrypt(&key, plaintext).unwrap();
        let pt = decrypt(&key, &ct, &nonce).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let salt = generate_salt();
        let key1 = derive_key("key-one", &salt).unwrap();
        let key2 = derive_key("key-two", &salt).unwrap();
        let (ct, nonce) = encrypt(&key1, b"secret").unwrap();
        assert!(decrypt(&key2, &ct, &nonce).is_err());
    }
}
