use anyhow::Result;
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::RngCore;
use zeroize::ZeroizeOnDrop;

/// 32-byte encryption key.
#[derive(ZeroizeOnDrop)]
pub struct EncryptionKey([u8; 32]);

impl EncryptionKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
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

/// Generate a random 32-byte encryption key (no Argon2id derivation).
pub fn generate_key() -> EncryptionKey {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    EncryptionKey(key)
}

/// Load an existing key from bytes, or return None if wrong length.
pub fn load_key(bytes: &[u8]) -> Option<EncryptionKey> {
    if bytes.len() != 32 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(bytes);
    Some(EncryptionKey(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let key = generate_key();
        let plaintext = b"hello, sirr!";
        let (ct, nonce) = encrypt(&key, plaintext).unwrap();
        let pt = decrypt(&key, &ct, &nonce).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = generate_key();
        let key2 = generate_key();
        let (ct, nonce) = encrypt(&key1, b"secret").unwrap();
        assert!(decrypt(&key2, &ct, &nonce).is_err());
    }

    #[test]
    fn generate_key_round_trip() {
        let key = generate_key();
        let plaintext = b"test with generated key";
        let (ct, nonce) = encrypt(&key, plaintext).unwrap();
        let pt = decrypt(&key, &ct, &nonce).unwrap();
        assert_eq!(pt, plaintext);
    }
}
