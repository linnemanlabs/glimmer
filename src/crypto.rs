use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use p256::{
    ecdh::EphemeralSecret,
    elliptic_curve::sec1::ToEncodedPoint,
    PublicKey, SecretKey,
};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

// Beacon-side: ephemeral keypair, used once

pub struct EphemeralKeypair {
    secret: EphemeralSecret,
    public: PublicKey,
}

impl EphemeralKeypair {
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random(&mut OsRng);
        let public = secret.public_key();
        EphemeralKeypair { secret, public }
    }

    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    }

    /// Consume the ephemeral secret to derive a session key.
    pub fn derive_session_key(
        self,
        peer_public_bytes: &[u8],
    ) -> Result<SessionKey, Box<dyn std::error::Error>> {
        let peer = PublicKey::from_sec1_bytes(peer_public_bytes)?;
        let shared = self.secret.diffie_hellman(&peer);
        Ok(SessionKey::from_shared_secret(shared.raw_secret_bytes()))
    }
}

// Server-side: static keypair, reusable

pub struct StaticKeypair {
    secret: SecretKey,
    public: PublicKey,
}

impl StaticKeypair {
    pub fn generate() -> Self {
        let secret = SecretKey::random(&mut OsRng);
        let public = secret.public_key();
        StaticKeypair { secret, public }
    }

    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    }

    /// Derive a session key using the server's static key and
    /// a beacon's ephemeral public key. Does not consume self.
    pub fn derive_session_key(
        &self,
        peer_public_bytes: &[u8],
    ) -> Result<SessionKey, Box<dyn std::error::Error>> {
        let peer = PublicKey::from_sec1_bytes(peer_public_bytes)?;
        let shared = p256::ecdh::diffie_hellman(
            self.secret.to_nonzero_scalar(),
            peer.as_affine(),
        );
        Ok(SessionKey::from_shared_secret(shared.raw_secret_bytes()))
    }
}

// Session Key

pub struct SessionKey {
    key: [u8; 32],
}

impl SessionKey {
    fn from_shared_secret(secret_bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(secret_bytes);
        let key: [u8; 32] = hasher.finalize().into();
        SessionKey { key }
    }

    // For development/testing only
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        SessionKey { key: bytes }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let cipher = Aes256Gcm::new_from_slice(&self.key)?;

        let mut nonce_bytes = [0u8; 12];
        rand::RngCore::fill_bytes(&mut OsRng, &mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| format!("encrypt: {}", e))?;

        let mut output = Vec::with_capacity(12 + ciphertext.len());
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);

        Ok(output)
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if data.len() < 12 {
            return Err("ciphertext too short".into());
        }

        let cipher = Aes256Gcm::new_from_slice(&self.key)?;
        let nonce = Nonce::from_slice(&data[..12]);
        let ciphertext = &data[12..];

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| format!("decrypt: {}", e))?;

        Ok(plaintext)
    }
}

impl Drop for SessionKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}