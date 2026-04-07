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
use crate::errors::CryptoError;

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
    ) -> Result<SessionKey, CryptoError> {
        let peer = PublicKey::from_sec1_bytes(peer_public_bytes)
            .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;
        let shared = self.secret.diffie_hellman(&peer);
        Ok(SessionKey::from_shared_secret(shared.raw_secret_bytes()))
    }
}

/// Held by the beacon between sending a request and receiving a response.
/// The private key exists only during this window, then is consumed on decrypt.
pub struct ResponseKeypair {
    secret: EphemeralSecret,
    public: PublicKey,
}

impl ResponseKeypair {
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random(&mut OsRng);
        let public = secret.public_key();
        ResponseKeypair { secret, public }
    }

    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    }

    /// Decrypt a server response. Consumes the keypair — private key is gone after this.
    pub fn decrypt_response(
        self,
        ciphertext: &[u8],
        server_pub_bytes: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let server_pub = PublicKey::from_sec1_bytes(server_pub_bytes)
            .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;

        let shared = self.secret.diffie_hellman(&server_pub);
        let response_key = SessionKey::from_shared_secret(shared.raw_secret_bytes());
        response_key.decrypt(ciphertext)
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

    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let secret = SecretKey::from_slice(bytes)
            .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;
        let public = secret.public_key();
        Ok(StaticKeypair { secret, public })
    }

    pub fn secret_bytes_hex(&self) -> String {
        hex::encode(self.secret.to_bytes())
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
    ) -> Result<SessionKey, CryptoError> {
        let peer = PublicKey::from_sec1_bytes(peer_public_bytes)
            .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;
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
    
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        let mut nonce_bytes = [0u8; 12];
        rand::RngCore::fill_bytes(&mut OsRng, &mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        let mut output = Vec::with_capacity(12 + ciphertext.len());
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);

        Ok(output)
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if data.len() < 12 {
            return Err(CryptoError::CiphertextTooShort(data.len()));
        }

        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
        let nonce = Nonce::from_slice(&data[..12]);
        let ciphertext = &data[12..];

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

        Ok(plaintext)
    }
}

impl Drop for SessionKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

pub fn key_id(public_key_bytes: &[u8]) -> [u8; 4] {
    let mut hasher = Sha256::new();
    hasher.update(public_key_bytes);
    let hash = hasher.finalize();
    let mut id = [0u8; 4];
    id.copy_from_slice(&hash[..4]);
    id
}

/// Encrypt a message for the server using per-message ephemeral keys.
/// The ephemeral private key exists only for the duration of this call.
/// Returns: [33 bytes ephemeral pubkey][nonce][ciphertext][tag]
pub fn encrypt_for_server(
    plaintext: &[u8],
    server_pub_bytes: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let ephemeral = EphemeralKeypair::generate();
    let eph_pub = ephemeral.public_key_bytes();

    // Derive one-time key — ephemeral private key is consumed here
    let one_time_key = ephemeral.derive_session_key(server_pub_bytes)?;

    // Encrypt — one_time_key is zeroized on drop after this
    let ciphertext = one_time_key.encrypt(plaintext)?;

    // Wire: [33 bytes eph pubkey][ciphertext]
    let mut output = Vec::with_capacity(33 + ciphertext.len());
    output.extend_from_slice(&eph_pub);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

/// Encrypt a message for the server AND request a response.
/// Returns the encrypted payload and the response keypair's private half
/// so the caller can decrypt the response.
/// Wire: [33 bytes send pubkey][33 bytes response pubkey][ciphertext]
pub fn encrypt_for_server_with_response(
    plaintext: &[u8],
    server_pub_bytes: &[u8],
) -> Result<(Vec<u8>, ResponseKeypair), CryptoError> {
    let send_ephemeral = EphemeralKeypair::generate();
    let send_pub = send_ephemeral.public_key_bytes();

    let response_kp = ResponseKeypair::generate();
    let response_pub = response_kp.public_key_bytes();

    // Derive one-time send key — send ephemeral consumed
    let one_time_key = send_ephemeral.derive_session_key(server_pub_bytes)?;
    let ciphertext = one_time_key.encrypt(plaintext)?;

    let mut output = Vec::with_capacity(33 + 33 + ciphertext.len());
    output.extend_from_slice(&send_pub);
    output.extend_from_slice(&response_pub);
    output.extend_from_slice(&ciphertext);

    Ok((output, response_kp))
}

/// Server-side: decrypt a per-message ephemeral payload.
/// Expects: [33 bytes ephemeral pubkey][ciphertext]
pub fn decrypt_from_beacon(
    data: &[u8],
    server_keypair: &StaticKeypair,
) -> Result<Vec<u8>, CryptoError> {
    if data.len() < 34 {
        return Err(CryptoError::CiphertextTooShort(data.len()));
    }

    let eph_pub = &data[..33];
    let ciphertext = &data[33..];

    let one_time_key = server_keypair.derive_session_key(eph_pub)?;
    let plaintext = one_time_key.decrypt(ciphertext)?;

    Ok(plaintext)
}

/// Server-side: decrypt a payload that includes a response pubkey.
/// Expects: [33 bytes send pubkey][33 bytes response pubkey][ciphertext]
/// Returns plaintext and the response pubkey for encrypting the reply.
pub fn decrypt_from_beacon_with_response(
    data: &[u8],
    server_keypair: &StaticKeypair,
) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    if data.len() < 67 {
        return Err(CryptoError::CiphertextTooShort(data.len()));
    }

    let send_pub = &data[..33];
    let response_pub = &data[33..66];
    let ciphertext = &data[66..];

    let one_time_key = server_keypair.derive_session_key(send_pub)?;
    let plaintext = one_time_key.decrypt(ciphertext)?;

    Ok((plaintext, response_pub.to_vec()))
}

/// Server-side: encrypt a response for a specific beacon.
/// Uses the response pubkey the beacon provided.
pub fn encrypt_response(
    plaintext: &[u8],
    beacon_response_pub: &[u8],
    server_keypair: &StaticKeypair,
) -> Result<Vec<u8>, CryptoError> {
    let peer = PublicKey::from_sec1_bytes(beacon_response_pub)
        .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;

    let shared = p256::ecdh::diffie_hellman(
        server_keypair.secret.to_nonzero_scalar(),
        peer.as_affine(),
    );

    let response_key = SessionKey::from_shared_secret(shared.raw_secret_bytes());
    response_key.encrypt(plaintext)
}