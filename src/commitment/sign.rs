//! Optional Ed25519 signing of the run root.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Status of a signature verification attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureStatus {
    /// Signature valid for the stated public key and root.
    Valid,
    /// Signature bytes invalid for key/root.
    Invalid,
    /// Public key unknown / not in trust set.
    UnknownKey,
    /// Key explicitly revoked.
    RevokedKey,
    /// No signature present.
    Missing,
}

impl SignatureStatus {
    /// Stable string form.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Invalid => "invalid",
            Self::UnknownKey => "unknown_key",
            Self::RevokedKey => "revoked_key",
            Self::Missing => "missing",
        }
    }
}

/// Signed run root envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRunRoot {
    /// Algorithm identifier.
    pub alg: String,
    /// Hex-encoded 32-byte public key.
    pub public_key: String,
    /// Hex-encoded signature over `root_hash` UTF-8 bytes.
    pub signature: String,
    /// Root hash that was signed.
    pub root_hash: String,
}

/// Generate a new Ed25519 signing key.
pub fn generate_signing_key() -> SigningKey {
    let mut secret = [0u8; 32];
    rand::fill(&mut secret);
    SigningKey::from_bytes(&secret)
}

/// Hex public key for a signing key.
pub fn public_key_hex(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().as_bytes())
}

/// Sign a run root hash.
pub fn sign_run_root(key: &SigningKey, root_hash: &str) -> SignedRunRoot {
    let sig = key.sign(root_hash.as_bytes());
    SignedRunRoot {
        alg: "ed25519".into(),
        public_key: public_key_hex(key),
        signature: hex::encode(sig.to_bytes()),
        root_hash: root_hash.to_string(),
    }
}

/// Verify a signed run root against an optional trust set.
///
/// - `trusted_keys`: if `Some`, the public key must be in this set (hex).
/// - `revoked_keys`: if present in this set → `RevokedKey`.
///
/// Signature validation **never** upgrades the integrity of underlying
/// observations; it only attests the root hash bytes.
pub fn verify_run_root_signature(
    signed: &SignedRunRoot,
    expected_root: &str,
    trusted_keys: Option<&[String]>,
    revoked_keys: &[String],
) -> SignatureStatus {
    if signed.root_hash != expected_root {
        return SignatureStatus::Invalid;
    }
    if revoked_keys.iter().any(|k| k == &signed.public_key) {
        return SignatureStatus::RevokedKey;
    }
    if let Some(trust) = trusted_keys {
        if !trust.iter().any(|k| k == &signed.public_key) {
            return SignatureStatus::UnknownKey;
        }
    }
    let pk_bytes = match hex::decode(&signed.public_key) {
        Ok(b) if b.len() == 32 => b,
        _ => return SignatureStatus::Invalid,
    };
    let sig_bytes = match hex::decode(&signed.signature) {
        Ok(b) if b.len() == 64 => b,
        _ => return SignatureStatus::Invalid,
    };
    let pk_arr: [u8; 32] = match pk_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return SignatureStatus::Invalid,
    };
    let sig_arr: [u8; 64] = match sig_bytes.try_into() {
        Ok(a) => a,
        Err(_) => return SignatureStatus::Invalid,
    };
    let vk = match VerifyingKey::from_bytes(&pk_arr) {
        Ok(v) => v,
        Err(_) => return SignatureStatus::Invalid,
    };
    let sig = Signature::from_bytes(&sig_arr);
    match vk.verify(expected_root.as_bytes(), &sig) {
        Ok(()) => SignatureStatus::Valid,
        Err(_) => SignatureStatus::Invalid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let key = generate_signing_key();
        let root = "abcd".repeat(16);
        let signed = sign_run_root(&key, &root);
        assert_eq!(
            verify_run_root_signature(&signed, &root, None, &[]),
            SignatureStatus::Valid
        );
        assert_eq!(
            verify_run_root_signature(&signed, "other", None, &[]),
            SignatureStatus::Invalid
        );
    }

    #[test]
    fn unknown_and_revoked_keys() {
        let key = generate_signing_key();
        let root = "ff".repeat(32);
        let signed = sign_run_root(&key, &root);
        let pk = signed.public_key.clone();
        assert_eq!(
            verify_run_root_signature(&signed, &root, Some(&["00".repeat(32)]), &[]),
            SignatureStatus::UnknownKey
        );
        assert_eq!(
            verify_run_root_signature(&signed, &root, Some(std::slice::from_ref(&pk)), &[]),
            SignatureStatus::Valid
        );
        assert_eq!(
            verify_run_root_signature(&signed, &root, None, &[pk]),
            SignatureStatus::RevokedKey
        );
    }
}
