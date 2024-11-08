use speck_cipher::{cipher::{BlockEncrypt, KeyInit}, Speck128_256};
use poly1305::Poly1305;
use rand_chacha::ChaCha20Rng;


type Key = [u8; 32]; // 256 bit / 32 byte key
type Tag = [u8; 16]; // 128 bit / 16 byte tag
type Challenge = [u8; 12]; // 96 bit / 12 byte nonce

pub fn validate_tag(
    tag: Tag,
    key: Key,
    challenge: Challenge,
    client_id: &str
) -> bool {
    let Ok(hash) = Poly1305::new_from_slice(&key) else { return false };
    let Ok(cipher) = Speck128_256::new_from_slice(&key) else { return false };
    let preimage = [client_id.as_bytes(), challenge.as_slice()].concat();
    let mut digest = hash.compute_unpadded(&preimage);
    cipher.encrypt_block(digest.as_mut_slice().into());
    let mut expected_tag = [0u8; 16];
    expected_tag.clone_from_slice(&digest.as_slice()[..16]);

    // constant time comparison (hopefully)
    let mut eq = true;
    for (b1, b2) in tag.iter().zip(expected_tag.iter()) {
        if b1 != b2 { eq = false }
    }
    return eq
}

pub fn compute_tag(
    key: Key,
    challenge: Challenge,
    client_id: &str
) -> Option<Tag> {
    let Ok(hash) = Poly1305::new_from_slice(&key) else { return None };
    let Ok(cipher) = Speck128_256::new_from_slice(&key) else { return None };
    let preimage = [challenge.as_slice(), client_id.as_bytes()].concat();
    let mut digest = hash.compute_unpadded(&preimage);
    cipher.encrypt_block(digest.as_mut_slice().into());
    let mut tag = [0u8; 16];
    tag.clone_from_slice(&digest.as_slice()[..16]);
    return Some(tag)
}
