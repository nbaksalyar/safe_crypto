// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

//! Crypto primitives

use super::Signature;
use ed25519_dalek::{Keypair, PublicKey, SecretKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH};
use errors::EncryptionError;
use maidsafe_utilities::serialisation::{deserialise, serialise};
use miscreant::siv::Aes128PmacSiv;
use rand::Rng;
use sha3::Sha3_512;
use x25519_dalek::{diffie_hellman, generate_public, generate_secret};

pub const SYMMETRIC_KEY_LEN: usize = 256 / 8;
pub const SIGN_PK_LEN: usize = PUBLIC_KEY_LENGTH;
pub const SIGN_SK_LEN: usize = SECRET_KEY_LENGTH;
pub const ENC_PK_LEN: usize = 32;
pub const ENC_SK_LEN: usize = 32;

#[derive(Serialize, Deserialize)]
struct CipherText {
    ephemeral_pk: [u8; ENC_PK_LEN],
    ciphertext: Vec<u8>,
}

pub fn encrypt_symmetric(
    sk: &[u8; SYMMETRIC_KEY_LEN],
    plaintext: &[u8],
    associated_data: &[u8],
) -> Vec<u8> {
    let mut enc = Aes128PmacSiv::new(sk);
    enc.seal(&[associated_data], plaintext)
}

pub fn decrypt_symmetric(
    sk: &[u8],
    ciphertext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    let mut dec = Aes128PmacSiv::new(sk);
    dec.open(&[associated_data], ciphertext)
        .map_err(EncryptionError::SymmetricError)
}

pub fn sign_detached(
    our_sk: &[u8; SECRET_KEY_LENGTH],
    message: &[u8],
) -> Result<Signature, EncryptionError> {
    let secret = SecretKey::from_bytes(our_sk).map_err(EncryptionError::DecodingError)?;
    let public = PublicKey::from_secret::<Sha3_512>(&secret);

    let keypair = Keypair { secret, public };
    let signature = keypair.sign::<Sha3_512>(message);

    Ok(Signature {
        internal: signature,
    })
}

pub fn verify_detached(
    their_pk: &[u8; PUBLIC_KEY_LENGTH],
    message: &[u8],
    signature: &Signature,
) -> Result<bool, EncryptionError> {
    let pk = PublicKey::from_bytes(their_pk).map_err(EncryptionError::DecodingError)?;
    Ok(pk.verify::<Sha3_512>(message, &signature.internal))
}

pub fn encrypt_anonymous<R: Rng>(
    csprng: &mut R,
    their_pk: &[u8; ENC_PK_LEN],
    plaintext: &[u8],
) -> Vec<u8> {
    // Generate an ephemeral key
    let our_sk = generate_secret(csprng);
    let our_pk = generate_public(&our_sk);

    let shared_secret = compute_shared_key(&our_sk, &their_pk);

    let ciphertext = encrypt(&shared_secret, &our_pk.as_bytes(), plaintext);
    serialise(&CipherText {
        ephemeral_pk: *our_pk.as_bytes(),
        ciphertext,
    }).unwrap()
}

pub fn decrypt_anonymous(
    our_sk: &[u8; ENC_SK_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    let CipherText {
        ephemeral_pk,
        ciphertext,
    } = deserialise(ciphertext)?;

    let shared_secret = compute_shared_key(&our_sk, &ephemeral_pk);

    decrypt(&shared_secret, &ephemeral_pk, &ciphertext)
}

pub fn compute_shared_key(our_sk: &[u8; ENC_SK_LEN], their_pk: &[u8; ENC_PK_LEN]) -> [u8; 32] {
    diffie_hellman(our_sk, their_pk)
}

pub fn encrypt(
    our_sk: &[u8; ENC_SK_LEN],
    their_pk: &[u8; ENC_PK_LEN],
    plaintext: &[u8],
) -> Vec<u8> {
    let shared_sk = compute_shared_key(our_sk, their_pk);
    encrypt_symmetric(&shared_sk, plaintext, their_pk)
}

pub fn decrypt(
    our_sk: &[u8; ENC_SK_LEN],
    their_pk: &[u8; ENC_PK_LEN],
    ciphertext: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    let shared_sk = compute_shared_key(our_sk, their_pk);
    decrypt_symmetric(&shared_sk, ciphertext, their_pk)
}
