// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crypto::{
    compute_shared_key, decrypt_anonymous, encrypt_anonymous, sign_detached, verify_detached,
    ENC_PK_LEN, ENC_SK_LEN, SIGN_PK_LEN, SIGN_SK_LEN,
};
use ed25519_dalek::Keypair;
use errors::EncryptionError;
use maidsafe_utilities::serialisation;
use rand::Rng;
use serde::{de::DeserializeOwned, Serialize};
use sha3::Sha3_512;
use shared_secret::SharedSecretKey;
use std::sync::Arc;
use x25519_dalek::{generate_public, generate_secret};
use Signature;

#[derive(Debug, Serialize, Deserialize, Hash, PartialOrd, Ord, PartialEq, Eq, Clone)]
pub struct PublicId {
    sign: [u8; SIGN_PK_LEN],
    encrypt: [u8; ENC_PK_LEN],
}

impl PublicId {
    pub fn encrypt_anonymous<T, R: Rng>(
        &self,
        csprng: &mut R,
        plaintext: &T,
    ) -> Result<Vec<u8>, EncryptionError>
    where
        T: Serialize,
    {
        let bytes = serialisation::serialise(plaintext).map_err(EncryptionError::Serialisation)?;
        Ok(self.encrypt_anonymous_bytes(csprng, &bytes))
    }

    pub fn encrypt_anonymous_bytes<R: Rng>(&self, csprng: &mut R, plaintext: &[u8]) -> Vec<u8> {
        encrypt_anonymous(csprng, &self.encrypt, plaintext)
    }

    pub fn verify_detached(
        &self,
        signature: &Signature,
        data: &[u8],
    ) -> Result<bool, EncryptionError> {
        verify_detached(&self.sign, data, signature)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretId {
    inner: Arc<SecretIdInner>,
    public: PublicId,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct SecretIdInner {
    sign: [u8; SIGN_SK_LEN],
    encrypt: [u8; ENC_SK_LEN],
}

#[cfg_attr(feature = "cargo-clippy", allow(new_without_default))]
impl SecretId {
    pub fn new<R>(csprng: &mut R) -> SecretId
    where
        R: Rng,
    {
        let sign_keypair = Keypair::generate::<Sha3_512, R>(csprng);

        let encrypt_sk = generate_secret(csprng);
        let encrypt_pk = generate_public(&encrypt_sk);

        let public = PublicId {
            sign: *sign_keypair.public.as_bytes(),
            encrypt: *encrypt_pk.as_bytes(),
        };
        SecretId {
            public,
            inner: Arc::new(SecretIdInner {
                sign: *sign_keypair.secret.as_bytes(),
                encrypt: encrypt_sk,
            }),
        }
    }

    pub fn public_id(&self) -> &PublicId {
        &self.public
    }

    pub fn decrypt_anonymous<T>(&self, ciphertext: &[u8]) -> Result<T, EncryptionError>
    where
        T: Serialize + DeserializeOwned,
    {
        let bytes = self.decrypt_anonymous_bytes(ciphertext)?;
        Ok(serialisation::deserialise(&bytes)?)
    }

    pub fn decrypt_anonymous_bytes(&self, ciphertext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        decrypt_anonymous(&self.inner.encrypt, ciphertext)
    }

    pub fn sign_detached(&self, data: &[u8]) -> Result<Signature, EncryptionError> {
        sign_detached(&self.inner.sign, data)
    }

    pub fn shared_key(&self, their_pk: &PublicId) -> SharedSecretKey {
        let precomputed = compute_shared_key(&self.inner.encrypt, &their_pk.encrypt);
        SharedSecretKey {
            precomputed: Arc::new(precomputed),
            my_pk: self.public.encrypt.clone(),
            their_pk: their_pk.encrypt.clone(),
        }
    }
}
