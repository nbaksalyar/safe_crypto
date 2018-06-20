// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crypto::{decrypt_symmetric, encrypt_symmetric, ENC_PK_LEN, SYMMETRIC_KEY_LEN};
use errors::EncryptionError;
use maidsafe_utilities::serialisation;
use serde::{de::DeserializeOwned, Serialize};
use std::sync::Arc;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SharedSecretKey {
    pub(crate) precomputed: Arc<[u8; SYMMETRIC_KEY_LEN]>,
    pub(crate) their_pk: [u8; ENC_PK_LEN],
    pub(crate) my_pk: [u8; ENC_PK_LEN],
}

impl SharedSecretKey {
    pub fn encrypt_bytes(&self, plaintext: &[u8]) -> Vec<u8> {
        encrypt_symmetric(&*self.precomputed, plaintext, &self.their_pk)
    }

    pub fn encrypt<T>(&self, plaintext: &T) -> Result<Vec<u8>, EncryptionError>
    where
        T: Serialize,
    {
        let bytes = serialisation::serialise(plaintext)?;
        Ok(self.encrypt_bytes(&bytes))
    }

    pub fn decrypt_bytes(&self, ciphertext: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        decrypt_symmetric(&*self.precomputed, ciphertext, &self.my_pk)
    }

    pub fn decrypt<T>(&self, ciphertext: &[u8]) -> Result<T, EncryptionError>
    where
        T: Serialize + DeserializeOwned,
    {
        let bytes = self.decrypt_bytes(ciphertext)?;
        Ok(serialisation::deserialise(&bytes)?)
    }
}
