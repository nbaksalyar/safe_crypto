// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use ed25519_dalek::DecodingError;
use maidsafe_utilities::serialisation::SerialisationError;
use miscreant::error::Error;

quick_error! {
    #[derive(Debug)]
    pub enum EncryptionError {
        DecryptVerify {
            description("error decrypting/verifying message")
        }
        Serialisation(e: SerialisationError) {
            description("error serialising/deserialising message")
            display("error serialising/deserialising message: {}", e)
            cause(e)
        }
        DecodingError(e: DecodingError) {
            description("error decoding secret or public key")
            display("error decoding key: {}", e)
        }
        SymmetricError(e: Error) {
            description("symmetric encryption/decryption failure")
            display("symmetric encryption/decryption error: {}", e)
            cause(e)
        }
    }
}

impl From<SerialisationError> for EncryptionError {
    fn from(e: SerialisationError) -> EncryptionError {
        EncryptionError::Serialisation(e)
    }
}
