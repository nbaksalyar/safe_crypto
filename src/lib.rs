// Copyright 2018 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

extern crate maidsafe_utilities;
extern crate serde;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate quick_error;
extern crate ed25519_dalek;
extern crate miscreant;
extern crate rand;
extern crate sha3;
extern crate x25519_dalek;

mod crypto;
mod errors;
mod id;
mod shared_secret;
#[cfg(test)]
mod tests;

pub use errors::EncryptionError;
pub use id::{PublicId, SecretId};
pub use shared_secret::SharedSecretKey;

/* Hash, PartialEq, Eq, PartialOrd, Ord, */

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Signature {
    pub(crate) internal: ed25519_dalek::Signature,
}
