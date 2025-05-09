use crate::structs::dictionary::DictionaryError;
use ark_piop::errors::SnarkError;
use thiserror::Error;
/// An `enum` specifying the possible failure modes of the DB-SNARK system.
#[derive(Error, Debug)]
#[allow(private_interfaces)]
pub enum VKDError {
    #[error("Error")]
    SnarkError(#[from] SnarkError),

    #[error("Error")]
    DictionaryError(#[from] DictionaryError),
}
