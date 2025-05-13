use crate::{
    bb::errors::BulletinBoardError, server::errors::ServerError,
    structs::dictionary::DictionaryError,
};
use ark_piop::errors::SnarkError;
use thiserror::Error;
/// An `enum` specifying the possible failure modes of the DB-SNARK system.
#[derive(Error, Debug)]
#[allow(private_interfaces)]
pub enum VKDError {
    #[error("Snark Error")]
    SnarkError(#[from] SnarkError),

    #[error("Dictionary Error")]
    DictionaryError(#[from] DictionaryError),

    #[error("Server Error")]
    ServerError(#[from] ServerError),

    #[error("Bulletin Board Error")]
    BulletinBoardError(#[from] BulletinBoardError),
}
