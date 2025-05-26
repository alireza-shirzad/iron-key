use crate::{
    bb::errors::BulletinBoardError, client::errors::ClientError, server::errors::ServerError,
    structs::dictionary::DictionaryError,
};
use thiserror::Error;
/// An `enum` specifying the possible failure modes of the DB-SNARK system.
#[derive(Error, Debug)]
#[allow(private_interfaces)]
pub enum VKDError {

    #[error("Dictionary Error")]
    DictionaryError(#[from] DictionaryError),

    #[error("Server Error")]
    ServerError(#[from] ServerError),

    #[error("Server Error")]
    ClientError(#[from] ClientError),

    #[error("Bulletin Board Error")]
    BulletinBoardError(#[from] BulletinBoardError),
}
