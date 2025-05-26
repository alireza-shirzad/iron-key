use std::error;

use thiserror::Error;

/// An `enum` specifying the possible failure modes of the DB-SNARK system.
#[derive(Error, Debug)]
#[allow(private_interfaces)]
pub(crate) enum ClientError {
    #[error("Client does not know its index yet.")]
    UnknownIndex,

    #[error("the lookup verification failed.")]
    LookupFailed,

    #[error("The self audit verification failed.")]
    SelfAuditFailed,
}
