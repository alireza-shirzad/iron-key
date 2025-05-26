use std::error;

use thiserror::Error;

/// An `enum` specifying the possible failure modes of the DB-SNARK system.
#[derive(Error, Debug)]
#[allow(private_interfaces)]
pub(crate) enum AuditorError {}
