use thiserror::Error;

/// An `enum` specifying the possible failure modes of the bulletin board
#[derive(Error, Debug)]
#[allow(private_interfaces)]
pub(crate) enum BulletinBoardError {
    #[error("The index is out of bounds.")]
    OutOfBounds,

    #[error("The bulletin board is empty.")]
    Empty,
}
