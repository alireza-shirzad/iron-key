use std::collections::LinkedList;

use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;

use ark_poly::DenseMultilinearExtension;
use ark_serialize::CanonicalSerialize;
use derivative::Derivative;
use subroutines::PolynomialCommitmentScheme;

use crate::{VKDResult, errors::VKDError, structs::update::IronEpochMessage};

use super::{BulletinBoard, errors::BulletinBoardError};

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct DummyBB<
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<E, Polynomial = DenseMultilinearExtension<E::ScalarField>, Point = Vec<<E as Pairing>::ScalarField>>
        + Send
        + Sync,
> {
    ledger: LinkedList<IronEpochMessage<E, MvPCS>>,
    size: usize,
}

impl<
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<E, Polynomial = DenseMultilinearExtension<E::ScalarField>, Point = Vec<<E as Pairing>::ScalarField>>
        + Send
        + Sync,
> BulletinBoard for DummyBB<E, MvPCS>
{
    type Message = IronEpochMessage<E, MvPCS>;

    fn broadcast(&mut self, message: IronEpochMessage<E, MvPCS>) -> VKDResult<()> {
        self.size += message.serialized_size(ark_serialize::Compress::Yes);
        self.ledger.push_front(message);
        Ok(())
    }

    fn read_last(&self) -> VKDResult<&IronEpochMessage<E, MvPCS>> {
        self.ledger
            .front()
            .ok_or(VKDError::BulletinBoardError(BulletinBoardError::Empty))
    }

    fn read(&self, epoch_num: usize) -> VKDResult<&IronEpochMessage<E, MvPCS>> {
        self.ledger
            .iter()
            .nth(epoch_num)
            .ok_or(VKDError::BulletinBoardError(
                BulletinBoardError::OutOfBounds,
            ))
    }

    fn num_epochs(&self) -> usize {
        self.ledger.len()
    }

    fn size(&self) -> usize {
        self.size
    }
}
