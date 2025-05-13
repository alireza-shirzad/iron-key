use std::collections::LinkedList;

use ark_ff::PrimeField;
use ark_piop::{arithmetic::mat_poly::mle::MLE, pcs::PCS};
use ark_serialize::CanonicalSerialize;

use crate::{VKDResult, errors::VKDError};

use super::{BulletinBoard, errors::BulletinBoardError};

#[derive(Default)]
pub struct DummyBB {
    ledger: LinkedList<Vec<u8>>,
    size: usize,
}

impl BulletinBoard for DummyBB {
    fn broadcast(&mut self, message: &[u8]) -> VKDResult<()> {
        self.size += message.serialized_size(ark_serialize::Compress::Yes);
        self.ledger.push_front(message.to_vec());
        Ok(())
    }

    fn read_last(&self) -> VKDResult<Vec<u8>> {
        self.ledger
            .front()
            .cloned()
            .ok_or(VKDError::BulletinBoardError(BulletinBoardError::Empty))
    }

    fn read(&self, epoch_num: usize) -> VKDResult<Vec<u8>> {
        self.ledger
            .iter()
            .nth(epoch_num)
            .cloned()
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
