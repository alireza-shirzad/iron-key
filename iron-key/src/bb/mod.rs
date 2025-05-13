pub mod dummybb;
pub mod errors;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::VKDResult;

pub trait BulletinBoard {
    fn is_empty(&self) -> bool {
        self.size() == 0
    }
    fn broadcast(&mut self, message: &[u8]) -> VKDResult<()>;
    fn read_last(&self) -> VKDResult<Vec<u8>>;
    fn read(&self, epoch_num: usize) -> VKDResult<Vec<u8>>;
    fn num_epochs(&self) -> usize;
    fn size(&self) -> usize;
}
