pub mod dummybb;
pub mod errors;
use ark_serialize::CanonicalSerialize;

use crate::VKDResult;

pub trait BulletinBoard {
    type Message: CanonicalSerialize;

    fn is_empty(&self) -> bool {
        self.size() == 0
    }
    fn broadcast(&mut self, message: Self::Message) -> VKDResult<()>;
    fn read_last(&self) -> VKDResult<&Self::Message>;
    fn read(&self, epoch_num: usize) -> VKDResult<&Self::Message>;
    fn num_epochs(&self) -> usize;
    fn size(&self) -> usize;
}
