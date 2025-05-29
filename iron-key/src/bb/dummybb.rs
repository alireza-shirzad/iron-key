use std::collections::LinkedList;

use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;

use ark_poly::DenseMultilinearExtension;
use ark_serialize::{CanonicalSerialize, Valid};
use derivative::Derivative;
use subroutines::{PolynomialCommitmentScheme, pcs::kzh::poly::DenseOrSparseMLE};

use crate::{
    VKDResult,
    errors::VKDError,
    structs::update::{IronEpochKeyMessage, IronEpochRegMessage},
};

use super::{BulletinBoard, errors::BulletinBoardError};

pub enum IronEpochMessage<
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        > + Send
        + Sync,
> {
    IronEpochKeyMessage(IronEpochKeyMessage<E, MvPCS>),
    IronEpochRegMessage(IronEpochRegMessage<E, MvPCS>),
}

impl<
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        > + Send
        + Sync,
> IronEpochMessage<E, MvPCS>
{
    pub fn get_key_message(&self) -> &IronEpochKeyMessage<E, MvPCS> {
        match self {
            IronEpochMessage::IronEpochKeyMessage(msg) => msg,
            _ => panic!("Called get_key_message() on non-key message variant"),
        }
    }

    pub fn get_reg_message(&self) -> &IronEpochRegMessage<E, MvPCS> {
        match self {
            IronEpochMessage::IronEpochRegMessage(msg) => msg,
            _ => panic!("Called get_reg_message() on non-reg message variant"),
        }
    }
}

impl<
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        > + Send
        + Sync,
> ark_serialize::CanonicalSerialize for IronEpochMessage<E, MvPCS>
{
    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        1 + match self {
            IronEpochMessage::IronEpochKeyMessage(msg) => msg.serialized_size(compress),
            IronEpochMessage::IronEpochRegMessage(msg) => msg.serialized_size(compress),
        }
    }

    fn serialize_with_mode<W: std::io::Write>(
        &self,
        mut writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        match self {
            IronEpochMessage::IronEpochKeyMessage(msg) => {
                writer.write_all(&[0])?;
                msg.serialize_with_mode(writer, compress)
            },
            IronEpochMessage::IronEpochRegMessage(msg) => {
                writer.write_all(&[1])?;
                msg.serialize_with_mode(writer, compress)
            },
        }
    }
}

impl<
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        > + Send
        + Sync,
> ark_serialize::CanonicalDeserialize for IronEpochMessage<E, MvPCS>
{
    fn deserialize_with_mode<R: std::io::Read>(
        mut reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        let mut tag = [0u8; 1];
        reader.read_exact(&mut tag)?;
        match tag[0] {
            0 => Ok(IronEpochMessage::IronEpochKeyMessage(
                ark_serialize::CanonicalDeserialize::deserialize_with_mode(
                    reader, compress, validate,
                )?,
            )),
            1 => Ok(IronEpochMessage::IronEpochRegMessage(
                ark_serialize::CanonicalDeserialize::deserialize_with_mode(
                    reader, compress, validate,
                )?,
            )),
            _ => Err(ark_serialize::SerializationError::InvalidData),
        }
    }
}
impl<
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        > + Send
        + Sync,
> Valid for IronEpochMessage<E, MvPCS>
{
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        match self {
            IronEpochMessage::IronEpochKeyMessage(msg) => msg.check(),
            IronEpochMessage::IronEpochRegMessage(msg) => msg.check(),
        }
    }
}

#[derive(Derivative)]
#[derivative(Default(bound = ""))]
pub struct DummyBB<
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        > + Send
        + Sync,
> {
    ledger: LinkedList<IronEpochMessage<E, MvPCS>>,
    size: usize,
}

impl<E, MvPCS> DummyBB<E, MvPCS>
where
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        > + Send
        + Sync,
{
    pub fn get_last_reg_update_message(&self) -> Option<&IronEpochRegMessage<E, MvPCS>> {
        for message in self.ledger.iter() {
            if let IronEpochMessage::IronEpochRegMessage(reg_msg) = message {
                return Some(reg_msg);
            }
        }
        None
    }

    pub fn get_last_key_update_message(&self) -> Option<&IronEpochKeyMessage<E, MvPCS>> {
        for message in self.ledger.iter() {
            if let IronEpochMessage::IronEpochKeyMessage(key_msg) = message {
                return Some(key_msg);
            }
        }
        None
    }
}

impl<
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        > + Send
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
