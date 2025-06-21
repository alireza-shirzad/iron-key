pub(crate) mod errors;

use std::{
    marker::PhantomData,
    ops::{Add, Sub},
};

use ark_ec::pairing::Pairing;

use ark_poly::Polynomial;
use subroutines::{PolynomialCommitmentScheme, poly::DenseOrSparseMLE};
use transcript::IOPTranscript;

use crate::{
    VKDClient, VKDDictionary, VKDLabel, VKDResult,
    bb::{BulletinBoard, dummybb::DummyBB},
    errors::VKDError,
    structs::{
        dictionary::IronDictionary, lookup::IronLookupProof, pp::IronClientKey,
        self_audit::IronSelfAuditProof,
    },
    utils::hash_to_mu_bits_with_offset,
};

pub struct IronClient<
    E: Pairing,
    T: VKDLabel<E>,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        >,
> {
    key: IronClientKey<E, MvPCS>,
    index: Option<<MvPCS::Polynomial as Polynomial<E::ScalarField>>::Point>,
    label: T,
}

impl<E, T, MvPCS> VKDClient<E, MvPCS> for IronClient<E, T, MvPCS>
where
    E: Pairing,
    <MvPCS as PolynomialCommitmentScheme<E>>::Commitment:
        Add<Output = <MvPCS as PolynomialCommitmentScheme<E>>::Commitment>,
    <MvPCS as PolynomialCommitmentScheme<E>>::Commitment:
        Sub<Output = <MvPCS as PolynomialCommitmentScheme<E>>::Commitment>,
    <MvPCS as PolynomialCommitmentScheme<E>>::Aux:
        Add<Output = <MvPCS as PolynomialCommitmentScheme<E>>::Aux>,
    <MvPCS as PolynomialCommitmentScheme<E>>::Aux:
        Sub<Output = <MvPCS as PolynomialCommitmentScheme<E>>::Aux>,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        > + Send
        + Sync,
    T: VKDLabel<E>,
{
    type Dictionary = IronDictionary<E, T>;
    type ClientKey = IronClientKey<E, MvPCS>;
    type LookupProof = IronLookupProof<E, MvPCS>;

    type SelfAuditProof = IronSelfAuditProof<E, MvPCS>;
    type BulletinBoard = DummyBB<E, MvPCS>;

    fn init(key: Self::ClientKey, label: T) -> Self {
        Self {
            key,
            index: None,
            label,
        }
    }

    fn get_label(&self) -> <Self::Dictionary as VKDDictionary<E>>::Label {
        self.label.clone()
    }

    fn lookup_verify(
        &mut self,
        label: <Self::Dictionary as VKDDictionary<E>>::Label,
        value: <Self::Dictionary as VKDDictionary<E>>::Value,
        proof: &Self::LookupProof,
        bulletin_board: &Self::BulletinBoard,
    ) -> VKDResult<bool>
    where
        <MvPCS as PolynomialCommitmentScheme<E>>::Commitment:
            Add<Output = <MvPCS as PolynomialCommitmentScheme<E>>::Commitment>,
        <MvPCS as PolynomialCommitmentScheme<E>>::Commitment:
            Sub<Output = <MvPCS as PolynomialCommitmentScheme<E>>::Commitment>,
    {
        // TODO: Fix this for real scenarios
        let last_reg_message = bulletin_board.get_last_reg_update_message().unwrap();
        let last_keys_message = bulletin_board.get_last_key_update_message().unwrap();
        let mut transcript = IOPTranscript::new(b"lookup");
        let b = MvPCS::batch_verify(
            self.key.get_pcs_verifier_param(),
            &[
                last_keys_message.get_value_commitment().clone(),
                last_reg_message.get_label_commitment().clone(),
            ],
            proof.get_auxes(),
            &proof.get_index(),
            &[value, label.to_field()],
            proof.get_batched_opening_proof(),
            &mut transcript,
        )
        .map_err(|_| VKDError::ClientError(errors::ClientError::LookupFailed))?;
        let (_label, _) = hash_to_mu_bits_with_offset::<E::ScalarField>(
            &self.label.to_string(),
            0,
            self.key.get_log_capacity(),
        );
        Ok(b)
    }

    fn self_audit_verify(
        &mut self,
        proof: Self::SelfAuditProof,
        bulletin_board: &Self::BulletinBoard,
    ) -> VKDResult<()> {
        // let last_epoch_message = bulletin_board.read_last()?;
        // let last_accumulator = last_epoch_message.get_difference_accumulator();
        // MvPCS::verify(
        //     &self.key.get_snark_vk().mv_pcs_vk,
        //     last_accumulator,
        //     &proof.get_index(),
        //     &E::ScalarField::zero(),
        //     proof.get_value_opening_proof(),
        // )
        // .map_err(|_| VKDError::ClientError(errors::ClientError::SelfAuditFailed))?;

        // self.check_index(
        //     proof.get_label_opening_proof(),
        //     last_epoch_message
        //         .get_dictionary_commitment()
        //         .label_commitment(),
        //     &proof.get_index(),
        // )?;

        todo!();
        Ok(())
    }
}

impl<E, T, MvPCS> IronClient<E, T, MvPCS>
where
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        >,
    T: VKDLabel<E>,
{
}
