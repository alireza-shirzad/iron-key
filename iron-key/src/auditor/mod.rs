pub(crate) mod errors;

use std::{
    marker::PhantomData,
    ops::{Add, Sub},
};

use crate::{
    VKDAuditor, VKDLabel, VKDResult,
    bb::dummybb::DummyBB,
    structs::{dictionary::IronDictionary, pp::IronAuditorKey, update::IronUpdateProof},
};
use ark_ec::{AdditiveGroup, pairing::Pairing};
use subroutines::{PolyIOP, PolynomialCommitmentScheme, ZeroCheck, poly::DenseOrSparseMLE};
pub struct IronAuditor<
    E: Pairing,
    T: VKDLabel<E>,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        > + Send
        + Sync,
> {
    _phantom_t: PhantomData<T>,
    key: IronAuditorKey<E, MvPCS>,
}

impl<E, MvPCS, T> VKDAuditor<E, MvPCS> for IronAuditor<E, T, MvPCS>
where
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        > + Send
        + Sync,
    <MvPCS as PolynomialCommitmentScheme<E>>::Commitment:
        Add<Output = <MvPCS as PolynomialCommitmentScheme<E>>::Commitment>,
    <MvPCS as PolynomialCommitmentScheme<E>>::Commitment:
        Sub<Output = <MvPCS as PolynomialCommitmentScheme<E>>::Commitment>,
    <MvPCS as PolynomialCommitmentScheme<E>>::Aux:
        Add<Output = <MvPCS as PolynomialCommitmentScheme<E>>::Aux>,
    <MvPCS as PolynomialCommitmentScheme<E>>::Aux:
        Sub<Output = <MvPCS as PolynomialCommitmentScheme<E>>::Aux>,
    T: VKDLabel<E>,
{
    type Dictionary = IronDictionary<E, T>;

    type UpdateProof = IronUpdateProof<E, MvPCS>;

    type StateCommitment = MvPCS::Commitment;

    type AuditorKey = IronAuditorKey<E, MvPCS>;

    type BulletinBoard = DummyBB<E, MvPCS>;
    fn init(key: Self::AuditorKey) -> Self {
        Self {
            _phantom_t: PhantomData,
            key,
        }
    }
    fn verify_update(&self, bulletin_board: &Self::BulletinBoard) -> VKDResult<bool>
    where
        <MvPCS as PolynomialCommitmentScheme<E>>::Commitment:
            Add<Output = <MvPCS as PolynomialCommitmentScheme<E>>::Commitment>,
        <MvPCS as PolynomialCommitmentScheme<E>>::Commitment:
            Sub<Output = <MvPCS as PolynomialCommitmentScheme<E>>::Commitment>,
        <MvPCS as PolynomialCommitmentScheme<E>>::Aux:
            Add<Output = <MvPCS as PolynomialCommitmentScheme<E>>::Aux>,
        <MvPCS as PolynomialCommitmentScheme<E>>::Aux:
            Sub<Output = <MvPCS as PolynomialCommitmentScheme<E>>::Aux>,
    {
        let reg_update_check_result = self.check_reg_update(bulletin_board)?;
        let keys_update_check_result = self.check_keys_update(bulletin_board)?;

        Ok(reg_update_check_result && keys_update_check_result)
    }
}

impl<E, MvPCS, T> IronAuditor<E, T, MvPCS>
where
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        > + Send
        + Sync,
    T: VKDLabel<E>,
{
    fn check_reg_update(&self, bulletin_board: &DummyBB<E, MvPCS>) -> VKDResult<bool> {
        // Get the two last registration messages
        let last_reg_message = bulletin_board.get_last_reg_update_message();
        let second_last_reg_message = bulletin_board.get_second_last_reg_update_message();

        let reg_update_check_result = match (last_reg_message, second_last_reg_message) {
            // If we have at least two registration messages, we can verify the update
            (Some(last_reg), Some(second_last_reg)) => {
                let mut transcript =
                    <PolyIOP<E::ScalarField> as ZeroCheck<E::ScalarField>>::init_transcript();
                transcript.append_message(b"iron-key", b"iron-key").unwrap();

                let sc_proof = last_reg
                    .get_update_proof()
                    .as_ref()
                    .unwrap()
                    .get_zerocheck_proof();
                let sc_aux = last_reg
                    .get_update_proof()
                    .as_ref()
                    .unwrap()
                    .get_zerocheck_aux();
                // Perform zero-check verification
                let zerocheck_proof =
                    <PolyIOP<E::ScalarField> as ZeroCheck<E::ScalarField>>::verify(
                        sc_proof,
                        sc_aux,
                        &mut transcript,
                    )
                    .unwrap();
                // Get the last two label commitments
                let last_label_commitment = last_reg.get_label_commitment();
                let second_last_label_commitment = second_last_reg.get_label_commitment();
                // Get the last two label auxs
                MvPCS::batch_verify(
                    self.key.get_pcs_verifier_param(),
                    &[
                        last_label_commitment.clone(),
                        second_last_label_commitment.clone(),
                    ],
                    None,
                    &zerocheck_proof.point,
                    &[E::ScalarField::ZERO, E::ScalarField::ZERO],
                    last_reg
                        .get_update_proof()
                        .as_ref()
                        .unwrap()
                        .get_opening_proof(),
                    &mut transcript,
                )
                .unwrap()
            },
            // If there is only one registration message, the auditor accepts anything
            (Some(_), None) => true,
            // If there are no registration messages, the auditor accepts anything
            (None, None) => true,
            // If there is a second last registration message, but no last one, this is an error
            (None, Some(_)) => {
                panic!("No last registration message found, but second last exists");
            },
        };
        Ok(reg_update_check_result)
    }

    fn check_keys_update(&self, bulletin_board: &DummyBB<E, MvPCS>) -> VKDResult<bool>
    where
        <MvPCS as PolynomialCommitmentScheme<E>>::Commitment:
            Add<Output = <MvPCS as PolynomialCommitmentScheme<E>>::Commitment>,
        <MvPCS as PolynomialCommitmentScheme<E>>::Commitment:
            Sub<Output = <MvPCS as PolynomialCommitmentScheme<E>>::Commitment>,
        <MvPCS as PolynomialCommitmentScheme<E>>::Aux:
            Add<Output = <MvPCS as PolynomialCommitmentScheme<E>>::Aux>,
        <MvPCS as PolynomialCommitmentScheme<E>>::Aux:
            Sub<Output = <MvPCS as PolynomialCommitmentScheme<E>>::Aux>,
    {
        let last_keys_update_message = bulletin_board.get_last_key_update_message();
        let second_last_keys_update_message = bulletin_board.get_second_last_key_update_message();

        let keys_update_check_result =
            match (last_keys_update_message, second_last_keys_update_message) {
                (Some(last_keys), Some(second_last_keys)) => {
                    let last_keys_commitment = last_keys.get_value_commitment();
                    let last_acc = last_keys.get_difference_accumulator();
                    let second_last_keys_commitment = second_last_keys.get_value_commitment();
                    let second_last_acc = second_last_keys.get_difference_accumulator();
                    let diff_commitment =
                        last_keys_commitment.clone() - second_last_keys_commitment.clone();
                    last_acc.clone() == (second_last_acc.clone() + diff_commitment.clone())
                },
                (Some(_), None) => true,
                (None, None) => true,
                (None, Some(_)) => {
                    panic!("No last keys update message found, but second last exists");
                },
            };
        Ok(keys_update_check_result)
    }
}
