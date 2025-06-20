pub(crate) mod errors;

use std::{
    marker::PhantomData,
    ops::{Add, Sub},
};

use ark_ec::pairing::Pairing;
use ark_ff::{Field, PrimeField};
use ark_poly::DenseMultilinearExtension;
use subroutines::{PolynomialCommitmentScheme, ZeroCheck, poly::DenseOrSparseMLE};
use ark_ec::AdditiveGroup;
use crate::{
    VKDAuditor, VKDClient, VKDDictionary, VKDLabel, VKDResult,
    bb::dummybb::DummyBB,
    structs::{dictionary::IronDictionary, pp::IronAuditorKey, update::IronUpdateProof},
};
use subroutines::PolyIOP;
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
            _phantom_t: PhantomData::default(),
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
        let last_reg_message = bulletin_board.get_last_reg_update_message();
        let second_last_reg_message = bulletin_board.get_second_last_reg_update_message();

        let reg_update_check_result = match (last_reg_message, second_last_reg_message) {
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
                let zerocheck_proof =
                    <PolyIOP<E::ScalarField> as ZeroCheck<E::ScalarField>>::verify(
                        sc_proof,
                        sc_aux,
                        &mut transcript,
                    )
                    .unwrap();
                let last_label_commitment = last_reg.get_label_commitment();
                let second_last_label_commitment = second_last_reg.get_label_commitment();

                let last_label_aux = last_reg.get_label_aux();
                let second_last_label_aux = second_last_reg.get_label_aux();
                let auxs = [last_label_aux.clone(), second_last_label_aux.clone()];
                let commitments = [
                    last_label_commitment.clone(),
                    second_last_label_commitment.clone(),
                ];
                let opening_proof = last_reg
                    .get_update_proof()
                    .as_ref()
                    .unwrap()
                    .get_opening_proof();
                //TODO: Fix the values
                MvPCS::batch_verify(
                    self.key.get_pcs_verifier_param(),
                    &commitments,
                    &auxs,
                    &zerocheck_proof.point,
                    &[E::ScalarField::ZERO, E::ScalarField::ZERO],
                    opening_proof,
                    &mut transcript,
                )
                .unwrap()
            },
            (Some(last_reg), None) => true,
            (None, None) => true,
            (None, Some(second_last_reg)) => {
                panic!("No last registration message found, but second last exists");
            },
        };

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
                (Some(last_keys), None) => true,
                (None, None) => true,
                (None, Some(second_last_keys)) => {
                    panic!("No last keys update message found, but second last exists");
                },
            };

        Ok(reg_update_check_result && keys_update_check_result)
    }
}
