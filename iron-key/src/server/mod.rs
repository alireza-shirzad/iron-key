pub(crate) mod errors;
#[cfg(test)]
mod tests;
use crate::{
    VKDDictionary, VKDLabel, VKDPublicParameters, VKDResult, VKDServer,
    bb::{BulletinBoard, dummybb::DummyBB},
    structs::{
        dictionary::{self, IronDictionary, IronDictionaryCommitment},
        lookup::IronLookupProof,
        pp::{IronPublicParameters, IronServerKey},
        self_audit::IronSelfAuditProof,
        update::{self, IronEpochMessage, IronUpdateProof},
    },
};
use arithmetic::VirtualPolynomial;
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_poly::DenseMultilinearExtension;
use ark_std::{One, UniformRand, Zero, end_timer, start_timer, test_rng};
use std::{
    collections::HashMap,
    marker::PhantomData,
    ops::{Add, Sub},
    sync::Arc,
};
use subroutines::{PolyIOP, PolynomialCommitmentScheme, ZeroCheck};

pub struct IronServer<
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseMultilinearExtension<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        > + Sync
        + Send,
    T: VKDLabel<E>,
> {
    dictionary: IronDictionary<E, T>,
    key: IronServerKey<E, MvPCS>,
}

impl<E, MvPCS, T> VKDServer<E, MvPCS> for IronServer<E, MvPCS, T>
where
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseMultilinearExtension<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
            Evaluation = E::ScalarField,
        > + Sync
        + Send,
    <MvPCS as PolynomialCommitmentScheme<E>>::Commitment:
        Add<Output = <MvPCS as PolynomialCommitmentScheme<E>>::Commitment>,
    <MvPCS as PolynomialCommitmentScheme<E>>::Commitment:
        Sub<Output = <MvPCS as PolynomialCommitmentScheme<E>>::Commitment>,
    T: VKDLabel<E>,
{
    type UpdateBatch = HashMap<T, E::ScalarField>;
    type StateCommitment = MvPCS::Commitment;
    type Dictionary = IronDictionary<E, T>;
    type LookupProof = IronLookupProof<E, MvPCS>;
    type UpdateProof = IronUpdateProof<E, MvPCS>;
    type SelfAuditProof = IronSelfAuditProof<E, MvPCS>;
    type PublicParameters = IronPublicParameters<E, MvPCS>;
    type ServerKey = IronServerKey<E, MvPCS>;
    type BulletinBoard = DummyBB<E, MvPCS>;

    fn init(pp: &Self::PublicParameters) -> Self {
        Self {
            dictionary: IronDictionary::new_with_capacity(pp.get_capacity()),
            key: pp.to_server_key(),
        }
    }

    fn update(
        &mut self,
        update_batch: Self::UpdateBatch,
        bulletin_board: &mut Self::BulletinBoard,
    ) -> VKDResult<()>
    where
        <MvPCS as PolynomialCommitmentScheme<E>>::Commitment:
            Add<Output = <MvPCS as PolynomialCommitmentScheme<E>>::Commitment>,
        <MvPCS as PolynomialCommitmentScheme<E>>::Commitment:
            Sub<Output = <MvPCS as PolynomialCommitmentScheme<E>>::Commitment>,
    {
        #[cfg(test)]
        {
            self.authenticate_batch(&update_batch)?;
        }
        let timer = start_timer!(|| "IronServer::update:: fetching current MLEs");
        let current_label_mle = self.dictionary.get_label_mle().clone();
        let current_value_mle = self.dictionary.get_value_mle().clone();
        end_timer!(timer);
        let timer = start_timer!(|| "IronServer::update:: inserting batch");
        self.dictionary.insert_batch(&update_batch)?;
        end_timer!(timer);
        let timer = start_timer!(|| "IronServer::update:: fetching new MLEs");
        let new_label_mle = self.dictionary.get_label_mle().clone();
        let new_value_mle = self.dictionary.get_value_mle().clone();
        end_timer!(timer);

        let timer = start_timer!(|| "IronServer::update:: computing diff MLE");
        let diff_label_mle = &new_label_mle - &current_label_mle;
        let diff_value_mle = &new_value_mle - &current_value_mle;
        end_timer!(timer);
        let timer = start_timer!(|| "IronServer::update:: computing diff commitment");
        let diff_label_com =
            MvPCS::commit(self.key.get_pcs_prover_param(), &diff_label_mle).unwrap();
        let diff_value_com =
            MvPCS::commit(self.key.get_pcs_prover_param(), &diff_value_mle).unwrap();
        end_timer!(timer);

        let iron_epoch_message = if bulletin_board.is_empty() {
            let dictionary_commitment =
                IronDictionaryCommitment::new(diff_label_com, diff_value_com.clone());
            IronEpochMessage::new(dictionary_commitment, diff_value_com, None)
        } else {
            let prove_update_timer = start_timer!(|| "IronServer::update:: Prove update");
            let sc_prep_timer = start_timer!(|| "IronServer::update:: Sumcheck preparation");
            let last_epoch_message = bulletin_board.read_last()?;
            let dictionary_commitment = last_epoch_message.get_dictionary_commitment();
            let last_value_comm = dictionary_commitment.value_commitment();
            let last_label_comm = dictionary_commitment.label_commitment();
            let new_value_comm = last_value_comm.clone() + diff_value_com.clone();
            let new_label_comm = last_label_comm.clone() + diff_label_com;
            let dictionary_commitment =
                IronDictionaryCommitment::new(new_label_comm, new_value_comm);
            let last_diff_accumulator = last_epoch_message.get_difference_accumulator();
            let difference_accumulator = last_diff_accumulator.clone() + diff_value_com;
            let mut target_virtual_poly = VirtualPolynomial::new(current_label_mle.num_vars);
            let current_label_arc_mle = Arc::new(current_label_mle);
            let new_label_arc_mle = Arc::new(new_label_mle);
            target_virtual_poly
                .add_mle_list(
                    [current_label_arc_mle.clone(), current_label_arc_mle.clone()],
                    E::ScalarField::one(),
                )
                .unwrap();
            target_virtual_poly
                .add_mle_list(
                    [current_label_arc_mle, new_label_arc_mle],
                    -E::ScalarField::one(),
                )
                .unwrap();
            let mut transcript =
                <PolyIOP<E::ScalarField> as ZeroCheck<E::ScalarField>>::init_transcript();
            transcript.append_message(b"iron-key", b"iron-key").unwrap();
            end_timer!(sc_prep_timer);
            let sumcheck_timer = start_timer!(|| "IronServer::update:: Sumcheck");
            let zerocheck_proof = <PolyIOP<E::ScalarField> as ZeroCheck<E::ScalarField>>::prove(
                &target_virtual_poly,
                &mut transcript,
            )
            .unwrap();
            end_timer!(sumcheck_timer);
            let opening_timer = start_timer!(|| "IronServer::update:: opening time");
            let opening_chall = transcript.get_and_append_challenge(b"iron-key").unwrap();
            let batched_poly = current_value_mle + new_value_mle * opening_chall;
            let update_proof = MvPCS::open(
                self.key.get_pcs_prover_param(),
                &batched_poly,
                &zerocheck_proof.point,
            );
            end_timer!(opening_timer);
            let iron_update_proof = IronUpdateProof::new(zerocheck_proof, update_proof.unwrap().0);
            end_timer!(prove_update_timer);
            IronEpochMessage::new(
                dictionary_commitment,
                difference_accumulator,
                Some(iron_update_proof),
            )
        };

        // Serialize the epoch message and broadcast it to the bulletin board
        bulletin_board.broadcast(iron_epoch_message)?;
        Ok(())
    }

    fn lookup_prove(
        &self,
        label: <Self::Dictionary as VKDDictionary<E>>::Label,
    ) -> VKDResult<Self::LookupProof> {
        let timer = start_timer!(|| "IronServer::lookup_prove");
        let index = self.dictionary.find_index(&label).unwrap();
        let index_boolean = Self::usize_to_field_bits(index, self.dictionary.log_max_size());
        let batched_poly = self.dictionary.get_label_mle() + self.dictionary.get_value_mle();
        let update_proof = MvPCS::open(
            self.key.get_pcs_prover_param(),
            &batched_poly,
            &index_boolean,
        )
        .unwrap();
        end_timer!(timer);
        Ok(IronLookupProof::new(
            index_boolean,
            update_proof.1,
            update_proof.0,
        ))
    }

    fn self_audit_prove(
        &self,
        _label: <Self::Dictionary as VKDDictionary<E>>::Label,
    ) -> VKDResult<Self::SelfAuditProof> {
        todo!()
    }
}

impl<E, MvPCS, T> IronServer<E, MvPCS, T>
where
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseMultilinearExtension<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        > + Sync
        + Send,
    T: VKDLabel<E>,
{
    #[cfg(test)]
    fn authenticate_batch(&self, update_batch: &HashMap<T, E::ScalarField>) -> VKDResult<()> {
        use errors::ServerError;

        use crate::errors::VKDError;

        let timer = start_timer!(|| "IronServer::authenticate_batch");
        let res = update_batch
            .iter()
            .any(|(label, _)| self.dictionary.contains(label));
        end_timer!(timer);
        if res {
            Err(VKDError::ServerError(ServerError::AlreadyRegistered))
        } else {
            Ok(())
        }
    }

    fn usize_to_field_bits(mut value: usize, k: usize) -> Vec<E::ScalarField> {
        let mut bits = vec![E::ScalarField::zero(); k];
        for i in 0..k {
            bits[k - 1 - i] = if value & 1 == 1 {
                E::ScalarField::one()
            } else {
                E::ScalarField::zero()
            };
            value >>= 1;
        }
        bits
    }
}
