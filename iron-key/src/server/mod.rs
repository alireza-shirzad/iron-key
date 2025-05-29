pub(crate) mod errors;
#[cfg(test)]
mod tests;
use crate::{
    VKDDictionary, VKDLabel, VKDPublicParameters, VKDResult, VKDServer,
    bb::{
        BulletinBoard,
        dummybb::{DummyBB, IronEpochMessage},
    },
    structs::{
        dictionary::IronDictionary,
        lookup::IronLookupProof,
        pp::{IronPublicParameters, IronServerKey},
        self_audit::IronSelfAuditProof,
        update::{IronEpochKeyMessage, IronEpochRegMessage, IronUpdateProof},
    },
};
use arithmetic::VirtualPolynomial;
use ark_ec::pairing::Pairing;
use ark_poly::MultilinearExtension;
use ark_std::{One, Zero, end_timer, start_timer};
use rayon::join;
use std::{
    collections::HashMap,
    ops::{Add, Sub},
    sync::Arc,
};
use subroutines::{
    PolyIOP, PolynomialCommitmentScheme, ZeroCheck, pcs::kzh::poly::DenseOrSparseMLE,
};
pub struct IronServer<
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
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
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
            Evaluation = E::ScalarField,
        > + Sync
        + Send,
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

    fn update_reg(
        &mut self,
        update_batch: &Self::UpdateBatch,
        bulletin_board: &mut Self::BulletinBoard,
    ) -> VKDResult<()>
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
        #[cfg(test)]
        {
            self.authenticate_batch(update_batch)?;
        }
        // Save the current label MLE
        let current_label_mle = self.dictionary.get_label_mle().clone();
        // Insert the batch to the dictionary
        self.dictionary.insert_batch(update_batch)?;
        // Now save the new label MLE
        let new_label_mle = self.dictionary.get_label_mle();
        // Compute the difference MLE
        let diff_label_mle = &*new_label_mle.borrow() - &*current_label_mle.borrow();
        // Commit to the diff commitment
        let diff_label_com =
            MvPCS::commit(self.key.get_pcs_prover_param(), &diff_label_mle).unwrap();
        // Compute the diff aux
        let diff_label_aux = MvPCS::comp_aux(
            self.key.get_pcs_prover_param(),
            &*new_label_mle.borrow(),
            &diff_label_com,
        )
        .unwrap();

        let iron_epoch_reg_message = match bulletin_board.get_last_reg_update_message() {
            // If it's the first time, the diff info is the new info
            None => {
                // Send the commitment
                IronEpochRegMessage::new(diff_label_com, None, diff_label_aux.clone())
            },
            Some(last_reg_message) => {
                // Get the last label commitment
                let last_label_comm = last_reg_message.get_label_commitment();
                // The new commitment is the last one plus the diff
                let new_label_comm = last_label_comm.clone() + diff_label_com;
                // The new aux is the saved one plus the diff aux --> Save the aux
                let last_label_aux = last_reg_message.get_label_aux();
                let new_label_aux = last_label_aux.clone() + diff_label_aux;
                // Intiate the transcipt for the zerocheck
                let mut transcript =
                    <PolyIOP<E::ScalarField> as ZeroCheck<E::ScalarField>>::init_transcript();
                transcript.append_message(b"iron-key", b"iron-key").unwrap();

                // let opening_chall =
                // transcript.get_and_append_challenge(b"iron-key").unwrap();
                let mut batched_poly = DenseOrSparseMLE::zero();
                batched_poly += &*new_label_mle.borrow();
                // batched_poly = &batched_poly * opening_chall;
                batched_poly += &*current_label_mle.borrow();
                // Build the target virtual polynomial to do the zerocheck on
                let mut target_virtual_poly =
                    VirtualPolynomial::new(current_label_mle.borrow().num_vars());
                let current_label_mle = Arc::new(current_label_mle.borrow().to_dense());
                let new_label_mle = Arc::new(new_label_mle.borrow().to_dense());
                target_virtual_poly
                    .add_mle_list(
                        [current_label_mle.clone(), current_label_mle.clone()],
                        E::ScalarField::one(),
                    )
                    .unwrap();
                target_virtual_poly
                    .add_mle_list([current_label_mle, new_label_mle], -E::ScalarField::one())
                    .unwrap();

                let zerocheck_proof =
                    <PolyIOP<E::ScalarField> as ZeroCheck<E::ScalarField>>::prove(
                        &target_virtual_poly,
                        &mut transcript,
                    )
                    .unwrap();

                let update_proof = MvPCS::open(
                    self.key.get_pcs_prover_param(),
                    &batched_poly,
                    &zerocheck_proof.point,
                );
                let iron_update_proof =
                    IronUpdateProof::new(zerocheck_proof, update_proof.unwrap().0);
                IronEpochRegMessage::new(new_label_comm, Some(iron_update_proof), new_label_aux)
            },
        };

        let iron_epoch_message = IronEpochMessage::IronEpochRegMessage(iron_epoch_reg_message);
        bulletin_board.broadcast(iron_epoch_message)?;
        Ok(())
    }

    fn update_keys(
        &mut self,
        update_batch: &Self::UpdateBatch,
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
            self.authenticate_batch(update_batch)?;
        }
        let current_value_mle = self.dictionary.get_value_mle().clone();
        self.dictionary.insert_batch(update_batch)?;
        let new_value_mle = self.dictionary.get_value_mle().clone();

        let diff_value_mle = &*new_value_mle.borrow() - &*current_value_mle.borrow();
        let (diff_value_com, diff_value_aux) = join(
            || MvPCS::commit(self.key.get_pcs_prover_param(), &diff_value_mle).unwrap(),
            || {
                MvPCS::comp_aux(
                    self.key.get_pcs_prover_param(),
                    &diff_value_mle,
                    &MvPCS::Commitment::default(),
                )
                .unwrap()
            },
        );

        let iron_epoch_key_message = match bulletin_board.get_last_key_update_message() {
            // If it's the first time, the diff info is the new info
            None => IronEpochKeyMessage::new(
                diff_value_com.clone(),
                diff_value_aux.clone(),
                diff_value_com,
                diff_value_aux,
            ),
            Some(last_key_message) => {
                let last_value_comm = last_key_message.get_value_commitment();
                let new_value_comm = last_value_comm.clone() + diff_value_com.clone();
                let new_value_aux =
                    last_key_message.get_value_aux().clone() + diff_value_aux.clone();
                let last_diff_accumulator = last_key_message.get_difference_accumulator();
                let difference_accumulator = last_diff_accumulator.clone() + diff_value_com;
                let difference_aux = last_key_message.get_difference_aux().clone() + diff_value_aux;
                IronEpochKeyMessage::new(
                    new_value_comm,
                    new_value_aux,
                    difference_accumulator,
                    difference_aux,
                )
            },
        };

        let iron_epoch_message = IronEpochMessage::IronEpochKeyMessage(iron_epoch_key_message);
        // Serialize the epoch message and broadcast it to the bulletin board
        bulletin_board.broadcast(iron_epoch_message)?;
        Ok(())
    }

    fn lookup_prove(
        &self,
        label: <Self::Dictionary as VKDDictionary<E>>::Label,
        bulletin_board: &mut Self::BulletinBoard,
    ) -> VKDResult<Self::LookupProof> {
        let index = self.dictionary.find_index(&label).unwrap();
        let last_reg_message = bulletin_board.get_last_reg_update_message().unwrap();
        let last_keys_message = bulletin_board.get_last_key_update_message().unwrap();
        let index_boolean = Self::usize_to_field_bits(index, self.dictionary.log_max_size());

        let label_mle_clone = self.dictionary.get_label_mle().borrow().clone();
        let value_mle_clone = self.dictionary.get_value_mle().borrow().clone();
        let (batched_poly, batched_aux) = join(
            || label_mle_clone + value_mle_clone,
            || last_reg_message.get_label_aux().clone() + last_keys_message.get_value_aux().clone(),
        );
        let update_proof = MvPCS::open(
            self.key.get_pcs_prover_param(),
            &batched_poly,
            &index_boolean,
        )
        .unwrap();
        Ok(IronLookupProof::new(
            index_boolean,
            update_proof.1,
            update_proof.0,
            batched_aux,
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
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
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
