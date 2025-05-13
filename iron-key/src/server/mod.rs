pub(crate) mod errors;
#[cfg(test)]
mod tests;
use std::{collections::HashMap, hash::Hash, io::Cursor, marker::PhantomData, sync::Arc};

use ark_ff::{Field, PrimeField};
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
    prover::Prover,
    to_bytes,
};
use ark_serialize::CanonicalDeserialize;
use ark_std::{end_timer, start_timer};
use errors::ServerError;

use crate::{
    VKDDictionary, VKDLabel, VKDPublicParameters, VKDResult, VKDServer,
    bb::{BulletinBoard, dummybb::DummyBB},
    errors::VKDError,
    structs::{
        dictionary::{self, IronDictionary, IronDictionaryCommitment},
        lookup::IronLookupProof,
        pp::{IronPublicParameters, IronServerKey},
        self_audit::IronSelfAuditProof,
        update::{self, IronEpochMessage, IronUpdateProof},
    },
};

pub struct IronServer<
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
    T: VKDLabel<F>,
> {
    dictionary: IronDictionary<F, T>,
    key: IronServerKey<F, MvPCS, UvPCS>,
    _phhantom_uvpc: PhantomData<UvPCS>,
}

impl<F, MvPCS, UvPCS, T> VKDServer<F, MvPCS> for IronServer<F, MvPCS, UvPCS, T>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
    T: VKDLabel<F>,
{
    type UpdateBatch = HashMap<T, F>;
    type StateCommitment = MvPCS::Commitment;
    type Dictionary = IronDictionary<F, T>;
    type LookupProof = IronLookupProof<F, MvPCS>;
    type UpdateProof = IronUpdateProof<F, MvPCS, UvPCS>;
    type SelfAuditProof = IronSelfAuditProof<F, MvPCS>;
    type PublicParameters = IronPublicParameters<F, MvPCS, UvPCS>;
    type ServerKey = IronServerKey<F, MvPCS, UvPCS>;
    type BulletinBoard = DummyBB;

    fn init(pp: &Self::PublicParameters) -> Self {
        Self {
            dictionary: IronDictionary::new_with_capacity(pp.get_capacity()),
            key: pp.to_server_key(),
            _phhantom_uvpc: PhantomData,
        }
    }

    fn update(
        &mut self,
        update_batch: Self::UpdateBatch,
        bulletin_board: &mut Self::BulletinBoard,
    ) -> VKDResult<()> {
        let timer = start_timer!(|| "IronServer::update");
        #[cfg(test)]
        {
            self.authenticate_batch(&update_batch)?;
        }
        let current_value_mle = self.dictionary.get_value_mle().clone();
        self.dictionary.insert_batch(&update_batch)?;
        let updated_value_mle = self.dictionary.get_value_mle().clone();
        let diff_value_mle = updated_value_mle - current_value_mle;
        let dictionary_commitment = self.commit_dictionary()?;

        let mut update_proof: Option<IronUpdateProof<F, MvPCS, UvPCS>> = None;
        if !bulletin_board.is_empty() {
            update_proof = Some(self.prove_update(update_batch)?);
        }

        // Update the difference accumulator
        let difference_accumulator =
            self.create_or_update_difference_accumulater(diff_value_mle, bulletin_board)?;
        // Assemble the epoch message
        let iron_epoch_message =
            IronEpochMessage::new(dictionary_commitment, difference_accumulator, update_proof);
        // Serialize the epoch message and broadcast it to the bulletin board
        bulletin_board.broadcast(&to_bytes!(&iron_epoch_message).unwrap())?;
        end_timer!(timer);
        Ok(())
    }

    fn lookup_prove(
        &self,
        _label: <Self::Dictionary as VKDDictionary<F>>::Label,
    ) -> VKDResult<(
        <Self::Dictionary as VKDDictionary<F>>::Value,
        Self::LookupProof,
    )> {
        todo!()
    }

    fn self_audit_prove(
        &self,
        _label: <Self::Dictionary as VKDDictionary<F>>::Label,
    ) -> VKDResult<Self::SelfAuditProof> {
        todo!()
    }
}

impl<F, MvPCS, UvPCS, T> IronServer<F, MvPCS, UvPCS, T>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
    T: VKDLabel<F>,
{
    #[cfg(test)]
    fn authenticate_batch(&self, update_batch: &HashMap<T, F>) -> VKDResult<()> {
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

    fn commit_dictionary(&self) -> VKDResult<dictionary::IronDictionaryCommitment<F, MvPCS>> {
        let timer = start_timer!(|| "IronServer::commit_dictionary");
        let label_mle_arc = Arc::new(self.dictionary.get_label_mle().clone());
        let value_mle_arc = Arc::new(self.dictionary.get_value_mle().clone());
        let label_commitment =
            MvPCS::commit(&self.key.get_snark_pk().mv_pcs_param, &label_mle_arc)?;
        let value_commitment =
            MvPCS::commit(&self.key.get_snark_pk().mv_pcs_param, &value_mle_arc)?;
        end_timer!(timer);
        Ok(IronDictionaryCommitment::new(
            label_commitment,
            value_commitment,
        ))
    }

    fn create_or_update_difference_accumulater(
        &self,
        diff_value_mle: MLE<F>,
        bulletin_board: &DummyBB,
    ) -> VKDResult<MvPCS::Commitment> {
        if bulletin_board.is_empty() {
            return Ok(MvPCS::commit(
                &self.key.get_snark_pk().mv_pcs_param,
                &Arc::new(diff_value_mle),
            )?);
        } else {
            let last_epoch_bytes = bulletin_board.read_last()?;
            let mut bytes = Vec::new();
            let mut reader = Cursor::new(bytes);
            let last_epoch: IronEpochMessage<F, MvPCS, UvPCS> =
                IronEpochMessage::deserialize_uncompressed(reader).unwrap();
        }
        todo!()
    }

    fn prove_update(
        &mut self,
        update_batch: HashMap<T, F>,
    ) -> VKDResult<IronUpdateProof<F, MvPCS, UvPCS>> {
        let timer = start_timer!(|| "IronServer::prove_update");
        let mut snark_prover =
            Prover::<F, MvPCS, UvPCS>::new_from_pk(self.key.get_snark_pk().clone());
        let current_label_mle = self.dictionary.get_label_mle().clone();
        let current_label_tr_p = snark_prover.track_mat_mv_poly(current_label_mle.clone());
        // TODO: See if we can parallelize this
        for (label, value) in update_batch.iter() {
            self.dictionary.insert(&label.clone(), *value)?;
        }
        let new_label_mle = self.dictionary.get_label_mle().clone();
        let new_label_tr_p = snark_prover.track_mat_mv_poly(new_label_mle.clone());
        let diff_tr_p = new_label_tr_p.sub_poly(&current_label_tr_p);
        snark_prover.add_mv_zerocheck_claim(diff_tr_p.get_id())?;
        let snark_proof = snark_prover.build_proof()?;
        end_timer!(timer);
        Ok(IronUpdateProof::new(snark_proof))
    }
}
