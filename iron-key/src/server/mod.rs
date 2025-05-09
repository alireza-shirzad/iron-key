use std::{collections::HashMap, marker::PhantomData};

use ark_ff::{Field, PrimeField};
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
    prover::Prover,
};

use crate::{
    VKDDictionary, VKDLabel, VKDPublicParameters, VKDResult, VKDServer,
    structs::{
        dictionary::{self, IronDictionary},
        lookup::IronLookupProof,
        pp::{IronPublicParameters, IronServerKey},
        self_audit::IronSelfAuditProof,
        update::IronUpdateProof,
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
    type UpdateBatch = HashMap<String, F>;
    type StateCommitment = MvPCS::Commitment;
    type Dictionary = IronDictionary<F, T>;
    type LookupProof = IronLookupProof<F, MvPCS>;
    type UpdateProof = IronUpdateProof<F>;
    type SelfAuditProof = IronSelfAuditProof<F, MvPCS>;
    type PublicParameters = IronPublicParameters<F, MvPCS, UvPCS>;
    type ServerKey = IronServerKey<F, MvPCS, UvPCS>;

    fn init(&self, pp: &Self::PublicParameters) -> Self {
        Self {
            dictionary: IronDictionary::new_with_capacity(pp.get_capacity()),
            key: pp.to_server_key(),
            _phhantom_uvpc: PhantomData,
        }
    }

    fn update(&self, update_batch: Self::UpdateBatch) -> VKDResult<Self::StateCommitment> {
        let snark_prover = Prover::<F, MvPCS, UvPCS>::new_from_pk(self.key.get_snark_pk().clone());

        // update_batch.iter().map(|(label, value)| {
        //     ( self.dictionary)
        // }).collect::<VKDResult<Vec<_>>>().map(|proofs| {

        todo!()
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
