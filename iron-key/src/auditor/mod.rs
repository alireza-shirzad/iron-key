use ark_ff::{Field, PrimeField};
use ark_piop::pcs::PCS;

use crate::{
    VKDAuditor, VKDClient, VKDDictionary, VKDLabel, VKDResult,
    structs::{dictionary::IronDictionary, update::IronUpdateProof},
};

pub struct IronAuditor<F: PrimeField, T: VKDLabel<F>> {
    _phantom_f: F,
    _phantom_t: T,
}

impl<F, PC, T> VKDAuditor<F, PC> for IronAuditor<F, T>
where
    F: PrimeField,
    PC: PCS<F>,
    T: VKDLabel<F>,
{
    type Dictionary = IronDictionary<F, T>;

    type UpdateProof = IronUpdateProof<F>;

    type StateCommitment = PC::Commitment;

    fn verify_update(
        &self,
        state_i: Self::StateCommitment,
        state_i_plus_1: Self::StateCommitment,
        label: <Self::Dictionary as VKDDictionary<F>>::Label,
        proof: Self::UpdateProof,
    ) -> VKDResult<bool> {
        todo!()
    }
}
