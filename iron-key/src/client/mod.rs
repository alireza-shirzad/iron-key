use ark_ff::{Field, PrimeField};
use ark_piop::pcs::PCS;

use crate::{
    VKDClient, VKDDictionary, VKDLabel, VKDResult,
    structs::{
        dictionary::IronDictionary, lookup::IronLookupProof, self_audit::IronSelfAuditProof,
    },
};

pub struct IronClient<F: PrimeField, T: VKDLabel<F>> {
    _phantom_f: F,
    _phantom_t: T,
}

impl<F, PC, T> VKDClient<F, PC> for IronClient<F, T>
where
    F: PrimeField,
    PC: PCS<F>,
    T: VKDLabel<F>,
{
    type Dictionary = IronDictionary<F, T>;

    type LookupProof = IronLookupProof<F, PC>;

    type SelfAuditProof = IronSelfAuditProof<F, PC>;

    fn lookup_verify(
        &self,
        label: T,
        value: <Self::Dictionary as VKDDictionary<F>>::Value,
        proof: Self::LookupProof,
    ) -> VKDResult<bool> {
        todo!()
    }

    fn self_audit_verify(&self, label: T, proof: Self::SelfAuditProof) -> VKDResult<bool> {
        todo!()
    }
}
