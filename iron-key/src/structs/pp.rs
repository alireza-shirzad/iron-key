use std::marker::PhantomData;

use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
    setup::structs::{ProvingKey, VerifyingKey},
};

use crate::VKDPublicParameters;

pub struct IronPublicParameters<F, MvPCS, UvPCS>
where
    F: ark_ff::PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    mv_snark_pk: ProvingKey<F, MvPCS, MvPCS>,
    mv_snark_vk: VerifyingKey<F, MvPCS, MvPCS>,
    _phantom_uvpcs: PhantomData<UvPCS>,
}

impl<F, MvPCS, UvPCS> VKDPublicParameters for IronPublicParameters<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    type ServerKey = IronServerKey<F, MvPCS, UvPCS>;
    type AuditorKey = IronAuditorKey<F, MvPCS>;
    type ClientKey = IronClientKey<F, MvPCS>;

    fn to_server_key(&self) -> Self::ServerKey {
        todo!()
    }

    fn to_auditor_key(&self) -> Self::AuditorKey {
        todo!()
    }

    fn to_client_key(&self) -> Self::ClientKey {
        todo!()
    }
    fn get_capacity(&self) -> usize {
        todo!()
    }
}

pub struct IronServerKey<F, MvPCS, UvPCS>
where
    F: ark_ff::PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    snark_pk: ProvingKey<F, MvPCS, UvPCS>,
}

impl<F, MvPCS, UvPCS> IronServerKey<F, MvPCS, UvPCS>
where
    F: ark_ff::PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub fn get_snark_pk(&self) -> &ProvingKey<F, MvPCS, UvPCS> {
        &self.snark_pk
    }
}

pub struct IronAuditorKey<F, MvPCS>
where
    F: ark_ff::PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
{
    _phantom_f: std::marker::PhantomData<F>,
    _phantom_mvpc: std::marker::PhantomData<MvPCS>,
}

pub struct IronClientKey<F, MvPCS>
where
    F: ark_ff::PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
{
    _phantom_f: std::marker::PhantomData<F>,
    _phantom_mvpc: std::marker::PhantomData<MvPCS>,
}
