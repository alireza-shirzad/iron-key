use std::{ops::Add, str::FromStr};

use crate::{
    VKD, VKDLabel, VKDResult, VKDSpecification,
    auditor::IronAuditor,
    client::IronClient,
    server::IronServer,
    structs::{
        IronSpecification, dictionary::IronDictionary, lookup::IronLookupProof,
        pp::IronPublicParameters, self_audit::IronSelfAuditProof, update::IronUpdateProof,
    },
};
use ark_ff::{BigInt, PrimeField};
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
    setup::KeyGenerator,
};
use num_bigint::BigUint;
use sha2::digest::crypto_common::KeyInit;

pub struct IronKey<F, MvPCS, UvPCS, T>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
    T: VKDLabel<F>,
{
    _phantom_f: std::marker::PhantomData<F>,
    _phantom_t: std::marker::PhantomData<T>,
    _phantom_mvpc: std::marker::PhantomData<MvPCS>,
    _phantom_upc: std::marker::PhantomData<UvPCS>,
}

impl<F, MvPCS, UvPCS, T> VKD<F, MvPCS> for IronKey<F, MvPCS, UvPCS, T>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
    <MvPCS as PCS<F>>::Commitment: Add<Output = <MvPCS as PCS<F>>::Commitment>,
    T: VKDLabel<F>,
{
    type PublicParameters = IronPublicParameters<F, MvPCS, UvPCS>;
    type Server = IronServer<F, MvPCS, UvPCS, T>;
    type Auditor = IronAuditor<F, T, MvPCS, UvPCS>;
    type Client = IronClient<F, T>;
    type Specification = IronSpecification;
    type Dictionary = IronDictionary<F, T>;
    type LookupProof = IronLookupProof<F, MvPCS>;
    type SelfAuditProof = IronSelfAuditProof<F, MvPCS>;
    type UpdateProof = IronUpdateProof<F, MvPCS, UvPCS>;
    type StateCommitment = <MvPCS as PCS<F>>::Commitment;
    type Label = T;

    fn setup(specification: Self::Specification) -> VKDResult<Self::PublicParameters> {
        let capacity = specification.get_capacity();
        let real_capacity = capacity.next_power_of_two();
        let num_vars = real_capacity.trailing_zeros() as usize;
        let key_generator = KeyGenerator::<F, MvPCS, UvPCS>::new().with_num_mv_vars(num_vars);
        let (snark_pk, snark_vk) = key_generator.gen_keys().unwrap();

        Ok(IronPublicParameters::new(capacity, snark_pk, snark_vk))
    }
}
