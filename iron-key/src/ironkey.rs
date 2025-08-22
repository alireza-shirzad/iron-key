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
use ark_ec::pairing::Pairing;
use ark_std::{end_timer, ops::Sub, start_timer, test_rng};
use std::ops::Add;
use subroutines::{PolynomialCommitmentScheme, pcs, poly::DenseOrSparseMLE};
pub struct IronKey<E, MvPCS, T>
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
    _phantom_f: std::marker::PhantomData<E::ScalarField>,
    _phantom_t: std::marker::PhantomData<T>,
    _phantom_mvpc: std::marker::PhantomData<MvPCS>,
}

impl<E, MvPCS, T> VKD<E, MvPCS> for IronKey<E, MvPCS, T>
where
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
            Evaluation = E::ScalarField,
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
    type PublicParameters = IronPublicParameters<E, MvPCS>;
    type Server = IronServer<E, MvPCS, T>;
    type Auditor = IronAuditor<E, T, MvPCS>;
    type Client = IronClient<E, T, MvPCS>;
    type Specification = IronSpecification<E, MvPCS>;
    type Dictionary = IronDictionary<E, T>;
    type LookupProof = IronLookupProof<E, MvPCS>;
    type SelfAuditProof = IronSelfAuditProof<E, MvPCS>;
    type UpdateProof = IronUpdateProof<E, MvPCS>;
    type StateCommitment = <MvPCS as PolynomialCommitmentScheme<E>>::Commitment;
    type Label = T;

    fn setup(specification: Self::Specification) -> VKDResult<Self::PublicParameters> {
        let timer = start_timer!(|| "IronKey::setup");
        let capacity = specification.get_capacity();
        let pcs_conf = specification.get_pcs_conf();
        let real_capacity = capacity.next_power_of_two();
        let num_vars = real_capacity.trailing_zeros() as usize;
        let mut rng = test_rng();
        let srs = MvPCS::gen_srs_for_testing(pcs_conf, &mut rng, num_vars).unwrap();
        end_timer!(timer);
        Ok(IronPublicParameters::<E, MvPCS>::new(real_capacity, srs))
    }
}
