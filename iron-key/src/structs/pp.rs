use ark_ec::pairing::Pairing;
use ark_std::log2;

use crate::VKDPublicParameters;
use ark_poly::DenseMultilinearExtension;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use subroutines::{PolynomialCommitmentScheme, pcs::kzh::poly::DenseOrSparseMLE};

pub struct IronPublicParameters<E, MvPCS>
where
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        >,
{
    capacity: usize,
    pcs_ck: MvPCS::ProverParam,
    pcs_vk: MvPCS::VerifierParam,
}

impl<E, MvPCS> VKDPublicParameters for IronPublicParameters<E, MvPCS>
where
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        >,
{
    type ServerKey = IronServerKey<E, MvPCS>;
    type AuditorKey = IronAuditorKey<E, MvPCS>;
    type ClientKey = IronClientKey<E, MvPCS>;

    fn to_server_key(&self) -> Self::ServerKey {
        IronServerKey::new(self.capacity, self.pcs_ck.clone())
    }

    fn to_auditor_key(&self) -> Self::AuditorKey {
        IronAuditorKey::new(self.capacity, self.pcs_vk.clone())
    }

    fn to_client_key(&self) -> Self::ClientKey {
        IronClientKey::new(log2(self.capacity) as usize, self.pcs_vk.clone())
    }
    fn get_capacity(&self) -> usize {
        self.capacity
    }
}

impl<E, MvPCS> IronPublicParameters<E, MvPCS>
where
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        >,
{
    pub fn new(capacity: usize, pcs_param: MvPCS::SRS) -> Self {
        let (pcs_ck, pcs_vk) =
            MvPCS::trim(pcs_param, None, Some(capacity.trailing_zeros() as usize)).unwrap();
        Self {
            capacity,
            pcs_ck,
            pcs_vk,
        }
    }
}

pub struct IronServerKey<E, MvPCS>
where
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        >,
{
    capacity: usize,
    pcs_prover_param: MvPCS::ProverParam,
}

impl<E, MvPCS> IronServerKey<E, MvPCS>
where
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        >,
{
    pub fn new(capacity: usize, pcs_prover_param: MvPCS::ProverParam) -> Self {
        Self {
            capacity,
            pcs_prover_param,
        }
    }

    pub fn get_pcs_prover_param(&self) -> &MvPCS::ProverParam {
        &self.pcs_prover_param
    }
    pub fn get_capacity(&self) -> usize {
        self.capacity
    }
}

pub struct IronAuditorKey<E, MvPCS>
where
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        >,
{
    capacity: usize,
    pcs_verifier_param: MvPCS::VerifierParam,
}

impl<E, MvPCS> IronAuditorKey<E, MvPCS>
where
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        >,
{
    pub fn new(capacity: usize, pcs_verifier_param: MvPCS::VerifierParam) -> Self {
        Self {
            capacity,
            pcs_verifier_param,
        }
    }
    pub fn get_pcs_verifier_param(&self) -> &MvPCS::VerifierParam {
        &self.pcs_verifier_param
    }

    pub fn get_capacity(&self) -> usize {
        self.capacity
    }
}

#[derive(Clone)]
pub struct IronClientKey<E, MvPCS>
where
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        >,
{
    log_capacity: usize,
    pcs_verifier_param: MvPCS::VerifierParam,
}

impl<E, MvPCS> IronClientKey<E, MvPCS>
where
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        >,
{


    pub fn new(log_capacity: usize, pcs_verifier_param: MvPCS::VerifierParam) -> Self {
        Self {
            log_capacity,
            pcs_verifier_param,
        }
    }

    pub fn get_pcs_verifier_param(&self) -> &MvPCS::VerifierParam {
        &self.pcs_verifier_param
    }
    pub fn get_log_capacity(&self) -> usize {
        self.log_capacity
    }
}
