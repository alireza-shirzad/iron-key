pub(crate) mod errors;

use ark_ec::pairing::Pairing;
use ark_ff::{Field, PrimeField};
use ark_poly::DenseMultilinearExtension;
use subroutines::{pcs::kzh::poly::DenseOrSparseMLE, PolynomialCommitmentScheme};

use crate::{
    VKDAuditor, VKDClient, VKDDictionary, VKDLabel, VKDResult,
    bb::dummybb::DummyBB,
    structs::{dictionary::IronDictionary, update::IronUpdateProof},
};

pub struct IronAuditor<
    E: Pairing,
    T: VKDLabel<E>,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        > + Send
        + Sync,
> {
    _phantom_f: E,
    _phantom_t: T,
    _phantom_mvpc: MvPCS,
}

impl<E, MvPCS, T> VKDAuditor<E, MvPCS> for IronAuditor<E, T, MvPCS>
where
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        > + Send
        + Sync,
    T: VKDLabel<E>,
{
    type Dictionary = IronDictionary<E, T>;

    type UpdateProof = IronUpdateProof<E, MvPCS>;

    type StateCommitment = MvPCS::Commitment;

    type BulletinBoard = DummyBB<E, MvPCS>;

    fn verify_update(
        &self,
        state_i: Self::StateCommitment,
        state_i_plus_1: Self::StateCommitment,
        label: <Self::Dictionary as VKDDictionary<E>>::Label,
        proof: Self::UpdateProof,
        bulletin_board: &Self::BulletinBoard,
    ) -> VKDResult<bool> {
        todo!()
    }
}
