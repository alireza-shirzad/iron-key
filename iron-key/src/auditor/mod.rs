use ark_ff::{Field, PrimeField};
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
};

use crate::{
    VKDAuditor, VKDClient, VKDDictionary, VKDLabel, VKDResult,
    bb::dummybb::DummyBB,
    structs::{dictionary::IronDictionary, update::IronUpdateProof},
};

pub struct IronAuditor<
    F: PrimeField,
    T: VKDLabel<F>,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
> {
    _phantom_f: F,
    _phantom_t: T,
    _phantom_mvpc: MvPCS,
    _phantom_upc: UvPCS,
}

impl<F, MvPCS, UvPCS, T> VKDAuditor<F, MvPCS> for IronAuditor<F, T, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
    T: VKDLabel<F>,
{
    type Dictionary = IronDictionary<F, T>;

    type UpdateProof = IronUpdateProof<F, MvPCS, UvPCS>;

    type StateCommitment = MvPCS::Commitment;

    type BulletinBoard = DummyBB;

    fn verify_update(
        &self,
        state_i: Self::StateCommitment,
        state_i_plus_1: Self::StateCommitment,
        label: <Self::Dictionary as VKDDictionary<F>>::Label,
        proof: Self::UpdateProof,
        bulletin_board: &Self::BulletinBoard,
    ) -> VKDResult<bool> {
        todo!()
    }
}
