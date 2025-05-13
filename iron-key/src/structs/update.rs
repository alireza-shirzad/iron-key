use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::PCS,
    prover::structs::proof::Proof,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use super::dictionary::IronDictionaryCommitment;

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct IronUpdateProof<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    snark_proof: Proof<F, MvPCS, UvPCS>,
}

impl<F, MvPCS, UvPCS> IronUpdateProof<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub fn new(snark_proof: Proof<F, MvPCS, UvPCS>) -> Self {
        Self { snark_proof }
    }
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct IronEpochMessage<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    dictionary_commitment: IronDictionaryCommitment<F, MvPCS>,
    difference_accumulator: MvPCS::Commitment,
    update_proof: Option<IronUpdateProof<F, MvPCS, UvPCS>>,
}

impl<F, MvPCS, UvPCS> IronEpochMessage<F, MvPCS, UvPCS>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
{
    pub fn new(
        dictionary_commitment: IronDictionaryCommitment<F, MvPCS>,
        difference_accumulator: MvPCS::Commitment,
        update_proof: Option<IronUpdateProof<F, MvPCS, UvPCS>>,
    ) -> Self {
        Self {
            dictionary_commitment,
            difference_accumulator,
            update_proof,
        }
    }
}
