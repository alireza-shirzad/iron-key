use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;

use ark_poly::{DenseMultilinearExtension, MultilinearExtension};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::marker::PhantomData;
use subroutines::{IOPProof, PolynomialCommitmentScheme};

use super::dictionary::IronDictionaryCommitment;
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct IronUpdateProof<E, MvPCS>
where
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseMultilinearExtension<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        > + Sync
        + Send,
{
    zerocheck_proof: IOPProof<E::ScalarField>,
    opening_proof: MvPCS::Proof,
}

impl<E, MvPCS> IronUpdateProof<E, MvPCS>
where
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseMultilinearExtension<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        > + Sync
        + Send,
{
    pub fn new(zerocheck_proof: IOPProof<E::ScalarField>, opening_proof: MvPCS::Proof) -> Self {
        Self {
            zerocheck_proof,
            opening_proof,
        }
    }

    pub fn get_zerocheck_proof(&self) -> &IOPProof<E::ScalarField> {
        &self.zerocheck_proof
    }
    pub fn get_opening_proof(&self) -> &MvPCS::Proof {
        &self.opening_proof
    }
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct IronEpochMessage<E, MvPCS>
where
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseMultilinearExtension<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        > + Sync
        + Send,
{
    dictionary_commitment: IronDictionaryCommitment<E, MvPCS>,
    difference_accumulator: MvPCS::Commitment,
    update_proof: Option<IronUpdateProof<E, MvPCS>>,
}

impl<E, MvPCS> IronEpochMessage<E, MvPCS>
where
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseMultilinearExtension<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        > + Sync
        + Send,
{
    pub fn new(
        dictionary_commitment: IronDictionaryCommitment<E, MvPCS>,
        difference_accumulator: MvPCS::Commitment,
        update_proof: Option<IronUpdateProof<E, MvPCS>>,
    ) -> Self {
        Self {
            dictionary_commitment,
            difference_accumulator,
            update_proof,
        }
    }

    pub fn get_dictionary_commitment(&self) -> &IronDictionaryCommitment<E, MvPCS> {
        &self.dictionary_commitment
    }
    pub fn get_difference_accumulator(&self) -> &MvPCS::Commitment {
        &self.difference_accumulator
    }
    pub fn get_update_proof(&self) -> &Option<IronUpdateProof<E, MvPCS>> {
        &self.update_proof
    }
}
