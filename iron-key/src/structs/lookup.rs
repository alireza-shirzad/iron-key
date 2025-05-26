use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_poly::{DenseMultilinearExtension, Polynomial};
use subroutines::PolynomialCommitmentScheme;

pub struct IronLookupProof<E, PC>
where
    E: Pairing,
    PC: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseMultilinearExtension<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        >,
{
    index: <PC::Polynomial as Polynomial<E::ScalarField>>::Point,
    value: E::ScalarField,
    batched_opening_proof: PC::Proof,
}

impl<E, PC> IronLookupProof<E, PC>
where
    E: Pairing,
    PC: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseMultilinearExtension<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        >,
{
    pub fn new(
        index: <PC::Polynomial as Polynomial<E::ScalarField>>::Point,
        value: E::ScalarField,
        batched_opening_proof: PC::Proof,
    ) -> Self {
        Self {
            index,
            value,
            batched_opening_proof,
        }
    }

    pub fn get_index(&self) -> <PC::Polynomial as Polynomial<E::ScalarField>>::Point {
        self.index.clone()
    }
    pub fn get_value(&self) -> E::ScalarField {
        self.value
    }
    pub fn get_batched_opening_proof(&self) -> &PC::Proof {
        &self.batched_opening_proof
    }
}
