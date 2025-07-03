use ark_ec::pairing::Pairing;
use ark_poly::Polynomial;
use ark_serialize::CanonicalSerialize;
use subroutines::{PolynomialCommitmentScheme, poly::DenseOrSparseMLE};

#[derive(CanonicalSerialize)]
pub struct IronLookupProof<E, PC>
where
    E: Pairing,
    PC: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        >,
{
    index: <PC::Polynomial as Polynomial<E::ScalarField>>::Point,
    label_opening_proof: (PC::Proof, PC::Evaluation),
    value_opening_proof: (PC::Proof, PC::Evaluation),
    auxes: Vec<PC::Aux>,
}


impl<E, PC> IronLookupProof<E, PC>
where
    E: Pairing,
    PC: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        >,
{
    pub fn new(
        index: <PC::Polynomial as Polynomial<E::ScalarField>>::Point,
        label_opening_proof: (PC::Proof, PC::Evaluation),
        value_opening_proof: (PC::Proof, PC::Evaluation),
        auxes: Vec<PC::Aux>,
    ) -> Self {
        Self {
            index,
            label_opening_proof,
            value_opening_proof,
            auxes,
        }
    }

    pub fn get_index(&self) -> <PC::Polynomial as Polynomial<E::ScalarField>>::Point {
        self.index.clone()
    }
    pub fn get_label_opening_proof(&self) -> (&PC::Proof, &PC::Evaluation) {
        (&self.label_opening_proof.0, &self.label_opening_proof.1)
    }

    pub fn get_value_opening_proof(&self) -> (&PC::Proof, &PC::Evaluation) {
        (&self.value_opening_proof.0, &self.value_opening_proof.1)
    }

    pub fn get_auxes(&self) -> &[PC::Aux] {
        &self.auxes
    }
}
