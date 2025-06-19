use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_poly::{DenseMultilinearExtension, Polynomial};
use ark_serialize::CanonicalSerialize;
use ark_std::{UniformRand, rand::Rng};
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
    value: E::ScalarField,
    batched_opening_proof: PC::BatchProof,
    auxes: Vec<PC::Aux>,
}

// impl<E, PC> ark_serialize::CanonicalSerialize for IronLookupProof<E, PC>
// where
//     E: Pairing,
//     PC: PolynomialCommitmentScheme<
//             E,
//             Polynomial = DenseOrSparseMLE<E::ScalarField>,
//             Point = Vec<<E as Pairing>::ScalarField>,
//         >,
// {
//     fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
//         self.index.serialized_size(compress)
//             + self.value.serialized_size(compress)
//             + self.batched_opening_proof.serialized_size(compress)
//     }

//     fn serialize_with_mode<W: std::io::Write>(
//         &self,
//         mut writer: W,
//         compress: ark_serialize::Compress,
//     ) -> Result<(), ark_serialize::SerializationError> {
//         self.index.serialize_with_mode(&mut writer, compress)?;
//         self.value.serialize_with_mode(&mut writer, compress)?;
//         self.batched_opening_proof
//             .serialize_with_mode(&mut writer, compress)?;
//         self.batched_aux
//             .serialize_with_mode(&mut writer, compress)?;
//         Ok(())
//     }
// }

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
        value: E::ScalarField,
        batched_opening_proof: PC::BatchProof,
        auxes: Vec<PC::Aux>,
    ) -> Self {
        Self {
            index,
            value,
            batched_opening_proof,
            auxes,
        }
    }

    pub fn get_index(&self) -> <PC::Polynomial as Polynomial<E::ScalarField>>::Point {
        self.index.clone()
    }
    pub fn get_value(&self) -> E::ScalarField {
        self.value
    }
    pub fn get_batched_opening_proof(&self) -> &PC::BatchProof {
        &self.batched_opening_proof
    }
    pub fn get_auxes(&self) -> &[PC::Aux] {
        &self.auxes
    }
}
