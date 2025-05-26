use crate::{
    VKDDictionary, VKDLabel, VKDResult, errors::VKDError, utils::hash_to_mu_bits_with_offset,
};
use ark_ec::{AdditiveGroup, pairing::Pairing};
use ark_ff::{Field, PrimeField};
use ark_poly::{DenseMultilinearExtension, univariate::DenseOrSparsePolynomial};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{Zero, fmt, fmt::Debug};
use std::collections::HashMap;
use subroutines::PolynomialCommitmentScheme;
use thiserror::Error;
pub struct IronDictionary<E: Pairing, T: VKDLabel<E>> {
    value_mle: DenseMultilinearExtension<E::ScalarField>,
    label_mle: DenseMultilinearExtension<E::ScalarField>,
    offsets: HashMap<T, usize>,
}

impl<E: Pairing, T: Debug + VKDLabel<E>> IronDictionary<E, T> {
    pub fn new_with_capacity(capacity: usize) -> Self {
        let real_capacity = capacity.next_power_of_two();
        let num_vars = real_capacity.trailing_zeros() as usize;
        let mle: DenseMultilinearExtension<E::ScalarField> =
            DenseMultilinearExtension::from_evaluations_vec(
                num_vars,
                vec![E::ScalarField::ZERO; real_capacity],
            );
        let offsets = HashMap::new();
        Self::new(mle.clone(), mle, offsets)
    }

    pub fn new(
        value_mle: DenseMultilinearExtension<E::ScalarField>,
        label_mle: DenseMultilinearExtension<E::ScalarField>,
        offsets: HashMap<T, usize>,
    ) -> Self {
        Self {
            value_mle,
            label_mle,
            offsets,
        }
    }

    pub fn contains(&self, label: &T) -> bool {
        self.offsets.contains_key(label)
    }

    pub fn get_label_mle(&self) -> &DenseMultilinearExtension<E::ScalarField> {
        &self.label_mle
    }

    pub fn get_value_mle(&self) -> &DenseMultilinearExtension<E::ScalarField> {
        &self.value_mle
    }
    pub fn get_offsets(&self) -> &HashMap<T, usize> {
        &self.offsets
    }

    pub fn max_size(&self) -> usize {
        debug_assert_eq!(self.label_mle.num_vars, self.value_mle.num_vars);
        1 << self.label_mle.num_vars
    }

    pub fn log_max_size(&self) -> usize {
        debug_assert_eq!(self.label_mle.num_vars, self.value_mle.num_vars);
        self.label_mle.num_vars
    }

    pub fn size(&self) -> usize {
        self.offsets.len()
    }

    pub fn find_index(&self, label: &T) -> VKDResult<usize> {
        let offset_opt = self.offsets.get(label);
        let offset = match offset_opt {
            Some(offset) => offset,
            None => {
                return VKDResult::Err(VKDError::DictionaryError(DictionaryError::LabelNotFound(
                    label.to_string(),
                )));
            },
        };
        let (label, _) = hash_to_mu_bits_with_offset::<E::ScalarField>(
            &label.to_string(),
            *offset,
            self.log_max_size(),
        );
        Ok(label)
    }

    pub fn get(&self, label: &T) -> VKDResult<E::ScalarField> {
        let index = self.find_index(label)?;
        debug_assert_eq!(
            label.to_field(),
            *self.label_mle.evaluations.get(index).unwrap()
        );
        Ok(*self.value_mle.evaluations.get(index).unwrap())
    }

    fn alloc_index(&mut self, label: &T) -> VKDResult<(usize, usize)> {
        let mut offset: usize = 0;
        let (mut index, _) = hash_to_mu_bits_with_offset::<E::ScalarField>(
            &label.to_string(),
            offset,
            self.log_max_size(),
        );
        let evaluations = &self.label_mle.evaluations;
        let mut value = evaluations.get(index).unwrap();
        while !value.is_zero() {
            offset += 1;
            (index, _) = hash_to_mu_bits_with_offset::<E::ScalarField>(
                &label.to_string(),
                offset,
                self.log_max_size(),
            );

            value = evaluations.get(index).unwrap();
        }
        Ok((offset, index))
    }

    pub fn insert(&mut self, label: &T, value: E::ScalarField) -> VKDResult<()> {
        if self.offsets.contains_key(label) {
            return VKDResult::Err(VKDError::DictionaryError(
                DictionaryError::LabelAlreadyExists(label.to_string()),
            ));
        }
        if self.offsets.len() >= self.max_size() {
            return VKDResult::Err(VKDError::DictionaryError(DictionaryError::DictionaryFull));
        }
        let (offset, index) = self.alloc_index(label)?;
        self.offsets.insert(label.clone(), offset);
        self.value_mle.evaluations[index] = value;
        self.label_mle.evaluations[index] = label.to_field();
        Ok(())
    }

    pub fn insert_batch(&mut self, batch: &HashMap<T, E::ScalarField>) -> VKDResult<()> {
        for (label, value) in batch.iter() {
            self.insert(label, *value)?;
        }
        Ok(())
    }

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Dictionary")
            .field("label_mle", &self.label_mle)
            .field("value_mle", &self.value_mle)
            .field("offsets", &self.offsets)
            .finish()
    }
}

impl<E: Pairing, T: VKDLabel<E>> VKDDictionary<E> for IronDictionary<E, T> {
    type Label = T;
    type Value = E::ScalarField;
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct IronDictionaryCommitment<E, PC>
where
    E: Pairing,
    PC: PolynomialCommitmentScheme<E>,
{
    label_commitment: PC::Commitment,
    value_commitment: PC::Commitment,
}

impl<E, PC> IronDictionaryCommitment<E, PC>
where
    E: Pairing,
    PC: PolynomialCommitmentScheme<E>,
{
    pub fn new(label_commitment: PC::Commitment, value_commitment: PC::Commitment) -> Self {
        Self {
            label_commitment,
            value_commitment,
        }
    }

    pub fn label_commitment(&self) -> &PC::Commitment {
        &self.label_commitment
    }

    pub fn value_commitment(&self) -> &PC::Commitment {
        &self.value_commitment
    }
}

/// An `enum` specifying the possible failure modes of the DB-SNARK system.
#[derive(Error, Debug)]
#[allow(private_interfaces)]
pub(crate) enum DictionaryError {
    #[error("The label '{0}' was not found in the dictionary.")]
    LabelNotFound(String),

    #[error("The label '{0}' already exists in the dictionary.")]
    LabelAlreadyExists(String),

    #[error("The dictionary is full.")]
    DictionaryFull,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use fake::{
        Fake,
        faker::internet::en::{FreeEmail, FreeEmailProvider, SafeEmail},
    };
    #[test]
    fn test_dictionary() {
        // const DICT_CAPACITY: usize = 1 << 4;
        // const NUM_ENTRIES: usize = 1 << 3;
        // let mut rng = ark_std::test_rng();
        // let mut dict: IronDictionary<Fr> =
        // IronDictionary::new_with_capacity(DICT_CAPACITY); for _ in 0.
        // .NUM_ENTRIES {     let label: String = FreeEmail().fake();
        //     let value = Fr::rand(&mut rng);
        //     dict.insert(&label, value).unwrap();
        // }
        // assert_eq!(dict.size(), NUM_ENTRIES);
        // assert_eq!(
        //     dict.mle
        //         .evaluations()
        //         .iter()
        //         .filter(|&&x| !x.is_zero())
        //         .count(),
        //     NUM_ENTRIES
        // );
    }
}
