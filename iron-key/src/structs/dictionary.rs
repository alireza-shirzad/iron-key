use crate::{IsDictionary, VKDResult, errors::VKDError, utils::hash_to_mu_bits_with_offset};
use ark_ff::Field;
use ark_piop::arithmetic::mat_poly::mle::MLE;
use ark_poly::DenseMultilinearExtension;
use ark_std::{Zero, fmt, fmt::Debug};
use std::collections::HashMap;
use thiserror::Error;
pub struct Dictionary<F: Field> {
    mle: MLE<F>,
    offsets: HashMap<String, usize>,
}
impl<F: Field> Debug for Dictionary<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Dictionary")
            .field("mle", &self.mle.evaluations())
            .field("offsets", &self.offsets)
            .finish()
    }
}
impl<F: Field> Dictionary<F> {
    pub fn new_with_capacity(capacity: usize) -> Self {
        let real_capacity = capacity.next_power_of_two();
        let num_vars = real_capacity.trailing_zeros() as usize;
        let mle: MLE<F> = MLE::new(
            DenseMultilinearExtension::from_evaluations_vec(num_vars, vec![F::ZERO; real_capacity]),
            None,
        );
        let offsets = HashMap::new();
        Self::new(mle, offsets)
    }

    pub fn new(mle: MLE<F>, offsets: HashMap<String, usize>) -> Self {
        Self { mle, offsets }
    }

    pub fn get_mle(&self) -> &MLE<F> {
        &self.mle
    }

    pub fn get_offsets(&self) -> &HashMap<String, usize> {
        &self.offsets
    }

    pub fn max_size(&self) -> usize {
        1 << self.mle.num_vars()
    }

    pub fn log_max_size(&self) -> usize {
        self.mle.num_vars()
    }

    pub fn size(&self) -> usize {
        self.offsets.len()
    }

    pub fn find_index(&self, label: &str) -> VKDResult<usize> {
        let offset_opt = self.offsets.get(label);
        let offset = match offset_opt {
            Some(offset) => offset,
            None => {
                return VKDResult::Err(VKDError::DictionaryError(DictionaryError::LabelNotFound(
                    label.to_string(),
                )));
            },
        };
        let (label, _) = hash_to_mu_bits_with_offset::<F>(label, *offset, self.log_max_size());
        Ok(label)
    }

    pub fn get(&self, label: &str) -> VKDResult<F> {
        let index = self.find_index(label)?;
        Ok(*self.mle.evaluations().get(index).unwrap())
    }

    fn alloc_index(&mut self, label: &str) -> VKDResult<(usize, usize)> {
        let mut offset: usize = 0;
        let (mut index, _) = hash_to_mu_bits_with_offset::<F>(label, offset, self.log_max_size());
        let evaluations = self.mle.evaluations();
        let mut value = evaluations.get(index).unwrap();
        while !value.is_zero() {
            offset += 1;
            (index, _) = hash_to_mu_bits_with_offset::<F>(label, offset, self.log_max_size());

            value = evaluations.get(index).unwrap();
        }
        Ok((offset, index))
    }

    pub fn insert(&mut self, label: &str, value: F) -> VKDResult<()> {
        if self.offsets.contains_key(label) {
            return VKDResult::Err(VKDError::DictionaryError(
                DictionaryError::LabelAlreadyExists(label.to_string()),
            ));
        }
        if self.offsets.len() >= self.max_size() {
            return VKDResult::Err(VKDError::DictionaryError(DictionaryError::DictionaryFull));
        }
        let (offset, index) = self.alloc_index(label)?;
        self.offsets.insert(label.to_string(), offset);
        self.mle.mat_mle_mut().evaluations[index] = value;
        Ok(())
    }
}

impl<F: Field> IsDictionary for Dictionary<F> {
    type Label = String;
    type Value = F;
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
    use ark_test_curves::bls12_381::Fr;
    use fake::{
        Fake,
        faker::internet::en::{FreeEmail, FreeEmailProvider, SafeEmail},
    };
    #[test]
    fn test_dictionary() {
        const DICT_CAPACITY: usize = 1 << 4;
        const NUM_ENTRIES: usize = 1 << 3;
        let mut rng = ark_std::test_rng();
        let mut dict: Dictionary<Fr> = Dictionary::new_with_capacity(DICT_CAPACITY);
        for _ in 0..NUM_ENTRIES {
            let label: String = FreeEmail().fake();
            let value = Fr::rand(&mut rng);
            dict.insert(&label, value).unwrap();
        }
        assert_eq!(dict.size(), NUM_ENTRIES);
        assert_eq!(
            dict.mle
                .evaluations()
                .iter()
                .filter(|&&x| !x.is_zero())
                .count(),
            NUM_ENTRIES
        );
    }
}
