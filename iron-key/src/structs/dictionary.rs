use crate::{
    VKDDictionary, VKDLabel, VKDResult, errors::VKDError, utils::hash_to_mu_bits_with_offset,
};
use ark_ec::{AdditiveGroup, pairing::Pairing};
use ark_ff::{Field, PrimeField};
use ark_poly::{
    DenseMultilinearExtension, MultilinearExtension, SparseMultilinearExtension,
    univariate::DenseOrSparsePolynomial,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    Zero,
    fmt::{self, Debug},
};
use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
    sync::Arc,
};
use subroutines::{PolynomialCommitmentScheme, pcs::kzh::poly::DenseOrSparseMLE};
use thiserror::Error;
pub struct IronDictionary<E: Pairing, T: VKDLabel<E>> {
    value_mle: Arc<RefCell<DenseOrSparseMLE<E::ScalarField>>>,
    label_mle: Arc<RefCell<DenseOrSparseMLE<E::ScalarField>>>,
    inner_dict: BTreeMap<T, E::ScalarField>,
    offsets: HashMap<T, usize>,
}

impl<E: Pairing, T: Debug + VKDLabel<E>> IronDictionary<E, T> {
    pub fn new_with_capacity(capacity: usize) -> Self {
        let real_capacity = capacity.next_power_of_two();
        let num_vars = real_capacity.trailing_zeros() as usize;

        // Create an empty sparse MLE since all values are initially zero
        let mle: DenseOrSparseMLE<E::ScalarField> = DenseOrSparseMLE::Sparse(
            SparseMultilinearExtension::from_evaluations(num_vars, std::iter::empty()),
        );
        let offsets = HashMap::new();
        let value_mle = Arc::new(RefCell::new(mle.clone()));
        let label_mle = Arc::new(RefCell::new(mle.clone()));
        let inner_dict = BTreeMap::new();
        Self::new(inner_dict, value_mle, label_mle, offsets)
    }

    pub fn new(
        inner_dict: BTreeMap<T, E::ScalarField>,
        value_mle: Arc<RefCell<DenseOrSparseMLE<E::ScalarField>>>,
        label_mle: Arc<RefCell<DenseOrSparseMLE<E::ScalarField>>>,
        offsets: HashMap<T, usize>,
    ) -> Self {
        Self {
            inner_dict,
            value_mle,
            label_mle,
            offsets,
        }
    }

    pub fn contains(&self, label: &T) -> bool {
        self.offsets.contains_key(label)
    }

    pub fn get_label_mle(&self) -> Arc<RefCell<DenseOrSparseMLE<E::ScalarField>>> {
        self.label_mle.clone()
    }

    pub fn get_value_mle(&self) -> Arc<RefCell<DenseOrSparseMLE<E::ScalarField>>> {
        self.value_mle.clone()
    }
    pub fn get_offsets(&self) -> &HashMap<T, usize> {
        &self.offsets
    }

    pub fn max_size(&self) -> usize {
        debug_assert_eq!(
            self.label_mle.borrow().num_vars(),
            self.value_mle.borrow().num_vars()
        );
        1 << self.label_mle.borrow().num_vars()
    }

    pub fn log_max_size(&self) -> usize {
        debug_assert_eq!(
            self.label_mle.borrow().num_vars(),
            self.value_mle.borrow().num_vars()
        );
        self.label_mle.borrow().num_vars()
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
        match &*self.value_mle.borrow() {
            DenseOrSparseMLE::Dense(dense_multilinear_extension) => {
                Ok(dense_multilinear_extension.evaluations[index])
            },
            DenseOrSparseMLE::Sparse(sparse_multilinear_extension) => {
                Ok(*sparse_multilinear_extension
                    .evaluations
                    .get(&index)
                    .unwrap())
            },
        }
    }

    fn alloc_index(&mut self, label: &T) -> VKDResult<(usize, usize)> {
        let mut offset: usize = 0;
        let (mut index, _) = hash_to_mu_bits_with_offset::<E::ScalarField>(
            &label.to_string(),
            offset,
            self.log_max_size(),
        );
        let mut value = match &*self.label_mle.borrow() {
            DenseOrSparseMLE::Dense(dense_multilinear_extension) => {
                let evaluations = &dense_multilinear_extension.evaluations;
                evaluations[index]
            },
            DenseOrSparseMLE::Sparse(sparse_multilinear_extension) => {
                let evaluations = &sparse_multilinear_extension.evaluations;
                *evaluations.get(&index).unwrap_or(&E::ScalarField::zero())
            },
        };
        while !value.is_zero() {
            offset += 1;
            (index, _) = hash_to_mu_bits_with_offset::<E::ScalarField>(
                &label.to_string(),
                offset,
                self.log_max_size(),
            );

            value = match &*self.label_mle.borrow() {
                DenseOrSparseMLE::Dense(dense_multilinear_extension) => {
                    let evaluations = &dense_multilinear_extension.evaluations;
                    evaluations[index]
                },
                DenseOrSparseMLE::Sparse(sparse_multilinear_extension) => {
                    let evaluations = &sparse_multilinear_extension.evaluations;
                    *evaluations.get(&index).unwrap_or(&E::ScalarField::zero())
                },
            };
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
        match &mut *self.value_mle.borrow_mut() {
            DenseOrSparseMLE::Dense(dense_multilinear_extension) => {
                dense_multilinear_extension.evaluations[index] = value;
            },
            DenseOrSparseMLE::Sparse(sparse_multilinear_extension) => {
                sparse_multilinear_extension
                    .evaluations
                    .insert(index, value);
            },
        }
        match &mut *self.label_mle.borrow_mut() {
            DenseOrSparseMLE::Dense(dense_multilinear_extension) => {
                dense_multilinear_extension.evaluations[index] = label.to_field();
            },
            DenseOrSparseMLE::Sparse(sparse_multilinear_extension) => {
                sparse_multilinear_extension
                    .evaluations
                    .insert(index, label.to_field());
            },
        }
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
