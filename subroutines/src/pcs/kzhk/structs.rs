use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};

use crate::poly::DenseOrSparseMLE;
use ark_serialize::{
    self, CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError, Valid,
    Validate, Write,
};
use ark_std::{cfg_iter_mut, ops::Sub, rand::Rng, UniformRand, Zero};
use derivative::Derivative;
use ndarray::{ArrayD, IxDyn};
#[cfg(feature = "parallel")]
use rayon::iter::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator};
use std::{
    fmt,
    ops::{Add, Deref, DerefMut},
};
///////////////// Commitment //////////////////////

#[derive(Derivative, CanonicalSerialize, CanonicalDeserialize)]
#[derivative(
    Default(bound = ""),
    Hash(bound = ""),
    Clone(bound = ""),
    Copy(bound = ""),
    Debug(bound = ""),
    PartialEq(bound = ""),
    Eq(bound = "")
)]
/// A commitment is an Affine point.
pub struct KZHKCommitment<E: Pairing> {
    /// the actual commitment is an affine point.
    com: E::G1Affine,
    nv: usize,
}
impl<E: Pairing> Add for KZHKCommitment<E> {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        debug_assert_eq!(self.nv, other.nv, "commitments for different nv!");
        let com = (self.com + other.com).into_affine();
        KZHKCommitment::new(com, self.nv)
    }
}

impl<E: Pairing> Sub for KZHKCommitment<E> {
    type Output = Self;
    fn sub(self, other: Self) -> Self {
        debug_assert_eq!(self.nv, other.nv, "commitments for different nv!");
        let com = (self.com - other.com).into_affine();
        KZHKCommitment::new(com, self.nv)
    }
}

impl<'a, 'b, E: Pairing> Add<&'b KZHKCommitment<E>> for &'a KZHKCommitment<E> {
    type Output = KZHKCommitment<E>;

    fn add(self, rhs: &'b KZHKCommitment<E>) -> Self::Output {
        debug_assert_eq!(self.nv, rhs.nv, "commitments for different nv!");
        let com = (self.com + rhs.com).into_affine();
        KZHKCommitment::new(com, self.nv)
    }
}

impl<'a, 'b, E: Pairing> Sub<&'b KZHKCommitment<E>> for &'a KZHKCommitment<E> {
    type Output = KZHKCommitment<E>;

    fn sub(self, rhs: &'b KZHKCommitment<E>) -> Self::Output {
        debug_assert_eq!(self.nv, rhs.nv, "commitments for different nv!");
        let com = (self.com - rhs.com).into_affine();
        KZHKCommitment::new(com, self.nv)
    }
}

impl<E: Pairing> KZHKCommitment<E> {
    /// Create a new commitment
    pub fn new(com: E::G1Affine, nv: usize) -> Self {
        Self { com, nv }
    }

    /// Get the commitment
    pub fn get_commitment(&self) -> E::G1Affine {
        self.com
    }

    /// Get the number of variables
    pub fn get_num_vars(&self) -> usize {
        self.nv
    }
}

////////////// Auxiliary information /////////////////

#[derive(Debug, Derivative, CanonicalSerialize, CanonicalDeserialize, Clone, PartialEq, Eq)]
pub struct KZHKAuxInfo<E: Pairing> {
    d_bool: Vec<Vec<E::G1Affine>>,
}

impl<E: Pairing> KZHKAuxInfo<E> {
    /// Create a new auxiliary information
    pub fn new(d_bool: Vec<Vec<E::G1Affine>>) -> Self {
        Self { d_bool }
    }

    /// Get the auxiliary information
    pub fn get_d_bool(&self) -> &Vec<Vec<E::G1Affine>> {
        &self.d_bool
    }
}

impl<E: Pairing> Default for KZHKAuxInfo<E> {
    fn default() -> Self {
        KZHKAuxInfo { d_bool: vec![] }
    }
}

impl<E: Pairing> Add for KZHKAuxInfo<E> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        if self == KZHKAuxInfo::default() {
            return rhs;
        }
        if rhs == KZHKAuxInfo::default() {
            return self;
        }
        assert_eq!(
            self.d_bool.len(),
            rhs.d_bool.len(),
            "Auxiliary information must have the same length"
        );
        todo!()
    }
}

impl<E: Pairing> Sub for KZHKAuxInfo<E> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        let mut output = vec![vec![E::G1Affine::zero(); self.d_bool[0].len()]; self.d_bool.len()];
        todo!()
    }
}

///////////// Opening Proof /////////////////

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq, Eq)]

/// proof of opening
pub struct KZHKOpeningProof<E: Pairing> {
    d: Vec<Vec<E::G1Affine>>,
    f: DenseOrSparseMLE<E::ScalarField>,
}

impl<E: Pairing> KZHKOpeningProof<E> {
    /// Create a new opening proof
    pub fn new(d: Vec<Vec<E::G1Affine>>, f: DenseOrSparseMLE<E::ScalarField>) -> Self {
        Self { d, f }
    }

    /// Get the evaluation of quotients
    pub fn get_d(&self) -> &Vec<Vec<E::G1Affine>> {
        &self.d
    }

    /// Get the opening proof
    pub fn get_f(&self) -> &DenseOrSparseMLE<E::ScalarField> {
        &self.f
    }
}

///////////////// Tensor and implementation ///////////////////

/// Local newtype wrapper around `ndarray::ArrayD<T>` so we can implement
/// `CanonicalSerialize`/`CanonicalDeserialize` without violating the orphan
/// rules.
#[derive(Clone, Debug)]
pub struct Tensor<T>(pub ArrayD<T>);

impl<T> From<ArrayD<T>> for Tensor<T> {
    fn from(a: ArrayD<T>) -> Self {
        Tensor(a)
    }
}
impl<T> From<Tensor<T>> for ArrayD<T> {
    fn from(w: Tensor<T>) -> Self {
        w.0
    }
}
impl<T> Deref for Tensor<T> {
    type Target = ArrayD<T>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl<T> DerefMut for Tensor<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

fn product_u64(shape: &[usize]) -> Result<u64, SerializationError> {
    let mut acc: u128 = 1;
    for &d in shape {
        acc = acc
            .checked_mul(d as u128)
            .ok_or(SerializationError::InvalidData)?;
    }
    u64::try_from(acc).map_err(|_| SerializationError::InvalidData)
}

/// Iterator to walk all indices in row-major order for a given shape.
struct RowMajorIx {
    idx: Vec<usize>,
    shape: Vec<usize>,
    done: bool,
}
impl RowMajorIx {
    fn new(shape: &[usize]) -> Self {
        let k = shape.len();
        let done = shape.iter().any(|&d| d == 0);
        Self {
            idx: vec![0; k],
            shape: shape.to_vec(),
            done,
        }
    }
}
impl Iterator for RowMajorIx {
    type Item = IxDyn;
    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let out = IxDyn(&self.idx);
        for ax in (0..self.shape.len()).rev() {
            self.idx[ax] += 1;
            if self.idx[ax] < self.shape[ax] {
                break;
            } else {
                self.idx[ax] = 0;
                if ax == 0 {
                    self.done = true;
                }
            }
        }
        Some(out)
    }
}

impl<T: CanonicalSerialize> CanonicalSerialize for Tensor<T> {
    fn serialize_with_mode<W: Write>(
        &self,
        mut w: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        // rank
        let rank = u32::try_from(self.ndim()).map_err(|_| SerializationError::InvalidData)?;
        rank.serialize_with_mode(&mut w, compress)?;
        // shape
        for &d in self.shape() {
            let d64 = u64::try_from(d).map_err(|_| SerializationError::InvalidData)?;
            d64.serialize_with_mode(&mut w, compress)?;
        }
        // element count
        let n = product_u64(self.shape())?;
        n.serialize_with_mode(&mut w, compress)?;
        // elements in row-major order
        let shape = self.shape().to_vec();
        if self.is_standard_layout() {
            if let Some(slice) = self.as_slice_memory_order() {
                for t in slice {
                    t.serialize_with_mode(&mut w, compress)?;
                }
                return Ok(());
            }
        }
        for ix in RowMajorIx::new(&shape) {
            self[ix].serialize_with_mode(&mut w, compress)?;
        }
        Ok(())
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        let mut sz = 0usize;
        sz += u32::default().serialized_size(compress);
        sz += self.shape().len() * u64::default().serialized_size(compress);
        sz += u64::default().serialized_size(compress);
        if self.is_standard_layout() {
            if let Some(slice) = self.as_slice_memory_order() {
                return sz
                    + slice
                        .iter()
                        .map(|t| t.serialized_size(compress))
                        .sum::<usize>();
            }
        }
        let shape = self.shape().to_vec();
        sz + RowMajorIx::new(&shape)
            .map(|ix| self[ix].serialized_size(compress))
            .sum::<usize>()
    }
}

impl<T: Valid> Valid for Tensor<T> {
    fn check(&self) -> Result<(), SerializationError> {
        // Check each element
        if self.is_standard_layout() {
            if let Some(slice) = self.as_slice_memory_order() {
                for t in slice {
                    t.check()?;
                }
                return Ok(());
            }
        }

        let shape = self.shape().to_vec();
        for ix in RowMajorIx::new(&shape) {
            self[ix].check()?;
        }
        Ok(())
    }
}

impl<T: Valid + CanonicalDeserialize> CanonicalDeserialize for Tensor<T> {
    fn deserialize_with_mode<R: Read>(
        mut r: R,
        compress: Compress,
        _validate: Validate,
    ) -> Result<Self, SerializationError> {
        let k = u32::deserialize_with_mode(&mut r, compress, Validate::No)?;
        let k = usize::try_from(k).map_err(|_| SerializationError::InvalidData)?;
        // shape
        let mut shape = Vec::with_capacity(k);
        for _ in 0..k {
            let d = u64::deserialize_with_mode(&mut r, compress, Validate::No)?;
            shape.push(usize::try_from(d).map_err(|_| SerializationError::InvalidData)?);
        }
        // element count check
        let n_hdr = u64::deserialize_with_mode(&mut r, compress, Validate::No)?;
        let n_calc = product_u64(&shape)?;
        if n_hdr != n_calc {
            return Err(SerializationError::InvalidData);
        }
        let n = usize::try_from(n_calc).map_err(|_| SerializationError::InvalidData)?;
        // elements in row-major order
        let mut data = Vec::with_capacity(n);
        for _ in 0..n {
            data.push(T::deserialize_with_mode(&mut r, compress, Validate::No)?);
        }
        let arr = ArrayD::from_shape_vec(IxDyn(&shape), data)
            .map_err(|_| SerializationError::InvalidData)?;
        Ok(Tensor(arr))
    }
}
