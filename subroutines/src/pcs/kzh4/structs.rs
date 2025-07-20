use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};

use crate::poly::DenseOrSparseMLE;
use ark_serialize::{self, CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_iter_mut, ops::Sub, rand::Rng, UniformRand, Zero};
use derivative::Derivative;
#[cfg(feature = "parallel")]
use rayon::iter::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator};
use std::{fmt, ops::Add};
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
pub struct KZH4Commitment<E: Pairing> {
    /// the actual commitment is an affine point.
    com: E::G1Affine,
    nv: usize,
}
impl<E: Pairing> Add for KZH4Commitment<E> {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        let com = (self.com + other.com).into_affine();
        KZH4Commitment::new(com, self.nv)
    }
}

impl<E: Pairing> Sub for KZH4Commitment<E> {
    type Output = Self;
    fn sub(self, other: Self) -> Self {
        let com = (self.com - other.com).into_affine();
        KZH4Commitment::new(com, self.nv)
    }
}

impl<'a, 'b, E: Pairing> Add<&'b KZH4Commitment<E>> for &'a KZH4Commitment<E> {
    type Output = KZH4Commitment<E>;

    fn add(self, rhs: &'b KZH4Commitment<E>) -> Self::Output {
        debug_assert_eq!(self.nv, rhs.nv, "commitments for different nv!");
        let com = (self.com + rhs.com).into_affine();
        KZH4Commitment::new(com, self.nv)
    }
}

impl<'a, 'b, E: Pairing> Sub<&'b KZH4Commitment<E>> for &'a KZH4Commitment<E> {
    type Output = KZH4Commitment<E>;

    fn sub(self, rhs: &'b KZH4Commitment<E>) -> Self::Output {
        debug_assert_eq!(self.nv, rhs.nv, "commitments for different nv!");
        let com = (self.com - rhs.com).into_affine();
        KZH4Commitment::new(com, self.nv)
    }
}

impl<E: Pairing> KZH4Commitment<E> {
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

#[derive(Debug, Derivative, CanonicalDeserialize, Clone, PartialEq, Eq)]
pub struct KZH4AuxInfo<E: Pairing> {
    d_x: Vec<E::G1Affine>,
    d_xy: Vec<E::G1Affine>,
}
impl<E> ark_serialize::CanonicalSerialize for KZH4AuxInfo<E>
where
    E: Pairing,
{
    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        0
    }

    fn serialize_with_mode<W: std::io::Write>(
        &self,
        mut writer: W,
        compress: ark_serialize::Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        Ok(())
    }
}
impl<E: Pairing> KZH4AuxInfo<E> {
    pub fn new(d_x: Vec<E::G1Affine>, d_xy: Vec<E::G1Affine>) -> Self {
        Self { d_x, d_xy }
    }
    pub fn get_d_x(&self) -> Vec<E::G1Affine> {
        self.d_x.clone()
    }
    pub fn get_d_xy(&self) -> Vec<E::G1Affine> {
        self.d_xy.clone()
    }
}

impl<E: Pairing> Default for KZH4AuxInfo<E> {
    fn default() -> Self {
        KZH4AuxInfo {
            d_x: vec![E::G1Affine::zero(); 0],
            d_xy: vec![E::G1Affine::zero(); 0],
        }
    }
}

impl<E: Pairing> Add for KZH4AuxInfo<E> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        // sanity-checks (optional)
        assert_eq!(self.d_x.len(), rhs.d_x.len());
        assert_eq!(self.d_xy.len(), rhs.d_xy.len());

        let len_x = self.d_x.len();
        let len_y = self.d_xy.len();
        let mut all = vec![E::G1Affine::zero(); len_x + len_y];

        // --- single parallel loop -------------------------------------------------
        cfg_iter_mut!(all).enumerate().for_each(|(idx, slot)| {
            *slot = if idx < len_x {
                // first quarter → d_x
                (self.d_x[idx] + rhs.d_x[idx]).into()
            } else {
                // second quarter → d_y
                let j = idx - len_x;
                (self.d_xy[j] + rhs.d_xy[j]).into()
            };
        });
        // --------------------------------------------------------------------------

        // split back *without copying*.
        let d_xy = all.split_off(len_x); // tail part
        let d_x = all; // head part

        Self { d_x, d_xy }
    }
}

impl<E: Pairing> Sub for KZH4AuxInfo<E> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        // sanity-checks (optional)
        assert_eq!(self.d_x.len(), rhs.d_x.len());
        assert_eq!(self.d_xy.len(), rhs.d_xy.len());

        let len_x = self.d_x.len();
        let len_y = self.d_xy.len();
        let mut all = vec![E::G1Affine::zero(); len_x + len_y];

        // --- single parallel loop -------------------------------------------------
        cfg_iter_mut!(all).enumerate().for_each(|(idx, slot)| {
            *slot = if idx < len_x {
                // first quarter → d_x
                (self.d_x[idx] - rhs.d_x[idx]).into()
            } else {
                // second quarter → d_y
                let j = idx - len_x;
                (self.d_xy[j] - rhs.d_xy[j]).into()
            };
        });
        // --------------------------------------------------------------------------

        // split back *without copying*.
        let d_xy = all.split_off(len_x); // tail part
        let d_x = all; // head part

        Self { d_x, d_xy }
    }
}

///////////// Opening Proof /////////////////

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq, Eq)]

/// proof of opening
pub struct KZH4OpeningProof<E: Pairing> {
    /// Evaluation of quotients
    d_y: Vec<E::G1Affine>,
    d_z: Vec<E::G1Affine>,
    f_star: DenseOrSparseMLE<E::ScalarField>,
}

impl<E: Pairing> KZH4OpeningProof<E> {
    /// Create a new opening proof
    pub fn new(
        d_y: Vec<E::G1Affine>,
        d_z: Vec<E::G1Affine>,
        f_star: DenseOrSparseMLE<E::ScalarField>,
    ) -> Self {
        Self { d_y, d_z, f_star }
    }

    /// Get the evaluation of quotients
    pub fn get_d_z(&self) -> Vec<E::G1Affine> {
        self.d_z.clone()
    }

    /// Get the evaluation of quotients
    pub fn get_d_y(&self) -> Vec<E::G1Affine> {
        self.d_y.clone()
    }
    /// Get the f_star
    pub fn get_f_star(&self) -> DenseOrSparseMLE<E::ScalarField> {
        self.f_star.clone()
    }
}
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct KZH4BatchOpeningProof<E: Pairing> {
    batch_proof: KZH4OpeningProof<E>,
}

impl<E: Pairing> KZH4BatchOpeningProof<E> {
    /// Create a new batch opening proof
    pub fn new(batch_proof: KZH4OpeningProof<E>) -> Self {
        Self { batch_proof }
    }

    /// Get the batch opening proof
    pub fn get_batch_proof(&self) -> KZH4OpeningProof<E> {
        self.batch_proof.clone()
    }
}
