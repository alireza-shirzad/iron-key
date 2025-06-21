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
pub struct KZH2Commitment<E: Pairing> {
    /// the actual commitment is an affine point.
    com: E::G1Affine,
    nv: usize,
}
impl<E: Pairing> Add for KZH2Commitment<E> {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        let com = (self.com + other.com).into_affine();
        KZH2Commitment::new(com, self.nv)
    }
}

impl<E: Pairing> Sub for KZH2Commitment<E> {
    type Output = Self;
    fn sub(self, other: Self) -> Self {
        let com = (self.com - other.com).into_affine();
        KZH2Commitment::new(com, self.nv)
    }
}

impl<'a, 'b, E: Pairing> Add<&'b KZH2Commitment<E>> for &'a KZH2Commitment<E> {
    type Output = KZH2Commitment<E>;

    fn add(self, rhs: &'b KZH2Commitment<E>) -> Self::Output {
        debug_assert_eq!(self.nv, rhs.nv, "commitments for different nv!");
        let com = (self.com + rhs.com).into_affine();
        KZH2Commitment::new(com, self.nv)
    }
}

impl<'a, 'b, E: Pairing> Sub<&'b KZH2Commitment<E>> for &'a KZH2Commitment<E> {
    type Output = KZH2Commitment<E>;

    fn sub(self, rhs: &'b KZH2Commitment<E>) -> Self::Output {
        debug_assert_eq!(self.nv, rhs.nv, "commitments for different nv!");
        let com = (self.com - rhs.com).into_affine();
        KZH2Commitment::new(com, self.nv)
    }
}

impl<E: Pairing> KZH2Commitment<E> {
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
pub struct KZH2AuxInfo<E: Pairing> {
    d: Vec<E::G1Affine>,
}

impl<E: Pairing> KZH2AuxInfo<E> {
    pub fn rand(rng: &mut impl Rng, nu: usize) -> Self {
        let d = (0..nu)
            .map(|_| E::G1Affine::rand(rng))
            .collect::<Vec<E::G1Affine>>();
        KZH2AuxInfo { d }
    }

    /// Create a new auxiliary information
    pub fn new(d: Vec<E::G1Affine>) -> Self {
        Self { d }
    }

    /// Get the auxiliary information
    pub fn get_d(&self) -> Vec<E::G1Affine> {
        self.d.clone()
    }
}

impl<E: Pairing> Default for KZH2AuxInfo<E> {
    fn default() -> Self {
        KZH2AuxInfo { d: vec![] }
    }
}

impl<E: Pairing> Add for KZH2AuxInfo<E> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        assert_eq!(
            self.d.len(),
            rhs.d.len(),
            "Auxiliary information must have the same length"
        );
        let mut output = vec![E::G1Affine::zero(); self.d.len()];
        cfg_iter_mut!(output).enumerate().for_each(|(i, v)| {
            *v = (self.d[i] + rhs.d[i]).into();
        });
        Self { d: output }
    }
}

impl<E: Pairing> Sub for KZH2AuxInfo<E> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        let mut output = vec![E::G1Affine::zero(); self.d.len()];
        cfg_iter_mut!(output).enumerate().for_each(|(i, v)| {
            *v = (self.d[i] - rhs.d[i]).into();
        });
        Self { d: output }
    }
}

///////////// Opening Proof /////////////////

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq, Eq)]

/// proof of opening
pub struct KZH2OpeningProof<E: Pairing> {
    /// Evaluation of quotients
    f_star: DenseOrSparseMLE<E::ScalarField>,
}

impl<E: Pairing> KZH2OpeningProof<E> {
    pub fn rand(rng: &mut impl Rng, nu: usize) -> Self {
        KZH2OpeningProof {
            f_star: DenseOrSparseMLE::rand(nu, rng),
        }
    }

    /// Create a new opening proof
    pub fn new(f_star: DenseOrSparseMLE<E::ScalarField>) -> Self {
        Self { f_star }
    }

    /// Get the opening proof
    pub fn get_f_star(&self) -> DenseOrSparseMLE<E::ScalarField> {
        self.f_star.clone()
    }
}

impl<E: Pairing> Default for KZH2OpeningProof<E> {
    fn default() -> Self {
        KZH2OpeningProof {
            f_star: DenseOrSparseMLE::zero(),
        }
    }
}
