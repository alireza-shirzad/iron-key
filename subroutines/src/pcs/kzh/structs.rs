use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};

use arithmetic::DenseMultilinearExtension;
use ark_serialize::{self, CanonicalDeserialize, CanonicalSerialize};
use ark_std::ops::Sub;
use derivative::Derivative;
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

///////////// Opening Proof /////////////////

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq, Eq)]

/// proof of opening
pub struct KZH2OpeningProof<E: Pairing> {
    /// Evaluation of quotients
    f_star: DenseMultilinearExtension<E::ScalarField>,
}

impl<E: Pairing> KZH2OpeningProof<E> {
    /// Create a new opening proof
    pub fn new(f_star: DenseMultilinearExtension<E::ScalarField>) -> Self {
        Self { f_star }
    }

    /// Get the opening proof
    pub fn get_f_star(&self) -> DenseMultilinearExtension<E::ScalarField> {
        self.f_star.clone()
    }
}

impl<E: Pairing> Default for KZH2OpeningProof<E> {
    fn default() -> Self {
        KZH2OpeningProof {
            f_star: DenseMultilinearExtension::default(),
        }
    }
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct KZH2BatchOpeningProof<E: Pairing> {
    batch_proof: KZH2OpeningProof<E>,
}

impl<E: Pairing> KZH2BatchOpeningProof<E> {
    /// Create a new batch opening proof
    pub fn new(batch_proof: KZH2OpeningProof<E>) -> Self {
        Self { batch_proof }
    }

    /// Get the batch opening proof
    pub fn get_batch_proof(&self) -> KZH2OpeningProof<E> {
        self.batch_proof.clone()
    }
}

impl<E: Pairing> Default for KZH2BatchOpeningProof<E> {
    fn default() -> Self {
        KZH2BatchOpeningProof {
            batch_proof: KZH2OpeningProof::default(),
        }
    }
}
