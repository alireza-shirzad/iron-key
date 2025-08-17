use std::sync::Arc;

use crate::{pcs::kzhk::structs::Tensor, PCSError, StructuredReferenceString};
use ark_ec::{pairing::Pairing, CurveGroup, PrimeGroup};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::Rng, One, UniformRand};
use ndarray::{ArrayD, IxDyn};
#[cfg(feature = "parallel")]
use rayon::{
    iter::{
        IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator,
        IntoParallelRefMutIterator, ParallelIterator,
    },
    vec,
};
/// Universal Parameter
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct KZHKUniversalParams<E: Pairing> {
    // A vector of size k representing the dimensions of the tensor
    // In case of k=2, the dimensions would be [nu, mu]
    // Also, the product of the dimensions would be N: the total number of elements in the tensor
    // (the size of polynomial)
    dimensions: Vec<usize>,
    // h_tensors = [H1,H2,...,Hk]
    h_tensors: Arc<Vec<Tensor<E::G1Affine>>>,
    // Vij: i\in[d], j\in[k]
    v_mat: Arc<Vec<Vec<E::G2Prepared>>>,
    // -V : The inverse of the G2 generator
    v: E::G2Affine,
    // G : The G1 generator
    g: E::G1Affine,
}

impl<E: Pairing> KZHKUniversalParams<E> {
    /// Create a new universal parameter
    pub fn new(
        dimensions: Vec<usize>,
        h_tensors: Arc<Vec<Tensor<E::G1Affine>>>,
        v_mat: Arc<Vec<Vec<E::G2Prepared>>>,
        v: E::G2Affine,
        g: E::G1Affine,
    ) -> Self {
        Self {
            dimensions,
            h_tensors,
            v_mat,
            v,
            g,
        }
    }

    pub fn get_dimensions(&self) -> &Vec<usize> {
        &self.dimensions
    }

    pub fn get_h_tensors(&self) -> &Vec<Tensor<E::G1Affine>> {
        &self.h_tensors
    }

    pub fn get_v_mat(&self) -> &Vec<Vec<E::G2Prepared>> {
        &self.v_mat
    }

    pub fn get_v(&self) -> E::G2Affine {
        self.v
    }

    pub fn get_g(&self) -> E::G1Affine {
        self.g
    }
}

/// Prover Parameters
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct KZHKProverParam<E: Pairing> {
    dimensions: Vec<usize>,
    h_tensors: Arc<Vec<Tensor<E::G1Affine>>>,
    v_mat: Arc<Vec<Vec<E::G2Prepared>>>,
}
impl<E: Pairing> KZHKProverParam<E> {
    /// Create a new prover parameter
    pub fn new(
        dimensions: Vec<usize>,
        h_tensors: Arc<Vec<Tensor<E::G1Affine>>>,
        v_mat: Arc<Vec<Vec<E::G2Prepared>>>,
    ) -> Self {
        Self {
            dimensions,
            h_tensors,
            v_mat,
        }
    }

    pub fn get_dimensions(&self) -> &Vec<usize> {
        &self.dimensions
    }

    pub fn get_h_tensors(&self) -> &Vec<Tensor<E::G1Affine>> {
        &self.h_tensors
    }

    pub fn get_v_mat(&self) -> &Vec<Vec<E::G2Prepared>> {
        &self.v_mat
    }
}

/// Verifier Parameters
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct KZHKVerifierParam<E: Pairing> {
    dimensions: Vec<usize>,
    h_tensor: Arc<Tensor<E::G1Affine>>,
    v: E::G2Affine,
    v_mat: Arc<Vec<Vec<E::G2Prepared>>>,
}

impl<E: Pairing> KZHKVerifierParam<E> {
    /// Create a new verifier parameter
    pub fn new(
        dimensions: Vec<usize>,
        h_tensor: Arc<Tensor<E::G1Affine>>,
        v: E::G2Affine,
        v_mat: Arc<Vec<Vec<E::G2Prepared>>>,
    ) -> Self {
        Self {
            dimensions,
            h_tensor,
            v,
            v_mat,
        }
    }

    pub fn get_dimensions(&self) -> &Vec<usize> {
        &self.dimensions
    }

    pub fn get_h_tensor(&self) -> &Tensor<E::G1Affine> {
        &self.h_tensor
    }

    pub fn get_v(&self) -> E::G2Affine {
        self.v
    }

    pub fn get_v_mat(&self) -> &Vec<Vec<E::G2Prepared>> {
        &self.v_mat
    }
}

impl<E: Pairing> StructuredReferenceString<E> for KZHKUniversalParams<E> {
    type ProverParam = KZHKProverParam<E>;
    type VerifierParam = KZHKVerifierParam<E>;

    /// Extract the prover parameters from the public parameters.
    fn extract_prover_param(&self, _supported_num_vars: usize) -> Self::ProverParam {
        KZHKProverParam::new(
            self.dimensions.clone(),
            self.h_tensors.clone(),
            self.v_mat.clone(),
        )
    }

    /// Extract the verifier parameters from the public parameters.
    fn extract_verifier_param(&self, _supported_num_vars: usize) -> Self::VerifierParam {
        KZHKVerifierParam::new(
            self.dimensions.clone(),
            self.h_tensors[self.dimensions.len() - 1].clone().into(),
            self.v,
            self.v_mat.clone(),
        )
    }

    fn trim(
        &self,
        supported_num_vars: usize,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), PCSError> {
        Ok((
            self.extract_prover_param(supported_num_vars),
            self.extract_verifier_param(supported_num_vars),
        ))
    }

    fn gen_srs_for_testing<R: Rng>(
        rng: &mut R,
        k: usize,
        num_vars: usize,
    ) -> Result<KZHKUniversalParams<E>, PCSError> {
        // Dimensions of the polynomials
        let d = num_vars / k;
        let remainder_d = num_vars % k;
        let mut dimensions = vec![d; k];
        dimensions[k - 1] += remainder_d;
        let _num_vars = vec![1 << d; k];
        // Sampling generators
        let g = E::G1::rand(rng);
        let v = E::G2::rand(rng);
        // Sampling trapdoors, mu_mat = (u_1, ..., u_k) where u_i = (u_(i,1), ...,
        // u_(i,d_i))
        let mu_mat = (0..k)
            .map(|i| {
                (0..(1 << dimensions[i]))
                    .map(|_| E::ScalarField::rand(rng))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        // Computing H_is

        let mut h_tensors = Vec::with_capacity(k);

        // Build H1 .. Hk
        for t in 0..k {
            // Shape of H_{t+1} is dimensions[t..]
            let shape = dimensions[t..].iter().map(|&d| 1 << d).collect::<Vec<_>>();

            // Handle the degenerate case where some axis is zero (ndarray allows it).
            let h_t = ArrayD::from_shape_fn(IxDyn(&shape), |ix| {
                // ix has length (k - t); ix[0] corresponds to axis t
                let mut s = E::ScalarField::one();
                for j in t..k {
                    let row = ix[j - t];
                    s *= mu_mat[j][row];
                }
                g.mul_bigint(s.into_bigint()).into_affine()
            });

            h_tensors.push(Tensor(h_t));
        }

        let h_tensors = Arc::new(h_tensors);

        let v_mat = (0..k)
            .map(|j| {
                (0..(1 << dimensions[j]))
                    .map(|i| {
                        let p = <E as Pairing>::G2Prepared::from(
                            v.mul_bigint(mu_mat[j][i].into_bigint()),
                        );
                        p
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let v_mat = Arc::new(v_mat);

        Ok(KZHKUniversalParams::new(
            dimensions,
            h_tensors,
            v_mat,
            v.into_affine(),
            g.into_affine(),
        ))
    }
}
