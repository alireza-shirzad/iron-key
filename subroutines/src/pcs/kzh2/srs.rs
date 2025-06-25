use std::sync::Arc;

use crate::{PCSError, StructuredReferenceString};
use ark_ec::{pairing::Pairing, CurveGroup, ScalarMul};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    cfg_into_iter, cfg_iter, cfg_iter_mut, end_timer, rand::Rng, start_timer, UniformRand,
};
#[cfg(feature = "parallel")]
use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator,
    IntoParallelRefMutIterator, ParallelIterator,
};
/// Universal Parameter
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct KZH2UniversalParams<E: Pairing> {
    nu: usize,
    mu: usize,
    h_mat: Arc<Vec<E::G1Affine>>,
    h_vec: Arc<Vec<E::G1Affine>>,
    v_vec: Arc<Vec<E::G2Affine>>,
    minus_v_prime: E::G2Affine,
    gi: Arc<Vec<E::G1Affine>>,
}

impl<E: Pairing> KZH2UniversalParams<E> {
    /// Create a new universal parameter
    pub fn new(
        nu: usize,
        mu: usize,
        h_mat: Arc<Vec<E::G1Affine>>,
        h_vec: Arc<Vec<E::G1Affine>>,
        v_vec: Arc<Vec<E::G2Affine>>,
        minus_v_prime: E::G2Affine,
        gi: Arc<Vec<E::G1Affine>>,
    ) -> Self {
        Self {
            nu,
            mu,
            h_mat,
            h_vec,
            v_vec,
            minus_v_prime,
            gi,
        }
    }

    pub fn get_nu(&self) -> usize {
        self.nu
    }
    pub fn get_mu(&self) -> usize {
        self.mu
    }

    pub fn get_h_mat(&self) -> &Vec<E::G1Affine> {
        &self.h_mat
    }
    pub fn get_h_vec(&self) -> &Vec<E::G1Affine> {
        &self.h_vec
    }
    pub fn get_v_vec(&self) -> &Vec<E::G2Affine> {
        &self.v_vec
    }
    pub fn get_minus_v_prime(&self) -> E::G2Affine {
        self.minus_v_prime
    }
    pub fn get_gi(&self) -> &Vec<E::G1Affine> {
        &self.gi
    }
}

/// Prover Parameters
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct KZH2ProverParam<E: Pairing> {
    nu: usize,
    mu: usize,
    h_mat: Arc<Vec<E::G1Affine>>,
    h_vec: Arc<Vec<E::G1Affine>>,
}
impl<E: Pairing> KZH2ProverParam<E> {
    /// Create a new prover parameter
    pub fn new(
        nu: usize,
        mu: usize,
        h_mat: Arc<Vec<E::G1Affine>>,
        h_vec: Arc<Vec<E::G1Affine>>,
    ) -> Self {
        Self {
            nu,
            mu,
            h_mat,
            h_vec,
        }
    }

    pub fn get_nu(&self) -> usize {
        self.nu
    }
    pub fn get_mu(&self) -> usize {
        self.mu
    }
    pub fn get_h_mat(&self) -> &Vec<E::G1Affine> {
        &self.h_mat
    }
    pub fn get_h_vec(&self) -> &Vec<E::G1Affine> {
        &self.h_vec
    }
}

/// Verifier Parameters
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct KZH2VerifierParam<E: Pairing> {
    nu: usize,
    mu: usize,
    h_vec: Arc<Vec<E::G1Affine>>,
    minus_v_prime: E::G2Affine,
    v_vec: Arc<Vec<E::G2Affine>>,
}

impl<E: Pairing> KZH2VerifierParam<E> {
    /// Create a new verifier parameter
    pub fn new(
        nu: usize,
        mu: usize,
        h_vec: Arc<Vec<E::G1Affine>>,
        minus_v_prime: E::G2Affine,
        v_vec: Arc<Vec<E::G2Affine>>,
    ) -> Self {
        Self {
            nu,
            mu,
            h_vec,
            minus_v_prime,
            v_vec,
        }
    }

    pub fn get_nu(&self) -> usize {
        self.nu
    }
    pub fn get_mu(&self) -> usize {
        self.mu
    }
    pub fn get_h_vec(&self) -> &Vec<E::G1Affine> {
        &self.h_vec
    }
    pub fn get_minus_v_prime(&self) -> E::G2Affine {
        self.minus_v_prime
    }
    pub fn get_v_vec(&self) -> &Vec<E::G2Affine> {
        &self.v_vec
    }
}

impl<E: Pairing> StructuredReferenceString<E> for KZH2UniversalParams<E> {
    type ProverParam = KZH2ProverParam<E>;
    type VerifierParam = KZH2VerifierParam<E>;

    /// Extract the prover parameters from the public parameters.
    fn extract_prover_param(&self, supported_num_vars: usize) -> Self::ProverParam {
        assert_eq!(supported_num_vars, self.nu + self.mu);
        KZH2ProverParam::new(self.nu, self.mu, self.h_mat.clone(), self.h_vec.clone())
    }

    /// Extract the verifier parameters from the public parameters.
    fn extract_verifier_param(&self, supported_num_vars: usize) -> Self::VerifierParam {
        assert_eq!(supported_num_vars, self.nu + self.mu);
        KZH2VerifierParam::new(
            self.nu,
            self.mu,
            self.h_vec.clone(),
            self.minus_v_prime,
            self.v_vec.clone(),
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
        num_vars: usize,
    ) -> Result<KZH2UniversalParams<E>, PCSError> {
        // Dimensions of the polynomials
        let nu = num_vars / 2;
        let mu = num_vars - nu;
        let m = 1usize << mu;
        let n = 1usize << nu;

        // Sampling generators
        let generators_1 = (0..m).map(|_| E::G1::rand(rng)).collect::<Vec<_>>();
        let v = E::G2::rand(rng);

        // Sampling trapdoors
        let tau_vec = (0..n)
            .map(|_| E::ScalarField::rand(rng))
            .collect::<Vec<_>>();
        let alpha = E::ScalarField::rand(rng);

        // Compute a constant part of the SRS
        let minus_v_prime: E::G2Affine = (-v * alpha).into_affine();

        // The following three vectors can be computed independently.
        let (v_vec, h_vec, h_mat_transpose);

        #[cfg(feature = "parallel")]
        {
            // To use this feature, add `rayon` to your Cargo.toml dependencies.
            // We use two nested calls to `rayon::join` to run the three closures in
            // parallel.
            use rayon;

            let (vecs_h, vec_v) = rayon::join(
                || {
                    rayon::join(
                        || {
                            generators_1
                                .par_iter()
                                .map(|g| (*g * alpha).into_affine())
                                .collect::<Vec<_>>()
                        },
                        || {
                            generators_1
                                .par_iter()
                                .map(|g| g.batch_mul(&tau_vec))
                                .collect::<Vec<_>>()
                        },
                    )
                },
                || v.batch_mul(&tau_vec),
            );
            h_vec = vecs_h.0;
            h_mat_transpose = vecs_h.1;
            v_vec = vec_v;
        }

        #[cfg(not(feature = "parallel"))]
        {
            // Without the "parallel" feature, compute them sequentially.
            v_vec = v.batch_mul(&tau_vec);
            h_vec = generators_1
                .iter()
                .map(|g| (*g * alpha).into_affine())
                .collect::<Vec<_>>();
            h_mat_transpose = generators_1
                .iter()
                .map(|g| g.batch_mul(&tau_vec))
                .collect::<Vec<_>>();
        }

        // Transpose h_mat_transpose to get the final h_mat matrix for commitments.
        // This part remains parallelized based on the cfg_into_iter macro.
        #[cfg(feature = "parallel")]
        let h_mat: Vec<E::G1Affine> = cfg_into_iter!(0..n)
            .flat_map_iter(|i| {
                let h = &h_mat_transpose;
                (0..m).map(move |j| h[j][i])
            })
            .collect();
        #[cfg(not(feature = "parallel"))]
        let h_mat: Vec<E::G1Affine> = (0..n) // std::ops::Range is an iterator
            .flat_map(|i| {
                (0..m).map({
                    let value = h_mat_transpose.clone();
                    move |j| value[j][i]
                })
            })
            .collect();
        Ok(KZH2UniversalParams::new(
            nu,
            mu,
            Arc::new(h_mat),
            Arc::new(h_vec),
            Arc::new(v_vec),
            minus_v_prime,
            Arc::new(generators_1.into_iter().map(|g| g.into_affine()).collect()),
        ))
    }
}
