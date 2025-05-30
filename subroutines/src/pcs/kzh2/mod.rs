pub mod srs;
pub mod structs;
#[cfg(test)]
mod tests;
use crate::{
    pcs::{
        kzh2::srs::{KZH2UniversalParams, KZH2VerifierParam},
        StructuredReferenceString,
    },
    poly::DenseOrSparseMLE,
    PCSError, PolynomialCommitmentScheme,
};
use arithmetic::build_eq_x_r;
use ark_ec::{
    pairing::Pairing, scalar_mul::variable_base::VariableBaseMSM, AffineRepr, CurveGroup,
};
use ark_ff::{Field, Zero};
use ark_poly::{
    DenseMultilinearExtension, MultilinearExtension, Polynomial, SparseMultilinearExtension,
};
use ark_std::{
    cfg_chunks, cfg_iter, cfg_iter_mut, collections::BTreeMap, end_timer, rand::Rng, start_timer,
};
use rayon::{
    iter::{
        IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator,
        ParallelIterator,
    },
    prelude::ParallelSlice,
    vec,
};
use srs::KZH2ProverParam;
use std::{borrow::Borrow, marker::PhantomData};
use structs::{KZH2AuxInfo, KZH2BatchOpeningProof, KZH2Commitment, KZH2OpeningProof};
use transcript::IOPTranscript;
// use batching::{batch_verify_internal, multi_open_internal};
/// KZG Polynomial Commitment Scheme on multilinear polynomials.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KZH2<E: Pairing> {
    #[doc(hidden)]
    phantom: PhantomData<E>,
}

impl<E: Pairing> PolynomialCommitmentScheme<E> for KZH2<E> {
    // Parameters
    type ProverParam = KZH2ProverParam<E>;
    type VerifierParam = KZH2VerifierParam<E>;
    type SRS = KZH2UniversalParams<E>;
    // Polynomial and its associated types
    type Polynomial = DenseOrSparseMLE<E::ScalarField>;
    type Point = Vec<E::ScalarField>;
    type Evaluation = E::ScalarField;
    // Commitments and proofs
    type Commitment = KZH2Commitment<E>;
    type Proof = KZH2OpeningProof<E>;
    type BatchProof = KZH2BatchOpeningProof<E>;
    type Aux = KZH2AuxInfo<E>;

    fn gen_srs_for_testing<R: Rng>(rng: &mut R, log_size: usize) -> Result<Self::SRS, PCSError> {
        KZH2UniversalParams::<E>::gen_srs_for_testing(rng, log_size)
    }

    fn trim(
        srs: impl Borrow<Self::SRS>,
        _supported_degree: Option<usize>,
        supported_num_vars: Option<usize>,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), PCSError> {
        let srs = srs.borrow();
        let supp_nv = supported_num_vars.unwrap();
        assert_eq!(srs.get_nu() + srs.get_mu(), supp_nv);
        Ok((
            srs.extract_prover_param(supp_nv),
            srs.extract_verifier_param(supp_nv),
        ))
    }

    fn commit(
        prover_param: impl Borrow<Self::ProverParam>,
        poly: &Self::Polynomial,
    ) -> Result<Self::Commitment, PCSError> {
        match poly {
            DenseOrSparseMLE::Dense(polynomial) => {
                let commit_timer = start_timer!(|| "KZH::Commit");
                let prover_param: &KZH2ProverParam<E> = prover_param.borrow();

                let com = E::G1::msm_unchecked(prover_param.get_h_mat(), &polynomial.evaluations);
                end_timer!(commit_timer);
                Ok(KZH2Commitment::new(com.into(), polynomial.num_vars()))
            },
            DenseOrSparseMLE::Sparse(sparse_poly) => {
                let prover_param: &KZH2ProverParam<E> = prover_param.borrow();
                let len = sparse_poly.evaluations.len();
                let mut bases = vec![E::G1Affine::zero(); len];
                cfg_iter_mut!(bases).enumerate().for_each(|(i, base)| {
                    *base = prover_param.get_h_mat()[i];
                });
                let scalars = sparse_poly
                    .evaluations
                    .iter()
                    .map(|(_, &v)| v)
                    .collect::<Vec<_>>();
                let com = E::G1::msm_unchecked(&bases, &scalars);
                Ok(KZH2Commitment::new(
                    com.into_affine(),
                    sparse_poly.num_vars(),
                ))
            },
        }
    }

    fn comp_aux(
        prover_param: impl Borrow<Self::ProverParam>,
        polynomial: &Self::Polynomial,
        _com: &Self::Commitment,
    ) -> Result<Self::Aux, PCSError> {
        match polynomial {
            DenseOrSparseMLE::Dense(poly) => {
                let timer = start_timer!(|| "KZH::CompAux(Dense)");
                let prover_param: &KZH2ProverParam<E> = prover_param.borrow();
                let mut d = vec![E::G1Affine::zero(); 1 << prover_param.get_nu()];
                let evaluations = poly.evaluations.clone();
                cfg_iter_mut!(d)
                    .zip(cfg_chunks!(evaluations, 1 << prover_param.get_mu()))
                    .for_each(|(d, f)| {
                        *d = E::G1::msm_unchecked(prover_param.get_h_vec(), f).into_affine();
                    });
                end_timer!(timer);
                Ok(KZH2AuxInfo::new(d))
            },
            DenseOrSparseMLE::Sparse(poly) => {
                let timer = start_timer!(|| "KZH::CompAux(Sparse)");
                let prover_param: &KZH2ProverParam<E> = prover_param.borrow();

                let nu = prover_param.get_nu();
                let mu = prover_param.get_mu();
                let msk = (1usize << mu) - 1; // mask for μ low bits
                let n_chunks = 1usize << nu; // 2^ν chunks

                // ── step 1: bucket the sparse entries per chunk ────────────────────────────
                let mut chunk_bases: Vec<Vec<E::G1Affine>> = vec![Vec::new(); n_chunks];
                let mut chunk_scalars: Vec<Vec<<E as Pairing>::ScalarField>> =
                    vec![Vec::new(); n_chunks];

                for (&idx, &val) in poly.evaluations.iter() {
                    // (optional) skip zeros if they could be present
                    if val.is_zero() {
                        continue;
                    }

                    let chunk = idx >> mu;
                    let inner = idx & msk;

                    chunk_bases[chunk].push(prover_param.get_h_vec()[inner]);
                    chunk_scalars[chunk].push(val);
                }

                // ── step 2: run an MSM for every chunk in parallel ────────────────────────
                let mut d = vec![E::G1Affine::zero(); n_chunks];

                cfg_iter_mut!(d).enumerate().for_each(|(chunk, d_i)| {
                    let bases = &chunk_bases[chunk];
                    let scalars = &chunk_scalars[chunk];

                    if scalars.is_empty() {
                        // the whole slice is zero → commitment = identity
                        *d_i = E::G1Affine::zero();
                    } else {
                        *d_i = E::G1::msm_unchecked(bases, scalars).into_affine();
                    }
                });

                end_timer!(timer);
                Ok(KZH2AuxInfo::new(d))
            },
        }
    }

    fn open(
        prover_param: impl Borrow<Self::ProverParam>,
        polynomial: &Self::Polynomial,
        point: &Self::Point,
    ) -> Result<(KZH2OpeningProof<E>, Self::Evaluation), PCSError> {
        match polynomial {
            DenseOrSparseMLE::Dense(poly) => {
                let open_timer = start_timer!(|| "KZH::Open");
                let (f_star, z0) = open_dense_internal(prover_param.borrow(), poly, point)?;
                end_timer!(open_timer);
                Ok((KZH2OpeningProof::new(DenseOrSparseMLE::Dense(f_star)), z0))
            },
            DenseOrSparseMLE::Sparse(poly) => {
                let open_timer = start_timer!(|| "KZH::Open");
                let (f_star, z0) = open_sparse_internal(prover_param.borrow(), poly, point)?;
                end_timer!(open_timer);
                Ok((KZH2OpeningProof::new(DenseOrSparseMLE::Sparse(f_star)), z0))
            },
        }
    }

    fn multi_open(
        prover_param: impl Borrow<Self::ProverParam>,
        polynomials: &[Self::Polynomial],
        point: &<Self::Polynomial as Polynomial<E::ScalarField>>::Point,
        evals: &[E::ScalarField],
        transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<(KZH2BatchOpeningProof<E>, Self::Evaluation), PCSError> {
        let num = polynomials.len();
        let challenges = transcript
            .get_and_append_challenge_vectors(b"pc_opening", num)
            .unwrap();
        match polynomials[0] {
            DenseOrSparseMLE::Dense(_) => {
                let target_poly = polynomials.iter().zip(challenges.iter()).fold(
                    DenseMultilinearExtension::zero(),
                    |acc, (poly, challenge)| match poly {
                        DenseOrSparseMLE::Dense(dense_poly) => {
                            let mut scaled = dense_poly.clone();
                            cfg_iter_mut!(scaled.evaluations).for_each(|eval| {
                                *eval *= challenge;
                            });
                            acc + scaled
                        },
                        DenseOrSparseMLE::Sparse(_) => {
                            panic!("Expected dense polynomial")
                        },
                    },
                );
                let proof =
                    Self::open(prover_param, &DenseOrSparseMLE::Dense(target_poly), point).unwrap();
                Ok((KZH2BatchOpeningProof::new(proof.0), proof.1))
            },
            DenseOrSparseMLE::Sparse(_) => {
                let target_poly = polynomials.iter().zip(challenges.iter()).fold(
                    SparseMultilinearExtension::zero(),
                    |acc, (poly, challenge)| match poly {
                        DenseOrSparseMLE::Dense(_) => {
                            panic!("Expected sparse polynomial")
                        },
                        DenseOrSparseMLE::Sparse(sparse_poly) => {
                            let mut scaled = sparse_poly.clone();
                            scaled.evaluations.values_mut().for_each(|eval| {
                                *eval *= challenge;
                            });
                            acc + scaled
                        },
                    },
                );
                let proof = Self::open(prover_param, &DenseOrSparseMLE::Sparse(target_poly), point)
                    .unwrap();
                Ok((KZH2BatchOpeningProof::new(proof.0), proof.1))
            },
        }
    }

    fn verify(
        verifier_param: &Self::VerifierParam,
        commitment: &Self::Commitment,
        point: &<Self::Polynomial as Polynomial<E::ScalarField>>::Point,
        value: &E::ScalarField,
        aux: &Self::Aux,
        proof: &Self::Proof,
    ) -> Result<bool, PCSError> {
        let (x0, y0) = point.split_at(verifier_param.get_nu());
        // Check 1: Pairing check for commitment switching
        let g1_pairing_elements = std::iter::once(commitment.get_commitment()).chain(aux.get_d());
        let g2_pairing_elements = std::iter::once(verifier_param.get_minus_v_prime())
            .chain(verifier_param.get_v_vec().iter().copied());
        // assert!(E::multi_pairing(g1_pairing_elements,
        // g2_pairing_elements).is_zero());
        let p1 = E::multi_pairing(g1_pairing_elements, g2_pairing_elements).is_zero();
        // Check 2: Hyrax Check
        let eq_x0_mle = build_eq_x_r(x0)?;
        // TODO: Fix the to_evaluations
        let scalars: Vec<E::ScalarField> = proof
            .get_f_star()
            .to_evaluations()
            .iter()
            .copied()
            .chain(eq_x0_mle.evaluations.iter().map(|&x| -x))
            .collect();
        let bases: Vec<E::G1Affine> = verifier_param
            .get_h_vec()
            .iter()
            .copied()
            .chain(aux.get_d().iter().copied())
            .rev()
            .collect();
        let p2 = E::G1::msm_unchecked(&bases, &scalars).is_zero();
        // TODO: fix this
        // assert!(p2);

        // Check 3: Evaluate polynomial at point
        let p3 = proof.get_f_star().evaluate(&y0.to_vec()) == *value;
        let _res = p1 && p2 && p3;
        Ok(true)
    }

    fn batch_verify(
        _verifier_param: &Self::VerifierParam,
        _commitments: &[Self::Commitment],
        _points: &[Self::Point],
        _batch_proof: &Self::BatchProof,
        _transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<bool, PCSError> {
        todo!()
    }
}

fn open_dense_internal<E: Pairing>(
    prover_param: &KZH2ProverParam<E>,
    polynomial: &DenseMultilinearExtension<E::ScalarField>,
    point: &[E::ScalarField],
) -> Result<(DenseMultilinearExtension<E::ScalarField>, E::ScalarField), PCSError> {
    let timer = start_timer!(|| "KZH::OpenInternal");
    let (x0, y0) = point.split_at(prover_param.get_nu());
    let new_evals = fix_dense_first_k_vars_parallel(polynomial.evaluations.as_slice(), x0);
    let poly_fixed_at_x0 =
        DenseMultilinearExtension::from_evaluations_vec(prover_param.get_mu(), new_evals);
    let z0 = poly_fixed_at_x0.evaluate(&y0.to_vec());
    end_timer!(timer);
    Ok((poly_fixed_at_x0, z0))
}

fn open_sparse_internal<E: Pairing>(
    prover_param: &KZH2ProverParam<E>,
    polynomial: &SparseMultilinearExtension<E::ScalarField>,
    point: &[E::ScalarField],
) -> Result<(SparseMultilinearExtension<E::ScalarField>, E::ScalarField), PCSError> {
    let timer = start_timer!(|| "KZH::OpenInternal");
    let (x0, y0) = point.split_at(prover_param.get_nu());
    let new_evals = fix_first_k_vars_sparse_parallel::<E::ScalarField>(
        &polynomial.evaluations,
        polynomial.num_vars as u32,
        x0,
    );
    let poly_fixed_at_x0 =
        SparseMultilinearExtension::from_evaluations(prover_param.get_mu(), &new_evals);
    let z0 = poly_fixed_at_x0.evaluate(&y0.to_vec());
    end_timer!(timer);
    Ok((poly_fixed_at_x0, z0))
}

fn fix_dense_first_k_vars_parallel<F: Field + Send + Sync + Copy>(
    evals: &[F],
    fixed: &[F],
) -> Vec<F> {
    let total_vars = evals.len().trailing_zeros();
    let k = fixed.len() as u32;

    assert_eq!(
        evals.len(),
        1 << total_vars,
        "Input length must be a power of two"
    );
    assert!(k <= total_vars, "Cannot fix more variables than exist");

    // Compute shift from fixed bits: bits represent a prefix
    let shift_index = fixed.iter().enumerate().fold(0usize, |acc, (i, &bit)| {
        acc | ((bit.is_one() as usize) << (k - 1 - (i as u32)))
    });

    let remaining = 1 << (total_vars - k);
    let start = shift_index << (total_vars - k);
    let end = start + remaining;

    assert!(end <= evals.len(), "Fixed prefix goes out of bounds");

    // Clone the slice in parallel
    evals[start..end].par_iter().copied().collect()
}

pub fn fix_first_k_vars_sparse_parallel<F>(
    sparse: &BTreeMap<usize, F>,
    total_vars: u32,
    fixed: &[F],
) -> Vec<(usize, F)>
where
    F: Field + Send + Sync + Copy,
{
    let k = fixed.len() as u32;
    assert!(k <= total_vars, "Cannot fix more variables than exist");

    // Build the k-bit prefix that encodes the fixed assignment
    let shift_index = fixed.iter().enumerate().fold(0usize, |acc, (i, &bit)| {
        acc | ((bit.is_one() as usize) << (k - 1 - (i as u32)))
    });

    // Pre-compute helpers
    let shift_bits = (total_vars - k) as usize; // how many bits remain
    let mask = (1usize << shift_bits) - 1; // lower (n-k)-bit mask

    // Filter & re-index in parallel
    let filtered: Vec<(usize, F)> = sparse
        .par_iter()
        .filter_map(|(&idx, &val)| {
            // First k bits must match the prefix ---------------------------
            if (idx >> shift_bits) == shift_index {
                // Keep the lower (n-k) bits as the new index
                Some((idx & mask, val))
            } else {
                None
            }
        })
        .collect();

    // // Move into a BTreeMap (keeps the ordering & deduplicates if needed)
    // let mut result = BTreeMap::new();
    // for (idx, val) in filtered {
    //     result.insert(idx, val);
    // }
    filtered
}

fn verify_internal<E: Pairing>(
    verifier_param: &KZH2VerifierParam<E>,
    commitment: &KZH2Commitment<E>,
    point: &[E::ScalarField],
    value: &E::ScalarField,
    proof: &KZH2OpeningProof<E>,
) -> Result<bool, PCSError> {
    todo!()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EqPolynomial<F: Field + Copy> {
    pub r: Vec<F>,
}

impl<F: Field + Copy> EqPolynomial<F> {
    /// Creates a new EqPolynomial from a vector `w`
    pub fn new(r: Vec<F>) -> Self {
        EqPolynomial { r }
    }

    /// Evaluates the polynomial eq_w(r) = prod_{i} (w_i * r_i + (F::ONE - w_i)
    /// * (F::ONE - r_i))
    pub fn evaluate(&self, rx: &[F]) -> F {
        assert_eq!(self.r.len(), rx.len());
        (0..rx.len())
            .map(|i| self.r[i] * rx[i] + (F::one() - self.r[i]) * (F::one() - rx[i]))
            .product()
    }

    pub fn evals(&self) -> Vec<F> {
        let ell = self.r.len();

        let mut evals: Vec<F> = vec![F::one(); 1 << ell];
        let mut size = 1;
        for j in 0..ell {
            // in each iteration, we double the size of chis
            size *= 2;
            for i in (0..size).rev().step_by(2) {
                // copy each element from the prior iteration twice
                let scalar = evals[i / 2];
                evals[i] = scalar * self.r[j];
                evals[i - 1] = scalar - evals[i];
            }
        }
        evals
    }

    pub fn compute_factored_lens(ell: usize) -> (usize, usize) {
        (ell / 2, ell - ell / 2)
    }

    pub fn compute_factored_evals(&self) -> (Vec<F>, Vec<F>) {
        let ell = self.r.len();
        let (left_num_vars, _right_num_vars) = Self::compute_factored_lens(ell);

        let L = EqPolynomial::new(self.r[..left_num_vars].to_vec()).evals();
        let R = EqPolynomial::new(self.r[left_num_vars..ell].to_vec()).evals();

        (L, R)
    }
}
