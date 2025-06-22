pub mod srs;
pub mod structs;
use arithmetic::eq_eval;
#[cfg(feature = "parallel")]
use rayon::prelude::*;
#[cfg(test)]
mod tests;
use crate::{
    pcs::{
        kzh4::srs::{KZH4UniversalParams, KZH4VerifierParam},
        StructuredReferenceString,
    },
    poly::DenseOrSparseMLE,
    PCSError, PolynomialCommitmentScheme,
};
use ark_ec::{
    pairing::Pairing, scalar_mul::variable_base::VariableBaseMSM, AffineRepr, CurveGroup,
};
use ark_ff::{AdditiveGroup, Field, Zero};
use ark_poly::{
    DenseMultilinearExtension, MultilinearExtension, Polynomial, SparseMultilinearExtension,
};
use ark_std::{cfg_iter_mut, collections::BTreeMap, end_timer, rand::Rng, start_timer};
#[cfg(feature = "parallel")]
use rayon::iter::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator};
// Conditional imports for Rayon
#[cfg(feature = "parallel")]
use rayon::join;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use srs::KZH4ProverParam;
use std::{borrow::Borrow, marker::PhantomData, ops::Neg};
use structs::{KZH4AuxInfo, KZH4BatchOpeningProof, KZH4Commitment, KZH4OpeningProof};
// use batching::{batch_verify_internal, multi_open_internal};
/// KZG Polynomial Commitment Scheme on multilinear polynomials.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KZH4<E: Pairing> {
    #[doc(hidden)]
    phantom: PhantomData<E>,
}

impl<E: Pairing> PolynomialCommitmentScheme<E> for KZH4<E> {
    // Parameters
    type ProverParam = KZH4ProverParam<E>;
    type VerifierParam = KZH4VerifierParam<E>;
    type SRS = KZH4UniversalParams<E>;
    // Polynomial and its associated types
    type Polynomial = DenseOrSparseMLE<E::ScalarField>;
    type Point = Vec<E::ScalarField>;
    type Evaluation = E::ScalarField;
    // Commitments and proofs
    type Commitment = KZH4Commitment<E>;
    type Proof = KZH4OpeningProof<E>;
    type BatchProof = KZH4BatchOpeningProof<E>;
    type Aux = KZH4AuxInfo<E>;

    fn gen_srs_for_testing<R: Rng>(rng: &mut R, log_size: usize) -> Result<Self::SRS, PCSError> {
        KZH4UniversalParams::<E>::gen_srs_for_testing(rng, log_size)
    }

    fn trim(
        srs: impl Borrow<Self::SRS>,
        _supported_degree: Option<usize>,
        supported_num_vars: Option<usize>,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), PCSError> {
        let srs = srs.borrow();
        let supp_nv = supported_num_vars.unwrap();
        assert_eq!(
            srs.get_num_vars_x()
                + srs.get_num_vars_y()
                + srs.get_num_vars_z()
                + srs.get_num_vars_t(),
            supp_nv
        );
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
                let prover_param: &KZH4ProverParam<E> = prover_param.borrow();

                let com = E::G1::msm_unchecked(&prover_param.get_h_xyzt(), &polynomial.evaluations);
                end_timer!(commit_timer);
                Ok(KZH4Commitment::new(com.into(), polynomial.num_vars()))
            },
            DenseOrSparseMLE::Sparse(sparse_poly) => {
                let prover_param: &KZH4ProverParam<E> = prover_param.borrow();
                let len = sparse_poly.evaluations.len();
                let mut bases = vec![E::G1Affine::zero(); len];
                cfg_iter_mut!(bases).enumerate().for_each(|(i, base)| {
                    *base = prover_param.get_h_xyzt()[i];
                });
                let scalars = sparse_poly
                    .evaluations
                    .iter()
                    .map(|(_, &v)| v)
                    .collect::<Vec<_>>();
                let com = E::G1::msm_unchecked(&bases, &scalars);
                Ok(KZH4Commitment::new(
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
        let prover_param = prover_param.borrow();

        // degrees of each variable block
        let degree_x = 1usize << prover_param.get_num_vars_x();
        let degree_y = 1usize << prover_param.get_num_vars_y();
        let degree_z = 1usize << prover_param.get_num_vars_z();
        let degree_t = 1usize << prover_param.get_num_vars_t();

        // helper closures ────────────────────────────────────────────────────────
        let eval_dx = |i: usize| -> E::G1Affine {
            match polynomial {
                DenseOrSparseMLE::Dense(poly) => E::G1::msm_unchecked(
                    &prover_param.get_h_yzt(),
                    &Self::get_dense_partial_evaluation_for_boolean_input(
                        poly,
                        i,
                        degree_y * degree_z * degree_t,
                    ),
                )
                .into(),
                DenseOrSparseMLE::Sparse(poly) => {
                    let slice = Self::get_sparse_partial_evaluation_for_boolean_input(
                        poly,
                        i,
                        degree_y * degree_z * degree_t,
                    );
                    if slice.is_empty() {
                        return E::G1Affine::zero();
                    }
                    let (mut bases, mut scalars) = (
                        Vec::with_capacity(slice.len()),
                        Vec::with_capacity(slice.len()),
                    );
                    for (idx, coeff) in slice {
                        bases.push(prover_param.get_h_yzt()[idx]);
                        scalars.push(coeff);
                    }
                    E::G1::msm_unchecked(&bases, &scalars).into()
                },
            }
        };

        let eval_dxy = |i: usize| -> E::G1Affine {
            match polynomial {
                DenseOrSparseMLE::Dense(poly) => E::G1::msm_unchecked(
                    &prover_param.get_h_zt(),
                    &Self::get_dense_partial_evaluation_for_boolean_input(
                        poly,
                        i,
                        degree_z * degree_t,
                    ),
                )
                .into(),
                DenseOrSparseMLE::Sparse(poly) => {
                    let slice = Self::get_sparse_partial_evaluation_for_boolean_input(
                        poly,
                        i,
                        degree_z * degree_t,
                    );
                    if slice.is_empty() {
                        return E::G1Affine::zero();
                    }
                    let (mut bases, mut scalars) = (
                        Vec::with_capacity(slice.len()),
                        Vec::with_capacity(slice.len()),
                    );
                    for (idx, coeff) in slice {
                        bases.push(prover_param.get_h_zt()[idx]);
                        scalars.push(coeff);
                    }
                    E::G1::msm_unchecked(&bases, &scalars).into()
                },
            }
        };

        // allocate result buffers
        let mut d_x = vec![E::G1Affine::zero(); degree_x];
        let mut d_xy = vec![E::G1Affine::zero(); degree_x * degree_y];

        // fill them (parallel feature ⇒ two nested levels of parallelism)
        #[cfg(feature = "parallel")]
        join(
            || {
                cfg_iter_mut!(d_x)
                    .enumerate()
                    .for_each(|(i, slot)| *slot = eval_dx(i));
            },
            || {
                cfg_iter_mut!(d_xy)
                    .enumerate()
                    .for_each(|(i, slot)| *slot = eval_dxy(i));
            },
        );

        #[cfg(not(feature = "parallel"))]
        {
            cfg_iter_mut!(d_x)
                .enumerate()
                .for_each(|(i, slot)| *slot = eval_dx(i));

            cfg_iter_mut!(d_xy)
                .enumerate()
                .for_each(|(i, slot)| *slot = eval_dxy(i));
        }

        Ok(KZH4AuxInfo::new(d_x, d_xy))
    }

    fn open(
        prover_param: impl Borrow<Self::ProverParam>,
        polynomial: &Self::Polynomial,
        point: &Self::Point,
        aux: &Self::Aux,
    ) -> Result<(KZH4OpeningProof<E>, Self::Evaluation), PCSError> {
        let prover_param = prover_param.borrow();
        let len = prover_param.get_num_vars_x()
            + prover_param.get_num_vars_y()
            + prover_param.get_num_vars_z()
            + prover_param.get_num_vars_t();

        assert_eq!(polynomial.num_vars(), len);

        let split_input = Self::split_input(
            prover_param.get_num_vars_x(),
            prover_param.get_num_vars_y(),
            prover_param.get_num_vars_z(),
            prover_param.get_num_vars_t(),
            point,
            E::ScalarField::ZERO,
        );

        let d_z = (0..1usize << prover_param.get_num_vars_z())
            .map(|i| match polynomial {
                DenseOrSparseMLE::Dense(dense_poly) => {
                    let scalars = Self::get_dense_partial_evaluation_for_boolean_input(
                        &dense_poly.fix_first_variables(
                            [split_input[0].as_slice(), split_input[1].as_slice()]
                                .concat()
                                .as_slice(),
                        ),
                        i,
                        prover_param.get_num_vars_t(),
                    );
                    E::G1::msm_unchecked(prover_param.get_h_t().as_slice(), &scalars).into()
                },
                DenseOrSparseMLE::Sparse(sparse_poly) => {
                    let scalars_map = Self::get_sparse_partial_evaluation_for_boolean_input(
                        //TODO: Fix this
                        &sparse_poly,
                        i,
                        prover_param.get_num_vars_t(),
                    );
                    let indices = scalars_map.keys().cloned().collect::<Vec<_>>();
                    let mut bases = vec![E::G1Affine::zero(); indices.len()];
                    cfg_iter_mut!(bases).enumerate().for_each(|(i, base)| {
                        *base = prover_param.get_h_t()[indices[i]];
                    });
                    let scalars = scalars_map.values().cloned().collect::<Vec<_>>();
                    E::G1::msm_unchecked(&bases, &scalars).into()
                },
            })
            .collect::<Vec<_>>();
        let d_y = (0..1usize << prover_param.get_num_vars_y())
            .map(|i| match polynomial {
                DenseOrSparseMLE::Dense(_) => {
                    let evals_vec = EqPolynomial::new(split_input[0].clone()).evals();
                    let scalars = evals_vec.as_slice();
                    let bases = &aux.get_d_xy()[(1usize << prover_param.get_num_vars_x()) * i
                        ..(1usize << prover_param.get_num_vars_x()) * i
                            + (1usize << prover_param.get_num_vars_x())];
                    E::G1::msm_unchecked(bases, &scalars).into()
                },
                DenseOrSparseMLE::Sparse(_) => {
                    // TODO: Check if this is correct
                    let bit_index = split_input[0].iter().fold(0usize, |acc, b| {
                        acc << 1 | if *b == E::ScalarField::ONE { 1 } else { 0 }
                    });
                    aux.get_d_xy()[(1usize << prover_param.get_num_vars_x()) * i + bit_index].into()
                },
            })
            .collect::<Vec<_>>();

        assert_eq!(
            split_input[0].len(),
            prover_param.get_num_vars_x(),
            "wrong length"
        );
        assert_eq!(
            split_input[1].len(),
            prover_param.get_num_vars_y(),
            "wrong length"
        );
        assert_eq!(
            split_input[2].len(),
            prover_param.get_num_vars_z(),
            "wrong length"
        );

        // compute the partial evaluation of the polynomial
        let f_star = polynomial.fix_first_variables(
            {
                let mut res = Vec::new();
                res.extend_from_slice(split_input[0].as_slice());
                res.extend_from_slice(split_input[1].as_slice());
                res.extend_from_slice(split_input[2].as_slice());
                res
            }
            .as_slice(),
        );
        let evaluation = f_star.evaluate(&split_input[3]);

        Ok((KZH4OpeningProof::new(d_y, d_z, f_star), evaluation))
    }

    fn verify(
        verifier_param: &Self::VerifierParam,
        commitment: &Self::Commitment,
        point: &<Self::Polynomial as Polynomial<E::ScalarField>>::Point,
        value: &E::ScalarField,
        aux: &Self::Aux,
        proof: &Self::Proof,
    ) -> Result<bool, PCSError> {
        let split_input = Self::split_input(
            verifier_param.get_num_vars_x(),
            verifier_param.get_num_vars_y(),
            verifier_param.get_num_vars_z(),
            verifier_param.get_num_vars_t(),
            point,
            E::ScalarField::ZERO,
        );

        // First pairing check
        let g1_pairing_elements = std::iter::once(commitment.get_commitment()).chain(aux.get_d_x());
        let v_x = verifier_param.get_v_x();
        let g2_pairing_elements =
            std::iter::once(verifier_param.get_minus_v()).chain(v_x.iter().copied());

        let p1 = E::multi_pairing(g1_pairing_elements, g2_pairing_elements).is_zero();
        ///////////////////////////////////////

        // Second pairing check

        let new_c = E::G1::msm(
            aux.get_d_x().to_vec().as_slice(),
            EqPolynomial::new(split_input[0].clone()).evals().as_slice(),
        )
        .unwrap()
        .into();

        let g1_pairing_elements = std::iter::once(new_c).chain(proof.get_d_y());
        let v_y = verifier_param.get_v_y();
        let g2_pairing_elements =
            std::iter::once(verifier_param.get_minus_v()).chain(v_y.iter().copied());

        let p2 = E::multi_pairing(g1_pairing_elements, g2_pairing_elements).is_zero();

        ///////////////////////////////////////////////////////////////////////////

        // Third pairing check

        let new_c = E::G1::msm(
            proof.get_d_y().to_vec().as_slice(),
            EqPolynomial::new(split_input[1].clone()).evals().as_slice(),
        )
        .unwrap()
        .into();

        let g1_pairing_elements = std::iter::once(new_c).chain(proof.get_d_z());
        let v_z = verifier_param.get_v_z();
        let g2_pairing_elements =
            std::iter::once(verifier_param.get_minus_v()).chain(v_z.iter().copied());

        let p3 = E::multi_pairing(g1_pairing_elements, g2_pairing_elements).is_zero();

        // hyrax style opening check

        let bases: Vec<E::G1Affine> = verifier_param
            .get_h_t()
            .iter()
            .chain(proof.get_d_z().iter())
            .cloned()
            .collect();
        let scalars = proof
            .get_f_star()
            .to_evaluations()
            .iter()
            .cloned()
            .chain(
                EqPolynomial::new(split_input[2].clone())
                    .evals()
                    .into_iter()
                    .map(|v| v.neg()),
            )
            .collect::<Vec<_>>();
        let p4 = E::G1::msm_unchecked(&bases, &scalars) == E::G1::zero();

        // Evaluation check
        let p5 = proof.get_f_star().evaluate(&split_input[3]) == *value;
        Ok(p1 && p2 && p3 && p4 && p5)
        // Ok(true)
    }
}

impl<E: Pairing> KZH4<E> {
    pub fn get_dense_partial_evaluation_for_boolean_input(
        dense_poly: &DenseMultilinearExtension<E::ScalarField>,
        index: usize,
        n: usize,
    ) -> Vec<E::ScalarField> {
        dense_poly.evaluations[n * index..n * index + n].to_vec()
    }

    pub fn get_sparse_partial_evaluation_for_boolean_input(
        sparse_poly: &SparseMultilinearExtension<E::ScalarField>,
        index: usize,
        n: usize,
    ) -> BTreeMap<usize, E::ScalarField> {
        let start = n * index; // first global idx we need
        let end = start + n; // one-past-last idx

        sparse_poly
        .evaluations
        // `start .. end` is start-inclusive, end-exclusive – same as the dense slice
        .range(start .. end)
        .map(|(&global_idx, &val)| {
            let local_idx = global_idx - start; // 0 ≤ local_idx < n
            (local_idx, val)
        })
        .collect()
    }

    fn split_input<T: Clone>(
        num_vars_x: usize,
        num_vars_y: usize,
        num_vars_z: usize,
        num_vars_t: usize,
        input: &[T],
        default: T,
    ) -> Vec<Vec<T>> {
        let total_length = num_vars_x + num_vars_y + num_vars_z + num_vars_t;

        // If r is smaller than the required length, extend it with zeros at the
        // beginning
        let mut extended_r = input.to_vec();
        if input.len() < total_length {
            let mut zeros = vec![default; total_length - input.len()];
            zeros.extend(extended_r); // Prepend zeros to the beginning
            extended_r = zeros;
        }

        // Split the vector into two parts
        let r_x = extended_r[..num_vars_x].to_vec();
        let r_y = extended_r[num_vars_x..num_vars_x + num_vars_y].to_vec();
        let r_z =
            extended_r[num_vars_x + num_vars_y..num_vars_x + num_vars_y + num_vars_z].to_vec();
        let r_t = extended_r[num_vars_x + num_vars_y + num_vars_z..].to_vec();

        vec![r_x, r_y, r_z, r_t]
    }
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

        let mut evals: Vec<F> = vec![F::one(); 1usize << ell];
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

        let l = EqPolynomial::new(self.r[..left_num_vars].to_vec()).evals();
        let r = EqPolynomial::new(self.r[left_num_vars..ell].to_vec()).evals();

        (l, r)
    }
}
