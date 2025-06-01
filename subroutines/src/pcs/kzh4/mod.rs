pub mod srs;
pub mod structs;
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
use arithmetic::build_eq_x_r;
use ark_ec::{
    pairing::Pairing, scalar_mul::variable_base::VariableBaseMSM, AffineRepr, CurveGroup,
};
use ark_ff::{AdditiveGroup, Field, Zero};
use ark_poly::{
    DenseMultilinearExtension, MultilinearExtension, Polynomial, SparseMultilinearExtension,
};
use ark_std::{cfg_iter_mut, collections::BTreeMap, end_timer, rand::Rng, start_timer};
use rayon::iter::{
    IndexedParallelIterator, IntoParallelRefIterator, IntoParallelRefMutIterator, ParallelIterator,
};
use srs::KZH4ProverParam;
use std::{borrow::Borrow, marker::PhantomData};
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

                let com = E::G1::msm_unchecked(prover_param.get_h_xyzt(), &polynomial.evaluations);
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
        Self::comp_aux_dense_internal(prover_param.borrow(), polynomial)
    }

    fn open(
        prover_param: impl Borrow<Self::ProverParam>,
        polynomial: &Self::Polynomial,
        point: &Self::Point,
    ) -> Result<(KZH4OpeningProof<E>, Self::Evaluation), PCSError> {
        match polynomial {
            DenseOrSparseMLE::Dense(poly) => {
                Self::open_dense_internal(prover_param.borrow(), poly, point)
            },
            DenseOrSparseMLE::Sparse(poly) => {
                Self::open_sparse_internal(prover_param.borrow(), poly, point)
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
        let split_input = Self::split_input(
            verifier_param.get_num_vars_x(),
            verifier_param.get_num_vars_y(),
            verifier_param.get_num_vars_z(),
            verifier_param.get_num_vars_z(),
            point,
            E::ScalarField::ZERO,
        );

        // making sure D_x is well-formatted
        let lhs = E::multi_pairing(aux.get_d_x(), verifier_param.get_v_x()).0;
        let rhs = E::pairing(commitment.get_commitment(), verifier_param.get_v()).0;

        let p1 = lhs == rhs;

        let concatenated: Vec<E::ScalarField> = split_input[0]
            .iter()
            .chain(split_input[1].iter())
            .cloned()
            .collect();



        dbg!(&EqPolynomial::new(concatenated.clone()).evals().as_slice().len());
        dbg!(concatenated.len());
        dbg!(aux.get_d_y().len());

        // making sure D_y is well formatted
        let new_c = E::G1::msm(
            aux.get_d_y().to_vec().as_slice(),
            EqPolynomial::new(concatenated).evals().as_slice(),
        )
        .unwrap();

        let lhs = E::multi_pairing(proof.get_d_z(), verifier_param.get_v_z()).0;
        let rhs = E::pairing(new_c, verifier_param.get_v()).0;

        let p2 = lhs == rhs;

        // making sure f^star is well formatter
        let lhs = E::G1::msm(
            verifier_param.get_h_t().as_slice(),
            proof.get_f_star().to_evaluations().as_slice(),
        )
        .unwrap();

        let rhs = E::G1::msm(
            proof
                .get_d_z()
                .iter()
                .map(|e| (*e).into())
                .collect::<Vec<_>>()
                .as_slice(),
            EqPolynomial::new(split_input[2].clone()).evals().as_slice(),
        )
        .unwrap();

        let p3 = lhs == rhs;

        // making sure the output of f_star and the given output are consistent
        let p4 = proof.get_f_star().evaluate(&split_input[3]) == *value;
        Ok(p1 && p2 && p3 && p4)
    }
}

impl<E: Pairing> KZH4<E> {
    fn comp_aux_dense_internal(
        prover_param: &KZH4ProverParam<E>,
        polynomial: &DenseOrSparseMLE<E::ScalarField>,
    ) -> Result<KZH4AuxInfo<E>, PCSError> {
        let degree_x = 1 << prover_param.get_num_vars_x();
        let degree_y = 1 << prover_param.get_num_vars_y();
        let degree_z = 1 << prover_param.get_num_vars_z();
        let degree_t = 1 << prover_param.get_num_vars_t();
        let d_x = match polynomial {
            DenseOrSparseMLE::Dense(poly) => (0..degree_x)
                .map(|i| {
                    E::G1::msm_unchecked(
                        prover_param.get_h_yzt().as_slice(),
                        Self::get_dense_partial_evaluation_for_boolean_input(
                            poly,
                            i,
                            degree_y * degree_z * degree_t,
                        )
                        .as_slice(),
                    )
                    .into()
                })
                .collect::<Vec<_>>(),
            DenseOrSparseMLE::Sparse(poly) => (0..degree_x)
                .map(|i| {
                    let slice = Self::get_sparse_partial_evaluation_for_boolean_input(
                        poly,
                        i,
                        degree_y * degree_z * degree_t,
                    );
                    if slice.is_empty() {
                        return E::G1Affine::zero();
                    }

                    let mut bases = Vec::<E::G1Affine>::with_capacity(slice.len());
                    let mut scalars = Vec::<E::ScalarField>::with_capacity(slice.len());

                    for (&local_idx, coeff) in slice.iter() {
                        bases.push(prover_param.get_h_yzt()[local_idx]);
                        scalars.push(*coeff);
                    }

                    E::G1::msm_unchecked(&bases, &scalars).into()
                })
                .collect(),
        };

        let d_y = match polynomial {
            DenseOrSparseMLE::Dense(poly) => (0..degree_x * degree_y)
                .map(|i| {
                    E::G1::msm_unchecked(
                        prover_param.get_h_zt().as_slice(),
                        Self::get_dense_partial_evaluation_for_boolean_input(
                            poly,
                            i,
                            degree_z * degree_t,
                        )
                        .as_slice(),
                    )
                    .into()
                })
                .collect::<Vec<_>>(),
            DenseOrSparseMLE::Sparse(poly) => (0..degree_x)
                .map(|i| {
                    let slice = Self::get_sparse_partial_evaluation_for_boolean_input(
                        poly,
                        i,
                        degree_z * degree_t,
                    );
                    if slice.is_empty() {
                        return E::G1Affine::zero();
                    }

                    let mut bases = Vec::<E::G1Affine>::with_capacity(slice.len());
                    let mut scalars = Vec::<E::ScalarField>::with_capacity(slice.len());

                    for (&local_idx, coeff) in slice.iter() {
                        bases.push(prover_param.get_h_zt()[local_idx]);
                        scalars.push(*coeff);
                    }

                    E::G1::msm_unchecked(&bases, &scalars).into()
                })
                .collect(),
        };

        Ok(KZH4AuxInfo::new(d_x, d_y))
    }

    fn open_dense_internal(
        prover_param: &KZH4ProverParam<E>,
        polynomial: &DenseMultilinearExtension<E::ScalarField>,
        point: &[E::ScalarField],
    ) -> Result<
        (
            KZH4OpeningProof<E>,
            <KZH4<E> as PolynomialCommitmentScheme<E>>::Evaluation,
        ),
        PCSError,
    > {
        let timer = start_timer!(|| "KZH::OpenInternal");

        let split_input = Self::split_input(
            prover_param.get_num_vars_x(),
            prover_param.get_num_vars_y(),
            prover_param.get_num_vars_z(),
            prover_param.get_num_vars_t(),
            point,
            E::ScalarField::ZERO,
        );

        let d_z = (0..(1 << prover_param.get_num_vars_z()))
            .map(|i| {
                E::G1::msm_unchecked(
                    prover_param.get_h_t().as_slice(),
                    Self::get_dense_partial_evaluation_for_boolean_input(
                        &polynomial.fix_variables(
                            [split_input[0].as_slice(), split_input[1].as_slice()]
                                .concat()
                                .as_slice(),
                        ),
                        i,
                        1 << prover_param.get_num_vars_t(),
                    )
                    .as_slice(),
                )
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
        let f_star = polynomial.fix_variables(
            {
                let mut res = Vec::new();
                res.extend_from_slice(split_input[0].as_slice());
                res.extend_from_slice(split_input[1].as_slice());
                res.extend_from_slice(split_input[2].as_slice());
                res
            }
            .as_slice(),
        );
        end_timer!(timer);
        Ok((
            KZH4OpeningProof::new(d_z, DenseOrSparseMLE::Dense(f_star)),
            polynomial.evaluate(&point.to_vec()),
        ))
    }
fn open_sparse_internal(
    prover_param: &KZH4ProverParam<E>,
    polynomial: &SparseMultilinearExtension<E::ScalarField>,
    point: &[E::ScalarField],
) -> Result<
    (
        KZH4OpeningProof<E>,
        <KZH4<E> as PolynomialCommitmentScheme<E>>::Evaluation,
    ),
    PCSError,
> {
    let timer = start_timer!(|| "KZH::OpenInternal-sparse");

    // ───── split the evaluation point into (x, y, z, t) ────────────────────────
    let split_input = Self::split_input(
        prover_param.get_num_vars_x(),
        prover_param.get_num_vars_y(),
        prover_param.get_num_vars_z(),
        prover_param.get_num_vars_t(),
        point,
        E::ScalarField::ZERO,
    );

    // Basic sanity (mirrors dense routine)
    assert_eq!(split_input[0].len(), prover_param.get_num_vars_x(), "wrong length");
    assert_eq!(split_input[1].len(), prover_param.get_num_vars_y(), "wrong length");
    assert_eq!(split_input[2].len(), prover_param.get_num_vars_z(), "wrong length");

    let h_t   = prover_param.get_h_t();                    // &[E::G1Affine]
    let deg_t = 1 << prover_param.get_num_vars_t();        // |t|-dimension
    let num_z = 1 << prover_param.get_num_vars_z();        // |z|-dimension

    // ───── build the vector  d_z  with a *single* MSM per z-assignment ─────────
    let d_z: Vec<E::G1> = (0..num_z)
        .map(|i| {
            // 1. fix x ∥ y variables
            let xy_fixed = polynomial.fix_variables(
                [split_input[0].as_slice(), split_input[1].as_slice()]
                    .concat()
                    .as_slice(),
            );

            // 2. sparse slice over the t-hypercube for this z-assignment
            let slice = Self::get_sparse_partial_evaluation_for_boolean_input(
                &xy_fixed,
                i,
                deg_t,
            );

            if slice.is_empty() {
                // all scalars are zero → MSM result is identity
                return E::G1::zero();
            }

            // 3. build trimmed MSM operands
            let mut bases   = Vec::<E::G1Affine>::with_capacity(slice.len());
            let mut scalars = Vec::<E::ScalarField>::with_capacity(slice.len());

            for (&local_idx, coeff) in slice.iter() {
                bases.push(h_t[local_idx]);  // copy the needed basis element
                scalars.push(*coeff);
            }

            // 4. compute MSM
            E::G1::msm_unchecked(&bases, &scalars)
        })
        .collect();

    // ───── fully fix x, y, z to get f★ (still over t variables) ───────────────
    let f_star = polynomial.fix_variables({
        let mut tmp = Vec::new();
        tmp.extend_from_slice(split_input[0].as_slice());
        tmp.extend_from_slice(split_input[1].as_slice());
        tmp.extend_from_slice(split_input[2].as_slice());
        tmp
    }.as_slice());

    end_timer!(timer);

    Ok((
        KZH4OpeningProof::new(d_z, DenseOrSparseMLE::Sparse(f_star)),
        polynomial.evaluate(&point.to_vec()),
    ))
}
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
        let start = n * index; // first global index we want
        let end = start + n; // one-past-last global index

        // Collect every (global_idx, value) that lives in [start, end),
        // shift the index so that it becomes 0-based inside the slice.
        sparse_poly
        .evaluations
        .range(start..end)              // &BTreeMap` supports range queries
        .map(|(global_idx, value)| {
            let local_idx = global_idx - start; // 0 ≤ local_idx < n
            (local_idx, *value)
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

        let l = EqPolynomial::new(self.r[..left_num_vars].to_vec()).evals();
        let r = EqPolynomial::new(self.r[left_num_vars..ell].to_vec()).evals();

        (l, r)
    }
}
