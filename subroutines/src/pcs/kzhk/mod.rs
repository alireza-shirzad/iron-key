use std::{borrow::Borrow, marker::PhantomData};

use crate::{
    pcs::kzhk::{
        srs::{KZHKProverParam, KZHKUniversalParams, KZHKVerifierParam},
        structs::{KZHKAuxInfo, KZHKCommitment, KZHKOpeningProof},
    },
    poly::DenseOrSparseMLE,
    PCSError, PolynomialCommitmentScheme, StructuredReferenceString,
};
use arithmetic::{build_eq_x_r, eq_eval};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, One};
use ark_poly::{DenseMultilinearExtension, MultilinearExtension, SparseMultilinearExtension};
use ark_std::{end_timer, rand::Rng, start_timer, Zero};
use transcript::IOPTranscript;
pub mod srs;
pub mod structs;
mod test;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KZHK<E: Pairing> {
    #[doc(hidden)]
    phantom: PhantomData<E>,
    k: usize,
}

impl<E> PolynomialCommitmentScheme<E> for KZHK<E>
where
    E: Pairing,
{
    type Config = usize;
    type ProverParam = KZHKProverParam<E>;
    type VerifierParam = KZHKVerifierParam<E>;
    type SRS = KZHKUniversalParams<E>;
    type Polynomial = DenseOrSparseMLE<E::ScalarField>;
    type Point = Vec<E::ScalarField>;
    type Evaluation = E::ScalarField;
    type Commitment = KZHKCommitment<E>;
    type Proof = KZHKOpeningProof<E>;
    type BatchProof = ();
    type Aux = KZHKAuxInfo<E>;

    fn gen_srs_for_testing<R: Rng>(
        conf: Self::Config,
        rng: &mut R,
        supported_size: usize,
    ) -> Result<Self::SRS, PCSError> {
        KZHKUniversalParams::gen_srs_for_testing(rng, conf, supported_size)
    }

    fn trim(
        srs: impl Borrow<Self::SRS>,
        supported_degree: Option<usize>,
        supported_num_vars: Option<usize>,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), PCSError> {
        let srs = srs.borrow();
        let supp_nv = supported_num_vars.unwrap();
        assert_eq!(srs.get_dimensions().iter().sum::<usize>(), supp_nv);
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
            DenseOrSparseMLE::Dense(poly) => Self::commit_dense(prover_param, poly),
            DenseOrSparseMLE::Sparse(poly) => Self::commit_sparse(prover_param, poly),
        }
    }

    fn comp_aux(
        prover_param: impl Borrow<Self::ProverParam>,
        polynomial: &Self::Polynomial,
        com: &Self::Commitment,
    ) -> Result<Self::Aux, PCSError> {
        match polynomial {
            DenseOrSparseMLE::Dense(poly) => Self::comp_aux_dense(prover_param, poly, com),
            DenseOrSparseMLE::Sparse(poly) => Self::comp_aux_sparse(prover_param, poly, com),
        }
    }

    fn open(
        prover_param: impl Borrow<Self::ProverParam>,
        polynomial: &Self::Polynomial,
        point: &Self::Point,
        aux: &Self::Aux,
    ) -> Result<(Self::Proof, Self::Evaluation), PCSError> {
        let timer = start_timer!(|| "KZH::Open");
        let is_boolean_point = point.iter().all(|&x| x.is_zero() || x.is_one());
        let result = match (is_boolean_point, polynomial) {
            (true, DenseOrSparseMLE::Dense(poly)) => {
                Self::open_dense_bool(prover_param, poly, point, aux)
            },
            (true, DenseOrSparseMLE::Sparse(poly)) => {
                Self::open_sparse_bool(prover_param, poly, point, aux)
            },
            (false, DenseOrSparseMLE::Dense(poly)) => {
                Self::open_dense(prover_param, poly, point, aux)
            },
            (false, DenseOrSparseMLE::Sparse(poly)) => {
                Self::open_sparse(prover_param, poly, point, aux)
            },
        };
        end_timer!(timer);
        result
    }

    fn multi_open(
        _prover_param: impl Borrow<Self::ProverParam>,
        _polynomials: &[&Self::Polynomial],
        _point: &Self::Point,
        _auxes: &[Self::Aux],
        _boolean: bool,
        _sparse: bool,
        _transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<(Self::BatchProof, Self::Evaluation), PCSError> {
        unimplemented!()
    }

    fn verify(
        verifier_param: &Self::VerifierParam,
        commitment: &Self::Commitment,
        point: &Self::Point,
        value: &E::ScalarField,
        _aux: Option<&Self::Aux>,
        proof: &Self::Proof,
    ) -> Result<bool, PCSError> {
        let timer = start_timer!(|| "KZH::Verify");
        let k = verifier_param.get_dimensions().len();
        let mut cj = commitment.get_commitment();
        let decomposed_point = KZHK::<E>::decompose_point(verifier_param.get_dimensions(), point);
        let pairing_loop_timer = start_timer!(|| "KZH::Verify::PairingLoop");
        for j in 0..(k - 1) {
            // Pairing Check
            let g1_prepared = <E as Pairing>::G1Prepared::from(cj);
            let g2_prepared = <E as Pairing>::G2Prepared::from(verifier_param.get_v());
            let left_gt = E::multi_pairing([g1_prepared], [g2_prepared]);

            let d_j_prepared = proof.get_d()[j]
                .iter()
                .map(|p| <E as Pairing>::G1Prepared::from(*p))
                .collect::<Vec<_>>();
            assert_eq!(d_j_prepared.len(), verifier_param.get_v_mat()[j].len());
            let right_gt = E::multi_pairing(d_j_prepared, verifier_param.get_v_mat()[j].clone());
            assert_eq!(left_gt, right_gt);

            // Updating Cj
            let eq_poly = build_eq_x_r(&decomposed_point[j]).unwrap();
            cj = E::G1::msm(&proof.get_d()[j], &eq_poly.evaluations)
                .unwrap()
                .into_affine();
        }
        end_timer!(pairing_loop_timer);
        // Checking c_{k-1}
        let cj_check_timer = start_timer!(|| "KZH::Verify::CJCheck");
        let alleged_last_cj = E::G1::msm(
            verifier_param
                .get_h_tensor()
                .as_slice_memory_order()
                .unwrap(),
            &proof.get_f().to_evaluations(),
        )
        .unwrap()
        .into_affine();
        assert_eq!(cj, alleged_last_cj);
        end_timer!(cj_check_timer);
        // Evaluation Check
        let eval_check_timer = start_timer!(|| "KZH::Verify::EvalCheck");
        assert_eq!(
            proof.get_f().fix_variables(&decomposed_point[k - 1])[0],
            *value
        );
        end_timer!(eval_check_timer);
        end_timer!(timer);
        Ok(true)
    }

    fn batch_verify(
        _verifier_param: &Self::VerifierParam,
        _commitments: &[Self::Commitment],
        _auxs: Option<&[Self::Aux]>,
        _point: &Self::Point,
        _values: &[E::ScalarField],
        _batch_proof: &Self::BatchProof,
        _transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<bool, PCSError> {
        unimplemented!()
    }
}

impl<E: Pairing> KZHK<E> {
    pub fn commit_dense(
        prover_param: impl Borrow<KZHKProverParam<E>>,
        poly: &DenseMultilinearExtension<E::ScalarField>,
    ) -> Result<KZHKCommitment<E>, PCSError> {
        let commit_timer = start_timer!(|| "KZH::Commit_Dense");
        let prover_param: &KZHKProverParam<E> = prover_param.borrow();
        let com = E::G1::msm(
            &prover_param.get_h_tensors()[0]
                .as_slice_memory_order()
                .unwrap(),
            &poly.evaluations,
        )
        .unwrap();
        end_timer!(commit_timer);
        Ok(KZHKCommitment::new(com.into(), poly.num_vars()))
    }

    pub fn commit_sparse(
        prover_param: impl Borrow<KZHKProverParam<E>>,
        sparse_poly: &SparseMultilinearExtension<E::ScalarField>,
    ) -> Result<KZHKCommitment<E>, PCSError> {
        let commit_timer = start_timer!(|| "KZH::Commit_Sparse");
        let prover_param: &KZHKProverParam<E> = prover_param.borrow();
        // The scalars for the MSM are the values from the sparse polynomial's
        // evaluation map.
        let scalars: Vec<E::ScalarField> = sparse_poly.evaluations.values().cloned().collect();
        // The bases for the MSM must correspond to the generator at the index
        // specified by the key in the sparse polynomial's evaluation map.
        let h_mat = prover_param.get_h_tensors()[0]
            .as_slice_memory_order()
            .unwrap();
        let bases: Vec<E::G1Affine> = sparse_poly
        .evaluations
        .keys()
        .map(|&index| h_mat[index]) // Use the key `index` to get the correct base.
        .collect();

        // Ensure that we have the same number of bases and scalars.
        assert_eq!(bases.len(), scalars.len());

        let com = E::G1::msm(&bases, &scalars).unwrap();
        end_timer!(commit_timer);
        Ok(KZHKCommitment::new(
            com.into_affine(),
            sparse_poly.num_vars(),
        ))
    }

    fn comp_aux_dense(
        prover_param: impl Borrow<KZHKProverParam<E>>,
        polynomial: &DenseMultilinearExtension<E::ScalarField>,
        _com: &KZHKCommitment<E>,
    ) -> Result<KZHKAuxInfo<E>, PCSError> {
        let prover_param: &KZHKProverParam<E> = prover_param.borrow();
        let dimensions = prover_param.get_dimensions();
        let k = dimensions.len();
        assert!(k >= 2, "need at least 2 blocks to build d_i's");

        let mut d_bool: Vec<Vec<E::G1Affine>> = Vec::with_capacity(k - 1);
        let mut prefix_vars: usize = 0;

        for j in 0..(k - 1) {
            // Update prefix sum of variables up to and including block j
            prefix_vars += dimensions[j];

            // Number of i's (outer loop) and length of each partial evaluation
            let outer = 1usize << prefix_vars;
            let rem_vars = polynomial.num_vars() - prefix_vars;
            let eval_len = 1usize << rem_vars;

            // Choose H_t. Natural generalization uses [j]; if you intended to always use
            // [0], replace `j` with `0` below.
            let h_slice = prover_param.get_h_tensors()[j + 1]
                .as_slice_memory_order()
                .expect("H_t must be contiguous (standard layout)");
            debug_assert_eq!(
                h_slice.len(),
                eval_len,
                "H_t length must equal partial eval length"
            );

            // Build d_{j+1}
            let d_j = (0..outer)
                .map(|i| {
                    let scalars =
                        KZHK::<E>::partially_eval_dense_poly_on_bool_point(polynomial, i, eval_len);
                    E::G1::msm(h_slice, scalars.as_slice())
                        .unwrap()
                        .into_affine()
                })
                .collect::<Vec<_>>();

            d_bool.push(d_j);
        }

        Ok(KZHKAuxInfo::new(d_bool))
    }

    fn comp_aux_sparse(
        prover_param: impl Borrow<KZHKProverParam<E>>,
        polynomial: &SparseMultilinearExtension<E::ScalarField>,
        com: &KZHKCommitment<E>,
    ) -> Result<KZHKAuxInfo<E>, PCSError> {
        todo!()
    }

    fn open_dense(
        prover_param: impl Borrow<KZHKProverParam<E>>,
        polynomial: &DenseMultilinearExtension<E::ScalarField>,
        point: &[E::ScalarField],
        _aux: &KZHKAuxInfo<E>,
    ) -> Result<(KZHKOpeningProof<E>, E::ScalarField), PCSError> {
        let timer = start_timer!(|| "KZH::Open_Dense");
        let prover_param: &KZHKProverParam<E> = prover_param.borrow();
        let mut d = Vec::new();
        let k = prover_param.get_dimensions().len();
        let decomposed_point = KZHK::<E>::decompose_point(prover_param.get_dimensions(), point);
        let mut partial_polynomial = polynomial.clone();
        for (j, point_part) in decomposed_point.iter().take(k - 1).enumerate() {
            let partial_polynomial_evals = &partial_polynomial.evaluations;
            let mut dj: Vec<E::G1Affine> = Vec::new();
            // Now start iterating over the boolean partial evaluations
            let num_chunks = 1 << prover_param.get_dimensions()[j];
            assert_eq!(partial_polynomial_evals.len() % num_chunks, 0);
            let chunk_len: usize = partial_polynomial_evals.len() / num_chunks; // = 2^(n-r)
            assert!(chunk_len > 0);

            // immutable
            for chunk in partial_polynomial_evals.chunks_exact(chunk_len) {
                dj.push(
                    E::G1::msm(
                        prover_param.get_h_tensors()[j + 1]
                            .as_slice_memory_order()
                            .unwrap(),
                        chunk,
                    )
                    .unwrap()
                    .into_affine(),
                );
            }
            d.push(dj);

            partial_polynomial = partial_polynomial.fix_variables(point_part);
        }
        let f = DenseOrSparseMLE::Dense(partial_polynomial.clone());
        let eval = partial_polynomial.fix_variables(&decomposed_point[k - 1])[0];
        end_timer!(timer);
        Ok((KZHKOpeningProof::new(d, f), eval))
    }

    fn open_dense_bool(
        prover_param: impl Borrow<KZHKProverParam<E>>,
        polynomial: &DenseMultilinearExtension<E::ScalarField>,
        point: &[E::ScalarField],
        aux: &KZHKAuxInfo<E>,
    ) -> Result<(KZHKOpeningProof<E>, E::ScalarField), PCSError> {
        todo!()
    }
    fn open_sparse(
        prover_param: impl Borrow<KZHKProverParam<E>>,
        polynomial: &SparseMultilinearExtension<E::ScalarField>,
        point: &[E::ScalarField],
        aux: &KZHKAuxInfo<E>,
    ) -> Result<(KZHKOpeningProof<E>, E::ScalarField), PCSError> {
        todo!()
    }
    fn open_sparse_bool(
        prover_param: impl Borrow<KZHKProverParam<E>>,
        polynomial: &SparseMultilinearExtension<E::ScalarField>,
        point: &[E::ScalarField],
        aux: &KZHKAuxInfo<E>,
    ) -> Result<(KZHKOpeningProof<E>, E::ScalarField), PCSError> {
        todo!()
    }
    pub fn partially_eval_dense_poly_on_bool_point(
        dense_poly: &DenseMultilinearExtension<E::ScalarField>,
        index: usize,
        n: usize,
    ) -> Vec<E::ScalarField> {
        dense_poly.evaluations[n * index..n * index + n].to_vec()
    }

    pub fn decompose_point(
        dimensions: &[usize],
        point: &[E::ScalarField],
    ) -> Vec<Vec<E::ScalarField>> {
        let mut decomposed = Vec::new();
        let mut start = 0;
        for &dim in dimensions {
            let end = start + dim;
            decomposed.push(point[start..end].to_vec());
            start = end;
        }
        decomposed
    }
}
