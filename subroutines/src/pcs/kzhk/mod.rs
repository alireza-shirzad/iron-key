use std::{borrow::Borrow, collections::BTreeMap, marker::PhantomData};

use crate::{
    pcs::kzhk::{
        srs::{KZHKProverParam, KZHKUniversalParams, KZHKVerifierParam},
        structs::{KZHKAuxInfo, KZHKCommitment, KZHKOpeningProof},
    },
    poly::DenseOrSparseMLE,
    PCSError, PolynomialCommitmentScheme, StructuredReferenceString,
};
use arithmetic::{build_eq_x_r, fix_last_variables, fix_last_variables_sparse};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, One};
use ark_poly::{DenseMultilinearExtension, MultilinearExtension, SparseMultilinearExtension};
use ark_std::{cfg_into_iter, cfg_iter, cfg_iter_mut, end_timer, rand::Rng, start_timer, Zero};
use transcript::IOPTranscript;
pub mod srs;
pub mod structs;

#[cfg(feature = "parallel")]
use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator,
    IntoParallelRefMutIterator, ParallelIterator,
};
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
        let timer = start_timer!(|| "KZH::Commit");
        let result = match poly {
            DenseOrSparseMLE::Dense(poly) => Self::commit_dense(prover_param, poly),
            DenseOrSparseMLE::Sparse(poly) => Self::commit_sparse(prover_param, poly),
        };
        end_timer!(timer);
        result
    }

    fn comp_aux(
        prover_param: impl Borrow<Self::ProverParam>,
        polynomial: &Self::Polynomial,
        com: &Self::Commitment,
    ) -> Result<Self::Aux, PCSError> {
        let timer = start_timer!(|| "KZH::CompAux");
        let result = match polynomial {
            DenseOrSparseMLE::Dense(poly) => Self::comp_aux_dense(prover_param, poly, com),
            DenseOrSparseMLE::Sparse(poly) => Self::comp_aux_sparse(prover_param, poly, com),
        };
        end_timer!(timer);
        result
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
        match proof.get_f() {
            DenseOrSparseMLE::Dense(f) => {
                assert_eq!(fix_last_variables(f, &decomposed_point[k - 1])[0], *value);
            },
            DenseOrSparseMLE::Sparse(f) => {
                assert_eq!(
                    fix_last_variables_sparse(f, &decomposed_point[k - 1])[0],
                    *value
                );
            },
        }
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
            prover_param.get_h_tensors()[0]
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
        let timer = start_timer!(|| "KZH::CompAux_Dense");
        let prover_param: &KZHKProverParam<E> = prover_param.borrow();
        let dimensions = prover_param.get_dimensions();
        let k = dimensions.len();
        assert!(k >= 2, "need at least 2 blocks to build d_i's");

        let mut d_bool: Vec<Vec<E::G1Affine>> = Vec::with_capacity(k - 1);
        let mut prefix_vars: usize = 0;

        for (j, &dim) in dimensions.iter().take(k - 1).enumerate() {
            // Update prefix sum of variables up to and including block j
            prefix_vars += dim;

            // Number of i's (outer loop) and length of each partial evaluation
            let dj_size = 1usize << prefix_vars;
            let rem_vars = polynomial.num_vars() - prefix_vars;
            let eval_len = 1usize << rem_vars;

            // Choose H_t. Natural generalization uses [j]; if you intended to always use
            // [0], replace `j` with `0` below.
            let h_slice = prover_param.get_h_tensors()[j + 1]
                .as_slice_memory_order()
                .expect("H_t must be contiguous (standard layout)");

            // Build d_{j}
            // TODO: Why can't we use d_j.par_iter_mut()?
            let mut d_j = vec![E::G1Affine::zero(); dj_size];
            d_j.iter_mut().enumerate().for_each(|(i, d_j_i)| {
                let scalars =
                    KZHK::<E>::partially_eval_dense_poly_on_bool_point(polynomial, i, eval_len);
                *d_j_i = E::G1::msm(h_slice, scalars.as_slice())
                    .unwrap()
                    .into_affine()
            });

            d_bool.push(d_j);
        }

        end_timer!(timer);
        Ok(KZHKAuxInfo::new(d_bool))
    }

    fn comp_aux_sparse(
        prover_param: impl Borrow<KZHKProverParam<E>>,
        polynomial: &SparseMultilinearExtension<E::ScalarField>,
        _com: &KZHKCommitment<E>,
    ) -> Result<KZHKAuxInfo<E>, PCSError> {
        let timer = start_timer!(|| "KZH::CompAux_Sparse");
        let prover_param: &KZHKProverParam<E> = prover_param.borrow();
        let dimensions = prover_param.get_dimensions();
        let k = dimensions.len();
        assert!(k >= 2, "need at least 2 blocks to build d_i's");

        let mut d_bool: Vec<Vec<E::G1Affine>> = Vec::with_capacity(k - 1);
        let mut prefix_vars: usize = 0;

        for (j, &dim) in dimensions.iter().take(k - 1).enumerate() {
            // Update prefix sum of variables up to and including block j
            prefix_vars += dim;

            // Number of i's (outer loop) and length of each partial evaluation
            let dj_size = 1usize << prefix_vars;
            let rem_vars = polynomial.num_vars() - prefix_vars;
            let eval_len = 1usize << rem_vars;

            // Choose H_t. Natural generalization uses [j]; if you intended to always use
            // [0], replace `j` with `0` below.
            let h_slice = prover_param.get_h_tensors()[j + 1]
                .as_slice_memory_order()
                .expect("H_t must be contiguous (standard layout)");

            // Build d_{j}
            let mut d_j = vec![E::G1Affine::zero(); dj_size];
            cfg_iter_mut!(d_j).enumerate().for_each(|(i, d_j_i)| {
                let scalars_map =
                    KZHK::<E>::partially_eval_sparse_poly_on_bool_point(polynomial, i, eval_len);
                let mut bases = Vec::with_capacity(scalars_map.len());
                let mut scalars = Vec::with_capacity(scalars_map.len());
                for (&local_idx, s) in scalars_map.iter() {
                    bases.push(h_slice[local_idx]);
                    scalars.push(*s);
                }

                *d_j_i = if scalars.is_empty() {
                    E::G1Affine::zero()
                } else {
                    E::G1::msm(&bases, &scalars).unwrap().into_affine()
                }
            });
            d_bool.push(d_j);
        }
        end_timer!(timer);
        Ok(KZHKAuxInfo::new(d_bool))
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
            // Now start iterating over the boolean partial evaluations
            let num_chunks = 1 << prover_param.get_dimensions()[j];
            assert_eq!(partial_polynomial_evals.len() % num_chunks, 0);
            let chunk_len: usize = partial_polynomial_evals.len() / num_chunks; // = 2^(n-r)
            assert!(chunk_len > 0);
            let h_slice = prover_param.get_h_tensors()[j + 1]
                .as_slice_memory_order()
                .expect("H_t must be contiguous");
            // immutable
            let dj: Vec<E::G1Affine> = cfg_into_iter!(0..num_chunks)
                .map(|i| {
                    let off = i * chunk_len;
                    let chunk = &partial_polynomial_evals[off..off + chunk_len];
                    E::G1::msm(h_slice, chunk).unwrap().into_affine()
                })
                .collect();
            d.push(dj);

            partial_polynomial = fix_last_variables(&partial_polynomial, point_part);
        }
        let f = DenseOrSparseMLE::Dense(partial_polynomial.clone());
        let eval = fix_last_variables(&partial_polynomial, &decomposed_point[k - 1])[0];
        end_timer!(timer);
        Ok((KZHKOpeningProof::new(d, f), eval))
    }

    fn open_dense_bool(
        prover_param: impl Borrow<KZHKProverParam<E>>,
        polynomial: &DenseMultilinearExtension<E::ScalarField>,
        point: &[E::ScalarField],
        aux: &KZHKAuxInfo<E>,
    ) -> Result<(KZHKOpeningProof<E>, E::ScalarField), PCSError> {
        let timer = start_timer!(|| "KZH::Open_Dense_Boolean");
        let prover_param: &KZHKProverParam<E> = prover_param.borrow();

        let aux_d_bool = aux.get_d_bool();
        let mut d: Vec<Vec<E::G1Affine>> = Vec::new();

        let dims = prover_param.get_dimensions();
        let k = dims.len();

        let decomposed_point = KZHK::<E>::decompose_point(dims, point);
        let mut partial_polynomial = polynomial.clone();

        // Track the integer encoding of the already-fixed (prefix) boolean blocks,
        // little-endian.
        let mut eb: usize = 0;

        for (j, partial_point) in decomposed_point.iter().take(k - 1).enumerate() {
            let block_dim = dims[j];
            let start = eb << block_dim; // == eb * 2^{block_dim}
            let end = start + (1 << block_dim);

            let aux_vec = &aux_d_bool[j];
            debug_assert!(end <= aux_vec.len(), "aux slice OOB");

            // Parallel clone of the aux slice -> d_j
            let d_j: Vec<E::G1Affine> = cfg_iter!(aux_vec[start..end]).cloned().collect();

            d.push(d_j);

            // Reduce the dense polynomial on this boolean block (sequential dependency)
            partial_polynomial =
                Self::fix_last_variables_boolean(&partial_polynomial, partial_point);

            // Update eb to include this block for the next iteration:
            // new_bits = [partial_point || old_bits] (LE), so:
            // eb_next = bits_le(partial_point) + (eb << block_dim)
            let s = Self::bits_le_to_usize(partial_point);
            eb = s + (eb << block_dim);
        }

        let f = DenseOrSparseMLE::Dense(partial_polynomial.clone());
        let eval =
            Self::fix_last_variables_boolean(&partial_polynomial, &decomposed_point[k - 1])[0];

        end_timer!(timer);
        Ok((KZHKOpeningProof::new(d, f), eval))
    }
    fn open_sparse(
        prover_param: impl Borrow<KZHKProverParam<E>>,
        polynomial: &SparseMultilinearExtension<E::ScalarField>,
        point: &[E::ScalarField],
        _aux: &KZHKAuxInfo<E>,
    ) -> Result<(KZHKOpeningProof<E>, E::ScalarField), PCSError> {
        let timer = start_timer!(|| "KZH::Open_Sparse");
        let prover_param: &KZHKProverParam<E> = prover_param.borrow();
        let mut d = Vec::new();
        let k = prover_param.get_dimensions().len();
        let decomposed_point = KZHK::<E>::decompose_point(prover_param.get_dimensions(), point);
        let mut partial_polynomial = polynomial.clone();

        for (j, point_part) in decomposed_point.iter().take(k - 1).enumerate() {
            // Same partitioning as dense:
            let num_chunks = 1usize << prover_param.get_dimensions()[j]; // 2^{block_j}
            let chunk_len =
                1usize << (partial_polynomial.num_vars - prover_param.get_dimensions()[j]); // 2^{remaining - block_j}
            let domain_len = 1usize << partial_polynomial.num_vars;
            debug_assert_eq!((num_chunks * chunk_len), domain_len);

            let h_slice = prover_param.get_h_tensors()[j + 1]
                .as_slice_memory_order()
                .expect("H_t must be contiguous");
            debug_assert_eq!(h_slice.len(), chunk_len);

            // Iterate windows in increasing "x-index" order (matches dense & verifier eq
            // order)
            let mut dj = vec![E::G1Affine::zero(); num_chunks];
            cfg_iter_mut!(dj).enumerate().for_each(|(i, d_j_i)| {
                let base = i * chunk_len;
                // Gather non-zeros in [base, base+chunk_len) and rebase to local [0..chunk_len)
                let mut bases = Vec::new();
                let mut scalars = Vec::new();
                for (&gidx, &val) in partial_polynomial.evaluations.range(base..base + chunk_len) {
                    let local = gidx - base;
                    bases.push(h_slice[local]);
                    scalars.push(val);
                }

                let acc = if scalars.is_empty() {
                    E::G1Affine::zero()
                } else {
                    E::G1::msm(&bases, &scalars).unwrap().into_affine()
                };
                *d_j_i = acc;
            });
            d.push(dj);

            // Reduce the last block by the point part (must match dense orientation)
            partial_polynomial = fix_last_variables_sparse(&partial_polynomial, point_part);
        }

        let f = DenseOrSparseMLE::Sparse(partial_polynomial.clone());
        let eval = fix_last_variables_sparse(&partial_polynomial, &decomposed_point[k - 1])[0];
        end_timer!(timer);
        Ok((KZHKOpeningProof::new(d, f), eval))
    }

    fn open_sparse_bool(
        prover_param: impl Borrow<KZHKProverParam<E>>,
        polynomial: &SparseMultilinearExtension<E::ScalarField>,
        point: &[E::ScalarField],
        aux: &KZHKAuxInfo<E>,
    ) -> Result<(KZHKOpeningProof<E>, E::ScalarField), PCSError> {
        let timer = start_timer!(|| "KZH::Open_Sparse_Boolean");
        let prover_param: &KZHKProverParam<E> = prover_param.borrow();
        let dims = prover_param.get_dimensions();
        let k = dims.len();

        let aux_d_bool = aux.get_d_bool();
        let decomposed_point = KZHK::<E>::decompose_point(dims, point);

        let mut d: Vec<Vec<E::G1Affine>> = Vec::with_capacity(k - 1);
        let mut partial_polynomial = polynomial.clone();

        // eb encodes the already-fixed boolean prefix in little-endian
        let mut eb: usize = 0;

        for (j, partial_point) in decomposed_point.iter().take(k - 1).enumerate() {
            let block_dim = dims[j];
            let start = eb << block_dim; // == eb * 2^{block_dim}
            let end = start + (1 << block_dim);

            let aux_vec = &aux_d_bool[j];
            debug_assert!(end <= aux_vec.len(), "aux slice OOB");

            // Parallel clone of aux slice -> d_j
            let d_j: Vec<E::G1Affine> = cfg_iter!(aux_vec[start..end]).cloned().collect();

            d.push(d_j);

            // Reduce the last block on the sparse polynomial (sequential dependency)
            partial_polynomial =
                Self::fix_last_variables_boolean_sparse(&partial_polynomial, partial_point);

            // Update eb to include this block for next iteration:
            // new_bits = [partial_point || old_bits] (LE)
            let s = Self::bits_le_to_usize(partial_point);
            eb = s + (eb << block_dim);
        }

        let f = DenseOrSparseMLE::Sparse(partial_polynomial.clone());
        let eval =
            Self::fix_last_variables_boolean_sparse(&partial_polynomial, &decomposed_point[k - 1])
                [0];

        end_timer!(timer);
        Ok((KZHKOpeningProof::new(d, f), eval))
    }
    pub fn partially_eval_dense_poly_on_bool_point(
        dense_poly: &DenseMultilinearExtension<E::ScalarField>,
        index: usize,
        n: usize,
    ) -> Vec<E::ScalarField> {
        cfg_iter!(dense_poly.evaluations[n * index..n * index + n])
            .cloned()
            .collect()
    }

    pub fn partially_eval_sparse_poly_on_bool_point(
        sparse_poly: &SparseMultilinearExtension<E::ScalarField>,
        index: usize,
        n: usize,
    ) -> BTreeMap<usize, E::ScalarField> {
        debug_assert!(n > 0 && n.is_power_of_two(), "n must be a power of two");
        let total = 1usize << sparse_poly.num_vars;
        debug_assert!(n <= total, "n must be <= 2^num_vars");
        debug_assert!(total % n == 0, "n must divide 2^num_vars");
        let num_prefix_assignments = total / n;
        debug_assert!(index < num_prefix_assignments, "index out of range");

        let base = index * n;

        // Collect only the non-zero entries (i.e., those present in the sparse map)
        // that fall in the contiguous window [base, base + n), and rebase to [0, n).
        sparse_poly
        .evaluations
        .range(base..base + n) // end is exclusive
        .map(|(&global_idx, v)| (global_idx - base, *v))
        .collect()
    }
    pub fn fix_last_variables_boolean(
        poly: &DenseMultilinearExtension<E::ScalarField>,
        point: &[E::ScalarField],
    ) -> DenseMultilinearExtension<E::ScalarField> {
        let n = poly.num_vars() - point.len();
        let index = Self::bits_le_to_usize(point);
        DenseMultilinearExtension::from_evaluations_vec(
            n,
            Self::partially_eval_dense_poly_on_bool_point(poly, index, 1 << n),
        )
    }
    pub fn fix_last_variables_boolean_sparse(
        poly: &SparseMultilinearExtension<E::ScalarField>,
        point: &[E::ScalarField],
    ) -> SparseMultilinearExtension<E::ScalarField> {
        // remaining vars after fixing the last |point| variables
        let n = poly.num_vars() - point.len();
        // little-endian: point[0] is LSB of the last block
        let index = Self::bits_le_to_usize(point);
        // grab the contiguous window and rebase indices to [0 .. 2^n)
        let evals_map = Self::partially_eval_sparse_poly_on_bool_point(poly, index, 1 << n);
        let evals: Vec<(usize, E::ScalarField)> = evals_map.into_iter().collect();

        SparseMultilinearExtension::from_evaluations(n, &evals)
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

    #[inline]
    pub fn bits_le_to_usize<F: Field>(bits: &[F]) -> usize {
        assert!(
            bits.len() <= usize::BITS as usize,
            "too many bits for usize"
        );
        assert!(
            bits.iter().all(|b| b.is_zero() || b.is_one()),
            "non-boolean bit"
        );
        let mut out: usize = 0;
        for (i, bit) in bits.iter().enumerate() {
            if bit.is_one() {
                out |= 1usize << i;
            }
        }
        out
    }


    /// LITTLE-ENDIAN: out[0] is LSB.
    /// Panics if `x` doesn't fit in `n_bits`.
    #[inline]
    pub fn usize_to_bits_le<F: Field>(x: usize, n_bits: usize) -> Vec<F> {
        assert!(n_bits <= usize::BITS as usize, "n_bits too large for usize");
        let mut out = Vec::with_capacity(n_bits);
        let mut v = x;
        for _ in 0..n_bits {
            out.push(if (v & 1) == 1 { F::one() } else { F::zero() });
            v >>= 1;
        }
        assert!(v == 0, "value {} does not fit in {} bits", x, n_bits);
        out
    }

    /// BIG-ENDIAN: out[0] is MSB.
    /// Panics if `x` doesn't fit in `n_bits`.
    #[inline]
    pub fn usize_to_bits_be<F: Field>(x: usize, n_bits: usize) -> Vec<F> {
        assert!(n_bits <= usize::BITS as usize, "n_bits too large for usize");
        let mut out = vec![F::zero(); n_bits];
        for i in 0..n_bits {
            let bit = ((x >> i) & 1) == 1;
            out[n_bits - 1 - i] = if bit { F::one() } else { F::zero() };
        }
        // If n_bits < needed, the highest shifted bits would be non-zero.
        assert!(
            (x >> n_bits) == 0,
            "value {} does not fit in {} bits",
            x,
            n_bits
        );
        out
    }
}
