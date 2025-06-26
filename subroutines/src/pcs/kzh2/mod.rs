pub mod srs;
pub mod structs;
#[cfg(test)]
mod tests;
use crate::{
    pcs::kzh2::srs::{KZH2ProverParam, KZH2VerifierParam},
    poly::DenseOrSparseMLE,
    PCSError, PolynomialCommitmentScheme,
};
use arithmetic::{
    build_eq_x_r, evaluate_last_dense, evaluate_last_sparse, fix_last_variables,
    fix_last_variables_sparse,
};
use ark_ec::{
    pairing::Pairing, scalar_mul::variable_base::VariableBaseMSM, AffineRepr, CurveGroup,
};
use ark_ff::{One, Zero};
use ark_poly::{
    DenseMultilinearExtension, MultilinearExtension, Polynomial, SparseMultilinearExtension,
};
#[cfg(feature = "parallel")]
use rayon::iter::IntoParallelIterator;

use crate::pcs::{kzh2::srs::KZH2UniversalParams, StructuredReferenceString};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_chunks, cfg_iter_mut, end_timer, rand::Rng, start_timer, test_rng};
#[cfg(feature = "parallel")]
use rayon::{
    iter::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator},
    prelude::ParallelSlice,
};
use std::{
    borrow::Borrow,
    env::current_dir,
    fs::File,
    io::{BufReader, BufWriter, Read, Write},
    marker::PhantomData,
};
use structs::{KZH2AuxInfo, KZH2Commitment, KZH2OpeningProof};
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
    type SRS = KZH2UniversalParams<E>;
    type ProverParam = KZH2ProverParam<E>;
    type VerifierParam = KZH2VerifierParam<E>;
    // Polynomial and its associated types
    type Polynomial = DenseOrSparseMLE<E::ScalarField>;
    type Point = Vec<E::ScalarField>;
    type Evaluation = E::ScalarField;
    // Commitments and proofs
    type Commitment = KZH2Commitment<E>;
    type Proof = KZH2OpeningProof<E>;
    type BatchProof = KZH2OpeningProof<E>;
    type Aux = KZH2AuxInfo<E>;

    fn gen_srs_for_testing<R: Rng>(rng: &mut R, log_size: usize) -> Result<Self::SRS, PCSError> {
        let srs_path = current_dir()
            .unwrap()
            .join(format!("../srs/srs_{}.bin", log_size));
        if srs_path.exists() {
            eprintln!("Loading SRS");
            let mut buffer = Vec::new();
            BufReader::new(File::open(&srs_path).unwrap())
                .read_to_end(&mut buffer)
                .unwrap();
            Ok(
                Self::SRS::deserialize_uncompressed_unchecked(&buffer[..]).unwrap_or_else(|_| {
                    panic!("Failed to deserialize SRS from {:?}", srs_path);
                }),
            )
        } else {
            eprintln!("Computing SRS");
            let srs = KZH2UniversalParams::<E>::gen_srs_for_testing(rng, log_size).unwrap();
            let mut serialized = Vec::new();
            srs.serialize_uncompressed(&mut serialized).unwrap();
            BufWriter::new(
                File::create(srs_path.clone())
                    .unwrap_or_else(|_| panic!("could not create file for SRS at {:?}", srs_path)),
            )
            .write_all(&serialized)
            .unwrap();
            Ok(srs)
        }
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
        println!("KZH2::Commit");
        match poly {
            DenseOrSparseMLE::Dense(dense_poly) => Self::commit_dense(prover_param, dense_poly),
            DenseOrSparseMLE::Sparse(sparse_poly) => Self::commit_sparse(prover_param, sparse_poly),
        }
    }

    fn comp_aux(
        prover_param: impl Borrow<Self::ProverParam>,
        polynomial: &Self::Polynomial,
        _com: &Self::Commitment,
    ) -> Result<Self::Aux, PCSError> {
        match polynomial {
            DenseOrSparseMLE::Dense(poly) => Self::comp_aux_dense(prover_param, poly),
            DenseOrSparseMLE::Sparse(poly) => Self::comp_aux_sparse(prover_param, poly),
        }
    }

    fn open(
        prover_param: impl Borrow<Self::ProverParam>,
        polynomial: &Self::Polynomial,
        point: &Self::Point,
        aux: &Self::Aux,
    ) -> Result<(KZH2OpeningProof<E>, Self::Evaluation), PCSError> {
        match polynomial {
            DenseOrSparseMLE::Dense(poly) => Self::open_dense(prover_param, poly, point, aux),
            DenseOrSparseMLE::Sparse(poly) => Self::open_sparse(prover_param, poly, point, aux),
        }
    }

    fn multi_open(
        prover_param: impl Borrow<Self::ProverParam>,
        polynomials: &[&Self::Polynomial],
        point: &<Self::Polynomial as Polynomial<E::ScalarField>>::Point,
        auxes: &[Self::Aux],
        _transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<(KZH2OpeningProof<E>, Self::Evaluation), PCSError> {
        let num_vars = point.len();
        let mut aggr_aux: KZH2AuxInfo<E> =
            KZH2AuxInfo::new(vec![E::G1Affine::zero(); auxes[0].get_d().len()]);
        let (agg_poly, aggr_aux) = match polynomials[0] {
            DenseOrSparseMLE::Dense(_) => {
                let mut aggr_poly = DenseMultilinearExtension::from_evaluations_vec(
                    num_vars,
                    vec![E::ScalarField::zero(); 1usize << num_vars],
                );
                for (poly, aux) in polynomials.iter().zip(auxes.iter()) {
                    if let DenseOrSparseMLE::Dense(dense_poly) = poly {
                        aggr_poly += dense_poly;
                        aggr_aux = aggr_aux + aux.clone();
                    } else {
                        panic!("All polynomials must be dense here");
                    }
                }
                (DenseOrSparseMLE::Dense(aggr_poly), aggr_aux)
            },
            DenseOrSparseMLE::Sparse(_) => {
                let mut aggr_poly =
                    SparseMultilinearExtension::from_evaluations(num_vars, Vec::new());
                for (poly, aux) in polynomials.iter().zip(auxes.iter()) {
                    if let DenseOrSparseMLE::Sparse(sparse_poly) = poly {
                        aggr_poly += sparse_poly;
                        aggr_aux = aggr_aux + aux.clone();
                    } else {
                        panic!("All polynomials must be sparse here");
                    }
                }

                (DenseOrSparseMLE::Sparse(aggr_poly), aggr_aux)
            },
        };
        Self::open(prover_param, &agg_poly, point, &aggr_aux)
    }

    fn verify(
        verifier_param: &Self::VerifierParam,
        commitment: &Self::Commitment,
        point: &<Self::Polynomial as Polynomial<E::ScalarField>>::Point,
        value: &E::ScalarField,
        aux: &Self::Aux,
        proof: &Self::Proof,
    ) -> Result<bool, PCSError> {
        let verify_timer = start_timer!(|| "KZH::Verify");
        let (x0, y0) = point.split_at(verifier_param.get_nu());
        // Check 1: Pairing check for commitment switching
        let check1_timer = start_timer!(|| "KZH::Verify::Check1");
        let g1_pairing_elements = std::iter::once(commitment.get_commitment()).chain(aux.get_d());
        let g2_pairing_elements = std::iter::once(verifier_param.get_minus_v_prime())
            .chain(verifier_param.get_v_vec().iter().copied());
        let p1 = E::multi_pairing(g1_pairing_elements, g2_pairing_elements).is_zero();
        end_timer!(check1_timer);
        // Check 2: Hyrax Check
        let check2_timer = start_timer!(|| "KZH::Verify::Check2");
        let eq_x0_mle = build_eq_x_r(x0).unwrap();
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
            .collect();
        let p2 = E::G1::msm(&bases, &scalars).unwrap().is_zero();
        end_timer!(check2_timer);
        // Check 3: Evaluate polynomial at point
        let check3_timer = start_timer!(|| "KZH::Verify::Check3");
        let p3 = match proof.get_f_star() {
            DenseOrSparseMLE::Dense(f_star) => evaluate_last_dense(&f_star, y0) == *value,
            DenseOrSparseMLE::Sparse(f_star) => evaluate_last_sparse(&f_star, y0) == *value,
        };
        end_timer!(check3_timer);
        let res = p1 && p2 && p3;
        end_timer!(verify_timer);
        Ok(res)
    }

    fn batch_verify(
        verifier_param: &Self::VerifierParam,
        commitments: &[Self::Commitment],
        auxs: &[Self::Aux],
        points: &Self::Point,
        values: &[E::ScalarField],
        batch_proof: &Self::BatchProof,
        _transcript: &mut IOPTranscript<E::ScalarField>,
    ) -> Result<bool, PCSError> {
        let mut aggr_comm = Self::Commitment::default();
        let mut aggr_aux = KZH2AuxInfo::new(vec![E::G1Affine::zero(); auxs[0].get_d().len()]);
        let mut aggr_value = E::ScalarField::zero();
        for ((comm, aux), value) in commitments.iter().zip(auxs.iter()).zip(values.iter()) {
            aggr_comm = aggr_comm + *comm;
            aggr_aux = aggr_aux + aux.clone();
            aggr_value += value;
        }

        Self::verify(
            verifier_param,
            &aggr_comm,
            points,
            &aggr_value,
            &aggr_aux,
            batch_proof,
        )
    }
}
impl<E: Pairing> KZH2<E> {
    pub fn commit_dense(
        prover_param: impl Borrow<KZH2ProverParam<E>>,
        poly: &DenseMultilinearExtension<E::ScalarField>,
    ) -> Result<KZH2Commitment<E>, PCSError> {
        println!("KZH2::Commit(Dense)");
        let commit_timer = start_timer!(|| "KZH::Commit");
        let prover_param: &KZH2ProverParam<E> = prover_param.borrow();
        println!("Prover param");
        let com = E::G1::msm(&prover_param.get_h_mat(), &poly.evaluations).unwrap();
        println!("MSM done");
        end_timer!(commit_timer);
        Ok(KZH2Commitment::new(com.into(), poly.num_vars()))
    }

    pub fn commit_sparse(
        prover_param: impl Borrow<KZH2ProverParam<E>>,
        sparse_poly: &SparseMultilinearExtension<E::ScalarField>,
    ) -> Result<KZH2Commitment<E>, PCSError> {
        println!("KZH2::Commit(Sparse)");
        let prover_param: &KZH2ProverParam<E> = prover_param.borrow();
        println!("Prover param");
        // The scalars for the MSM are the values from the sparse polynomial's
        // evaluation map.
        let scalars: Vec<E::ScalarField> = sparse_poly.evaluations.values().cloned().collect();
        println!("Scalars collected");
        // The bases for the MSM must correspond to the generator at the index
        // specified by the key in the sparse polynomial's evaluation map.
        let h_mat = prover_param.get_h_mat();
        println!("H matrix collected");
        let bases: Vec<E::G1Affine> = sparse_poly
        .evaluations
        .keys()
        .map(|&index| h_mat[index]) // Use the key `index` to get the correct base.
        .collect();

        println!("Bases collected");
        // Ensure that we have the same number of bases and scalars.
        assert_eq!(bases.len(), scalars.len());

        let com = E::G1::msm(&bases, &scalars).unwrap();

        println!("MSM done");
        Ok(KZH2Commitment::new(
            com.into_affine(),
            sparse_poly.num_vars(),
        ))
    }

    fn open_dense(
        prover_param: impl Borrow<KZH2ProverParam<E>>,
        polynomial: &DenseMultilinearExtension<E::ScalarField>,
        point: &[E::ScalarField],
        _aux: &KZH2AuxInfo<E>,
    ) -> Result<(KZH2OpeningProof<E>, E::ScalarField), PCSError> {
        let open_timer = start_timer!(|| "KZH::Open");
        let prover_param: &KZH2ProverParam<E> = prover_param.borrow();
        let (x0, y0) = point.split_at(prover_param.get_nu());
        let f_star = fix_last_variables(polynomial, x0);
        let z0 = fix_last_variables(&f_star, y0).evaluations[0];
        end_timer!(open_timer);
        Ok((KZH2OpeningProof::new(DenseOrSparseMLE::Dense(f_star)), z0))
    }

    fn open_sparse(
        prover_param: impl Borrow<KZH2ProverParam<E>>,
        polynomial: &SparseMultilinearExtension<E::ScalarField>,
        point: &[E::ScalarField],
        _aux: &KZH2AuxInfo<E>,
    ) -> Result<(KZH2OpeningProof<E>, E::ScalarField), PCSError> {
        let open_timer = start_timer!(|| "KZH::Open");
        let prover_param: &KZH2ProverParam<E> = prover_param.borrow();
        let (x0, y0) = point.split_at(prover_param.get_nu());
        let f_star = fix_last_variables_sparse(polynomial, x0);
        let binding = fix_last_variables_sparse(&f_star, y0);
        let z0 = binding
            .evaluations
            .get(&0)
            .cloned()
            .unwrap_or(E::ScalarField::zero());
        end_timer!(open_timer);
        Ok((KZH2OpeningProof::new(DenseOrSparseMLE::Sparse(f_star)), z0))
    }

    fn comp_aux_dense(
        prover_param: impl Borrow<KZH2ProverParam<E>>,
        polynomial: &DenseMultilinearExtension<E::ScalarField>,
    ) -> Result<KZH2AuxInfo<E>, PCSError> {
        let timer = start_timer!(|| "KZH::CompAux(Dense)");
        let prover_param: &KZH2ProverParam<E> = prover_param.borrow();
        let mut d = vec![E::G1Affine::zero(); 1usize << prover_param.get_nu()];
        let evaluations = polynomial.evaluations.clone();
        cfg_iter_mut!(d)
            .zip(cfg_chunks!(evaluations, 1usize << prover_param.get_mu()))
            .for_each(|(d, f)| {
                *d = E::G1::msm(&prover_param.get_h_vec(), f)
                    .unwrap()
                    .into_affine();
            });
        end_timer!(timer);
        Ok(KZH2AuxInfo::new(d))
    }

    fn comp_aux_sparse(
        prover_param: impl Borrow<KZH2ProverParam<E>>,
        polynomial: &SparseMultilinearExtension<E::ScalarField>,
    ) -> Result<KZH2AuxInfo<E>, PCSError> {
        let timer = start_timer!(|| "KZH::CompAux(Sparse)");
        let prover_param: &KZH2ProverParam<E> = prover_param.borrow();

        let nu = prover_param.get_nu();
        let mu = prover_param.get_mu();
        let msk = (1usize << mu) - 1; // mask for μ low bits
        let n_chunks = 1usize << nu; // 2^ν chunks

        // ── step 1: bucket the sparse entries per chunk ────────────────────────────
        let mut chunk_bases: Vec<Vec<E::G1Affine>> = vec![Vec::new(); n_chunks];
        let mut chunk_scalars: Vec<Vec<<E as Pairing>::ScalarField>> = vec![Vec::new(); n_chunks];

        for (&idx, &val) in polynomial.evaluations.iter() {
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
                *d_i = E::G1::msm(bases, scalars).unwrap().into_affine();
            }
        });

        end_timer!(timer);
        Ok(KZH2AuxInfo::new(d))
    }
}
