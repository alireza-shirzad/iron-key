use ark_ec::{AdditiveGroup, VariableBaseMSM, pairing::Pairing};
use ark_piop::{arithmetic::mat_poly::mle::MLE, pcs::PCS};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rayon::iter::IntoParallelIterator;
use std::marker::PhantomData;
use structs::{KZH2Commitment, KZH2Opening, KZH2SRS};
pub mod structs;
use rayon::iter::ParallelIterator;
/// Define the new struct that encapsulates the functionality of polynomial
/// commitment
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct KZH2<E: Pairing> {
    phantom: PhantomData<E>,
}

impl<E: Pairing> PCS<E::ScalarField> for KZH2<E> {
    type ProverParam;

    type VerifierParam;

    type SRS = KZH2SRS<E>;

    type Poly = MLE<E::ScalarField>;

    type Commitment = KZH2Commitment<E>;

    type Proof = KZH2Opening<E>;

    type BatchProof;

    fn gen_srs_for_testing<R: ark_std::rand::Rng>(
        rng: &mut R,
        supported_size: usize,
    ) -> ark_piop::errors::SnarkResult<Self::SRS> {
        let (degree_x, degree_y): (usize, usize) =
            Self::get_degree_from_maximum_supported_degree(maximum_degree);

        let degree_x = 1 << degree_x;
        let degree_y = 1 << degree_y;

        // sample G_0, G_1, ..., G_m generators from group one
        let G1_generator_vec: Vec<_> = (0..degree_y).map(|_| E::G1Affine::rand(rng)).collect();

        // sample V, generator for group two
        let G2_generator = E::G2Affine::rand(rng);

        // sample trapdoors tau_0, tau_1, ..., tau_n, alpha
        let tau: Vec<E::ScalarField> = (0..degree_x).map(|_| E::ScalarField::rand(rng)).collect();

        let alpha = E::ScalarField::rand(rng);

        // generate matrix_H
        let matrix_H: Vec<Vec<_>> = (0..degree_x)
            .into_par_iter()
            .map(|i| {
                let mut row = Vec::new();
                for j in 0..degree_y {
                    let g = G1_generator_vec[j].mul(tau[i]);
                    row.push(g.into());
                }
                row
            })
            .collect();

        let vec_H: Vec<_> = (0..degree_y)
            .map(|j| G1_generator_vec[j].mul(alpha).into())
            .collect();
        let vec_V: Vec<_> = (0..degree_x).map(|j| G2_generator.mul(tau[j])).collect();

        // generate V_prime
        let v_prime = G2_generator.mul(alpha);

        // return the output
        let srs = KZH2SRS {
            degree_x,
            degree_y,
            h_xy: matrix_H,
            h_y: vec_H,
            v_x: vec_V,
            v_prime,
        };
        Ok(srs)
    }

    fn trim(
        srs: impl std::borrow::Borrow<Self::SRS>,
        supported_degree: Option<usize>,
        supported_num_vars: Option<usize>,
    ) -> ark_piop::errors::SnarkResult<(Self::ProverParam, Self::VerifierParam)> {
        todo!()
    }

    fn commit(
        prover_param: impl std::borrow::Borrow<Self::ProverParam>,
        poly: &std::sync::Arc<Self::Poly>,
    ) -> ark_piop::errors::SnarkResult<Self::Commitment> {
        let len = srs.degree_x.log_2() + srs.degree_y.log_2();
        let poly = poly.extend_number_of_variables(len);
        assert_eq!(poly.num_variables, len);
        assert_eq!(poly.len, 1 << poly.num_variables);
        assert_eq!(poly.evaluation_over_boolean_hypercube.len(), poly.len);

        let comm = KZH2Commitment {
            c: {
                // Collect all points and scalars into single vectors
                let mut base = Vec::new();
                let mut scalar = Vec::new();

                for i in 0..srs.degree_x {
                    // Collect points from matrix_H
                    base.extend_from_slice(srs.H_xy[i].as_slice());
                    // Collect corresponding scalars from partial evaluations
                    scalar.extend_from_slice(
                        poly.get_partial_evaluation_for_boolean_input(i, srs.degree_y)
                            .as_slice(),
                    );
                }

                E::G1::msm_unchecked(&base, &scalar).into_affine()
            },
            aux: (0..srs.degree_x)
                .into_par_iter() // Parallelize the D^{(x)} computation
                .map(|i| {
                    E::G1::msm_unchecked(
                        srs.H_y.as_slice(),
                        poly.get_partial_evaluation_for_boolean_input(i, srs.degree_y).as_slice(),
                    )
                })
                .collect::<Vec<_>>(),
        };
        Ok(comm)
    }

    fn open(
        prover_param: impl std::borrow::Borrow<Self::ProverParam>,
        polynomial: &std::sync::Arc<Self::Poly>,
        point: &<Self::Poly as ark_poly::Polynomial<E::ScalarField>>::Point,
    ) -> ark_piop::errors::SnarkResult<(Self::Proof, E::ScalarField)> {
        let len = srs.degree_x.log_2() + srs.degree_y.log_2();
        let poly = poly.extend_number_of_variables(len);
        assert_eq!(poly.num_variables, len);
        assert_eq!(poly.len, 1 << poly.num_variables);
        assert_eq!(poly.evaluation_over_boolean_hypercube.len(), poly.len);

        let split_input = Self::split_input(&srs, input, E::ScalarField::ZERO);

        let proof = KZH2Opening {
            d_x: com.aux.clone().into_iter().map(|g| g.into()).collect(),
            f_star: poly.partial_evaluation(split_input[0].as_slice()),
        };
        Ok(proof)
    }

    fn verify(
        verifier_param: &Self::VerifierParam,
        commitment: &Self::Commitment,
        point: &<Self::Poly as ark_poly::Polynomial<E::ScalarField>>::Point,
        value: &E::ScalarField,
        proof: &Self::Proof,
    ) -> ark_piop::errors::SnarkResult<bool> {
        let split_input = Self::split_input(&srs, input, E::ScalarField::ZERO);

        // Step 1: pairing check
        // Combine the pairings into a single multi-pairing
        let g1_elems: Vec<_> = std::iter::once(com.C.clone())
            .chain(open.D_x.iter().map(|g1| (E::G1Affine::zero() - g1).into()))
            .collect();

        let g2_elems: Vec<_> = std::iter::once(srs.V_prime.clone())
            .chain(srs.V_x.iter().cloned())
            .collect();

        // Perform the combined pairing check
        E::multi_pairing(&g1_elems, &g2_elems).check().unwrap();

        // Step 2: MSM check
        let negated_eq_evals: Vec<_> = EqPolynomial::new(split_input[0].clone())
            .evals()
            .into_iter()
            .map(|scalar| -scalar)
            .collect();

        let scalars: Vec<_> = open
            .f_star
            .evaluation_over_boolean_hypercube
            .iter()
            .chain(negated_eq_evals.iter())
            .cloned()
            .collect();

        let bases: Vec<_> = srs.H_y.iter().chain(open.D_x.iter()).cloned().collect();

        assert!(E::G1::msm_unchecked(&bases, &scalars).is_zero());

        // Step 3: complete poly eval
        let y_expected = open.f_star.evaluate(split_input[1].as_slice());
        assert_eq!(y_expected, *output);
        Ok(true)
    }
}
