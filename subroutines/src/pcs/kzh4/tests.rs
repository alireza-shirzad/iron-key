use super::*;
use ark_bls12_381::{Bls12_381 as E, Fr};
use ark_ec::pairing::Pairing;
use ark_std::{rand::Rng, test_rng, vec::Vec, UniformRand};
use rayon::vec;
use std::sync::Arc;

fn test_single_helper<R: Rng>(
    params: &KZH4UniversalParams<E>,
    poly: &DenseOrSparseMLE<Fr>,
    rng: &mut R,
) -> Result<(), PCSError> {
    let nv = poly.num_vars();
    assert_ne!(nv, 0);
    let (ck, vk) = KZH4::trim(params, None, Some(nv))?;
    let point: Vec<_> = (0..nv).map(|_| Fr::rand(rng)).collect();
    let timer = start_timer!(|| "Commit");
    let com = KZH4::commit(&ck, poly)?;
    let aux = KZH4::comp_aux(&ck, poly, &com)?;
    end_timer!(timer);
    let (proof, value) = KZH4::open(&ck, poly, &point)?;

    assert_eq!(poly.evaluate(&point), value);
    KZH4::verify(&vk, &com, &point, &value, &aux, &proof)?;

    // let value = Fr::rand(rng);
    // assert!(!KZH4::verify(&vk, &com, &point, &value, &proof)?);

    Ok(())
}

#[test]
fn test_single_commit() -> Result<(), PCSError> {
    let nv = 4;
    let mut rng = test_rng();
    let params = KZH4::<E>::gen_srs_for_testing(&mut rng, nv)?;

    // normal polynomials
    let poly1 = DenseOrSparseMLE::Dense(DenseMultilinearExtension::rand(nv, &mut rng));
    // let poly1 = DenseMultilinearExtension::from_evaluations_vec(nv,
    // vec![Fr::zero(); 1 << nv]);
    test_single_helper(&params, &poly1, &mut rng)?;

    // // single-variate polynomials
    // let poly2 = DenseMultilinearExtension::rand(nv, &mut rng);
    // test_single_helper(&params, &poly2, &mut rng)?;

    Ok(())
}

#[test]
fn setup_commit_verify_constant_polynomial() {
    let mut rng = test_rng();

    // normal polynomials
    assert!(KZH4::<E>::gen_srs_for_testing(&mut rng, 0).is_err());
}

#[test]
fn test() {
    let poly: DenseMultilinearExtension<Fr> = DenseMultilinearExtension::from_evaluations_vec(
        2,
        vec![Fr::from(1), Fr::from(2), Fr::from(3), Fr::from(4)],
    );
    dbg!(&poly.evaluations);

    let eval = poly.evaluate(&vec![Fr::from(0), Fr::from(1)]);
}
