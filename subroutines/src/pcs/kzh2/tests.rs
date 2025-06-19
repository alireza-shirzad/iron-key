use super::*;
use ark_bn254::{Bn254 as E, Fr};
use ark_ec::pairing::Pairing;
use ark_std::{rand::Rng, test_rng, vec::Vec, UniformRand};
#[cfg(feature = "parallel")]
use rayon::vec;
use std::sync::Arc;

fn test_single_helper<R: Rng>(
    params: &KZH2UniversalParams<E>,
    poly: &DenseOrSparseMLE<Fr>,
    rng: &mut R,
) -> Result<(), PCSError> {
    let nv = poly.num_vars();
    assert_ne!(nv, 0);
    let (ck, vk) = KZH2::trim(params, None, Some(nv))?;
    let point: Vec<_> = (0..nv).map(|_| Fr::rand(rng)).collect();
    let com = KZH2::commit(&ck, poly)?;
    let aux = KZH2::comp_aux(&ck, poly, &com)?;
    let (proof, value) = KZH2::open(&ck, poly, &point, &aux)?;

    // assert_eq!(poly.evaluate(&point), value);
    assert!(KZH2::verify(&vk, &com, &point, &value, &aux, &proof)?);

    // let value = Fr::rand(rng);
    // assert!(!KZH2::verify(&vk, &com, &point, &value, &proof)?);

    Ok(())
}

#[test]
fn test_single_commit() -> Result<(), PCSError> {
    let nv = 4;
    let mut rng = test_rng();
    let params = KZH2::<E>::gen_srs_for_testing(&mut rng, nv)?;

    // normal polynomials
    let poly1 = DenseOrSparseMLE::Dense(DenseMultilinearExtension::rand(nv, &mut rng));
    test_single_helper(&params, &poly1, &mut rng)?;

    // // single-variate polynomials
    // let poly2 = DenseMultilinearExtension::rand(nv, &mut rng);
    // test_single_helper(&params, &poly2, &mut rng)?;

    Ok(())
}

// #[test]
// fn setup_commit_verify_constant_polynomial() {
//     let mut rng = test_rng();

//     // normal polynomials
//     assert!(KZH2::<E>::gen_srs_for_testing(&mut rng, 0).is_err());
// }

// #[test]
// fn test() {
//     let poly: DenseMultilinearExtension<Fr> =
// DenseMultilinearExtension::from_evaluations_vec(         2,
//         vec![Fr::from(1), Fr::from(2), Fr::from(3), Fr::from(4)],
//     );
//     dbg!(&poly.evaluations);

//     let eval = poly.evaluate(&vec![Fr::from(0), Fr::from(1)]);
// }



