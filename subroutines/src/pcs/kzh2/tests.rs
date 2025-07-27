use super::*;
use ark_bn254::{Bn254 as E, Fr};
use ark_std::{test_rng, vec::Vec, UniformRand};

fn test_single_helper(nv: usize, is_sparse: bool) -> Result<(), PCSError> {
    let mut rng = test_rng();
    let poly = if is_sparse {
        DenseOrSparseMLE::Sparse(SparseMultilinearExtension::rand(nv, &mut rng))
    } else {
        DenseOrSparseMLE::Dense(DenseMultilinearExtension::rand(nv, &mut rng))
    };
    let params = KZH2::<E>::gen_srs_for_testing(&mut rng, nv)?;
    let (ck, vk) = KZH2::trim(params, None, Some(nv))?;
    let point: Vec<_> = (0..nv).map(|_| Fr::rand(&mut rng)).collect();
    let com = KZH2::commit(&ck, &poly)?;
    let aux = KZH2::comp_aux(&ck, &poly, &com)?;
    let (proof, value) = KZH2::open(&ck, &poly, &point, &aux)?;
    assert!(KZH2::verify(&vk, &com, &point, &value, Some(&aux), &proof)?);

    Ok(())
}

#[test]
fn test_dense() -> Result<(), PCSError> {
    test_single_helper(2, false)?;
    test_single_helper(3, false)?;
    test_single_helper(4, false)?;
    test_single_helper(5, false)?;
    test_single_helper(6, false)?;
    test_single_helper(7, false)?;
    test_single_helper(8, false)?;
    test_single_helper(9, false)?;
    test_single_helper(10, false)?;
    test_single_helper(11, false)?;
    test_single_helper(12, false)?;
    test_single_helper(13, false)?;
    test_single_helper(14, false)?;
    test_single_helper(15, false)?;
    Ok(())
}
#[test]
fn test_sparse() -> Result<(), PCSError> {
    test_single_helper(2, true)?;
    test_single_helper(3, true)?;
    test_single_helper(4, true)?;
    test_single_helper(5, true)?;
    test_single_helper(6, true)?;
    test_single_helper(8, true)?;
    test_single_helper(9, true)?;
    test_single_helper(10, true)?;
    test_single_helper(11, true)?;
    test_single_helper(12, true)?;
    test_single_helper(13, true)?;
    test_single_helper(14, true)?;
    test_single_helper(15, true)?;
    Ok(())
}
