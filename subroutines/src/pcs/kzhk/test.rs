use super::*;
use ark_bn254::{Bn254 as E, Fr};
use ark_std::{test_rng, vec::Vec, UniformRand};

fn test_single_helper(nv: usize, is_sparse: bool, k: usize) -> Result<(), PCSError> {
    let mut rng = test_rng();
    let poly = if is_sparse {
        DenseOrSparseMLE::Sparse(SparseMultilinearExtension::<Fr>::rand(nv, &mut rng))
    } else {
        DenseOrSparseMLE::Dense(DenseMultilinearExtension::<Fr>::rand(nv, &mut rng))
    };
    let params = KZHK::<E>::gen_srs_for_testing(k, &mut rng, nv)?;
    let (ck, vk) = KZHK::trim(params, None, Some(nv))?;
    let point: Vec<_> = (0..nv).map(|_| Fr::rand(&mut rng)).collect();
    let com = KZHK::<E>::commit(&ck, &poly)?;
    let aux = KZHK::<E>::comp_aux(&ck, &poly, &com)?;
    let (proof, value) = KZHK::<E>::open(&ck, &poly, &point, &aux)?;
    assert!(KZHK::<E>::verify(
        &vk,
        &com,
        &point,
        &value,
        Some(&aux),
        &proof
    )?);

    Ok(())
}

#[test]
fn test_dense_k2() -> Result<(), PCSError> {
    test_single_helper(2, false, 2)?;
    test_single_helper(3, false, 2)?;
    test_single_helper(4, false, 2)?;
    test_single_helper(5, false, 2)?;
    test_single_helper(6, false, 2)?;
    test_single_helper(7, false, 2)?;
    test_single_helper(8, false, 2)?;
    test_single_helper(9, false, 2)?;
    test_single_helper(10, false, 2)?;
    test_single_helper(11, false, 2)?;
    test_single_helper(12, false, 2)?;
    test_single_helper(13, false, 2)?;
    test_single_helper(14, false, 2)?;
    test_single_helper(15, false, 2)?;
    Ok(())
}
#[test]
fn test_dense_k3() -> Result<(), PCSError> {
    test_single_helper(3, false, 3)?;
    test_single_helper(4, false, 3)?;
    test_single_helper(5, false, 3)?;
    test_single_helper(6, false, 3)?;
    test_single_helper(7, false, 3)?;
    test_single_helper(8, false, 3)?;
    test_single_helper(9, false, 3)?;
    test_single_helper(10, false, 3)?;
    test_single_helper(11, false, 3)?;
    test_single_helper(12, false, 3)?;
    test_single_helper(13, false, 3)?;
    test_single_helper(14, false, 3)?;
    test_single_helper(15, false, 3)?;
    Ok(())
}

#[test]
fn test_dense_k4() -> Result<(), PCSError> {
    test_single_helper(4, false, 4)?;
    test_single_helper(5, false, 4)?;
    test_single_helper(6, false, 4)?;
    test_single_helper(7, false, 4)?;
    test_single_helper(8, false, 4)?;
    test_single_helper(9, false, 4)?;
    test_single_helper(10, false, 4)?;
    test_single_helper(11, false, 4)?;
    test_single_helper(12, false, 4)?;
    test_single_helper(13, false, 4)?;
    test_single_helper(14, false, 4)?;
    test_single_helper(15, false, 4)?;
    Ok(())
}
#[test]
fn test_sparse() -> Result<(), PCSError> {
    // test_single_helper(2, true, 2)?;
    // test_single_helper(3, true, 2)?;
    // test_single_helper(4, true, 2)?;
    // test_single_helper(5, true, 2)?;
    // test_single_helper(6, true, 2)?;
    // test_single_helper(8, true, 2)?;
    // test_single_helper(9, true, 2)?;
    test_single_helper(10, true, 2)?;
    // test_single_helper(11, true, 2)?;
    // test_single_helper(12, true, 2)?;
    // test_single_helper(13, true, 2)?;
    // test_single_helper(14, true, 2)?;
    // test_single_helper(15, true, 2)?;
    Ok(())
}
