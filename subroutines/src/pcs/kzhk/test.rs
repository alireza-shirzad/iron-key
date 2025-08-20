use super::*;
use ark_bn254::{Bn254 as E, Fr};
use ark_std::{test_rng, vec::Vec, UniformRand};

fn test_single_helper(
    nv: usize,
    is_sparse: bool,
    is_boolean: bool,
    k: usize,
) -> Result<(), PCSError> {
    let mut rng = test_rng();
    let poly = if is_sparse {
        DenseOrSparseMLE::Sparse(SparseMultilinearExtension::<Fr>::rand(nv, &mut rng))
    } else {
        DenseOrSparseMLE::Dense(DenseMultilinearExtension::<Fr>::rand(nv, &mut rng))
    };
    let params = KZHK::<E>::gen_srs_for_testing(k, &mut rng, nv)?;
    let (ck, vk) = KZHK::trim(params, None, Some(nv))?;
    let point = match is_boolean {
        true => (0..nv)
            .map(|_| Fr::from((usize::rand(&mut rng) % 2) as i64))
            .collect::<Vec<_>>(),
        false => (0..nv).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>(),
    };
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
    test_single_helper(2, false, false, 2)?;
    test_single_helper(3, false, false, 2)?;
    test_single_helper(4, false, false, 2)?;
    test_single_helper(5, false, false, 2)?;
    test_single_helper(6, false, false, 2)?;
    test_single_helper(7, false, false, 2)?;
    test_single_helper(8, false, false, 2)?;
    test_single_helper(9, false, false, 2)?;
    test_single_helper(10, false, false, 2)?;
    test_single_helper(11, false, false, 2)?;
    test_single_helper(12, false, false, 2)?;
    test_single_helper(13, false, false, 2)?;
    test_single_helper(14, false, false, 2)?;
    test_single_helper(15, false, false, 2)?;
    Ok(())
}

#[test]
fn test_dense_boolean_k2() -> Result<(), PCSError> {
    test_single_helper(2, false, true, 2)?;
    test_single_helper(3, false, true, 2)?;
    test_single_helper(4, false, true, 2)?;
    test_single_helper(5, false, true, 2)?;
    test_single_helper(6, false, true, 2)?;
    test_single_helper(7, false, true, 2)?;
    test_single_helper(8, false, true, 2)?;
    test_single_helper(9, false, true, 2)?;
    test_single_helper(10, false, true, 2)?;
    test_single_helper(11, false, true, 2)?;
    test_single_helper(12, false, true, 2)?;
    test_single_helper(13, false, true, 2)?;
    test_single_helper(14, false, true, 2)?;
    test_single_helper(15, false, true, 2)?;
    Ok(())
}

#[test]
fn test_sparse_k2() -> Result<(), PCSError> {
    test_single_helper(2, true, false, 2)?;
    test_single_helper(3, true, false, 2)?;
    test_single_helper(4, true, false, 2)?;
    test_single_helper(5, true, false, 2)?;
    test_single_helper(6, true, false, 2)?;
    test_single_helper(7, true, false, 2)?;
    test_single_helper(8, true, false, 2)?;
    test_single_helper(9, true, false, 2)?;
    test_single_helper(10, true, false, 2)?;
    test_single_helper(11, true, false, 2)?;
    test_single_helper(12, true, false, 2)?;
    test_single_helper(13, true, false, 2)?;
    test_single_helper(14, true, false, 2)?;
    test_single_helper(15, true, false, 2)?;
    Ok(())
}

#[test]
fn test_sparse_boolean_k2() -> Result<(), PCSError> {
    test_single_helper(2, true, true, 2)?;
    test_single_helper(3, true, true, 2)?;
    test_single_helper(4, true, true, 2)?;
    test_single_helper(5, true, true, 2)?;
    test_single_helper(6, true, true, 2)?;
    test_single_helper(7, true, true, 2)?;
    test_single_helper(8, true, true, 2)?;
    test_single_helper(9, true, true, 2)?;
    test_single_helper(10, true, true, 2)?;
    test_single_helper(11, true, true, 2)?;
    test_single_helper(12, true, true, 2)?;
    test_single_helper(13, true, true, 2)?;
    test_single_helper(14, true, true, 2)?;
    test_single_helper(15, true, true, 2)?;
    Ok(())
}

#[test]
fn test_dense_k3() -> Result<(), PCSError> {
    test_single_helper(3, false, false, 3)?;
    test_single_helper(4, false, false, 3)?;
    test_single_helper(5, false, false, 3)?;
    test_single_helper(6, false, false, 3)?;
    test_single_helper(7, false, false, 3)?;
    test_single_helper(8, false, false, 3)?;
    test_single_helper(9, false, false, 3)?;
    test_single_helper(10, false, false, 3)?;
    test_single_helper(11, false, false, 3)?;
    test_single_helper(12, false, false, 3)?;
    test_single_helper(13, false, false, 3)?;
    test_single_helper(14, false, false, 3)?;
    test_single_helper(15, false, false, 3)?;
    Ok(())
}

#[test]
fn test_dense_boolean_k3() -> Result<(), PCSError> {
    test_single_helper(3, false, true, 3)?;
    test_single_helper(4, false, true, 3)?;
    test_single_helper(5, false, true, 3)?;
    test_single_helper(6, false, true, 3)?;
    test_single_helper(7, false, true, 3)?;
    test_single_helper(8, false, true, 3)?;
    test_single_helper(9, false, true, 3)?;
    test_single_helper(10, false, true, 3)?;
    test_single_helper(11, false, true, 3)?;
    test_single_helper(12, false, true, 3)?;
    test_single_helper(13, false, true, 3)?;
    test_single_helper(14, false, true, 3)?;
    test_single_helper(15, false, true, 3)?;
    Ok(())
}

#[test]
fn test_sparse_k3() -> Result<(), PCSError> {
    test_single_helper(3, true, false, 3)?;
    test_single_helper(4, true, false, 3)?;
    test_single_helper(5, true, false, 3)?;
    test_single_helper(6, true, false, 3)?;
    test_single_helper(7, true, false, 3)?;
    test_single_helper(8, true, false, 3)?;
    test_single_helper(9, true, false, 3)?;
    test_single_helper(10, true, false, 3)?;
    test_single_helper(11, true, false, 3)?;
    test_single_helper(12, true, false, 3)?;
    test_single_helper(13, true, false, 3)?;
    test_single_helper(14, true, false, 3)?;
    test_single_helper(15, true, false, 3)?;
    Ok(())
}

#[test]
fn test_sparse_boolean_k3() -> Result<(), PCSError> {
    test_single_helper(3, true, true, 3)?;
    test_single_helper(4, true, true, 3)?;
    test_single_helper(5, true, true, 3)?;
    test_single_helper(6, true, true, 3)?;
    test_single_helper(7, true, true, 3)?;
    test_single_helper(8, true, true, 3)?;
    test_single_helper(9, true, true, 3)?;
    test_single_helper(10, true, true, 3)?;
    test_single_helper(11, true, true, 3)?;
    test_single_helper(12, true, true, 3)?;
    test_single_helper(13, true, true, 3)?;
    test_single_helper(14, true, true, 3)?;
    test_single_helper(15, true, true, 3)?;
    Ok(())
}

#[test]
fn test_dense_k4() -> Result<(), PCSError> {
    test_single_helper(4, false, false, 4)?;
    test_single_helper(5, false, false, 4)?;
    test_single_helper(6, false, false, 4)?;
    test_single_helper(7, false, false, 4)?;
    test_single_helper(8, false, false, 4)?;
    test_single_helper(9, false, false, 4)?;
    test_single_helper(10, false, false, 4)?;
    test_single_helper(11, false, false, 4)?;
    test_single_helper(12, false, false, 4)?;
    test_single_helper(13, false, false, 4)?;
    test_single_helper(14, false, false, 4)?;
    test_single_helper(15, false, false, 4)?;
    Ok(())
}

#[test]
fn test_dense_boolean_k4() -> Result<(), PCSError> {
    test_single_helper(4, false, true, 4)?;
    test_single_helper(5, false, true, 4)?;
    test_single_helper(6, false, true, 4)?;
    test_single_helper(7, false, true, 4)?;
    test_single_helper(8, false, true, 4)?;
    test_single_helper(9, false, true, 4)?;
    test_single_helper(10, false, true, 4)?;
    test_single_helper(11, false, true, 4)?;
    test_single_helper(12, false, true, 4)?;
    test_single_helper(13, false, true, 4)?;
    test_single_helper(14, false, true, 4)?;
    test_single_helper(15, false, true, 4)?;
    Ok(())
}
#[test]
fn test_sparse_k4() -> Result<(), PCSError> {
    test_single_helper(4, true, false, 4)?;
    test_single_helper(5, true, false, 4)?;
    test_single_helper(6, true, false, 4)?;
    test_single_helper(7, true, false, 4)?;
    test_single_helper(8, true, false, 4)?;
    test_single_helper(9, true, false, 4)?;
    test_single_helper(10, true, false, 4)?;
    test_single_helper(11, true, false, 4)?;
    test_single_helper(12, true, false, 4)?;
    test_single_helper(13, true, false, 4)?;
    test_single_helper(14, true, false, 4)?;
    test_single_helper(15, true, false, 4)?;
    Ok(())
}

#[test]
fn test_sparse_boolean_k4() -> Result<(), PCSError> {
    test_single_helper(4, true, true, 4)?;
    test_single_helper(5, true, true, 4)?;
    test_single_helper(6, true, true, 4)?;
    test_single_helper(7, true, true, 4)?;
    test_single_helper(8, true, true, 4)?;
    test_single_helper(9, true, true, 4)?;
    test_single_helper(10, true, true, 4)?;
    test_single_helper(11, true, true, 4)?;
    test_single_helper(12, true, true, 4)?;
    test_single_helper(13, true, true, 4)?;
    test_single_helper(14, true, true, 4)?;
    test_single_helper(15, true, true, 4)?;
    Ok(())
}

#[test]
fn test_dense_k5() -> Result<(), PCSError> {
    test_single_helper(5, false, false, 4)?;
    test_single_helper(6, false, false, 4)?;
    test_single_helper(7, false, false, 4)?;
    test_single_helper(8, false, false, 4)?;
    test_single_helper(9, false, false, 5)?;
    test_single_helper(10, false, false, 5)?;
    test_single_helper(11, false, false, 5)?;
    test_single_helper(12, false, false, 5)?;
    test_single_helper(13, false, false, 5)?;
    test_single_helper(14, false, false, 5)?;
    test_single_helper(15, false, false, 5)?;
    Ok(())
}

#[test]
fn test_dense_boolean_k5() -> Result<(), PCSError> {
    test_single_helper(5, false, true, 4)?;
    test_single_helper(6, false, true, 4)?;
    test_single_helper(7, false, true, 4)?;
    test_single_helper(8, false, true, 4)?;
    test_single_helper(9, false, true, 5)?;
    test_single_helper(10, false, true, 5)?;
    test_single_helper(11, false, true, 5)?;
    test_single_helper(12, false, true, 5)?;
    test_single_helper(13, false, true, 5)?;
    test_single_helper(14, false, true, 5)?;
    test_single_helper(15, false, true, 5)?;
    Ok(())
}
#[test]
fn test_sparse_k5() -> Result<(), PCSError> {
    test_single_helper(5, true, false, 4)?;
    test_single_helper(6, true, false, 4)?;
    test_single_helper(7, true, false, 4)?;
    test_single_helper(8, true, false, 4)?;
    test_single_helper(9, true, false, 5)?;
    test_single_helper(10, true, false, 5)?;
    test_single_helper(11, true, false, 5)?;
    test_single_helper(12, true, false, 5)?;
    test_single_helper(13, true, false, 5)?;
    test_single_helper(14, true, false, 5)?;
    test_single_helper(15, true, false, 5)?;
    Ok(())
}

#[test]
fn test_sparse_boolean_k5() -> Result<(), PCSError> {
    test_single_helper(5, true, true, 4)?;
    test_single_helper(6, true, true, 4)?;
    test_single_helper(7, true, true, 4)?;
    test_single_helper(8, true, true, 4)?;
    test_single_helper(9, true, true, 5)?;
    test_single_helper(10, true, true, 5)?;
    test_single_helper(11, true, true, 5)?;
    test_single_helper(12, true, true, 5)?;
    test_single_helper(13, true, true, 5)?;
    test_single_helper(14, true, true, 5)?;
    test_single_helper(15, true, true, 5)?;
    Ok(())
}
