pub mod errors;
pub mod multilinear_polynomial;
pub mod univariate_polynomial;
pub mod util;
pub mod virtual_polynomial;


#[inline]
pub fn bits_le_to_usize<F: ark_ff::Field>(bits: &[F]) -> usize {
    debug_assert!(
        bits.len() <= usize::BITS as usize,
        "too many bits for usize"
    );
    debug_assert!(
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
pub fn usize_to_bits_le<F: ark_ff::Field>(x: usize, n_bits: usize) -> Vec<F> {
    debug_assert!(n_bits <= usize::BITS as usize, "n_bits too large for usize");
    let mut out = Vec::with_capacity(n_bits);
    let mut v = x;
    for _ in 0..n_bits {
        out.push(if (v & 1) == 1 { F::one() } else { F::zero() });
        v >>= 1;
    }
    debug_assert!(v == 0, "value {} does not fit in {} bits", x, n_bits);
    out
}


