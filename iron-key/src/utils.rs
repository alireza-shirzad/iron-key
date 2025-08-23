use ark_ff::{Field, PrimeField};
use sha2::{Digest, Sha256};

/// Hashes the input string and returns:
/// (1) the first `mu` bits as a usize, and
/// (2) the bit representation as Vec<bool> of length `mu`
pub fn hash_to_mu_bits<F: PrimeField>(input: &str, mu: usize) -> (usize, Vec<F>) {
    debug_assert!(mu <= usize::BITS as usize, "μ must be ≤ usize width");
    debug_assert!(mu <= 256, "SHA-256 only gives 256 bits");

    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let hash_bytes = hasher.finalize();

    let mut bits = Vec::with_capacity(mu);
    let mut val: usize = 0;

    for byte in hash_bytes.iter() {
        for i in (0..8).rev() {
            if bits.len() >= mu {
                return (val, bits);
            }
            let bit = (byte >> i) & 1 == 1;
            if bit {
                bits.push(F::one());
            } else {
                bits.push(F::zero());
            }
            val = (val << 1) | (bit as usize);
        }
    }

    (val, bits)
}

pub fn hash_to_mu_bits_with_offset<F: PrimeField>(
    input: &str,
    offset: usize,
    mu: usize,
) -> (usize, Vec<F>) {
    let concatenated_label = format!("{}{}", offset, input);
    hash_to_mu_bits::<F>(&concatenated_label, mu)
}
