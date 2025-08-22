use std::sync::Arc;

use crate::{
    cfg_for_each_with_scratch, pcs::kzhk::structs::Tensor, PCSError, StructuredReferenceString,
};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, cfg_iter_mut, rand::Rng, One, UniformRand};
use ndarray::{ArrayD, IxDyn};
use num_bigint::BigUint;
use num_traits::ToPrimitive;
#[cfg(feature = "parallel")]
use rayon::{
    iter::{
        IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator,
        IntoParallelRefMutIterator, ParallelIterator,
    },
    vec,
};
/// Universal Parameter
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct KZHKUniversalParams<E: Pairing> {
    // A vector of size k representing the dimensions of the tensor
    // In case of k=2, the dimensions would be [nu, mu]
    // Also, the product of the dimensions would be N: the total number of elements in the tensor
    // (the size of polynomial)
    dimensions: Vec<usize>,
    // h_tensors = [H1,H2,...,Hk]
    h_tensors: Arc<Vec<Tensor<E::G1Affine>>>,
    // Vij: i\in[d], j\in[k]
    v_mat: Arc<Vec<Vec<E::G2Prepared>>>,
    // -V : The inverse of the G2 generator
    v: E::G2Affine,
    // G : The G1 generator
    g: E::G1Affine,
    // h: Another G1 generator
    h: E::G1Affine,
    // hiding_sparsity
    hiding_sparsity: usize,
}

impl<E: Pairing> KZHKUniversalParams<E> {
    /// Create a new universal parameter
    pub fn new(
        dimensions: Vec<usize>,
        h_tensors: Arc<Vec<Tensor<E::G1Affine>>>,
        v_mat: Arc<Vec<Vec<E::G2Prepared>>>,
        v: E::G2Affine,
        g: E::G1Affine,
        h: E::G1Affine,
        hiding_sparsity: usize,
    ) -> Self {
        Self {
            dimensions,
            h_tensors,
            v_mat,
            v,
            g,
            h,
            hiding_sparsity,
        }
    }

    pub fn get_dimensions(&self) -> &Vec<usize> {
        &self.dimensions
    }

    pub fn get_h_tensors(&self) -> &Vec<Tensor<E::G1Affine>> {
        &self.h_tensors
    }

    pub fn get_v_mat(&self) -> &Vec<Vec<E::G2Prepared>> {
        &self.v_mat
    }

    pub fn get_v(&self) -> E::G2Affine {
        self.v
    }

    pub fn get_g(&self) -> E::G1Affine {
        self.g
    }
    pub fn get_h(&self) -> E::G1Affine {
        self.h
    }
    pub fn get_hiding_sparsity(&self) -> usize {
        self.hiding_sparsity
    }
}

/// Prover Parameters
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct KZHKProverParam<E: Pairing> {
    dimensions: Vec<usize>,
    h_tensors: Arc<Vec<Tensor<E::G1Affine>>>,
    v_mat: Arc<Vec<Vec<E::G2Prepared>>>,
    h: E::G1Affine,
    hiding_sparsity: usize,
}
impl<E: Pairing> KZHKProverParam<E> {
    /// Create a new prover parameter
    pub fn new(
        dimensions: Vec<usize>,
        h_tensors: Arc<Vec<Tensor<E::G1Affine>>>,
        v_mat: Arc<Vec<Vec<E::G2Prepared>>>,
        h: E::G1Affine,
        hiding_sparsity: usize,
    ) -> Self {
        Self {
            dimensions,
            h_tensors,
            v_mat,
            h,
            hiding_sparsity,
        }
    }

    pub fn get_dimensions(&self) -> &Vec<usize> {
        &self.dimensions
    }

    pub fn get_h_tensors(&self) -> &Vec<Tensor<E::G1Affine>> {
        &self.h_tensors
    }

    pub fn get_v_mat(&self) -> &Vec<Vec<E::G2Prepared>> {
        &self.v_mat
    }

    pub fn get_h(&self) -> E::G1Affine {
        self.h
    }

    pub fn get_hiding_sparsity(&self) -> usize {
        self.hiding_sparsity
    }
}

/// Verifier Parameters
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct KZHKVerifierParam<E: Pairing> {
    dimensions: Vec<usize>,
    h_tensor: Arc<Tensor<E::G1Affine>>,
    minus_v: E::G2Affine,
    v_mat: Arc<Vec<Vec<E::G2Prepared>>>,
    h: E::G1Affine,
    hiding_sparsity: usize,
}

impl<E: Pairing> KZHKVerifierParam<E> {
    /// Create a new verifier parameter
    pub fn new(
        dimensions: Vec<usize>,
        h_tensor: Arc<Tensor<E::G1Affine>>,
        v: E::G2Affine,
        v_mat: Arc<Vec<Vec<E::G2Prepared>>>,
        h: E::G1Affine,
        hiding_sparsity: usize,
    ) -> Self {
        Self {
            dimensions,
            h_tensor,
            minus_v: -v,
            v_mat,
            h,
            hiding_sparsity,
        }
    }

    pub fn get_dimensions(&self) -> &Vec<usize> {
        &self.dimensions
    }

    pub fn get_h_tensor(&self) -> &Tensor<E::G1Affine> {
        &self.h_tensor
    }

    pub fn get_minus_v(&self) -> E::G2Affine {
        self.minus_v
    }

    pub fn get_v_mat(&self) -> &Vec<Vec<E::G2Prepared>> {
        &self.v_mat
    }

    pub fn get_h(&self) -> E::G1Affine {
        self.h
    }

    pub fn get_hiding_sparsity(&self) -> usize {
        self.hiding_sparsity
    }
}

impl<E: Pairing> StructuredReferenceString<E> for KZHKUniversalParams<E> {
    type ProverParam = KZHKProverParam<E>;
    type VerifierParam = KZHKVerifierParam<E>;

    /// Extract the prover parameters from the public parameters.
    fn extract_prover_param(&self, _supported_num_vars: usize) -> Self::ProverParam {
        KZHKProverParam::new(
            self.dimensions.clone(),
            self.h_tensors.clone(),
            self.v_mat.clone(),
            self.h.clone(),
            self.hiding_sparsity,
        )
    }

    /// Extract the verifier parameters from the public parameters.
    fn extract_verifier_param(&self, _supported_num_vars: usize) -> Self::VerifierParam {
        KZHKVerifierParam::new(
            self.dimensions.clone(),
            self.h_tensors[self.dimensions.len() - 1].clone().into(),
            self.v,
            self.v_mat.clone(),
            self.h.clone(),
            self.hiding_sparsity,
        )
    }

    fn trim(
        &self,
        supported_num_vars: usize,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), PCSError> {
        Ok((
            self.extract_prover_param(supported_num_vars),
            self.extract_verifier_param(supported_num_vars),
        ))
    }

    fn gen_srs_for_testing<R: Rng>(
        rng: &mut R,
        k: usize,
        num_vars: usize,
    ) -> Result<KZHKUniversalParams<E>, PCSError> {
        // ----- Dimensions -----
        let d = num_vars / k;
        let remainder_d = num_vars % k;
        let mut dimensions = vec![d; k];
        for dim in dimensions.iter_mut().take(remainder_d) {
            *dim += 1;
        }

        // ----- Sample small public generators (sequential; RNG is not Sync) -----
        let g = E::G1::rand(rng);
        let h = E::G1::rand(rng);
        let v = E::G2::rand(rng);

        // ----- Sample trapdoors mu_mat (sequential to respect rng borrowing) -----
        // mu_mat[j] has length 2^{d_j}
        let mu_mat: Vec<Vec<E::ScalarField>> = (0..k)
            .map(|j| {
                (0..(1usize << dimensions[j]))
                    .map(|_| E::ScalarField::rand(rng))
                    .collect()
            })
            .collect();

        // Share read-only data with workers
        let mu_mat = Arc::new(mu_mat);
        let dimensions_arc = Arc::new(dimensions.clone());

        // ---------- Build all H_t tensors in parallel ----------
        // H_{t} has shape: (2^{d_t}, 2^{d_{t+1}}, ..., 2^{d_{k-1}})
        // element at coords (r_t, r_{t+1}, ..., r_{k-1}) = g^{ ∏_{j=t}^{k-1}
        // mu_mat[j][r_j] }
        let h_tensors: Vec<Tensor<E::G1Affine>> = cfg_into_iter!(0..k)
            .map(|t| {
                let dims = &dimensions_arc[t..];
                let shape: Vec<usize> = dims.iter().map(|&dj| 1usize << dj).collect();

                // Total elements in this tensor
                let len: usize = shape.iter().product();

                // Pre-allocate a flat buffer and fill it in parallel
                let mut flat: Vec<E::G1Affine> = vec![E::G1Affine::zero(); len];

                // Small scratch vec for index decoding per-thread
                cfg_for_each_with_scratch!(
                    cfg_iter_mut!(flat).enumerate(),
                    || Vec::with_capacity(shape.len()),
                    |coords_scratch, (idx, slot)| {
                        #[cfg(feature = "parallel")]
                        decode_coords(idx, &shape, coords_scratch);
                        #[cfg(not(feature = "parallel"))]
                        decode_coords(idx, &shape, &mut coords_scratch);
                        // Multiply scalars across axes: s = ∏ mu_mat[j][r_j]
                        let mut s = E::ScalarField::one();
                        for (axis_off, &row) in coords_scratch.iter().enumerate() {
                            let j = t + axis_off;
                            s *= mu_mat[j][row];
                        }

                        *slot = g.mul_bigint(s.into_bigint()).into_affine();
                    }
                );

                // Convert flat buffer into ndarray with C-order
                let arr = ArrayD::from_shape_vec(IxDyn(&shape), flat)
                    .expect("shape consistent with buffer length");
                Tensor(arr)
            })
            .collect();

        let h_tensors = Arc::new(h_tensors);

        // ---------- Build v_mat in parallel ----------
        // v_mat[j][i] = G2Prepared( v^{ mu_mat[j][i] } )
        let v_mat: Vec<Vec<<E as Pairing>::G2Prepared>> = cfg_into_iter!(0..k)
            .map(|j| {
                let rows = 1usize << dimensions_arc[j];
                cfg_into_iter!(0..rows)
                    .map(|i| {
                        let s = mu_mat[j][i];
                        let vp = v.mul_bigint(s.into_bigint());
                        <E as Pairing>::G2Prepared::from(vp)
                    })
                    .collect()
            })
            .collect();

        let v_mat = Arc::new(v_mat);

        let hiding_sparsity = ceil_k_root_scaled(1u128 << num_vars, k as u32) as usize;

        Ok(KZHKUniversalParams::new(
            (*dimensions_arc).clone(),
            h_tensors,
            v_mat,
            v.into_affine(),
            g.into_affine(),
            h.into_affine(),
            hiding_sparsity,
        ))
    }
}
// Helper: mixed-radix decode of a flat index into coordinates (C-order).
#[inline]
fn decode_coords(mut idx: usize, bases: &[usize], out_coords: &mut Vec<usize>) {
    // C-order (row-major): last axis varies fastest.
    out_coords.clear();
    out_coords.reserve_exact(bases.len());
    for &base in bases.iter().rev() {
        let c = idx % base;
        idx /= base;
        out_coords.push(c);
    }
    out_coords.reverse();
}
/// ceil( k * N^{1/k} ) exactly (no floating-point).
pub fn ceil_k_root_scaled(N: u128, k: u32) -> u128 {
    assert!(k > 0, "k must be >= 1");
    if N == 0 {
        return 0;
    }
    if k == 1 {
        return N;
    }

    // Floor k-th root of N (u128), by integer binary search.
    let r_floor = kth_root_floor_u128(N, k);

    // Search m in [k*r_floor, k*(r_floor+1)] s.t. m is the smallest with (m/k)^k >=
    // N. Equivalently: m^k >= N * k^k.
    let lo = (r_floor as u128).saturating_mul(k as u128);
    let hi = ((r_floor + 1) as u128).saturating_mul(k as u128);

    let target = BigUint::from(N) * pow_big(&BigUint::from(k as u128), k);
    let mut l = BigUint::from(lo);
    let mut r = BigUint::from(hi);
    let one = BigUint::one();

    while &l < &r {
        let mid = (&l + &r) >> 1; // integer mid
        let lhs = pow_big(&mid, k); // mid^k
        if lhs >= target {
            r = mid; // feasible
        } else {
            l = &mid + &one; // infeasible
        }
    }
    l.to_u128().expect("result does not fit in u128")
}

/// floor( N^{1/k} ) for u128 by binary search.
fn kth_root_floor_u128(N: u128, k: u32) -> u128 {
    if N <= 1 {
        return N;
    }
    let mut lo: u128 = 1;
    let mut hi: u128 = N; // 128 iterations worst-case

    let mut ans = 1;
    while lo <= hi {
        let mid = lo + ((hi - lo) >> 1);
        if pow_le_u128(mid, k, N) {
            ans = mid;
            lo = mid + 1;
        } else {
            hi = mid - 1;
        }
    }
    ans
}

/// Returns true iff x^k <= n, computed without overflow (early exit).
fn pow_le_u128(mut x: u128, k: u32, n: u128) -> bool {
    if k == 0 {
        return 1 <= n;
    }
    let mut acc: u128 = 1;
    for _ in 0..k {
        // Early stop if acc*x would exceed n
        if x != 0 && acc > n / x {
            return false;
        }
        acc *= x;
    }
    acc <= n
}

/// BigUint pow by repeated squaring.
fn pow_big(x: &BigUint, mut k: u32) -> BigUint {
    let mut base = x.clone();
    let mut acc = BigUint::one();
    while k > 0 {
        if (k & 1) == 1 {
            acc *= &base;
        }
        if k > 1 {
            // Avoid simultaneous mutable and immutable borrow of base
            base = &base * &base;
        }
        k >>= 1;
    }
    acc
}
