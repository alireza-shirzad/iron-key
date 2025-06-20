use ark_ff::{Field, PrimeField};
use ark_poly::{univariate::DenseOrSparsePolynomial, SparseMultilinearExtension};
use ark_std::{end_timer, rand::RngCore, start_timer};
#[cfg(feature = "parallel")]
use rayon::prelude::{IndexedParallelIterator, IntoParallelRefMutIterator, ParallelIterator};
use std::{collections::BTreeMap, sync::Arc};

pub use ark_poly::DenseMultilinearExtension;

/// Sample a random list of multilinear polynomials.
/// Returns
/// - the list of polynomials,
/// - its sum of polynomial evaluations over the boolean hypercube.
pub fn random_mle_list<F: PrimeField, R: RngCore>(
    nv: usize,
    degree: usize,
    rng: &mut R,
) -> (Vec<Arc<DenseMultilinearExtension<F>>>, F) {
    let start = start_timer!(|| "sample random mle list");
    let mut multiplicands = Vec::with_capacity(degree);
    for _ in 0..degree {
        multiplicands.push(Vec::with_capacity(1 << nv))
    }
    let mut sum = F::zero();

    for _ in 0..(1 << nv) {
        let mut product = F::one();

        for e in multiplicands.iter_mut() {
            let val = F::rand(rng);
            e.push(val);
            product *= val;
        }
        sum += product;
    }

    let list = multiplicands
        .into_iter()
        .map(|x| Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, x)))
        .collect();

    end_timer!(start);
    (list, sum)
}

// Build a randomize list of mle-s whose sum is zero.
pub fn random_zero_mle_list<F: PrimeField, R: RngCore>(
    nv: usize,
    degree: usize,
    rng: &mut R,
) -> Vec<Arc<DenseMultilinearExtension<F>>> {
    let start = start_timer!(|| "sample random zero mle list");

    let mut multiplicands = Vec::with_capacity(degree);
    for _ in 0..degree {
        multiplicands.push(Vec::with_capacity(1 << nv))
    }
    for _ in 0..(1 << nv) {
        multiplicands[0].push(F::zero());
        for e in multiplicands.iter_mut().skip(1) {
            e.push(F::rand(rng));
        }
    }

    let list = multiplicands
        .into_iter()
        .map(|x| Arc::new(DenseMultilinearExtension::from_evaluations_vec(nv, x)))
        .collect();

    end_timer!(start);
    list
}

pub fn identity_permutation<F: PrimeField>(num_vars: usize, num_chunks: usize) -> Vec<F> {
    let len = (num_chunks as u64) * (1u64 << num_vars);
    (0..len).map(F::from).collect()
}

/// A list of MLEs that represents an identity permutation
pub fn identity_permutation_mles<F: PrimeField>(
    num_vars: usize,
    num_chunks: usize,
) -> Vec<Arc<DenseMultilinearExtension<F>>> {
    let mut res = vec![];
    for i in 0..num_chunks {
        let shift = (i * (1 << num_vars)) as u64;
        let s_id_vec = (shift..shift + (1u64 << num_vars)).map(F::from).collect();
        res.push(Arc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars, s_id_vec,
        )));
    }
    res
}

pub fn random_permutation<F: PrimeField, R: RngCore>(
    num_vars: usize,
    num_chunks: usize,
    rng: &mut R,
) -> Vec<F> {
    let len = (num_chunks as u64) * (1u64 << num_vars);
    let mut s_id_vec: Vec<F> = (0..len).map(F::from).collect();
    let mut s_perm_vec = vec![];
    for _ in 0..len {
        let index = rng.next_u64() as usize % s_id_vec.len();
        s_perm_vec.push(s_id_vec.remove(index));
    }
    s_perm_vec
}

/// A list of MLEs that represent a random permutation
pub fn random_permutation_mles<F: PrimeField, R: RngCore>(
    num_vars: usize,
    num_chunks: usize,
    rng: &mut R,
) -> Vec<Arc<DenseMultilinearExtension<F>>> {
    let s_perm_vec = random_permutation(num_vars, num_chunks, rng);
    let mut res = vec![];
    let n = 1 << num_vars;
    for i in 0..num_chunks {
        res.push(Arc::new(DenseMultilinearExtension::from_evaluations_vec(
            num_vars,
            s_perm_vec[i * n..i * n + n].to_vec(),
        )));
    }
    res
}

pub fn evaluate_opt<F: Field>(poly: &DenseMultilinearExtension<F>, point: &[F]) -> F {
    assert_eq!(poly.num_vars, point.len());
    fix_first_variables(poly, point).evaluations[0]
}

pub fn fix_first_variables<F: Field>(
    poly: &DenseMultilinearExtension<F>,
    partial_point: &[F],
) -> DenseMultilinearExtension<F> {
    assert!(
        partial_point.len() <= poly.num_vars,
        "invalid size of partial point"
    );
    let nv = poly.num_vars;
    let mut poly = poly.evaluations.to_vec();
    let dim = partial_point.len();
    // evaluate single variable of partial point from left to right
    for (i, point) in partial_point.iter().enumerate().take(dim) {
        poly = fix_one_variable_helper(&poly, nv - i, point);
    }

    DenseMultilinearExtension::<F>::from_evaluations_slice(nv - dim, &poly[..(1 << (nv - dim))])
}

fn fix_one_variable_helper<F: Field>(data: &[F], nv: usize, point: &F) -> Vec<F> {
    let mut res = vec![F::zero(); 1 << (nv - 1)];

    // evaluate single variable of partial point from left to right
    #[cfg(not(feature = "parallel"))]
    for i in 0..(1 << (nv - 1)) {
        res[i] = data[i] + (data[(i << 1) + 1] - data[i << 1]) * point;
    }

    #[cfg(feature = "parallel")]
    res.par_iter_mut().enumerate().for_each(|(i, x)| {
        *x = data[i << 1] + (data[(i << 1) + 1] - data[i << 1]) * point;
    });

    res
}

pub fn evaluate_no_par<F: Field>(poly: &DenseMultilinearExtension<F>, point: &[F]) -> F {
    assert_eq!(poly.num_vars, point.len());
    fix_first_variables_no_par(poly, point).evaluations[0]
}

fn fix_first_variables_no_par<F: Field>(
    poly: &DenseMultilinearExtension<F>,
    partial_point: &[F],
) -> DenseMultilinearExtension<F> {
    assert!(
        partial_point.len() <= poly.num_vars,
        "invalid size of partial point"
    );
    let nv = poly.num_vars;
    let mut poly = poly.evaluations.to_vec();
    let dim = partial_point.len();
    // evaluate single variable of partial point from left to right
    for i in 1..dim + 1 {
        let r = partial_point[i - 1];
        for b in 0..(1 << (nv - i)) {
            poly[b] = poly[b << 1] + (poly[(b << 1) + 1] - poly[b << 1]) * r;
        }
    }
    DenseMultilinearExtension::from_evaluations_slice(nv - dim, &poly[..(1 << (nv - dim))])
}

pub fn fix_last_variables<F: PrimeField>(
    poly: &DenseMultilinearExtension<F>,
    partial_point: &[F],
) -> DenseMultilinearExtension<F> {
    assert!(
        partial_point.len() <= poly.num_vars,
        "invalid size of partial point"
    );

    let is_boolean_point = partial_point.iter().all(|&x| x.is_zero() || x.is_one());
    let nu = partial_point.len();
    let mu = poly.num_vars - nu;

    if is_boolean_point {
        // --- OPTIMIZED PATH for boolean points ---
        // This corresponds to selecting a slice from the evaluations vector.

        // Convert the boolean point to its integer representation.
        // We assume the point's variables are ordered from LSB to MSB
        // corresponding to the last `nu` variables.
        let mut target_x_index = 0;
        for (i, &bit) in partial_point.iter().enumerate() {
            if bit.is_one() {
                target_x_index |= 1 << i;
            }
        }
        
        // The new polynomial's evaluations are a slice of the original.
        // The size of the slice is the number of evaluations for a mu-variate polynomial.
        let slice_size = 1 << mu;
        
        // The starting point of the slice is determined by the integer value
        // of the boolean point.
        let start = target_x_index * slice_size;
        let end = start + slice_size;
        
        let new_evals = &poly.evaluations[start..end];

        DenseMultilinearExtension::<F>::from_evaluations_slice(mu, new_evals)

    } else {
        // --- GENERAL PATH for non-boolean (random) points ---
        // This is the original, more expensive implementation.

        let mut current_evals = poly.evaluations.to_vec();
        
        // Evaluate single variable of partial point from right to left (MSB to LSB).
        for (i, point) in partial_point.iter().rev().enumerate() {
            current_evals = fix_last_variable_helper(&current_evals, poly.num_vars - i, point);
        }

        DenseMultilinearExtension::<F>::from_evaluations_slice(mu, &current_evals[..1 << mu])
    }
}


fn fix_last_variable_helper<F: Field>(data: &[F], nv: usize, point: &F) -> Vec<F> {
    let half_len = 1 << (nv - 1);
    let mut res = vec![F::zero(); half_len];

    // evaluate single variable of partial point from left to right
    #[cfg(not(feature = "parallel"))]
    for b in 0..half_len {
        res[b] = data[b] + (data[b + half_len] - data[b]) * point;
    }

    #[cfg(feature = "parallel")]
    res.par_iter_mut().enumerate().for_each(|(i, x)| {
        *x = data[i] + (data[i + half_len] - data[i]) * point;
    });

    res
}

pub fn fix_last_variables_sparse<F: Field>(
    poly: &SparseMultilinearExtension<F>,
    // This is x0, the point for the last `nu` variables
    partial_point_x: &[F],
) -> SparseMultilinearExtension<F> {
    let is_boolean_point = partial_point_x.iter().all(|&x| x.is_zero() || x.is_one());
    let nu = partial_point_x.len();
    assert!(nu <= poly.num_vars, "Invalid size of partial point");
    let mu = poly.num_vars - nu;

    let mut new_evals: BTreeMap<usize, F> = BTreeMap::new();

    if is_boolean_point {
        // OPTIMIZED PATH for boolean points (zeros and ones).
        // This is a simple selection/filtering operation, no field arithmetic needed.

        // First, convert the boolean point into its integer representation.
        let mut target_x_index = 0;
        // The point's coordinates are for variables from LSB to MSB.
        for (i, &bit) in partial_point_x.iter().enumerate() {
            if bit.is_one() {
                target_x_index |= 1 << i;
            }
        }
        
        // Iterate over the polynomial's evaluations and select the ones
        // that fall into the hypercube slice defined by `target_x_index`.
        for (&full_index, &value) in &poly.evaluations {
            let y_index = full_index & ((1 << mu) - 1);
            let x_index = full_index >> mu;

            if x_index == target_x_index {
                new_evals.insert(y_index, value);
            }
        }
    } else {
        // GENERAL PATH for non-boolean points.
        // This requires evaluating the Lagrange basis polynomials.
        for (&full_index, &value) in &poly.evaluations {
            let y_index = full_index & ((1 << mu) - 1);
            let x_index = full_index >> mu;

            let mut lagrange_eval = F::one();
            for i in 0..nu {
                let point_val_at_i = partial_point_x[i];
                // The i-th point coordinate corresponds to the i-th LSB of x_index.
                let bit_of_x_idx = (x_index >> i) & 1;

                if bit_of_x_idx == 1 {
                    lagrange_eval *= point_val_at_i;
                } else {
                    lagrange_eval *= F::one() - point_val_at_i;
                }
            }
            
            let contribution = value * lagrange_eval;
            *new_evals.entry(y_index).or_insert_with(F::zero) += contribution;
        }
    }
    
    // Collect the BTreeMap into a Vec of tuples to pass to the constructor.
    let final_evaluations: Vec<(usize, F)> = new_evals.into_iter().collect();
    
    // Use the public constructor instead of direct instantiation.
    SparseMultilinearExtension::from_evaluations(mu, &final_evaluations)
}
pub fn evaluate_last_dense<F: PrimeField>(f: &DenseMultilinearExtension<F>, point: &[F]) -> F {
    assert_eq!(f.num_vars, point.len());
    fix_last_variables(f, point).evaluations[0]
}

pub fn evaluate_last_sparse<F: PrimeField>(f: &SparseMultilinearExtension<F>, point: &[F]) -> F {
    assert_eq!(f.num_vars, point.len());
    *fix_last_variables_sparse(f, point)
        .evaluations
        .values()
        .next()
        .unwrap()
}
#[test]
fn test_fix_last_variables_sparse() {
    use ark_bn254::{Bn254 as E, Fr};
    let poly = SparseMultilinearExtension::from_evaluations(
        3,
        &[
            (0, Fr::from(0)),
            (1, Fr::from(1)),
            (2, Fr::from(2)),
            (3, Fr::from(3)),
            (4, Fr::from(4)),
            (5, Fr::from(5)),
            (6, Fr::from(6)),
            (7, Fr::from(7)),
        ],
    );
    let res = fix_last_variables_sparse(&poly, &[Fr::from(0)]);
    dbg!(res.evaluations);
}
