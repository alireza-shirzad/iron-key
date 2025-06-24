use ark_bn254::{Bn254 as E, Fr};
use ark_ff::UniformRand;
use ark_poly::{DenseMultilinearExtension, MultilinearExtension, SparseMultilinearExtension};
use ark_std::{rand::Rng, test_rng};
use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex},
};

use divan::Bencher;
use once_cell::sync::Lazy;
use subroutines::{
    pcs::{
        PolynomialCommitmentScheme,
        kzh2::{
            KZH2,
            srs::{KZH2ProverParam, KZH2VerifierParam},
            structs::KZH2Commitment,
        },
    },
    poly::DenseOrSparseMLE,
};
// ---

type ProverKey = KZH2ProverParam<E>;
type VerifierKey = KZH2VerifierParam<E>;

// Static cache for prover and verifier keys, keyed by the number of variables
// `nv`. This avoids re-generating the SRS for each benchmark combination.
static KEY_CACHE: Lazy<Mutex<HashMap<usize, Arc<(ProverKey, VerifierKey)>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Helper function to get or create the prover and verifier keys for a given
/// `nv`.
fn get_or_create_keys(nv: usize) -> Arc<(ProverKey, VerifierKey)> {
    let mut cache = KEY_CACHE.lock().unwrap();
    cache
        .entry(nv)
        .or_insert_with(|| {
            println!("\nCache miss: Creating new keys for nv = {}", nv);
            let mut rng = test_rng();
            let params = KZH2::<E>::gen_srs_for_testing(&mut rng, nv)
                .expect("Failed to generate SRS for testing");
            let (ck, vk) =
                KZH2::<E>::trim(params, None, Some(nv)).expect("Failed to trim parameters");
            Arc::new((ck, vk))
        })
        .clone()
}

/// Parameters for a single benchmark instance, carried around by Divan.
#[derive(Copy, Clone, Debug)]
struct BenchParams {
    /// Number of variables in the polynomial.
    pub nv: usize,
    /// Whether to use a sparse or dense polynomial representation.
    pub is_sparse: bool,
    /// Whether to open at a boolean point or a random point.
    pub is_boolean_point: bool,
}

impl fmt::Display for BenchParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[nv={}, poly={}, point={}]",
            self.nv,
            if self.is_sparse { "Sparse" } else { "Dense" },
            if self.is_boolean_point {
                "Boolean"
            } else {
                "Random"
            }
        )
    }
}

/// Prepares all inputs required for the `KZH2::open` function.
/// This includes generating the polynomial, the point, and the auxiliary info.
fn prepare_open_inputs(
    nv: usize,
    is_sparse: bool,
    is_boolean_point: bool,
) -> (
    Arc<ProverKey>,
    DenseOrSparseMLE<Fr>,
    Vec<Fr>,
    KZH2Commitment<E>,
) {
    let mut rng = test_rng();
    let (ck, _) = &*get_or_create_keys(nv);

    // Generate a random polynomial of the specified type.
    let poly = if is_sparse {
        DenseOrSparseMLE::Sparse(SparseMultilinearExtension::rand(nv, &mut rng))
    } else {
        DenseOrSparseMLE::Dense(DenseMultilinearExtension::rand(nv, &mut rng))
    };

    // Generate the point for the opening.
    let point: Vec<Fr> = if is_boolean_point {
        (0..nv)
            .map(|_| {
                if rng.r#gen() {
                    // Using .gen() from the Rng trait
                    Fr::from(1)
                } else {
                    Fr::from(0)
                }
            })
            .collect()
    } else {
        (0..nv).map(|_| Fr::rand(&mut rng)).collect()
    };

    // Commit to the polynomial to generate the auxiliary info required for opening.
    let com = KZH2::commit(ck, &poly).unwrap();

    (ck.clone().into(), poly, point, com)
}

// Compile-time list of parameters to benchmark.
// We test nv from 10 to 30, for the four specified cases.
// Note: nv = 31 and 32 cause memory issues due to large SRS sizes.
pub const PARAMS: &[BenchParams] = &{
    const fn build_params() -> [BenchParams; (32 - 10 + 1) * 4] {
        let mut out = [BenchParams {
            nv: 0,
            is_sparse: false,
            is_boolean_point: false,
        }; (32 - 10 + 1) * 4];
        let mut i: usize = 0;
        let mut nv: usize = 31;
        while nv <= 32 {
            // Case 1: Dense, Random Point
            // out[i] = BenchParams {
            //     nv,
            //     is_sparse: false,
            //     is_boolean_point: false,
            // };
            // i += 1;
            // Case 2: Dense, Boolean Point
            out[i] = BenchParams {
                nv,
                is_sparse: false,
                is_boolean_point: true,
            };
            i += 1;
            // Case 3: Sparse, Random Point
            out[i] = BenchParams {
                nv,
                is_sparse: true,
                is_boolean_point: false,
            };
            i += 1;
            // Case 4: Sparse, Boolean Point
            out[i] = BenchParams {
                nv,
                is_sparse: true,
                is_boolean_point: true,
            };
            i += 1;
            nv += 1;
        }
        out
    }
    build_params()
};

#[divan::bench(
    max_time = 10,
    sample_count = 10,
    sample_size = 10,
    args = PARAMS
)]
fn bench_open(bencher: Bencher, params: BenchParams) {
    let (ck, poly, point, com) =
        prepare_open_inputs(params.nv, params.is_sparse, params.is_boolean_point);

    // Pre-compute aux info outside the benchmark loop.
    // We pass a reference to the ProverKey inside the Arc.
    let aux = KZH2::comp_aux(&*ck, &poly, &com).unwrap();

    bencher.bench_local(|| {
        // This benchmarks the `KZH2::open` function.
        // We also pass a reference here to avoid moving the Arc.
        KZH2::open(&*ck, &poly, &point, &aux)
    });
}
