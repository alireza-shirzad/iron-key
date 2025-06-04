use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex}, // Added Arc and Mutex
};

use ark_bn254::{Bn254, Fr};
use divan::Bencher;
use iron_key::{
    VKD,
    VKDServer,
    bb::dummybb::DummyBB,
    ironkey::IronKey,
    server::IronServer,
    structs::pp::IronPublicParameters, // Ensure this path is correct for your project
    structs::{IronLabel, IronSpecification},
};
use once_cell::sync::Lazy; // Added Lazy
use subroutines::pcs::kzh4::KZH4;

// Type alias for the Public Parameters
type AppPublicParameters = IronPublicParameters<Bn254, KZH4<Bn254>>;

// Static cache for public parameters, keyed by log_capacity (u64)
static PP_CACHE: Lazy<Mutex<HashMap<u64, Arc<AppPublicParameters>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Helper function to get or create PP for a given log_capacity
fn get_or_create_pp(log_capacity: u64) -> Arc<AppPublicParameters> {
    let mut cache = PP_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    cache
        .entry(log_capacity)
        .or_insert_with(|| {
            eprintln!(
                "Cache miss: Creating new IronPublicParameters for log_capacity = {}",
                log_capacity
            );
            let system_spec = IronSpecification::new(1 << log_capacity);
            let pp = IronKey::<Bn254, KZH4<Bn254>, IronLabel>::setup(system_spec)
                .expect("Failed to setup IronPublicParameters");
            Arc::new(pp)
        })
        .clone()
}

/// Triplet carried around by Divan.
#[derive(Copy, Clone, Debug)]
struct Params(
    pub u64, // log_capacity
    pub u64, // log_update_size
    pub u64, // initial_batch_size
);

impl fmt::Display for Params {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[log(capacity)={}, log(|update|)={}, log(init-update)={}]",
            self.0, self.1, self.2
        )
    }
}

/// Builds a server, a warm-up batch of `initial_batch_size`,
/// and the real update batch of size `2^log_update_size`.
/// This function now uses the PP cache.
fn prepare_prover_update_prove_inputs(
    log_capacity: u64,
    log_update_size: u64,
    log_initial_batch_size: u64,
) -> (
    IronServer<Bn254, KZH4<Bn254>, IronLabel>,
    HashMap<IronLabel, Fr>,
    DummyBB<Bn254, KZH4<Bn254>>,
) {
    let initial_batch_size_val = 1 << log_initial_batch_size; // Renamed to avoid conflict if log_initial_batch_size was 0

    // Get PP from cache or create it if it's not there for the given log_capacity
    let pp_arc = get_or_create_pp(log_capacity);

    // Initialize server with the (potentially cached) public parameters
    let mut server: IronServer<_, _, _> = IronServer::init(&*pp_arc); // Dereference Arc
    let mut bulletin_board = DummyBB::default();

    // Warm-up batch just to create the path in the tree.
    let initial_batch: HashMap<_, _> = (1..=initial_batch_size_val)
        .map(|i| (IronLabel::new(&i.to_string()), Fr::from(i as u64)))
        .collect();

    if initial_batch_size_val > 0 {
        // Only update if there's an initial batch
        server
            .update_reg(&initial_batch, &mut bulletin_board) // Assuming update_reg for warm-up
            .unwrap();
    }

    // Batch whose size we actually benchmark.
    let update_batch_size = 1 << log_update_size;
    let update_batch: HashMap<_, _> = (1..=update_batch_size)
        .map(|i| {
            (
                IronLabel::new(&(i + initial_batch_size_val).to_string()), // Ensure unique labels
                Fr::from(i + initial_batch_size_val),
            )
        })
        .collect();

    (server, update_batch, bulletin_board)
}

/// Compile-time list of (log_capacity, log_update_size, 3) triplets for light
/// tests.
pub const PARAMS: &[Params] = &{
    const INIT: u64 = 2; // log_initial_batch_size
    // The size 663 seems specific. Ensure it matches the loop logic.
    // Sum of (n-2+1) for n from 3 to 33: Sum of (n-1) for n from 3 to 33.
    // (3-1) + (4-1) + ... + (33-1) = 2 + 3 + ... + 32
    // This is sum(1..32) - sum(1..1) = (32*33/2) - 1 = 16*33 - 1 = 528 - 1 = 527
    // If k goes from 0 to n-2, there are n-2-0+1 = n-1 items for each n.
    // n=3: 2 items (k=0,1)
    // n=4: 3 items (k=0,1,2)
    // ...
    // n=33: 32 items (k=0..31)
    // Total = sum_{i=2}^{32} i = (sum_{i=1}^{32} i) - 1 = (32*33/2) - 1 = 528 - 1 =
    // 527 Please double-check the array size `663`. If it's correct, the loop
    // might be different or include other cases. For now, I'll keep 663 as per
    // your code, but this calculation suggests 527.
    const PARAMS_ARRAY_SIZE: usize = 527; // Based on calculation for n=3..33, k=0..n-2

    const fn build_light() -> [Params; PARAMS_ARRAY_SIZE] {
        // Adjusted size based on calculation
        let mut out = [Params(0, 0, 0); PARAMS_ARRAY_SIZE]; // Initialize with dummy
        let mut i = 0;

        let mut n = 3; // log_capacity
        while n <= 33 {
            let mut k = 0; // log_update_size
            // k <= n - 2 means k can go up to n-2.
            // Number of values for k is (n-2) - 0 + 1 = n-1.
            while k <= n - 2 {
                if i < PARAMS_ARRAY_SIZE {
                    // Boundary check
                    out[i] = Params(n, k, INIT);
                }
                i += 1;
                k += 1;
            }
            n += 1;
        }
        // If i != PARAMS_ARRAY_SIZE at the end, there's a mismatch in size calculation.
        // For safety, one might panic here in a debug build if i != PARAMS_ARRAY_SIZE
        out
    }
    build_light()
};

#[divan::bench(
    max_time     = 10,
    sample_count = 1,
    sample_size  = 1,
    args         = PARAMS
)]
fn light_update_reg(bencher: Bencher, Params(cap, _upd_log_size, init): Params) {
    // _upd_log_size is passed to prepare_prover_update_prove_inputs,
    // where it's used to determine the size of `update_batch`.
    // The benchmark itself uses this `update_batch`.
    let (mut server, update_batch, mut bb) =
        prepare_prover_update_prove_inputs(cap, _upd_log_size, init);

    bencher.bench_local(|| {
        // This benchmarks the update_reg with the `update_batch`
        // whose size is determined by `_upd_log_size`.
        server.update_reg(&update_batch, &mut bb).unwrap();
    });
}

// Ensure main function is present for Divan if this is the main benchmark file
fn main() {
    divan::main();
}
