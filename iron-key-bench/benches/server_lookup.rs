use std::{
    collections::HashMap,
    sync::{Arc, Mutex}, // Added Arc and Mutex
};

use ark_bn254::{Bn254, Fr};
use divan::Bencher;
use iron_key::{
    VKD, VKDServer,
    bb::dummybb::DummyBB,
    ironkey::IronKey,
    server::IronServer,
    structs::{IronLabel, IronSpecification},
    structs::pp::IronPublicParameters, // Make sure this import is correct
};
use once_cell::sync::Lazy; // Added Lazy
use subroutines::pcs::kzh4::KZH4;

// Type alias for the Public Parameters
type AppPublicParameters = IronPublicParameters<Bn254, KZH4<Bn254>>;

// Static cache for public parameters, keyed by log_capacity
static PP_CACHE: Lazy<Mutex<HashMap<usize, Arc<AppPublicParameters>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Helper function to get or create PP for a given log_capacity
fn get_or_create_pp(log_capacity: usize) -> Arc<AppPublicParameters> {
    let mut cache = PP_CACHE.lock().unwrap_or_else(|e| e.into_inner()); // Handle poisoned mutex if necessary
    cache
        .entry(log_capacity)
        .or_insert_with(|| {
            eprintln!(
                "Cache miss: Creating new IronPublicParameters for log_capacity = {}",
                log_capacity
            );
            let spec = IronSpecification::new(1 << log_capacity);
            let pp = IronKey::<Bn254, KZH4<Bn254>, IronLabel>::setup(spec)
                .expect("Failed to setup IronPublicParameters");
            Arc::new(pp)
        })
        .clone()
}

/// Build a server that has already processed `batch_size` updates.
fn server_with_updates(
    log_capacity: usize,
) -> (
    IronServer<Bn254, KZH4<Bn254>, IronLabel>,
    DummyBB<Bn254, KZH4<Bn254>>,
) {
    const BATCH_SIZE: usize = 1; // This BATCH_SIZE is for the initial updates, not log_capacity

    // Get PP from cache or create it if it's not there for the given log_capacity
    let pp_arc = get_or_create_pp(log_capacity);

    // Initialize server with the (potentially cached) public parameters
    let mut server = IronServer::<Bn254, KZH4<Bn254>, IronLabel>::init(&*pp_arc); // Dereference Arc to get &AppPublicParameters
    let mut bb = DummyBB::default();

    // Build `BATCH_SIZE` distinct (label, value) pairs for initial server state.
    // Note: Using a constant BATCH_SIZE = 1 here for these updates.
    let updates: HashMap<IronLabel, Fr> = (1..=BATCH_SIZE)
        .map(|i| (IronLabel::new(&i.to_string()), Fr::from(i as u64)))
        .collect();

    // Perform initial updates if required by the benchmark scenario
    if BATCH_SIZE > 0 { // Only update if BATCH_SIZE is meaningful
        server.update_reg(&updates, &mut bb).unwrap(); // Assuming update_reg is part of your server's API
        server.update_keys(&updates, &mut bb).unwrap();
    }
    
    (server, bb)
}

/// Benchmark `lookup_prove` after different-sized update batches.
/// The `args` list controls `log_capacity` values.
#[divan::bench(args = [4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29])]
fn lookup_prove_after_updates(bencher: Bencher, log_capacity_arg: usize) {
    // Use with_inputs to create a new server for each thread/argument set.
    // `log_capacity_arg` from `args` is passed to `server_with_updates`.
    bencher
        .with_inputs(|| server_with_updates(log_capacity_arg))
        .bench_values(|(server, mut bb)| {
            // The label "1" was inserted if BATCH_SIZE >= 1 in server_with_updates
            server.lookup_prove(IronLabel::new("1"), &mut bb).unwrap()
        });
}

// Ensure main function is present for Divan if this is the main benchmark file
fn main() {
    divan::main();
}