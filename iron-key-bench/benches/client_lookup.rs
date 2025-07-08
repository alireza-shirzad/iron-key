use std::{
    collections::HashMap,
    sync::{Arc, Mutex}, // Added Arc and Mutex
};

use ark_bn254::{Bn254, Fr};
use divan::Bencher;
use iron_key::{
    VKD, VKDClient, VKDPublicParameters, VKDServer,
    bb::dummybb::DummyBB,
    client::{self, IronClient},
    ironkey::IronKey,
    server::IronServer,
    structs::{IronLabel, IronSpecification, lookup::IronLookupProof, pp::IronPublicParameters},
};
use once_cell::sync::Lazy; // Added Lazy
use subroutines::pcs::kzh2::KZH2;

// Type alias for the Public Parameters
type AppPublicParameters = IronPublicParameters<Bn254, KZH2<Bn254>>;

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
            let spec = IronSpecification::new(1usize << log_capacity);
            let pp = IronKey::<Bn254, KZH2<Bn254>, IronLabel>::setup(spec)
                .expect("Failed to setup IronPublicParameters");
            Arc::new(pp)
        })
        .clone()
}

/// Build a server that has already processed `batch_size` updates.
fn server_with_updates(
    log_capacity: usize,
) -> (
    IronClient<Bn254, IronLabel, KZH2<Bn254>>,
    IronLookupProof<Bn254, KZH2<Bn254>>,
    DummyBB<Bn254, KZH2<Bn254>>,
) {
    let batch_size: usize = 1 << (log_capacity / 2); // This BATCH_SIZE is for the initial updates, not log_capacity
    // Get PP from cache or create it if it's not there for the given log_capacity
    let pp_arc = get_or_create_pp(log_capacity);
    // Initialize server with the (potentially cached) public parameters
    let mut server = IronServer::<Bn254, KZH2<Bn254>, IronLabel>::init(&*pp_arc); // Dereference Arc to get &AppPublicParameters
    let mut bb = DummyBB::default();

    // Build `BATCH_SIZE` distinct (label, value) pairs for initial server state.
    // Note: Using a constant BATCH_SIZE = 1 here for these updates.
    let updates: HashMap<IronLabel, Fr> = (1..=batch_size)
        .map(|i| (IronLabel::new(&i.to_string()), Fr::from(i as u64)))
        .collect();
    // // Perform initial updates if required by the benchmark scenario
    // if batch_size > 0 { // Only update if BATCH_SIZE is meaningful
    server.update_reg(&updates, &mut bb).unwrap(); // Assuming update_reg is part of your server's API
    server.update_keys(&updates, &mut bb).unwrap();
    let label = IronLabel::new("1");

    let proof = server.lookup_prove(label.clone(), &mut bb).unwrap();

    let client =
        IronClient::<Bn254, IronLabel, KZH2<Bn254>>::init(pp_arc.to_client_key(), label.clone());

    (client, proof, bb)
}

/// Benchmark `lookup_prove` after different-sized update batches.
/// The `args` list controls `log_capacity` values.
#[divan::bench(    max_time     = 1,args = [20,21,22,23,24,25,26,27,28,29,30,31,32])]
fn lookup_prove_after_updates(bencher: Bencher, log_capacity_arg: usize) {
    bencher
        // build a brand-new (server, bb, label) for *each* iteration
        .with_inputs(|| server_with_updates(log_capacity_arg))
        // pass it *by reference* so the tuple itself is not dropped inside the timer
        .bench_local_refs(|(client, proof, bb)| {
            client.lookup_verify(client.get_label(), Fr::from(1u64), proof, bb)
        });
}
