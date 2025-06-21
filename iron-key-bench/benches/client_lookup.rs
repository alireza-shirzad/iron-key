use ark_bn254::{Bn254 as E, Bn254, Fr};
use ark_serialize::CanonicalSerialize;
use divan::Bencher;
use iron_key::{
    VKD,
    VKDClient,
    VKDPublicParameters,
    VKDServer, // Assuming VKDPublicParameters might be an alias or related
    bb::dummybb::DummyBB,
    client::{self, IronClient},
    ironkey::IronKey, // Used for IronKey::setup
    server::IronServer,
    structs::pp::IronPublicParameters, // The actual type for PP
    structs::{IronLabel, IronSpecification, lookup::IronLookupProof},
};
use once_cell::sync::Lazy; // For caching
use std::{
    collections::HashMap,
    sync::{Arc, Mutex}, // For caching
};
use subroutines::pcs::kzh2::KZH2;

// Type alias for the Public Parameters returned by setup and used by
// server/client key derivation
type AppPublicParameters = IronPublicParameters<E, KZH2<E>>;

// Static cache for public parameters, keyed by log_capacity (u64)
static PP_CACHE: Lazy<Mutex<HashMap<u64, Arc<AppPublicParameters>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Helper function to get or create AppPublicParameters for a given
/// log_capacity
fn get_or_create_pp(log_capacity: u64) -> Arc<AppPublicParameters> {
    let mut cache = PP_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    cache
        .entry(log_capacity)
        .or_insert_with(|| {
            eprintln!(
                "Cache miss: Creating new IronPublicParameters for log_capacity = {}",
                log_capacity
            );
            let spec = IronSpecification::new(1 << log_capacity);
            // IronKey::<..., IronLabel> specifies generics for the IronKey struct itself,
            // its `setup` method returns Result<IronPublicParameters<E, Pcs>, _>
            let pp = IronKey::<Bn254, KZH2<Bn254>, IronLabel>::setup(spec)
                .expect("Failed to setup IronPublicParameters");
            Arc::new(pp)
        })
        .clone()
}

fn prepare_verifier_lookup_intput(
    log_capacity: u64,
    log_initial_batch_size: u64,
) -> (
    usize,
    IronClient<E, IronLabel, KZH2<E>>,
    Fr,
    IronLookupProof<E, KZH2<E>>,
    DummyBB<E, KZH2<E>>,
) {
    // Get PP from cache or create it if it's not there for the given log_capacity
    let pp_arc = get_or_create_pp(log_capacity);
    let pp_ref = &*pp_arc; // pp_ref is &AppPublicParameters

    let mut server = IronServer::<Bn254, KZH2<Bn254>, IronLabel>::init(pp_ref);
    let mut bulletin_board = DummyBB::default();
    let initial_batch_size_val = 1 << log_initial_batch_size;

    // Build `initial_batch_size_val` distinct (label, value) pairs.
    let updates: HashMap<IronLabel, Fr> = (1..=initial_batch_size_val)
        .map(|i| (IronLabel::new(&i.to_string()), Fr::from(i as u64)))
        .collect();

    if initial_batch_size_val > 0 {
        server.update_reg(&updates, &mut bulletin_board).unwrap();
        server.update_keys(&updates, &mut bulletin_board).unwrap();
    }

    let lookup_proof = server
        .lookup_prove(IronLabel::new("1"), &mut bulletin_board) // Assumes "1" was inserted
        .unwrap();

    // Assuming IronPublicParameters (pp_ref) has a method to_client_key()
    let client_key = pp_ref.to_client_key();
    let client_key_size = client_key.serialized_size(ark_serialize::Compress::Yes);
    let client: IronClient<_, _, _> = IronClient::init(client_key, IronLabel::new("1"));

    (
        client_key_size,
        client,
        lookup_proof.get_value(),
        lookup_proof,
        bulletin_board,
    )
}

#[divan::bench(args = [20,21,22,23,24,25,26,27,28,29,30,31,32])]
fn lookup_prove_after_updates(bencher: Bencher, batch_size: usize) {
    // batch_size is log_capacity here
    let current_log_capacity = batch_size as u64;
    let log_initial_batch_size = 1_u64; // Fixed for these benchmarks

    bencher
        .with_inputs(|| {
            prepare_verifier_lookup_intput(current_log_capacity, log_initial_batch_size)
        })
        .bench_values(|(_, mut client, value, lookup_proof, bb)| {
            client
                .lookup_verify(IronLabel::new("1"), value, &lookup_proof, &bb)
                .unwrap();
        });

    // This call will also benefit from the PP_CACHE
    let (client_key_size, _, _, proof, _) =
        prepare_verifier_lookup_intput(current_log_capacity, log_initial_batch_size);
    // Note: This print will occur for *each* batch_size arg after its benchmark
    // run. If you want it once overall, you'd need a different structure or a
    // global flag.
    println!(
        "\n[log_capacity={}] Lookup proof size: {} Bytes",
        current_log_capacity,
        proof.serialized_size(ark_serialize::Compress::Yes)
    );
    println!(
        "[log_capacity={}] Client key size: {} Bytes\n",
        current_log_capacity, client_key_size
    );
}

// Ensure main function is present for Divan if this is the main benchmark file
fn main() {
    divan::main();
}
