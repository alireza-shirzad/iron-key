use std::collections::HashMap;

use ark_bls12_381::{Bls12_381, Fr};
use divan::Bencher;
use iron_key::{
    VKD, VKDServer,
    bb::dummybb::DummyBB,
    ironkey::IronKey,
    server::IronServer,
    structs::{IronLabel, IronSpecification},
};
use subroutines::pcs::kzh::KZH2;

/// Build a server that has already processed `batch_size` updates.
fn server_with_updates(log_capacity: usize) -> IronServer<Bls12_381, KZH2<Bls12_381>, IronLabel> {
    const BATCH_SIZE: usize = 1;
    let spec = IronSpecification::new(1 << log_capacity);

    let pp = IronKey::<Bls12_381, KZH2<Bls12_381>, IronLabel>::setup(spec).unwrap();
    let mut server = IronServer::<Bls12_381, KZH2<Bls12_381>, IronLabel>::init(&pp);
    let mut bb = DummyBB::default();

    // Build `batch_size` distinct (label, value) pairs.
    let updates: HashMap<IronLabel, Fr> = (1..=BATCH_SIZE)
        .map(|i| (IronLabel::new(&i.to_string()), Fr::from(i as u64)))
        .collect();
    server.update_reg(&updates, &mut bb).unwrap();
    server
}

/// Benchmark `lookup_prove` after different-sized update batches.
///
/// The `args` list controls the batch sizes; adjust freely.
#[divan::bench(args = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26], max_time = 60)]
fn lookup_prove_after_updates(bencher: Bencher, batch_size: usize) {
    // Use with_inputs to create a new server for each thread, avoiding Sync
    // requirement
    bencher
        .with_inputs(|| server_with_updates(batch_size))
        .bench_values(|server| server.lookup_prove(IronLabel::new("1")));
}
