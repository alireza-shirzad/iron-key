//! Benchmarks `IronServer::update` for many (log_capacity, log_update_size)
//! pairs.  The tiny “warm-up” batch size is now a real parameter that lives
//! inside `PARAMS`, but we keep its value fixed at 3 for every entry so it
//! is **not** swept during the run.

use ark_bls12_381::{Bls12_381 as E, Bls12_381, Fr};
use divan::Bencher;
use iron_key::{
    VKD, VKDClient, VKDPublicParameters, VKDServer,
    bb::dummybb::DummyBB,
    client::IronClient,
    ironkey::IronKey,
    server::IronServer,
    structs::{IronLabel, IronSpecification, lookup::IronLookupProof},
};
use subroutines::pcs::kzh2::KZH2;
use std::collections::HashMap;
fn prepare_verifier_lookup_intput(
    log_capacity: u64,
    log_initial_batch_size: u64,
) -> (
    IronClient<E, IronLabel, KZH2<E>>,
    Fr,
    IronLookupProof<E, KZH2<E>>,
    DummyBB<E, KZH2<E>>,
) {
    let spec = IronSpecification::new(1 << log_capacity);

    let pp = IronKey::<Bls12_381, KZH2<Bls12_381>, IronLabel>::setup(spec).unwrap();
    let mut server = IronServer::<Bls12_381, KZH2<Bls12_381>, IronLabel>::init(&pp);
    let mut bulletin_board = DummyBB::default();
    let initial_batch_size = 1 << log_initial_batch_size;
    // Build `batch_size` distinct (label, value) pairs.
    let updates: HashMap<IronLabel, Fr> = (1..=initial_batch_size)
        .map(|i| (IronLabel::new(&i.to_string()), Fr::from(i as u64)))
        .collect();
    server.update_reg(&updates, &mut bulletin_board).unwrap();
    server.update_keys(&updates, &mut bulletin_board).unwrap();
    let lookup_proof = server
        .lookup_prove(IronLabel::new("1"), &mut bulletin_board)
        .unwrap();
    let client: IronClient<_, _, _> = IronClient::init(pp.to_client_key(), IronLabel::new("1"));

    (
        client,
        lookup_proof.get_value(),
        lookup_proof,
        bulletin_board,
    )
}

#[divan::bench(args = [4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29], max_time = 60)]
fn lookup_prove_after_updates(bencher: Bencher, batch_size: usize) {
    // Use with_inputs to create a new server for each thread, avoiding Sync
    // requirement
    bencher
        .with_inputs(|| prepare_verifier_lookup_intput(batch_size as u64, 1))
        .bench_values(|(mut client, value, lookup_proof, bb)| {
            client.lookup_verify(value, &lookup_proof, &bb).unwrap();
        });
}
