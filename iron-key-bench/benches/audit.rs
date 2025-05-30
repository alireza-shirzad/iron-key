//! Benchmarks `IronServer::update` for many (log_capacity, log_update_size)
//! pairs.  The tiny “warm-up” batch size is now a real parameter that lives
//! inside `PARAMS`, but we keep its value fixed at 3 for every entry so it
//! is **not** swept during the run.

use ark_bls12_381::{Bls12_381 as E, Bls12_381, Fr};
use divan::Bencher;
use iron_key::{
    VKD, VKDAuditor, VKDPublicParameters, VKDServer,
    auditor::IronAuditor,
    bb::dummybb::DummyBB,
    ironkey::IronKey,
    server::IronServer,
    structs::{IronLabel, IronSpecification},
};
use subroutines::pcs::kzh2::KZH2;
use std::collections::HashMap;
fn prepare_verifier_lookup_intput(
    log_capacity: u64,
    log_first_batch_size: u64,
    log_second_batch_size: u64,
) -> (IronAuditor<E, IronLabel, KZH2<E>>, DummyBB<E, KZH2<E>>) {
    let spec = IronSpecification::new(1 << log_capacity);

    let pp = IronKey::<Bls12_381, KZH2<Bls12_381>, IronLabel>::setup(spec).unwrap();
    let mut server = IronServer::<Bls12_381, KZH2<Bls12_381>, IronLabel>::init(&pp);
    let mut bulletin_board = DummyBB::default();
    let first_batch_size = 1 << log_first_batch_size;
    let second_batch_size = 1 << log_second_batch_size;
    // Build `batch_size` distinct (label, value) pairs.
    let updates1: HashMap<IronLabel, Fr> = (1..=first_batch_size)
        .map(|i| (IronLabel::new(&i.to_string()), Fr::from(i as u64)))
        .collect();
    server.update_reg(&updates1, &mut bulletin_board).unwrap();
    server.update_keys(&updates1, &mut bulletin_board).unwrap();

    let updates2: HashMap<IronLabel, Fr> = ((first_batch_size + 1)..=(second_batch_size + 1))
        .map(|i| (IronLabel::new(&i.to_string()), Fr::from(i as u64)))
        .collect();
    server.update_reg(&updates2, &mut bulletin_board).unwrap();
    server.update_keys(&updates2, &mut bulletin_board).unwrap();

    let auditor: IronAuditor<_, _, _> = IronAuditor::init(pp.to_auditor_key());

    (auditor, bulletin_board)
}

#[divan::bench(args = [7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29], max_time = 60)]
fn audit(bencher: Bencher, batch_size: usize) {
    // Use with_inputs to create a new server for each thread, avoiding Sync
    // requirement
    bencher
        .with_inputs(|| prepare_verifier_lookup_intput(batch_size as u64, 2, 2))
        .bench_values(|(auditor, bulltin_board)| auditor.verify_update(&bulltin_board));
}
