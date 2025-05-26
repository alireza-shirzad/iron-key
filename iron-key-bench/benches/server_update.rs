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

fn prepare_prover_update_prove_inputs(
    log_capacity: usize,
    log_update_size: usize,
) -> (
    IronServer<Bls12_381, KZH2<Bls12_381>, IronLabel>,
    HashMap<IronLabel, Fr>,
    DummyBB<Bls12_381, KZH2<Bls12_381>>,
) {
    const LOG_CAPACITY: usize = 27;
    let system_spec = IronSpecification::new(1 << LOG_CAPACITY);
    let pp = IronKey::<Bls12_381, KZH2<Bls12_381>, IronLabel>::setup(system_spec).unwrap();
    let mut server: IronServer<Bls12_381, KZH2<Bls12_381>, IronLabel> = IronServer::init(&pp);
    let mut bulletin_board = DummyBB::default();

    let update_batch1: HashMap<IronLabel, Fr> = HashMap::from([
        (IronLabel::new("1"), Fr::from(1)),
        (IronLabel::new("2"), Fr::from(2)),
        (IronLabel::new("3"), Fr::from(3)),
    ]);

    server.update(update_batch1, &mut bulletin_board).unwrap();
    let update_batch1: HashMap<IronLabel, Fr> = HashMap::from([
        (IronLabel::new("4"), Fr::from(4)),
        (IronLabel::new("5"), Fr::from(5)),
        (IronLabel::new("6"), Fr::from(6)),
    ]);
    (server, update_batch1, bulletin_board)
}

#[divan::bench(sample_count = 1, sample_size = 1)]
fn update(bencher: Bencher) {
    bencher
        .with_inputs(prepare_prover_update_prove_inputs)
        .bench_values(|(mut server, update_batch, mut bulletin_board)| {
            server.update(update_batch, &mut bulletin_board).unwrap();
        });
}
