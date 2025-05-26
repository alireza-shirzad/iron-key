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
    log_capacity: u64,
    log_update_size: u64,
) -> (
    IronServer<Bls12_381, KZH2<Bls12_381>, IronLabel>,
    HashMap<IronLabel, Fr>,
    DummyBB<Bls12_381, KZH2<Bls12_381>>,
) {
    let system_spec = IronSpecification::new(1 << log_capacity);
    let pp = IronKey::<Bls12_381, KZH2<Bls12_381>, IronLabel>::setup(system_spec).unwrap();
    let mut server: IronServer<Bls12_381, KZH2<Bls12_381>, IronLabel> = IronServer::init(&pp);
    let mut bulletin_board = DummyBB::default();

    let initial_update_batch: HashMap<IronLabel, Fr> = HashMap::from([
        (IronLabel::new("1"), Fr::from(1)),
        (IronLabel::new("2"), Fr::from(2)),
        (IronLabel::new("3"), Fr::from(3)),
    ]);

    server
        .update(initial_update_batch, &mut bulletin_board)
        .unwrap();
    let updates: HashMap<IronLabel, Fr> = (1..=(1 << log_update_size))
        .map(|i| (IronLabel::new(&i.to_string()), Fr::from(i as u64)))
        .collect();
    (server, updates, bulletin_board)
}

pub const PARAMS: &[(u64, u64)] = &{
    const fn generate_pairs() -> [(u64, u64); 530] {
        let mut pairs = [(0, 0); 530];
        let mut i = 0;

        // Add (1, 0) and (2, 0)
        pairs[i] = (1, 0);
        i += 1;
        pairs[i] = (2, 0);
        i += 1;

        // For n = 3 to 33: (n, 0), ..., (n, n-2)
        let mut n = 3;
        while n <= 33 {
            let mut k = 0;
            while k <= n - 2 {
                pairs[i] = (n, k);
                i += 1;
                k += 1;
            }
            n += 1;
        }

        pairs
    }
    generate_pairs()
};

#[divan::bench(args = PARAMS,sample_count = 1, sample_size = 1)]
fn update(bencher: Bencher, (log_capacity, log_update_size): (u64, u64)) {
    let (mut server, update_batch, mut bulletin_board) =
        prepare_prover_update_prove_inputs(log_capacity, log_update_size);
    bencher.bench_local(|| {
        server
            .update(update_batch.clone(), &mut bulletin_board)
            .unwrap();
    });
}
