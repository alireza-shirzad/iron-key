//! Benchmarks `IronServer::update` for many (log_capacity, log_update_size)
//! pairs.  The tiny “warm-up” batch size is now a real parameter that lives
//! inside `PARAMS`, but we keep its value fixed at 3 for every entry so it
//! is **not** swept during the run.

use std::{collections::HashMap, fmt};

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

/// Triplet carried around by Divan.
#[derive(Copy, Clone, Debug)]
struct Params(
    pub u64, // log_capacity
    pub u64, // log_update_size
    pub u64, // initial_batch_size
);

/// We still only *show* the first two numbers in the report.
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
fn prepare_prover_update_prove_inputs(
    log_capacity: u64,
    log_update_size: u64,
    log_initial_batch_size: u64,
) -> (
    IronServer<Bls12_381, KZH2<Bls12_381>, IronLabel>,
    HashMap<IronLabel, Fr>,
    DummyBB<Bls12_381, KZH2<Bls12_381>>,
) {
    let initial_batch_size = 1 << log_initial_batch_size;
    let system_spec = IronSpecification::new(1 << log_capacity);
    let pp = IronKey::<Bls12_381, KZH2<Bls12_381>, IronLabel>::setup(system_spec).unwrap();
    let mut server: IronServer<_, _, _> = IronServer::init(&pp);
    let mut bulletin_board = DummyBB::default();

    // Warm-up batch just to create the path in the tree.
    let initial_batch: HashMap<_, _> = (1..=initial_batch_size)
        .map(|i| (IronLabel::new(&i.to_string()), Fr::from(i as u64)))
        .collect();
    server
        .update_reg(&initial_batch, &mut bulletin_board)
        .unwrap();

    // Batch whose size we actually benchmark.
    let update_batch: HashMap<_, _> = (1..=(1 << log_update_size))
        .map(|i| {
            (
                IronLabel::new(&(i + initial_batch_size).to_string()),
                Fr::from(i + initial_batch_size),
            )
        })
        .collect();

    (server, update_batch, bulletin_board)
}

/// Compile-time list of (log_capacity, log_update_size, **3**) triplets.
pub const PARAMS: &[Params] = &{
    const INIT: u64 = 1;
    const fn build() -> [Params; 530] {
        let mut out = [Params(4, 1, 0); 530];
        let mut i = 0;

        // (1,0,3) and (2,0,3)
        out[i] = Params(1, 0, 0);
        i += 1;
        out[i] = Params(2, 0, 0);
        i += 1;

        // (n,0…n−2,3) for n = 3..=33
        let mut n = 3;
        while n <= 33 {
            let mut k = 0;
            while k <= n - 2 {
                out[i] = Params(n, k, INIT);
                i += 1;
                k += 1;
            }
            n += 1;
        }
        out
    }
    build()
};

/// Divan benchmark.
///
/// * 60 s wall-time cap so 200×200 samples fit.
/// * `args = PARAMS` sweeps the (log_capacity, log_update_size) pairs; the
///   warm-up size is always 3.
#[divan::bench(
    max_time     = 60,
    sample_count = 1,
    sample_size  = 1,
    args         = PARAMS
)]
fn update(bencher: Bencher, Params(cap, upd, init): Params) {
    let (mut server, update_batch, mut bb) = prepare_prover_update_prove_inputs(cap, upd, init);

    bencher.bench_local(|| {
        server.update_reg(&update_batch, &mut bb).unwrap();
    });
}
