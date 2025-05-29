// //! Benchmarks `IronServer::update` for many (log_capacity, log_update_size)
// //! pairs.  The tiny “warm-up” batch size is now a real parameter that lives
// //! inside `PARAMS`, but we keep its value fixed at 3 for every entry so it
// //! is **not** swept during the run.

// use ark_bls12_381::{Bls12_381 as E, Fr};
// use ark_ec::{CurveGroup, ScalarMul};
// use ark_poly::{MultilinearExtension, SparseMultilinearExtension};
// use ark_std::{UniformRand, cfg_iter};
// use divan::Bencher;
// use iron_key::{
//     bb::{
//         dummybb::{DummyBB, IronEpochMessage}, BulletinBoard
//     }, client::IronClient, ironkey::IronKey, server::IronServer, structs::{
//         lookup::IronLookupProof, pp::IronClientKey, update::{IronEpochRegMessage, IronUpdateProof}, IronLabel, IronSpecification
//     }, VKDClient, VKDServer, VKD
// };
// use ark_bls12_381::Bls12_381;
// use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
// use std::{collections::HashMap, fmt};
// use subroutines::pcs::kzh::{
//     KZH2,
//     poly::DenseOrSparseMLE,
//     srs::KZH2VerifierParam,
//     structs::{KZH2AuxInfo, KZH2Commitment, KZH2OpeningProof},
// };
// /// Triplet carried around by Divan.
// #[derive(Copy, Clone, Debug)]
// struct Params(
//     pub u64, // log_capacity
//     pub u64, // log_update_size
//     pub u64, // initial_batch_size
// );

// /// We still only *show* the first two numbers in the report.
// impl fmt::Display for Params {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         write!(
//             f,
//             "[log(capacity)={}, log(|update|)={}, log(init-update)={}]",
//             self.0, self.1, self.2
//         )
//     }
// }

// fn prepare_verifier_lookup_intput(
//     log_capacity: u64,
//     log_update_size: u64,
//     log_initial_batch_size: u64,
// ) -> (
//     IronClient<E, IronLabel, KZH2<E>>,
//     Fr,
//     IronLookupProof<E, KZH2<E>>,
//     DummyBB<E, KZH2<E>>,
// ) {
//     let initial_batch_size = 1 << log_initial_batch_size;
//     let system_spec = IronSpecification::new(1 << log_capacity);
//     let pp = IronKey::<Bls12_381, KZH2<Bls12_381>, IronLabel>::setup(system_spec).unwrap();
//     let mut server: IronServer<_, _, _> = IronServer::init(&pp);
//     let mut bulletin_board = DummyBB::default();

//     // Warm-up batch just to create the path in the tree.
//     let initial_batch: HashMap<_, _> = (1..=initial_batch_size)
//         .map(|i| (IronLabel::new(&i.to_string()), Fr::from(i as u64)))
//         .collect();
//     server
//         .update_reg(&initial_batch, &mut bulletin_board)
//         .unwrap();
//     server
//         .update_keys(&initial_batch, &mut bulletin_board)
//         .unwrap();

//     let lookup_proof = server
//         .lookup_prove(IronLabel::new("1"), &mut bulletin_board)
//         .unwrap();

//     (client, value, lookup_proof, bulletin_board)
// }

// /// Compile-time list of (log_capacity, log_update_size, 3) triplets for light
// /// tests.
// pub const PARAMS: &[Params] = &{
//     const INIT: u64 = 2;
//     const fn build_light() -> [Params; 663] {
//         let mut out = [Params(1, 0, 0); 663];
//         let mut i = 0;

//         // (n, 0..=n-2, INIT) for n = 3..=26
//         let mut n = 3;
//         while n <= 33 {
//             let mut k = 0;
//             while k <= n - 2 {
//                 out[i] = Params(n, k, INIT);
//                 i += 1;
//                 k += 1;
//             }
//             n += 1;
//         }

//         out
//     }
//     build_light()
// };

// #[divan::bench(
//     max_time     = 60,
//     sample_count = 1,
//     sample_size  = 1,
//     args         = PARAMS
// )]
// fn client_lookup(bencher: Bencher, Params(cap, upd, init): Params) {
//     let (mut client, value, lookup_proof, bulletin_board) =
//         prepare_verifier_lookup_intput(cap, upd, init);
//     bencher.bench_local(|| {
//         client
//             .lookup_verify(value, &lookup_proof, &bulletin_board)
//             .unwrap()
//     });
// }
