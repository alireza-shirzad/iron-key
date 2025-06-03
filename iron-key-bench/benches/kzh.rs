// use ark_bn254::{Bn254, Fr};
// use ark_ff::{UniformRand, Zero};
// use ark_poly::DenseMultilinearExtension;
// use ark_serialize::CanonicalDeserialize;
// use ark_std::{
//     rand::{SeedableRng, rngs::StdRng},
//     test_rng,
// };
// use divan::Bencher;

// use rand::seq::index::sample;
// use std::{
//     env::current_dir,
//     fs::File,
//     io::{BufReader, Read},
// };
// use subroutines::pcs::{
//     PolynomialCommitmentScheme,
//     kzh::{
//         KZH2,
//         srs::{KZH2ProverParam, KZH2UniversalParams},
//     },
// };
// fn prepare_prover_inputs() -> (KZH2ProverParam<Bn254>, DenseMultilinearExtension<Fr>) {
//     const LOG_CAPACITY: usize = 25;
//     const LOG_DENSITY: usize = 20;
//     let srs_path = current_dir()
//         .unwrap()
//         .join(format!("../srs/srs_{}.bin", LOG_CAPACITY));
//     let mut buffer = Vec::new();
//     BufReader::new(File::open(&srs_path).unwrap())
//         .read_to_end(&mut buffer)
//         .unwrap();
//     let srs = KZH2UniversalParams::<Bn254>::deserialize_uncompressed_unchecked(&buffer[..])
//         .unwrap_or_else(|_| {
//             panic!("Failed to deserialize SRS from {:?}", srs_path);
//         });
//     let (pk, vk) = KZH2::<Bn254>::trim(srs, None, Some(LOG_CAPACITY)).unwrap();
//     let mut evals = vec![Fr::from(0); 1 << LOG_CAPACITY];
//     let mut t_rng = rand::rng();
//     // Sample k unique positions from the vector
//     let indices = sample(&mut t_rng, 1 << LOG_CAPACITY, 1 << LOG_DENSITY).into_vec();

//     let mut rng = test_rng();
//     for idx in indices {
//         // Generate a random non-zero field element
//         let mut value = Fr::from(0);
//         while value.is_zero() {
//             value = Fr::rand(&mut rng);
//         }
//         evals[idx] = value;
//     }
//     let polynomial = DenseMultilinearExtension::<Fr>::from_evaluations_vec(LOG_CAPACITY, evals);
//     dbg!(
//         polynomial
//             .evaluations
//             .iter()
//             .filter(|&x| !x.is_zero())
//             .count()
//     );
//     (pk, polynomial)
// }

// #[divan::bench(sample_count = 1, sample_size = 1)]
// fn commit(bencher: Bencher) {
//     bencher
//         .with_inputs(prepare_prover_inputs)
//         .bench_values(|(pk, polynomial)| {
//             KZH2::<Bn254>::commit(pk, &polynomial).unwrap();
//         });
// }
