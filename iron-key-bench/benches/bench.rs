mod audit;
mod client_lookup;
mod kzh;
mod kzh_opening;
mod server_lookup;
mod server_update_keys;
mod server_update_reg;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, UniformRand};
use divan::Bencher;
use sha2::{Digest, Sha256};
#[divan::bench]
fn field_multiplication(bencher: Bencher) {
    let mut rng = ark_std::test_rng();

    let a = Fr::rand(&mut rng);
    let b = Fr::rand(&mut rng);
    bencher.bench(|| {
        let mut res = a;
        res *= b;
        res
    });
}

#[divan::bench]
fn sha256_hash(bencher: Bencher) {
    let mut rng = ark_std::test_rng();
    let x = Fr::rand(&mut rng);
    let x_bytes = x.into_bigint().to_bytes_le(); // Convert field element to little-endian bytes
    bencher.bench(|| {
        let mut hasher = Sha256::new();
        hasher.update(&x_bytes);
        hasher.finalize()
    });
}

fn main() {
    rayon::ThreadPoolBuilder::new()
    .num_threads(100)   // or whatever you like
    .build_global()
    .expect("global pool already built");
    divan::Divan::from_args().main();
}
