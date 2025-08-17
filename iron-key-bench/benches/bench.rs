mod audit;
mod client_lookup;
mod kzh;
mod kzh_opening;
mod server_lookup;
mod server_update_keys;
mod server_update_reg;
use ark_bn254 as E;
use ark_bn254::Fr;
use ark_ec::VariableBaseMSM;
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
#[divan::bench]
fn zk(bencher: Bencher) {
    let mut rng = ark_std::test_rng();
    let num = 4096;
    let scalars = (0..num).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
    let bases = (0..num)
        .map(|_| E::G1Affine::rand(&mut rng))
        .collect::<Vec<_>>();
    bencher.bench(|| <E::G1Projective as VariableBaseMSM>::msm(&bases, &scalars));
}

fn main() {
    divan::Divan::from_args().main();
}
