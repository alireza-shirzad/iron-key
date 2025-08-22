use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use num_bigint::BigUint;
use subroutines::PolynomialCommitmentScheme;

use crate::{VKDLabel, VKDSpecification};

pub mod dictionary;
pub mod lookup;
pub mod pp;
pub mod self_audit;
pub mod update;

pub struct IronSpecification<E: Pairing, PC: PolynomialCommitmentScheme<E>> {
    capacity: usize,
    pcs_conf: PC::Config,
}

impl<E: Pairing, PC: PolynomialCommitmentScheme<E>> IronSpecification<E, PC> {
    pub fn new(capacity: usize, pcs_conf: PC::Config) -> Self {
        Self { capacity, pcs_conf }
    }
}

impl<E: Pairing, PC: PolynomialCommitmentScheme<E>> VKDSpecification<E, PC>
    for IronSpecification<E, PC>
{
    fn get_capacity(&self) -> usize {
        self.capacity
    }
    fn get_pcs_conf(&self) -> <PC>::Config {
        self.pcs_conf.clone()
    }
}

#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub struct IronLabel {
    label: String,
}

impl IronLabel {
    pub fn new(label: &str) -> Self {
        Self {
            label: label.to_string(),
        }
    }
}

impl std::fmt::Display for IronLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label)
    }
}

impl<E: Pairing> VKDLabel<E> for IronLabel {
    fn to_field(&self) -> E::ScalarField {
        let bigint = self.label.parse::<BigUint>().ok().unwrap();
        let bytes = bigint.to_bytes_le();
        E::ScalarField::from_le_bytes_mod_order(&bytes)
    }
}

#[test]
fn test_label() {
    let label = IronLabel {
        label: "12345678901234567890".to_string(),
    };
    let field: ark_bn254::Fr = <IronLabel as VKDLabel<ark_bn254::Bn254>>::to_field(&label);
}
