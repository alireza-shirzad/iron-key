use ark_ff::PrimeField;
use num_bigint::BigUint;

use crate::{VKDLabel, VKDSpecification};

pub mod dictionary;
pub mod lookup;
pub mod pp;
pub mod self_audit;
pub mod update;

pub struct IronSpecification {
    capacity: usize,
}

impl IronSpecification {
    pub fn new(capacity: usize) -> Self {
        Self { capacity }
    }
}

impl VKDSpecification for IronSpecification {
    fn get_capacity(&self) -> usize {
        self.capacity
    }
}

#[derive(Clone, Debug, PartialEq, Hash, Eq)]
pub struct IronLabel {
    label: String,
}

impl IronLabel {
    pub fn new(label: &str) -> Self {
        Self { label: label.to_string() }
    }

}

impl std::fmt::Display for IronLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label)
    }
}

impl<F: PrimeField> VKDLabel<F> for IronLabel {
    fn to_field(&self) -> F {
        let bigint = self.label.parse::<BigUint>().ok().unwrap();
        let bytes = bigint.to_bytes_le();
        F::from_le_bytes_mod_order(&bytes)
    }
}

#[test]
fn test_label() {
    let label = IronLabel {
        label: "12345678901234567890".to_string(),
    };
    let field: ark_bls12_381::Fr = label.to_field();
    println!("Field: {}", field);
}
