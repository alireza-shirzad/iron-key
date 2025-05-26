use ark_ec::pairing::Pairing;
use subroutines::PolynomialCommitmentScheme;

pub struct IronSelfAuditProof<E, PC>
where
    E: Pairing,
    PC: PolynomialCommitmentScheme<E>,
{
    index: PC::Point,
    value_opening_proof: PC::Proof,
    label_opening_proof: Option<PC::Proof>,
}

impl<E, PC> IronSelfAuditProof<E, PC>
where
    E: Pairing,
    PC: PolynomialCommitmentScheme<E>,
{
    pub fn new(
        index: PC::Point,
        value_opening_proof: PC::Proof,
        label_opening_proof: Option<PC::Proof>,
    ) -> Self {
        Self {
            index,
            label_opening_proof,
            value_opening_proof,
        }
    }
}
impl<E, PC> IronSelfAuditProof<E, PC>
where
    E: Pairing,
    PC: PolynomialCommitmentScheme<E>,
{
    pub fn get_index(&self) -> PC::Point {
        self.index.clone()
    }

    pub fn get_label_opening_proof(&self) -> &Option<PC::Proof> {
        &self.label_opening_proof
    }

    pub fn get_value_opening_proof(&self) -> &PC::Proof {
        &self.value_opening_proof
    }
}
