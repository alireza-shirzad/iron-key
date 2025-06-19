use arithmetic::VPAuxInfo;
use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use subroutines::{IOPProof, PolynomialCommitmentScheme};
use subroutines::poly::DenseOrSparseMLE;
#[derive(CanonicalSerialize, Clone)]
pub struct IronUpdateProof<E, MvPCS>
where
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        > + Sync
        + Send,
{
    zerocheck_proof: IOPProof<E::ScalarField>,
    zerocheck_aux: VPAuxInfo<E::ScalarField>,
    opening_proof: MvPCS::BatchProof,
}

impl<E, MvPCS> IronUpdateProof<E, MvPCS>
where
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        > + Sync
        + Send,
{
    pub fn new(
        zerocheck_proof: IOPProof<E::ScalarField>,
        zerocheck_aux: VPAuxInfo<E::ScalarField>,
        opening_proof: MvPCS::BatchProof,
    ) -> Self {
        Self {
            zerocheck_proof,
            zerocheck_aux,
            opening_proof,
        }
    }

    pub fn get_zerocheck_proof(&self) -> &IOPProof<E::ScalarField> {
        &self.zerocheck_proof
    }
    pub fn get_zerocheck_aux(&self) -> &VPAuxInfo<E::ScalarField> {
        &self.zerocheck_aux
    }
    pub fn get_opening_proof(&self) -> &MvPCS::BatchProof {
        &self.opening_proof
    }
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone)]
pub struct IronEpochKeyMessage<E, MvPCS>
where
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        > + Sync
        + Send,
{
    value_commitment: MvPCS::Commitment,
    value_aux: MvPCS::Aux,
    difference_accumulator: MvPCS::Commitment,
    difference_aux: MvPCS::Aux,
}

impl<E, MvPCS> IronEpochKeyMessage<E, MvPCS>
where
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        > + Sync
        + Send,
{
    pub fn new(
        difference_accumulator: MvPCS::Commitment,
        difference_aux: MvPCS::Aux,
        value_commitment: MvPCS::Commitment,
        value_aux: MvPCS::Aux,
    ) -> Self {
        Self {
            value_commitment,
            difference_accumulator,
            value_aux,
            difference_aux,
        }
    }

    pub fn get_value_commitment(&self) -> &MvPCS::Commitment {
        &self.value_commitment
    }
    pub fn get_difference_accumulator(&self) -> &MvPCS::Commitment {
        &self.difference_accumulator
    }
    pub fn get_value_aux(&self) -> &MvPCS::Aux {
        &self.value_aux
    }
    pub fn get_difference_aux(&self) -> &MvPCS::Aux {
        &self.difference_aux
    }
}

#[derive(CanonicalSerialize, Clone)]
pub struct IronEpochRegMessage<E, MvPCS>
where
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        > + Sync
        + Send,
{
    label_commitment: MvPCS::Commitment,
    label_aux: MvPCS::Aux,
    update_proof: Option<IronUpdateProof<E, MvPCS>>,
}

impl<E, MvPCS> IronEpochRegMessage<E, MvPCS>
where
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        > + Sync
        + Send,
{
    pub fn new(
        label_commitment: MvPCS::Commitment,
        update_proof: Option<IronUpdateProof<E, MvPCS>>,
        label_aux: MvPCS::Aux,
    ) -> Self {
        Self {
            label_commitment,
            update_proof,
            label_aux,
        }
    }

    pub fn get_label_commitment(&self) -> &MvPCS::Commitment {
        &self.label_commitment
    }
    pub fn get_update_proof(&self) -> &Option<IronUpdateProof<E, MvPCS>> {
        &self.update_proof
    }
    pub fn get_label_aux(&self) -> &MvPCS::Aux {
        &self.label_aux
    }
}
