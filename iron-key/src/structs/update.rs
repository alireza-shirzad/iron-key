use arithmetic::virtual_polynomial::VPAuxInfo;
use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use subroutines::{IOPProof, PolynomialCommitmentScheme, poly::DenseOrSparseMLE};
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
    new_reg_eval: E::ScalarField,
    current_reg_eval: E::ScalarField,
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
        new_reg_eval: E::ScalarField,
        current_reg_eval: E::ScalarField,
        opening_proof: MvPCS::BatchProof,
    ) -> Self {
        Self {
            zerocheck_proof,
            zerocheck_aux,
            new_reg_eval,
            current_reg_eval,
            opening_proof,
        }
    }

    pub fn get_zerocheck_proof(&self) -> &IOPProof<E::ScalarField> {
        &self.zerocheck_proof
    }
    pub fn get_zerocheck_aux(&self) -> &VPAuxInfo<E::ScalarField> {
        &self.zerocheck_aux
    }
    pub fn get_new_reg_eval(&self) -> &E::ScalarField {
        &self.new_reg_eval
    }
    pub fn get_current_reg_eval(&self) -> &E::ScalarField {
        &self.current_reg_eval
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
    difference_accumulator: MvPCS::Commitment,
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
        value_commitment: MvPCS::Commitment,
    ) -> Self {
        Self {
            value_commitment,
            difference_accumulator,
        }
    }

    pub fn get_value_commitment(&self) -> &MvPCS::Commitment {
        &self.value_commitment
    }
    pub fn get_difference_accumulator(&self) -> &MvPCS::Commitment {
        &self.difference_accumulator
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
    ) -> Self {
        Self {
            label_commitment,
            update_proof,
        }
    }

    pub fn get_label_commitment(&self) -> &MvPCS::Commitment {
        &self.label_commitment
    }
    pub fn get_update_proof(&self) -> &Option<IronUpdateProof<E, MvPCS>> {
        &self.update_proof
    }
}
