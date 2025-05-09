use ark_ec::pairing::Pairing;
use ark_piop::{arithmetic::mat_poly::mle::MLE, pcs::PolynomialCommitment};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
#[derive(Default, Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct KZH2Commitment<E: Pairing> {
    /// the commitment C to the polynomial
    pub c: E::G1Affine,
    /// auxiliary data which is in fact Pedersen commitments to rows of the
    /// polynomial
    pub aux: Vec<E::G1>,
}
impl<E: Pairing> PolynomialCommitment<E::ScalarField> for KZH2Commitment<E> {
    fn num_vars(&self) -> usize {
        todo!()
    }
    fn set_num_vars(&mut self, nv: usize) {
        todo!()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct KZH2SRS<E: Pairing> {
    /// degree_x = 2 ^ length of x variable
    pub degree_x: usize,
    /// degree_y = 2 ^ length of y variable
    pub degree_y: usize,

    pub h_xy: Vec<Vec<E::G1Affine>>,
    pub h_y: Vec<E::G1Affine>,

    pub v_x: Vec<E::G2>,

    pub v_prime: E::G2,
}

#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct KZH2Opening<E: Pairing> {
    pub d_x: Vec<E::G1Affine>,
    pub f_star: MLE<E::ScalarField>,
}
impl<E: Pairing> Default for KZH2Opening<E> {
    fn default() -> Self {
        Self {
            d_x: vec![],
            f_star: MLE::default(),
        }
    }
}
