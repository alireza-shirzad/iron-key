// Copyright (c) 2023 Espresso Systems (espressosys.com)
// This file is part of the HyperPlonk library.

// You should have received a copy of the MIT License
// along with the HyperPlonk library. If not, see <https://mit-license.org/>.

//! This module defines structs that are shared by all sub protocols.

use arithmetic::VirtualPolynomial;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/// An IOP proof is a collections of
/// - messages from prover to verifier at each round through the interactive
///   protocol.
/// - a point that is generated by the transcript for evaluation
#[derive(Clone, Debug, Default, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct IOPProof<F: PrimeField> {
    pub point: Vec<F>,
    pub proofs: Vec<IOPProverMessage<F>>,
}


/// A message from the prover to the verifier at a given round
/// is a list of evaluations.
#[derive(Clone, Debug, Default, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct IOPProverMessage<F: PrimeField> {
    pub(crate) evaluations: Vec<F>,
}

/// Prover State of a PolyIOP.
pub struct IOPProverState<F: PrimeField> {
    /// sampled randomness given by the verifier
    pub challenges: Vec<F>,
    /// the current round number
    pub(crate) round: usize,
    /// pointer to the virtual polynomial
    pub(crate) poly: VirtualPolynomial<F>,
    /// points with precomputed barycentric weights for extrapolating smaller
    /// degree uni-polys to `max_degree + 1` evaluations.
    pub(crate) extrapolation_aux: Vec<(Vec<F>, Vec<F>)>,
}

/// Prover State of a PolyIOP
pub struct IOPVerifierState<F: PrimeField> {
    pub(crate) round: usize,
    pub(crate) num_vars: usize,
    pub(crate) max_degree: usize,
    pub(crate) finished: bool,
    /// a list storing the univariate polynomial in evaluation form sent by the
    /// prover at each round
    pub(crate) polynomials_received: Vec<Vec<F>>,
    /// a list storing the randomness sampled by the verifier at each round
    pub(crate) challenges: Vec<F>,
}
