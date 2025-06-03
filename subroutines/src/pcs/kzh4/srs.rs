use crate::{PCSError, StructuredReferenceString};
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_iter_mut, rand::Rng, UniformRand};
use std::{ops::Mul, sync::Arc};
/// Universal Parameter
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct KZH4UniversalParams<E: Pairing> {
    pub num_vars_x: usize,
    pub num_vars_y: usize,
    pub num_vars_z: usize,
    pub num_vars_t: usize,

    pub h_xyzt: Arc<Vec<E::G1Affine>>,
    pub h_yzt: Arc<Vec<E::G1Affine>>,
    pub h_zt: Arc<Vec<E::G1Affine>>,
    pub h_t: Arc<Vec<E::G1Affine>>,

    pub v_x: Arc<Vec<E::G2Affine>>,
    pub v_y: Arc<Vec<E::G2Affine>>,
    pub v_z: Arc<Vec<E::G2Affine>>,
    pub v_t: Arc<Vec<E::G2Affine>>,

    pub v: E::G2Affine,
}

impl<E: Pairing> KZH4UniversalParams<E> {
    pub fn new(
        num_vars_x: usize,
        num_vars_y: usize,
        num_vars_z: usize,
        num_vars_t: usize,
        h_xyzt: Arc<Vec<E::G1Affine>>,
        h_yzt: Arc<Vec<E::G1Affine>>,
        h_zt: Arc<Vec<E::G1Affine>>,
        h_t: Arc<Vec<E::G1Affine>>,
        v_x: Arc<Vec<E::G2Affine>>,
        v_y: Arc<Vec<E::G2Affine>>,
        v_z: Arc<Vec<E::G2Affine>>,
        v_t: Arc<Vec<E::G2Affine>>,
        v: E::G2Affine,
    ) -> Self {
        Self {
            num_vars_x,
            num_vars_y,
            num_vars_z,
            num_vars_t,
            h_xyzt,
            h_yzt,
            h_zt,
            h_t,
            v_x,
            v_y,
            v_z,
            v_t,
            v,
        }
    }
    pub fn get_num_vars_x(&self) -> usize {
        self.num_vars_x
    }
    pub fn get_num_vars_y(&self) -> usize {
        self.num_vars_y
    }
    pub fn get_num_vars_z(&self) -> usize {
        self.num_vars_z
    }
    pub fn get_num_vars_t(&self) -> usize {
        self.num_vars_t
    }
    pub fn get_h_xyzt(&self) -> Arc<Vec<E::G1Affine>> {
        self.h_xyzt.clone()
    }
    pub fn get_h_yzt(&self) -> Arc<Vec<E::G1Affine>> {
        self.h_yzt.clone()
    }
    pub fn get_h_zt(&self) -> Arc<Vec<E::G1Affine>> {
        self.h_zt.clone()
    }
    pub fn get_h_t(&self) -> Arc<Vec<E::G1Affine>> {
        self.h_t.clone()
    }
    pub fn get_v_x(&self) -> Arc<Vec<E::G2Affine>> {
        self.v_x.clone()
    }
    pub fn get_v_y(&self) -> Arc<Vec<E::G2Affine>> {
        self.v_y.clone()
    }
    pub fn get_v_z(&self) -> Arc<Vec<E::G2Affine>> {
        self.v_z.clone()
    }
    pub fn get_v_t(&self) -> Arc<Vec<E::G2Affine>> {
        self.v_t.clone()
    }
    pub fn get_v(&self) -> E::G2Affine {
        self.v
    }
}

/// Prover Parameters
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct KZH4ProverParam<E: Pairing> {
    num_vars_x: usize,
    num_vars_y: usize,
    num_vars_z: usize,
    num_vars_t: usize,
    h_xyzt: Arc<Vec<E::G1Affine>>,
    h_yzt: Arc<Vec<E::G1Affine>>,
    h_zt: Arc<Vec<E::G1Affine>>,
    h_t: Arc<Vec<E::G1Affine>>,
}
impl<E: Pairing> KZH4ProverParam<E> {
    pub fn new(
        num_vars_x: usize,
        num_vars_y: usize,
        num_vars_z: usize,
        num_vars_t: usize,
        h_xyzt: Arc<Vec<E::G1Affine>>,
        h_yzt: Arc<Vec<E::G1Affine>>,
        h_zt: Arc<Vec<E::G1Affine>>,
        h_t: Arc<Vec<E::G1Affine>>,
    ) -> Self {
        Self {
            num_vars_x,
            num_vars_y,
            num_vars_z,
            num_vars_t,
            h_xyzt,
            h_yzt,
            h_zt,
            h_t,
        }
    }
    pub fn get_num_vars_x(&self) -> usize {
        self.num_vars_x
    }
    pub fn get_num_vars_y(&self) -> usize {
        self.num_vars_y
    }
    pub fn get_num_vars_z(&self) -> usize {
        self.num_vars_z
    }
    pub fn get_num_vars_t(&self) -> usize {
        self.num_vars_t
    }
    pub fn get_h_xyzt(&self) -> Arc<Vec<E::G1Affine>> {
        self.h_xyzt.clone()
    }
    pub fn get_h_yzt(&self) -> Arc<Vec<E::G1Affine>> {
        self.h_yzt.clone()
    }
    pub fn get_h_zt(&self) -> Arc<Vec<E::G1Affine>> {
        self.h_zt.clone()
    }
    pub fn get_h_t(&self) -> Arc<Vec<E::G1Affine>> {
        self.h_t.clone()
    }
}

/// Verifier Parameters
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct KZH4VerifierParam<E: Pairing> {
    num_vars_x: usize,
    num_vars_y: usize,
    num_vars_z: usize,
    num_vars_t: usize,
    h_t: Arc<Vec<E::G1Affine>>,
    v_x: Arc<Vec<E::G2Affine>>,
    v_y: Arc<Vec<E::G2Affine>>,
    v_z: Arc<Vec<E::G2Affine>>,
    v_t: Arc<Vec<E::G2Affine>>,
    v: E::G2Affine,
}

impl<E: Pairing> KZH4VerifierParam<E> {
    pub fn new(
        num_vars_x: usize,
        num_vars_y: usize,
        num_vars_z: usize,
        num_vars_t: usize,
        h_t: Arc<Vec<E::G1Affine>>,
        v_x: Arc<Vec<E::G2Affine>>,
        v_y: Arc<Vec<E::G2Affine>>,
        v_z: Arc<Vec<E::G2Affine>>,
        v_t: Arc<Vec<E::G2Affine>>,
        v: E::G2Affine,
    ) -> Self {
        Self {
            num_vars_x,
            num_vars_y,
            num_vars_z,
            num_vars_t,
            h_t,
            v_x,
            v_y,
            v_z,
            v_t,
            v,
        }
    }

    pub fn get_num_vars_x(&self) -> usize {
        self.num_vars_x
    }
    pub fn get_num_vars_y(&self) -> usize {
        self.num_vars_y
    }
    pub fn get_num_vars_z(&self) -> usize {
        self.num_vars_z
    }
    pub fn get_num_vars_t(&self) -> usize {
        self.num_vars_t
    }
    pub fn get_h_t(&self) -> Arc<Vec<E::G1Affine>> {
        self.h_t.clone()
    }
    pub fn get_v_x(&self) -> Arc<Vec<E::G2Affine>> {
        self.v_x.clone()
    }
    pub fn get_v_y(&self) -> Arc<Vec<E::G2Affine>> {
        self.v_y.clone()
    }
    pub fn get_v_z(&self) -> Arc<Vec<E::G2Affine>> {
        self.v_z.clone()
    }
    pub fn get_v_t(&self) -> Arc<Vec<E::G2Affine>> {
        self.v_t.clone()
    }
    pub fn get_v(&self) -> E::G2Affine {
        self.v
    }
}

impl<E: Pairing> StructuredReferenceString<E> for KZH4UniversalParams<E> {
    type ProverParam = KZH4ProverParam<E>;
    type VerifierParam = KZH4VerifierParam<E>;

    /// Extract the prover parameters from the public parameters.
    fn extract_prover_param(&self, supported_num_vars: usize) -> Self::ProverParam {
        assert_eq!(
            supported_num_vars,
            self.num_vars_x + self.num_vars_y + self.num_vars_z + self.num_vars_t
        );
        KZH4ProverParam::new(
            self.num_vars_x,
            self.num_vars_y,
            self.num_vars_z,
            self.num_vars_t,
            self.h_xyzt.clone(),
            self.h_yzt.clone(),
            self.h_zt.clone(),
            self.h_t.clone(),
        )
    }

    /// Extract the verifier parameters from the public parameters.
    fn extract_verifier_param(&self, supported_num_vars: usize) -> Self::VerifierParam {
        assert_eq!(
            supported_num_vars,
            self.num_vars_x + self.num_vars_y + self.num_vars_z + self.num_vars_t
        );
        KZH4VerifierParam::new(
            self.num_vars_x,
            self.num_vars_y,
            self.num_vars_z,
            self.num_vars_t,
            self.h_t.clone(),
            self.v_x.clone(),
            self.v_y.clone(),
            self.v_z.clone(),
            self.v_t.clone(),
            self.v,
        )
    }

    fn trim(
        &self,
        supported_num_vars: usize,
    ) -> Result<(Self::ProverParam, Self::VerifierParam), PCSError> {
        Ok((
            self.extract_prover_param(supported_num_vars),
            self.extract_verifier_param(supported_num_vars),
        ))
    }

    fn gen_srs_for_testing<R: Rng>(rng: &mut R, num_vars: usize) -> Result<Self, PCSError> {
        let (num_vars_x, num_vars_y, num_vars_z, num_vars_t) =
            Self::get_num_vars_from_maximum_num_vars(num_vars);
        let (degree_x, degree_y, degree_z, degree_t) = (
            1 << num_vars_x,
            1 << num_vars_y,
            1 << num_vars_z,
            1 << num_vars_t,
        );

        let (g, v) = (E::G1Affine::rand(rng), E::G2Affine::rand(rng));
        let tau_x: Vec<E::ScalarField> = (0..degree_x).map(|_| E::ScalarField::rand(rng)).collect();
        let tau_y: Vec<E::ScalarField> = (0..degree_y).map(|_| E::ScalarField::rand(rng)).collect();
        let tau_z: Vec<E::ScalarField> = (0..degree_z).map(|_| E::ScalarField::rand(rng)).collect();
        let tau_t: Vec<E::ScalarField> = (0..degree_t).map(|_| E::ScalarField::rand(rng)).collect();
        let mut h_xyzt = vec![E::G1Affine::zero(); degree_x * degree_y * degree_z * degree_t];
        let mut h_yzt = vec![E::G1Affine::zero(); degree_y * degree_z * degree_t];
        let mut h_zt = vec![E::G1Affine::zero(); degree_z * degree_t];
        let mut h_t = vec![E::G1Affine::zero(); degree_t];

        let mut v_x = vec![E::G2Affine::zero(); degree_x];
        let mut v_y = vec![E::G2Affine::zero(); degree_y];
        let mut v_z = vec![E::G2Affine::zero(); degree_z];
        let mut v_t = vec![E::G2Affine::zero(); degree_t];

        // ───────────── parallel (Rayon) version ─────────────────────────────────────
        #[cfg(feature = "parallel")]
        {
            use rayon::prelude::*;

            rayon::scope(|s| {
                // ---------------- h_xyzt ----------------
                s.spawn(|_| {
                    h_xyzt.par_iter_mut().enumerate().for_each(|(i, slot)| {
                        let (i_x, i_y, i_z, i_t) =
                            Self::decompose_index(i, degree_y, degree_z, degree_t);

                        let scalar = tau_x[i_x] * tau_y[i_y] * tau_z[i_z] * tau_t[i_t];

                        *slot = g.mul(scalar).into();
                    });
                });

                // ---------------- h_yzt -----------------
                s.spawn(|_| {
                    h_yzt.par_iter_mut().enumerate().for_each(|(i, slot)| {
                        let i_y = i / (degree_z * degree_t);
                        let rem = i % (degree_z * degree_t);
                        let i_z = rem / degree_t;
                        let i_t = rem % degree_t;

                        let scalar = tau_y[i_y] * tau_z[i_z] * tau_t[i_t];
                        *slot = g.mul(scalar).into();
                    });
                });

                // ---------------- h_zt ------------------
                s.spawn(|_| {
                    h_zt.par_iter_mut().enumerate().for_each(|(i, slot)| {
                        let i_z = i / degree_t;
                        let i_t = i % degree_t;

                        let scalar = tau_z[i_z] * tau_t[i_t];
                        *slot = g.mul(scalar).into();
                    });
                });

                // ---------------- h_t -------------------
                s.spawn(|_| {
                    h_t.par_iter_mut().enumerate().for_each(|(i, slot)| {
                        *slot = g.mul(tau_t[i]).into();
                    });
                });

                // ---------------- v_x -------------------
                s.spawn(|_| {
                    v_x.par_iter_mut().enumerate().for_each(|(i, slot)| {
                        *slot = v.mul(tau_x[i]).into();
                    });
                });

                // ---------------- v_y -------------------
                s.spawn(|_| {
                    v_y.par_iter_mut().enumerate().for_each(|(i, slot)| {
                        *slot = v.mul(tau_y[i]).into();
                    });
                });

                // ---------------- v_z -------------------
                s.spawn(|_| {
                    v_z.par_iter_mut().enumerate().for_each(|(i, slot)| {
                        *slot = v.mul(tau_z[i]).into();
                    });
                });

                // ---------------- v_t -------------------
                s.spawn(|_| {
                    v_t.par_iter_mut().enumerate().for_each(|(i, slot)| {
                        *slot = v.mul(tau_t[i]).into();
                    });
                });
            });
        }

        // ───────────── sequential fallback (no "parallel" feature) ──────────────────
        #[cfg(not(feature = "parallel"))]
        {
            cfg_iter_mut!(h_xyzt).enumerate().for_each(|(i, slot)| {
                let (i_x, i_y, i_z, i_t) = Self::decompose_index(i, degree_y, degree_z, degree_t);
                *slot = g
                    .mul(tau_x[i_x] * tau_y[i_y] * tau_z[i_z] * tau_t[i_t])
                    .into();
            });

            cfg_iter_mut!(h_yzt).enumerate().for_each(|(i, slot)| {
                let i_y = i / (degree_z * degree_t);
                let rem = i % (degree_z * degree_t);
                let i_z = rem / degree_t;
                let i_t = rem % degree_t;
                *slot = g.mul(tau_y[i_y] * tau_z[i_z] * tau_t[i_t]).into();
            });

            cfg_iter_mut!(h_zt).enumerate().for_each(|(i, slot)| {
                let i_z = i / degree_t;
                let i_t = i % degree_t;
                *slot = g.mul(tau_z[i_z] * tau_t[i_t]).into();
            });

            cfg_iter_mut!(h_t).enumerate().for_each(|(i, slot)| {
                *slot = g.mul(tau_t[i]).into();
            });

            cfg_iter_mut!(v_x).enumerate().for_each(|(i, slot)| {
                *slot = v.mul(tau_x[i]).into();
            });

            cfg_iter_mut!(v_y).enumerate().for_each(|(i, slot)| {
                *slot = v.mul(tau_y[i]).into();
            });

            cfg_iter_mut!(v_z).enumerate().for_each(|(i, slot)| {
                *slot = v.mul(tau_z[i]).into();
            });

            cfg_iter_mut!(v_t).enumerate().for_each(|(i, slot)| {
                *slot = v.mul(tau_t[i]).into();
            });
        }

        let h_xyzt = Arc::new(h_xyzt);
        let h_yzt = Arc::new(h_yzt);
        let h_zt = Arc::new(h_zt);
        let h_t = Arc::new(h_t);
        let v_x = Arc::new(v_x);
        let v_y = Arc::new(v_y);
        let v_z = Arc::new(v_z);
        let v_t = Arc::new(v_t);
        Ok(KZH4UniversalParams {
            num_vars_x,
            num_vars_y,
            num_vars_z,
            num_vars_t,
            h_xyzt,
            h_yzt,
            h_zt,
            h_t,
            v_x,
            v_y,
            v_z,
            v_t,
            v,
        })
    }
}

impl<E: Pairing> KZH4UniversalParams<E> {
    fn get_num_vars_from_maximum_num_vars(n: usize) -> (usize, usize, usize, usize) {
        match n % 4 {
            0 => (n / 4, n / 4, n / 4, n / 4),
            1 => (n / 4 + 1, n / 4, n / 4, n / 4),
            2 => (n / 4 + 1, n / 4 + 1, n / 4, n / 4),
            3 => (n / 4 + 1, n / 4 + 1, n / 4 + 1, n / 4),
            _ => unreachable!(),
        }
    }

    fn decompose_index(
        i: usize,
        degree_y: usize,
        degree_z: usize,
        degree_t: usize,
    ) -> (usize, usize, usize, usize) {
        // Compute i_z first, as it is the highest order term
        let i_x = i / (degree_y * degree_z * degree_t);

        // Compute the remainder after removing the contribution of i_z
        let remainder = i % (degree_y * degree_z * degree_t);

        // Compute i_y next, as it is the middle order term
        let i_y = remainder / (degree_z * degree_t);

        // Finally, compute i_x as the lowest order term
        let remainder = remainder % (degree_z * degree_t);

        let i_z = remainder / degree_t;

        let i_t = remainder % degree_t;

        (i_x, i_y, i_z, i_t)
    }
}
