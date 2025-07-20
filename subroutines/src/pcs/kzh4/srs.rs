use std::sync::Arc;

use crate::{PCSError, StructuredReferenceString};
use ark_ec::{pairing::Pairing, CurveGroup, ScalarMul};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    cfg_into_iter, cfg_iter, cfg_iter_mut, end_timer, rand::Rng, start_timer, UniformRand, Zero,
};
#[cfg(feature = "parallel")]
use rayon::iter::{
    IndexedParallelIterator, IntoParallelIterator, IntoParallelRefIterator,
    IntoParallelRefMutIterator, ParallelIterator,
};
/// Universal Parameter
#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct KZH4UniversalParams<E: Pairing> {
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

    minus_v: E::G2Affine,
}

impl<E: Pairing> KZH4UniversalParams<E> {
    /// Create a new universal parameter
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

        minus_v: E::G2Affine,
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
            minus_v,
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
    pub fn get_minus_v(&self) -> E::G2Affine {
        self.minus_v
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
    minus_v: E::G2Affine,
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
        minus_v: E::G2Affine,
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
            minus_v,
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
    pub fn get_minus_v(&self) -> E::G2Affine {
        self.minus_v
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
            self.minus_v,
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

        // Note: Your code uses E::G1::rand(rng) which is likely Projective.
        // If batch_mul is a method on Affine, you might need g.into() or g_affine =
        // g.into() For this example, I'm assuming g and v are the correct types
        // expected by batch_mul. If batch_mul is a method on Projective (as in
        // my placeholder), this is fine.
        let g_proj = E::G1::rand(rng); // Assuming G1 is Projective type
        let v_proj = E::G2::rand(rng); // Assuming G2 is Projective type

        let tau_x: Vec<E::ScalarField> = (0..degree_x).map(|_| E::ScalarField::rand(rng)).collect();
        let tau_y: Vec<E::ScalarField> = (0..degree_y).map(|_| E::ScalarField::rand(rng)).collect();
        let tau_z: Vec<E::ScalarField> = (0..degree_z).map(|_| E::ScalarField::rand(rng)).collect();
        let tau_t: Vec<E::ScalarField> = (0..degree_t).map(|_| E::ScalarField::rand(rng)).collect();

        // These variables will be assigned the results from the parallel/sequential
        // blocks.
        let h_xyzt: Vec<E::G1Affine>;
        let h_yzt: Vec<E::G1Affine>;
        let h_zt: Vec<E::G1Affine>;
        let h_t: Vec<E::G1Affine>;
        let v_x: Vec<E::G2Affine>;
        let v_y: Vec<E::G2Affine>;
        let v_z: Vec<E::G2Affine>;
        let v_t: Vec<E::G2Affine>;

        // Shadow references for captures. Note: these are now for projective types.
        let g_base_ref = &g_proj;
        let v_base_ref = &v_proj;
        let tau_x_s = &tau_x;
        let tau_y_s = &tau_y;
        let tau_z_s = &tau_z;
        let tau_t_s = &tau_t;

        #[cfg(feature = "parallel")]
        {
            use rayon::prelude::*;

            // Define closures for each computation. Each returns its respective Vec.
            let task_h_xyzt = || {
                let mut scalars =
                    vec![E::ScalarField::zero(); degree_x * degree_y * degree_z * degree_t];
                scalars.par_iter_mut().enumerate().for_each(|(i, slot)| {
                    let (i_x, i_y, i_z, i_t) =
                        Self::decompose_index(i, degree_y, degree_z, degree_t);
                    *slot = tau_x_s[i_x] * tau_y_s[i_y] * tau_z_s[i_z] * tau_t_s[i_t];
                });
                g_base_ref.batch_mul(&scalars)
            };

            let task_h_yzt = || {
                let mut scalars = vec![E::ScalarField::zero(); degree_y * degree_z * degree_t];
                scalars.par_iter_mut().enumerate().for_each(|(i, slot)| {
                    let i_y = i / (degree_z * degree_t);
                    let rem = i % (degree_z * degree_t);
                    let i_z = rem / degree_t;
                    let i_t = rem % degree_t;
                    *slot = tau_y_s[i_y] * tau_z_s[i_z] * tau_t_s[i_t];
                });
                g_base_ref.batch_mul(&scalars)
            };

            let task_h_zt = || {
                let mut scalars = vec![E::ScalarField::zero(); degree_z * degree_t];
                scalars.par_iter_mut().enumerate().for_each(|(i, slot)| {
                    let i_z = i / degree_t;
                    let i_t = i % degree_t;
                    *slot = tau_z_s[i_z] * tau_t_s[i_t];
                });
                g_base_ref.batch_mul(&scalars)
            };

            let task_h_t = || g_base_ref.batch_mul(tau_t_s);
            let task_v_x = || v_base_ref.batch_mul(tau_x_s);
            let task_v_y = || v_base_ref.batch_mul(tau_y_s);
            let task_v_z = || v_base_ref.batch_mul(tau_z_s);
            let task_v_t = || v_base_ref.batch_mul(tau_t_s);

            // Use nested rayon::join to execute tasks in parallel and get results.
            // join(A, join(B, join(C, D))) pattern is common for >2 tasks.
            let (
                res_h_xyzt,
                (res_h_yzt, (res_h_zt, (res_h_t, (res_v_x, (res_v_y, (res_v_z, res_v_t)))))),
            ) = rayon::join(task_h_xyzt, || {
                rayon::join(task_h_yzt, || {
                    rayon::join(task_h_zt, || {
                        rayon::join(task_h_t, || {
                            rayon::join(task_v_x, || {
                                rayon::join(task_v_y, || rayon::join(task_v_z, task_v_t))
                            })
                        })
                    })
                })
            });

            h_xyzt = res_h_xyzt;
            h_yzt = res_h_yzt;
            h_zt = res_h_zt;
            h_t = res_h_t;
            v_x = res_v_x;
            v_y = res_v_y;
            v_z = res_v_z;
            v_t = res_v_t;
        }
        #[cfg(not(feature = "parallel"))]
        {
            // Sequential version
            let mut scalars_h_xyzt =
                vec![E::ScalarField::zero(); degree_x * degree_y * degree_z * degree_t];
            scalars_h_xyzt.iter_mut().enumerate().for_each(|(i, slot)| {
                let (i_x, i_y, i_z, i_t) = Self::decompose_index(i, degree_y, degree_z, degree_t);
                *slot = tau_x_s[i_x] * tau_y_s[i_y] * tau_z_s[i_z] * tau_t_s[i_t];
            });
            h_xyzt = g_base_ref.batch_mul(&scalars_h_xyzt);

            let mut scalars_h_yzt = vec![E::ScalarField::zero(); degree_y * degree_z * degree_t];
            scalars_h_yzt.iter_mut().enumerate().for_each(|(i, slot)| {
                let i_y = i / (degree_z * degree_t);
                let rem = i % (degree_z * degree_t);
                let i_z = rem / degree_t;
                let i_t = rem % degree_t;
                *slot = tau_y_s[i_y] * tau_z_s[i_z] * tau_t_s[i_t];
            });
            h_yzt = g_base_ref.batch_mul(&scalars_h_yzt);

            let mut scalars_h_zt = vec![E::ScalarField::zero(); degree_z * degree_t];
            scalars_h_zt.iter_mut().enumerate().for_each(|(i, slot)| {
                let i_z = i / degree_t;
                let i_t = i % degree_t;
                *slot = tau_z_s[i_z] * tau_t_s[i_t];
            });
            h_zt = g_base_ref.batch_mul(&scalars_h_zt);

            h_t = g_base_ref.batch_mul(tau_t_s);
            v_x = v_base_ref.batch_mul(tau_x_s);
            v_y = v_base_ref.batch_mul(tau_y_s);
            v_z = v_base_ref.batch_mul(tau_z_s);
            v_t = v_base_ref.batch_mul(tau_t_s);
        }

        let h_xyzt_arc = Arc::new(h_xyzt);
        let h_yzt_arc = Arc::new(h_yzt);
        let h_zt_arc = Arc::new(h_zt);
        let h_t_arc = Arc::new(h_t);
        let v_x_arc = Arc::new(v_x);
        let v_y_arc = Arc::new(v_y);
        let v_z_arc = Arc::new(v_z);
        let v_t_arc = Arc::new(v_t);

        Ok(KZH4UniversalParams {
            num_vars_x,
            num_vars_y,
            num_vars_z,
            num_vars_t,
            h_xyzt: h_xyzt_arc,
            h_yzt: h_yzt_arc,
            h_zt: h_zt_arc,
            h_t: h_t_arc,
            v_x: v_x_arc,
            v_y: v_y_arc,
            v_z: v_z_arc,
            v_t: v_t_arc,
            minus_v: (-v_proj).into(), /* Convert final v to affine if KZH4UniversalParams
                                        * expects affine */
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
