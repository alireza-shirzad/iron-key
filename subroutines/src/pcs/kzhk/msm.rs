//! msm.rs — size-aware MSM wrapper (E: Pairing), same signature shape as
//! arkworks `msm`.
//!
//! Example switch-over:
//!   // old:
//!   // let cj = E::G1::msm(&proof.get_d()[j], &eq_poly.evaluations)?;
//!   // new:
//!   let cj = msm_wrapper_g1::<E>(&proof.get_d()[j], &eq_poly.evaluations)?;
//!
//! Env (optional):
//!   MSM_AUTOTUNE=1
//!   MSM_PHYS_CORES=<int>

use once_cell::sync::OnceCell;
#[cfg(feature = "parallel")]
use rayon::ThreadPoolBuilder;
use std::env;

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::PrimeField;

// ===============================
// Public API (G1 / G2 wrappers)
// ===============================

/// G1 wrapper with `Result` like arkworks' `msm`.
pub fn msm_wrapper_g1<E: Pairing>(
    bases: &[<E::G1 as CurveGroup>::Affine],
    scalars: &[E::ScalarField],
) -> Result<E::G1, usize>
where
    E::ScalarField: PrimeField,
    <E::G1 as CurveGroup>::Affine: AffineRepr<ScalarField = E::ScalarField, Group = E::G1>,
{
    msm_wrapper_affine::<E, <E::G1 as CurveGroup>::Affine>(bases, scalars)
}

/// G2 wrapper with `Result` like arkworks' `msm`.
pub fn msm_wrapper_g2<E: Pairing>(
    bases: &[<E::G2 as CurveGroup>::Affine],
    scalars: &[E::ScalarField],
) -> Result<E::G2, usize>
where
    E::ScalarField: PrimeField,
    <E::G2 as CurveGroup>::Affine: AffineRepr<ScalarField = E::ScalarField, Group = E::G2>,
{
    msm_wrapper_affine::<E, <E::G2 as CurveGroup>::Affine>(bases, scalars)
}

/// Generic affine wrapper tied to `E::ScalarField`. Returns `Result<_, usize>`
/// to match arkworks.
pub fn msm_wrapper_affine<E, A>(bases: &[A], scalars: &[E::ScalarField]) -> Result<A::Group, usize>
where
    E: Pairing,
    E::ScalarField: PrimeField,
    A: AffineRepr<ScalarField = E::ScalarField>,
{
    if bases.len() != scalars.len() {
        return Err(bases.len().min(scalars.len()));
    }

    let n = bases.len();
    let phys = detect_physical_cores();
    let threads = threads_for_n(n, phys);

    let pool = ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .expect("failed to build rayon pool");

    pool.install(|| inner_msm_affine::<A>(bases, scalars))
}

/// Force a specific number of threads (handy for experiments).
pub fn msm_with_threads_affine<E, A>(
    bases: &[A],
    scalars: &[E::ScalarField],
    threads: usize,
) -> Result<A::Group, usize>
where
    E: Pairing,
    E::ScalarField: PrimeField,
    A: AffineRepr<ScalarField = E::ScalarField>,
{
    if bases.len() != scalars.len() {
        return Err(bases.len().min(scalars.len()));
    }
    let pool = ThreadPoolBuilder::new()
        .num_threads(threads.max(1))
        .build()
        .expect("failed to build rayon pool");
    pool.install(|| inner_msm_affine::<A>(bases, scalars))
}
// ===============================
// Inner MSM kernel (swap if you have your own)
// ===============================

#[inline(always)]
fn inner_msm_affine<A>(bases: &[A], scalars: &[A::ScalarField]) -> Result<A::Group, usize>
where
    A: AffineRepr,
    A::ScalarField: PrimeField,
    A::Group: VariableBaseMSM,
{
    // arkworks MSM (projective/group element out)
    <A::Group as VariableBaseMSM>::msm(bases, scalars)
}
// ===============================
// Thread selection
// ===============================

#[derive(Clone, Copy, Debug)]
struct Breakpoints {
    t2: usize,
    t4: usize,
    t8: usize,
    t16: usize,
    cap: usize,
}
static BKPTS: OnceCell<Breakpoints> = OnceCell::new();

fn threads_for_n(n: usize, phys_cores: usize) -> usize {
    let bk = BKPTS.get_or_init(|| {
        if env::var("MSM_AUTOTUNE").ok().as_deref() == Some("1") {
            quick_autotune(phys_cores)
        } else {
            heuristic_breakpoints(phys_cores)
        }
    });

    let mut t = if n < bk.t2 {
        1
    } else if n < bk.t4 {
        2
    } else if n < bk.t8 {
        4
    } else if n < bk.t16 {
        8
    } else {
        16
    };

    t = t.min(bk.cap).max(1);
    t
}

fn heuristic_breakpoints(phys_cores: usize) -> Breakpoints {
    Breakpoints {
        t2: 128,
        t4: 512,
        t8: 2_048,
        t16: 8_192,
        cap: phys_cores.min(16),
    }
}

fn quick_autotune(phys_cores: usize) -> Breakpoints {
    // Placeholder: keep heuristic; replace with a sweep if you want per-curve
    // tuning.
    heuristic_breakpoints(phys_cores)
}

// ===============================
// System helpers
// ===============================

fn detect_physical_cores() -> usize {
    if let Ok(override_val) = env::var("MSM_PHYS_CORES") {
        if let Ok(v) = override_val.parse::<usize>() {
            if v >= 1 {
                return v;
            }
        }
    }
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .max(1)
}

// ===============================
// Tests (optional; adjust curve as needed)
// ===============================
#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Bn254;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::UniformRand;
    use ark_std::test_rng;

    #[test]
    fn msm_wrapper_matches_lengths_and_runs() {
        let mut rng = test_rng();

        // G1
        let n = 83usize;
        let pts_g1: Vec<<<Bn254 as Pairing>::G1 as CurveGroup>::Affine> = (0..n)
            .map(|_| <Bn254 as Pairing>::G1::rand(&mut rng).into_affine())
            .collect();
        let sc: Vec<<Bn254 as Pairing>::ScalarField> = (0..n)
            .map(|_| <Bn254 as Pairing>::ScalarField::rand(&mut rng))
            .collect();

        let _out = msm_wrapper_g1::<Bn254>(&pts_g1, &sc).unwrap();

        // length error
        assert!(msm_wrapper_g1::<Bn254>(&pts_g1[..n - 1], &sc).is_err());
    }
}
