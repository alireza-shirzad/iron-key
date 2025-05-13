use std::{fmt::Debug, hash::Hash};

use ark_ff::PrimeField;
use ark_piop::pcs::PCS;
use errors::VKDError;

// pub(crate) mod kzh;
mod IronKey;
pub mod auditor;
pub mod bb;
pub mod client;
pub mod errors;
pub mod ironkey;
pub mod server;
pub mod structs;
pub mod utils;

type VKDResult<T> = Result<T, VKDError>;

pub trait VKD<F, PC>
where
    F: PrimeField,
    PC: PCS<F>,
{
    type Server: VKDServer<
            F,
            PC,
            Dictionary = Self::Dictionary,
            LookupProof = Self::LookupProof,
            SelfAuditProof = Self::SelfAuditProof,
        >;
    type Auditor: VKDAuditor<
            F,
            PC,
            Dictionary = Self::Dictionary,
            UpdateProof = Self::UpdateProof,
            StateCommitment = Self::StateCommitment,
        >;
    type Client: VKDClient<
            F,
            PC,
            Dictionary = Self::Dictionary,
            LookupProof = Self::LookupProof,
            SelfAuditProof = Self::SelfAuditProof,
        >;
    type Specification: VKDSpecification;
    type PublicParameters;
    type Dictionary: VKDDictionary<F, Label = Self::Label>;
    type Label: VKDLabel<F>;
    type LookupProof;
    type SelfAuditProof;
    type UpdateProof;
    type StateCommitment;
    fn setup(system_spec: Self::Specification) -> VKDResult<Self::PublicParameters>;
}

pub trait VKDServer<F, PC>
where
    F: PrimeField,
    PC: PCS<F>,
{
    type UpdateBatch;
    type StateCommitment;
    type Dictionary: VKDDictionary<F>;
    type BulletinBoard;
    type LookupProof;
    type UpdateProof;
    type SelfAuditProof;
    type ServerKey;
    type PublicParameters: VKDPublicParameters;
    fn init(pp: &Self::PublicParameters) -> Self;
    fn update(
        &mut self,
        update_batch: Self::UpdateBatch,
        bulletin_board: &mut Self::BulletinBoard,
    ) -> VKDResult<()>;
    fn lookup_prove(
        &self,
        label: <Self::Dictionary as VKDDictionary<F>>::Label,
    ) -> VKDResult<(
        <Self::Dictionary as VKDDictionary<F>>::Value,
        Self::LookupProof,
    )>;
    fn self_audit_prove(
        &self,
        label: <Self::Dictionary as VKDDictionary<F>>::Label,
    ) -> VKDResult<Self::SelfAuditProof>;
}

pub trait VKDClient<F, PC>
where
    F: PrimeField,
    PC: PCS<F>,
{
    type Dictionary: VKDDictionary<F>;
    type LookupProof;
    type SelfAuditProof;
    type BulletinBoard;
    fn lookup_verify(
        &self,
        label: <Self::Dictionary as VKDDictionary<F>>::Label,
        value: <Self::Dictionary as VKDDictionary<F>>::Value,
        proof: Self::LookupProof,
        bulletin_board: &Self::BulletinBoard,
    ) -> VKDResult<bool>;

    fn self_audit_verify(
        &self,
        label: <Self::Dictionary as VKDDictionary<F>>::Label,
        proof: Self::SelfAuditProof,
        bulletin_board: &Self::BulletinBoard,
    ) -> VKDResult<bool>;
}

pub trait VKDAuditor<F, PC>
where
    F: PrimeField,
    PC: PCS<F>,
{
    type Dictionary: VKDDictionary<F>;
    type UpdateProof;
    type StateCommitment;
    type BulletinBoard;
    fn verify_update(
        &self,
        state_i: Self::StateCommitment,
        state_i_plus_1: Self::StateCommitment,
        label: <Self::Dictionary as VKDDictionary<F>>::Label,
        proof: Self::UpdateProof,
        bulltin_board: &Self::BulletinBoard,
    ) -> VKDResult<bool>;
}

pub trait VKDDictionary<F: PrimeField> {
    type Label: VKDLabel<F>;
    type Value;
}

pub trait VKDSpecification {
    fn get_capacity(&self) -> usize;
}

pub trait VKDPublicParameters {
    type ServerKey;
    type AuditorKey;
    type ClientKey;

    fn to_server_key(&self) -> Self::ServerKey;
    fn to_auditor_key(&self) -> Self::AuditorKey;
    fn to_client_key(&self) -> Self::ClientKey;
    fn get_capacity(&self) -> usize;
}

pub trait VKDLabel<F: PrimeField>: Debug + Hash + Eq + ToString + Clone {
    fn to_field(&self) -> F;
}
