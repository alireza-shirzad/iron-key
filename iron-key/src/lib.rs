use errors::VKDError;

// pub(crate) mod kzh;
pub mod auditor;
pub mod client;
pub mod errors;
pub mod server;
pub mod structs;
pub mod utils;

type VKDResult<T> = Result<T, VKDError>;

pub trait VKD {
    type PublicParameters;
    type Server: IsServer<
            Dictionary = Self::Dictionary,
            LookupProof = Self::LookupProof,
            SelfAuditProof = Self::SelfAuditProof,
        >;
    type Auditor: IsAuditor<
            Dictionary = Self::Dictionary,
            UpdateProof = Self::UpdateProof,
            StateCommitment = Self::StateCommitment,
        >;
    type Client: IsClient<
            Dictionary = Self::Dictionary,
            LookupProof = Self::LookupProof,
            SelfAuditProof = Self::SelfAuditProof,
        >;
    type Specification;
    type Dictionary: IsDictionary;
    type LookupProof;
    type SelfAuditProof;
    type UpdateProof;
    type StateCommitment;
    fn setup(&self, system_spec: Self::Specification) -> VKDResult<Self::PublicParameters>;
}

pub trait IsServer {
    type UpdateBatch;
    type StateCommitment;
    type Dictionary: IsDictionary;
    type LookupProof;
    type UpdateProof;
    type SelfAuditProof;
    fn init(&self) -> Self::StateCommitment;
    fn update(&self, update_batch: Self::UpdateBatch) -> VKDResult<Self::StateCommitment>;
    fn lookup_prove(
        &self,
        label: <Self::Dictionary as IsDictionary>::Label,
    ) -> VKDResult<(<Self::Dictionary as IsDictionary>::Value, Self::LookupProof)>;
    fn self_audit_prove(
        &self,
        label: <Self::Dictionary as IsDictionary>::Label,
    ) -> VKDResult<Self::SelfAuditProof>;
}

pub trait IsClient {
    type Dictionary: IsDictionary;
    type LookupProof;
    type SelfAuditProof;
    fn lookup_verify(
        &self,
        label: <Self::Dictionary as IsDictionary>::Label,
        value: <Self::Dictionary as IsDictionary>::Value,
        proof: Self::LookupProof,
    ) -> VKDResult<bool>;

    fn self_audit_verify(
        &self,
        label: <Self::Dictionary as IsDictionary>::Label,
        proof: Self::SelfAuditProof,
    ) -> VKDResult<bool>;
}

pub trait IsAuditor {
    type Dictionary: IsDictionary;
    type UpdateProof;
    type StateCommitment;
    fn verify_update(
        &self,
        state_i: Self::StateCommitment,
        state_i_plus_1: Self::StateCommitment,
        label: <Self::Dictionary as IsDictionary>::Label,
        proof: Self::UpdateProof,
    ) -> VKDResult<bool>;
}

pub trait IsDictionary {
    type Label;
    type Value;
}
