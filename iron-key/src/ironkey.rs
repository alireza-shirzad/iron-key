use crate::{
    VKD, VKDLabel, VKDResult, VKDSpecification,
    auditor::IronAuditor,
    client::IronClient,
    server::IronServer,
    structs::{
        dictionary::IronDictionary, lookup::IronLookupProof, self_audit::IronSelfAuditProof,
        update::IronUpdateProof,
    },
};
use ark_ff::PrimeField;
use ark_piop::{
    arithmetic::mat_poly::{lde::LDE, mle::MLE},
    pcs::{PCS, kzg10::KZG10, pst13::PST13},
    setup::KeyGenerator,
};

pub struct IronKey<F, MvPCS, UvPCS, T>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
    T: VKDLabel<F>,
{
    _phantom_f: std::marker::PhantomData<F>,
    _phantom_t: std::marker::PhantomData<T>,
    _phantom_mvpc: std::marker::PhantomData<MvPCS>,
    _phantom_upc: std::marker::PhantomData<UvPCS>,
}

impl<F, MvPCS, UvPCS, T> VKD<F, MvPCS> for IronKey<F, MvPCS, UvPCS, T>
where
    F: PrimeField,
    MvPCS: PCS<F, Poly = MLE<F>>,
    UvPCS: PCS<F, Poly = LDE<F>>,
    T: VKDLabel<F>,
{
    type PublicParameters = ();
    type Server = IronServer<F, MvPCS, UvPCS, T>;
    type Auditor = IronAuditor<F, T>;
    type Client = IronClient<F, T>;
    type Specification = IronSpecification;
    type Dictionary = IronDictionary<F, T>;
    type LookupProof = IronLookupProof<F, MvPCS>;
    type SelfAuditProof = IronSelfAuditProof<F, MvPCS>;
    type UpdateProof = IronUpdateProof<F>;
    type StateCommitment = <MvPCS as PCS<F>>::Commitment;
    type Label = T;

    fn setup(&self, specification: Self::Specification) -> VKDResult<Self::PublicParameters> {
        let capacity = specification.get_capacity();
        let real_capacity = capacity.next_power_of_two();
        let num_vars = real_capacity.trailing_zeros() as usize;
        let key_generator = KeyGenerator::<F, MvPCS, UvPCS>::new().with_num_mv_vars(num_vars);
        let (pk, vk) = key_generator.gen_keys().unwrap();

        todo!()
    }
}

pub struct IronSpecification {
    capacity: usize,
}

impl IronSpecification {
    pub fn new(capacity: usize) -> Self {
        Self { capacity }
    }
}

impl VKDSpecification for IronSpecification {
    fn get_capacity(&self) -> usize {
        self.capacity
    }
}
