use ark_ff::PrimeField;
use ark_piop::pcs::PCS;

pub struct IronLookupProof<F, PC>
where
    F: PrimeField,
    PC: PCS<F>,
{
    _phantom: F,
    _phantom_pc: PC,
}
