pub(crate) mod errors;

use ark_ec::pairing::Pairing;
use ark_ff::{Field, PrimeField};

use ark_poly::{DenseMultilinearExtension, Polynomial};
use subroutines::{PolynomialCommitmentScheme, pcs::kzh::poly::DenseOrSparseMLE};

use crate::{
    VKDClient, VKDDictionary, VKDLabel, VKDResult,
    bb::{BulletinBoard, dummybb::DummyBB},
    errors::VKDError,
    structs::{
        dictionary::IronDictionary, lookup::IronLookupProof, pp::IronClientKey,
        self_audit::IronSelfAuditProof,
    },
};

pub struct IronClient<
    E: Pairing,
    T: VKDLabel<E>,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        >,
> {
    key: IronClientKey<E, MvPCS>,
    index: Option<<MvPCS::Polynomial as Polynomial<E::ScalarField>>::Point>,
    label: T,
    _phantom_t: T,
}

impl<E, T, MvPCS> VKDClient<E, MvPCS> for IronClient<E, T, MvPCS>
where
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        > + Send
        + Sync,
    T: VKDLabel<E>,
{
    type Dictionary = IronDictionary<E, T>;
    type ClientKey = IronClientKey<E, MvPCS>;
    type LookupProof = IronLookupProof<E, MvPCS>;

    type SelfAuditProof = IronSelfAuditProof<E, MvPCS>;
    type BulletinBoard = DummyBB<E, MvPCS>;
    fn get_label(&self) -> <Self::Dictionary as VKDDictionary<E>>::Label {
        self.label.clone()
    }

    fn lookup_verify(
        &mut self,
        value: <Self::Dictionary as VKDDictionary<E>>::Value,
        proof: Self::LookupProof,
        bulletin_board: &Self::BulletinBoard,
    ) -> VKDResult<()> {
        // let last_epoch_message = bulletin_board.read_last()?;
        // let last_value_commitment = last_epoch_message
        //     .get_dictionary_commitment()
        //     .value_commitment();
        // MvPCS::verify(
        //     &self.key.get_snark_vk().mv_pcs_vk,
        //     last_value_commitment,
        //     &proof.get_index(),
        //     &value,
        //     proof.get_value_opening_proof(),
        // )
        // .map_err(|_| VKDError::ClientError(errors::ClientError::LookupFailed))?;

        // self.check_index(
        //     proof.get_label_opening_proof(),
        //     last_epoch_message
        //         .get_dictionary_commitment()
        //         .label_commitment(),
        //     &proof.get_index(),
        // )?;
        todo!();
        Ok(())
    }

    fn self_audit_verify(
        &mut self,
        proof: Self::SelfAuditProof,
        bulletin_board: &Self::BulletinBoard,
    ) -> VKDResult<()> {
        // let last_epoch_message = bulletin_board.read_last()?;
        // let last_accumulator = last_epoch_message.get_difference_accumulator();
        // MvPCS::verify(
        //     &self.key.get_snark_vk().mv_pcs_vk,
        //     last_accumulator,
        //     &proof.get_index(),
        //     &E::ScalarField::zero(),
        //     proof.get_value_opening_proof(),
        // )
        // .map_err(|_| VKDError::ClientError(errors::ClientError::SelfAuditFailed))?;

        // self.check_index(
        //     proof.get_label_opening_proof(),
        //     last_epoch_message
        //         .get_dictionary_commitment()
        //         .label_commitment(),
        //     &proof.get_index(),
        // )?;

        todo!();
        Ok(())
    }
}

impl<E, T, MvPCS> IronClient<E, T, MvPCS>
where
    E: Pairing,
    MvPCS: PolynomialCommitmentScheme<
            E,
            Polynomial = DenseOrSparseMLE<E::ScalarField>,
            Point = Vec<<E as Pairing>::ScalarField>,
        >,
    T: VKDLabel<E>,
{
    fn check_index(
        &mut self,
        label_opening_proof: &Option<MvPCS::Proof>,
        label_commitment: &MvPCS::Commitment,
        claimed_index: &<MvPCS::Polynomial as Polynomial<E::ScalarField>>::Point,
    ) -> VKDResult<()> {
        // if self.index.is_none() {
        //     match label_opening_proof {
        //         Some(opening_proof) => {
        //             MvPCS::verify(
        //                 &self.key.get_snark_vk().mv_pcs_vk,
        //                 label_commitment,
        //                 claimed_index,
        //                 &self.get_label().to_field(),
        //                 opening_proof,
        //             )
        //             .map_err(|_|
        // VKDError::ClientError(errors::ClientError::UnknownIndex))?;
        //         },
        //         None => {
        //             return
        // Err(VKDError::ClientError(errors::ClientError::UnknownIndex));
        //         },
        //     }
        // }
        todo!();
        Ok(())
    }
}
