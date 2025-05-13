use std::{collections::HashMap, ops::Add};

use super::IronServer;
use crate::{
    IronKey::IronKey,
    VKD, VKDServer,
    bb::{BulletinBoard, dummybb::DummyBB},
    structs::{IronLabel, IronSpecification},
};
use ark_bls12_381::{Bls12_381, Fr};
use ark_piop::pcs::{kzg10::KZG10, pst13::PST13};



#[test]
fn test_server() {
    // const LOG_CAPACITY: usize = 6;
    // let system_spec = IronSpecification::new(1 << LOG_CAPACITY);
    // let pp =
    //     IronKey::<Fr, PST13<Bls12_381>, KZG10<Bls12_381>, IronLabel>::setup(system_spec).unwrap();
    // let mut server: IronServer<Fr, PST13<Bls12_381>, KZG10<Bls12_381>, IronLabel> =
    //     IronServer::init(&pp);
    // let mut bulletin_board = DummyBB::default();

    // let update_batch: HashMap<IronLabel, Fr> = HashMap::from([
    //     (IronLabel::new("1"), Fr::from(1)),
    //     (IronLabel::new("2"), Fr::from(2)),
    //     (IronLabel::new("3"), Fr::from(3)),
    // ]);

    // server.update(update_batch, &mut bulletin_board).unwrap();
}
