use std::{collections::HashMap, ops::Add};

use super::IronServer;
use crate::{
    VKD, VKDServer,
    bb::{BulletinBoard, dummybb::DummyBB},
    ironkey::IronKey,
    structs::{IronLabel, IronSpecification},
};
use ark_bls12_381::{Bls12_381, Fr};
use subroutines::pcs::kzh::KZH2;

#[test]
fn test_server() {
    const LOG_CAPACITY: usize = 26;
    let system_spec = IronSpecification::new(1 << LOG_CAPACITY);
    let pp = IronKey::<Bls12_381, KZH2<Bls12_381>, IronLabel>::setup(system_spec).unwrap();
    let mut server: IronServer<Bls12_381, KZH2<Bls12_381>, IronLabel> = IronServer::init(&pp);
    let mut bulletin_board = DummyBB::<Bls12_381, KZH2<Bls12_381>>::default();

    let update_batch1: HashMap<IronLabel, Fr> = HashMap::from([
        (IronLabel::new("1"), Fr::from(1)),
        (IronLabel::new("2"), Fr::from(2)),
        (IronLabel::new("3"), Fr::from(3)),
    ]);

    server.update(update_batch1, &mut bulletin_board).unwrap();
    let bb_size_1 = bulletin_board.size();
    let update_batch1: HashMap<IronLabel, Fr> = HashMap::from([
        (IronLabel::new("4"), Fr::from(4)),
        (IronLabel::new("5"), Fr::from(5)),
        (IronLabel::new("6"), Fr::from(6)),
        (IronLabel::new("7"), Fr::from(7)),
    ]);

    server.update(update_batch1, &mut bulletin_board).unwrap();
    let bb_size_2 = bulletin_board.size();
    println!("Per epoch size: {}", bb_size_2 - bb_size_1);
}
