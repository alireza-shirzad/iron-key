use std::{collections::HashMap, ops::Add};

use super::IronServer;
use crate::{
    VKD, VKDAuditor, VKDClient, VKDPublicParameters, VKDServer,
    auditor::IronAuditor,
    bb::{BulletinBoard, dummybb::DummyBB},
    client::IronClient,
    ironkey::IronKey,
    structs::{IronLabel, IronSpecification, pp::IronClientKey},
};
use ark_bn254::{Bn254, Fr};
use ark_ff::Field;
use subroutines::pcs::kzhk::KZHK;

#[test]
fn test_server() {
    const LOG_CAPACITY: usize = 16;
    let system_spec = IronSpecification::new(1usize << LOG_CAPACITY, true);
    let pp = IronKey::<Bn254, KZHK<Bn254>, IronLabel>::setup(system_spec).unwrap();
    let mut server: IronServer<Bn254, KZHK<Bn254>, IronLabel> = IronServer::init(&pp);
    let mut client =
        IronClient::<Bn254, IronLabel, KZHK<Bn254>>::init(pp.to_client_key(), IronLabel::new("3"));
    let mut auditor = IronAuditor::<Bn254, IronLabel, KZHK<Bn254>>::init(pp.to_auditor_key());
    let mut bulletin_board = DummyBB::<Bn254, KZHK<Bn254>>::default();

    let update_batch1: HashMap<IronLabel, Fr> = HashMap::from([
        (IronLabel::new("1"), Fr::from(1)),
        (IronLabel::new("2"), Fr::from(2)),
        (IronLabel::new("3"), Fr::from(3)),
    ]);

    server
        .update_reg(&update_batch1, &mut bulletin_board)
        .unwrap();
    let update_batch1: HashMap<IronLabel, Fr> = HashMap::from([
        (IronLabel::new("4"), Fr::from(4)),
        (IronLabel::new("5"), Fr::from(5)),
        (IronLabel::new("6"), Fr::from(6)),
        (IronLabel::new("7"), Fr::from(7)),
    ]);

    server
        .update_keys(&update_batch1, &mut bulletin_board)
        .unwrap();

    let lookup_proof = server
        .lookup_prove(IronLabel::new("1"), &mut bulletin_board)
        .unwrap();
    let _client_res =
        client.lookup_verify(IronLabel::new("1"), Fr::ONE, &lookup_proof, &bulletin_board);
    let _auditor_res = auditor.verify_update(&bulletin_board);
}
