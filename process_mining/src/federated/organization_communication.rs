use crate::dfg::DirectlyFollowsGraph;
use crate::event_log::Attribute;
use crate::federated::organization_struct::{
    PrivateKeyOrganization, PublicKeyOrganization,
};
use std::collections::{HashMap, LinkedList};
use tfhe::{FheUint32, FheUint8};

pub fn communicate<'a>(
    org_a: &mut PrivateKeyOrganization,
    org_b: &mut PublicKeyOrganization,
) -> DirectlyFollowsGraph<'a> {
    println!("Start communication");

    let (server_key, public_key) = org_a.get_public_keys();
    org_b.set_public_keys(public_key, server_key);

    let activities_b = org_b.find_activities();
    let agreed_activity_to_pos = org_a.update_with_foreign_activities(activities_b);
    org_b.set_activity_to_pos(agreed_activity_to_pos);

    let org_a_encrypted_data: HashMap<Attribute, (Vec<FheUint8>, Vec<FheUint32>)> = org_a.encrypt_all_data();
    let org_b_secrets: Vec<(FheUint8, FheUint8)> = org_b.find_all_conditions(org_a_encrypted_data);

    let mut graph: DirectlyFollowsGraph = org_a.evaluate_secrets_to_dfg(org_b_secrets);
    graph.recalculate_activity_counts();
    
    graph
}
