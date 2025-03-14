use crate::dfg::DirectlyFollowsGraph;
use crate::federated::organization_struct::{PrivateKeyOrganization, PublicKeyOrganization};
use std::collections::HashMap;
use tfhe::{FheUint16, FheUint32};

pub fn communicate<'a>(
    org_a: &'a mut PrivateKeyOrganization,
    org_b: &'a mut PublicKeyOrganization,
) -> DirectlyFollowsGraph<'a> {
    println!("Start communication");

    let (server_key, public_key) = org_a.get_public_keys();
    org_b.set_public_keys(public_key, server_key);

    let activities_b = org_b.find_activities();
    let agreed_activity_to_pos = org_a.update_with_foreign_activities(activities_b);
    org_b.set_activity_to_pos(agreed_activity_to_pos);

    let org_a_encrypted_data: HashMap<String, (Vec<FheUint16>, Vec<FheUint32>)> =
        org_a.encrypt_all_data();
    org_b.set_foreign_case_to_trace(org_a_encrypted_data);
    org_b.compute_all_case_names();
    let org_b_secrets = org_b.find_all_secrets();
    
    let mut graph: DirectlyFollowsGraph = org_a.evaluate_secrets_to_dfg(org_b_secrets);
    graph.recalculate_activity_counts();
    graph
}
