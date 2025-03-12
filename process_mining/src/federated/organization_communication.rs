use crate::dfg::DirectlyFollowsGraph;
use crate::event_log::Attribute;
use crate::federated::organization_struct::{
    ComputationInstruction, PrivateKeyOrganization, PublicKeyOrganization,
};
use indicatif::ParallelProgressIterator;
use indicatif::ProgressIterator;
use rayon::iter::ParallelIterator;
use rayon::prelude::IntoParallelIterator;
use std::collections::{HashMap, LinkedList};
use tfhe::{FheUint32, FheUint8};

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

    let org_a_encrypted_data: HashMap<String, (Vec<FheUint8>, Vec<FheUint32>)> =
        org_a.encrypt_all_data();
    org_b.set_foreign_case_to_trace(org_a_encrypted_data);
    org_b.compute_all_case_names();
    org_b.find_all_instructions();

    // let mut unfinished = true;

    let edges: Vec<(String, String)> = (0..org_b.get_instructions_len())
        .into_par_iter()
        .progress_count(org_b.get_instructions_len() as u64)
        .filter_map(|pos| {
            let (secret, _) = org_b.compute_next_instruction(pos);
            match org_a.evaluate_secret_to_dfg(secret) {
                None => None,
                Some(val) => Some(val),
            }
        })
        .collect();
    
    org_a.edges_to_dfg(edges)

    // println!("{}", org_b.instructions.clone().len());

    // let org_b_secrets: Vec<(FheUint8, FheUint8)> = instructions.into_iter().map(|i| org_b.compute(i)).collect();
    // let org_b_secrets: Vec<(FheUint8, FheUint8)> = tqdm(instructions.into_iter()).map(|i| org_b.compute(i)).collect();
    //
    // let mut graph: DirectlyFollowsGraph = org_a.evaluate_secrets_to_dfg(org_b_secrets);
    // org_a.recalculate_activity_counts()
    //
    // graph

    // org_a.get_dfg()
}
