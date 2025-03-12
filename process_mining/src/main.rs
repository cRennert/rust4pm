use process_mining::dfg::DirectlyFollowsGraph;
use process_mining::event_log::event_log_splitter::{ActivityBasedEventLogSplitter, RandomEventLogSplitter};
use process_mining::federated::organization_communication;
use process_mining::federated::organization_struct::{
    PrivateKeyOrganization, PublicKeyOrganization,
};
use std::collections::HashSet;
use std::path::PathBuf;
use quick_xml::reader;
use tfhe::{generate_keys, ConfigBuilder, FheUint8};
use tfhe::array::FheArrayBase;
use tfhe::prelude::*;
// use process_mining::dfg::image_export::export_dfg_image_png;
use process_mining::{export_xes_event_log_to_file_path, import_xes_file, XESImportOptions};
use process_mining::dfg::image_export::export_dfg_image_png;
use process_mining::event_log::export_xes::export_xes_event_log_to_file;

fn get_test_data_path() -> PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("test_data")
}
// fn main() {
//     let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
//         .join("test_data")
//         .join("xes")
//         .join("BPI Challenge 2017 - Offer log.xes");
//     let mut options = XESImportOptions::default();
//     options.sort_events_with_timestamp_key = Some("time:timestamp".to_string());
//     let log = import_xes_file(&path, options).unwrap();
// 
//     // let mut activities_org_a = HashSet::new();
//     // let mut activities_org_b = HashSet::new();
//     // 
//     // activities_org_a.insert("Analyze Defect");
//     // activities_org_a.insert("Archive Repair");
//     // activities_org_a.insert("Inform User");
//     // activities_org_a.insert("Register");
//     //  
//     // activities_org_b.insert("Repair (Complex)");
//     // activities_org_b.insert("Repair (Simple)");
//     // activities_org_b.insert("Restart Repair");
//     // activities_org_b.insert("Test Repair");
// 
//     // let activity_sets = vec![activities_org_a, activities_org_b];
// 
//     let mut splitter = RandomEventLogSplitter::new(&log, 2);
//     let event_logs = splitter.split();
// 
//     // let mut iter = event_logs.into_iter();
//     // 
//     // let event_log_a = iter.next().unwrap();
//     // let event_log_b = iter.next().unwrap();
//     // 
//     // let mut org_a = PrivateKeyOrganization::new(event_log_a);
//     // let mut org_b = PublicKeyOrganization::new(event_log_b);
//     // 
//     // let result: DirectlyFollowsGraph =
//     //     organization_communication::communicate(&mut org_a, &mut org_b);
//     let path_output_A = get_test_data_path().join("export").join("BPI Challenge 2017 - Offer log_A.xes");
//     let path_output_B = get_test_data_path().join("export").join("BPI Challenge 2017 - Offer log_B.xes");
//     
//     export_xes_event_log_to_file_path(&event_logs[0], path_output_A);
//     export_xes_event_log_to_file_path(&event_logs[1], path_output_B);
// }

fn main() {
    // let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
    //     .join("test_data")
    //     .join("xes")
    //     .join("500_traces.xes");
    // let mut options = XESImportOptions::default();
    // options.sort_events_with_timestamp_key = Some("time:timestamp".to_string());
    // let log = import_xes_file(&path, options).unwrap();
    // 
    // let mut activities_org_a = HashSet::new();
    // let mut activities_org_b = HashSet::new();
    // 
    // activities_org_a.insert("Analyze Defect");
    // activities_org_a.insert("Archive Repair");
    // activities_org_a.insert("Inform User");
    // activities_org_a.insert("Register");
    // 
    // activities_org_b.insert("Repair (Complex)");
    // activities_org_b.insert("Repair (Simple)");
    // activities_org_b.insert("Restart Repair");
    // activities_org_b.insert("Test Repair");
    // 
    // let activity_sets = vec![activities_org_a, activities_org_b];
    // 
    // let splitter = ActivityBasedEventLogSplitter::new(&log, &activity_sets);
    // let mut event_logs = splitter.split();
    // 
    // let mut iter = event_logs.into_iter();
    // 
    // let event_log_a = iter.next().unwrap();
    // let event_log_b = iter.next().unwrap();
    
    let mut options = XESImportOptions::default();
    options.sort_events_with_timestamp_key = Some("time:timestamp".to_string());
    
    let path1 = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("test_data")
        .join("xes")
        .join("Sepsis Cases - Event Log_A.xes");
    let event_log_a = import_xes_file(path1, options.clone()).unwrap();
    
    let path2 = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("test_data")
        .join("xes")
        .join("Sepsis Cases - Event Log_B.xes");
    let event_log_b = import_xes_file(path2, options.clone()).unwrap();
    
    let mut org_a = PrivateKeyOrganization::new(event_log_a);
    let mut org_b = PublicKeyOrganization::new(event_log_b);
    
    let result: &DirectlyFollowsGraph =
        organization_communication::communicate(&mut org_a, &mut org_b);
    let path_output = get_test_data_path().join("export").join("Sepsis Cases.png");
    export_dfg_image_png(result, &path_output).unwrap();
}

// fn main_old() {
//     let now = Instant::now();
//     let config = ConfigBuilder::default().build();
//     let (client_key, _) = generate_keys(config);
//     let server_key = tfhe::ServerKey::new(&client_key);
//     let public_key = PublicKey::new(&client_key);
//
//     // Client-side
//     // let (client_key1, server_key1) = generate_keys(config);
//     // let (client_key2, server_key2) = generate_keys(config);
//
//     let mut elapsed = now.elapsed();
//     println!("Elapsed: {:.2?}", elapsed);
//
//     let clear_a = 27u32;
//     let clear_b = 128u32;
//
//     let b = FheUint8::encrypt(clear_b, &public_key);
//     let a = FheUint8::encrypt(clear_a, &public_key);
//
//     //Server-side
//     // set_server_key(&server_key1);
//
//     // println!("{}", b.ge(&a).decrypt(&client_key1));
//
//     // let d: FheUint8 = c.decrypt(&client_key1);
//     // set_server_key(&server_key2);
//     // let e: u32 = d.decrypt(&client_key2);
//     // println!("{}", e);
//
//     set_server_key(server_key);
//
//     let result = a + b;
//
//     let a = FheUint8::encrypt(clear_a, &public_key);
//     let b = FheUint8::encrypt(clear_b, &public_key);
//     let result2 = b.ge(&b);
//     let result2_decrypt = result2.decrypt(&client_key);
//     println!("{}", result2_decrypt);
//
//     //Client-side
//     let decrypted_result: u32 = result.decrypt(&client_key);
//
//     let clear_result = clear_a + clear_b;
//
//     assert_eq!(decrypted_result, clear_result);
//     println!("Success!");
//     println!("{}", clear_result);
//     elapsed = now.elapsed();
//     println!("Elapsed: {:.2?}", elapsed);
// }

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "graphviz-export")]
    use std::path::PathBuf;
    use process_mining::dfg::image_export::export_dfg_image_png;
    use process_mining::{import_xes_file, XESImportOptions};

    fn get_test_data_path() -> PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("test_data")
    }

    #[test]
    fn main_test() {
    }
}
