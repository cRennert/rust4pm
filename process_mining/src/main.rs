use process_mining::dfg::image_export::export_dfg_image_png;
use process_mining::dfg::DirectlyFollowsGraph;
use process_mining::federated::organization_communication;
use process_mining::federated::organization_struct::{
    PrivateKeyOrganization, PublicKeyOrganization,
};
use process_mining::{import_xes_file, XESImportOptions};
use std::env;
use std::path::PathBuf;

fn get_test_data_path() -> PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("test_data")
}
fn main() {

    //read args
    let mut args: Vec<String> = env::args().collect();
    args.remove(0);
    let path1 = args.remove(0);
    let path2 = args.remove(0);
    let output_path = args.remove(0);

    //read logs
    let mut options = XESImportOptions::default();
    options.sort_events_with_timestamp_key = Some("time:timestamp".to_string());
    let log1 = import_xes_file(path1, options.clone()).unwrap();
    let log2 = import_xes_file(path2, options).unwrap();

    let debug = false;
    
    //setup keys
    let mut org_a = PrivateKeyOrganization::new(log1, debug);
    let mut org_b = PublicKeyOrganization::new(log2);

    let result: DirectlyFollowsGraph =
        organization_communication::communicate(&mut org_a, &mut org_b, 100);
    export_dfg_image_png(&result, &output_path).unwrap();
}
