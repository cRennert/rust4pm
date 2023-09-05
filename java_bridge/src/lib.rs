#![allow(non_snake_case)]

mod copy_log {
    mod copy_log_shared;
    mod java_log_to_rust;
    mod rust_log_to_java;
}
use jni::{
    objects::{JClass, JIntArray, JString},
    sys::jlong,
    JNIEnv,
};

use jni_fn::jni_fn;
use pm_rust::{add_start_end_acts, EventLog};

#[jni_fn("org.processmining.alpharevisitexperiments.bridge.HelloProcessMining")]
pub unsafe fn addStartEndToRustLog<'local>(mut _env: JNIEnv<'local>, _: JClass, pointer: jlong) {
    let mut log_pointer = Box::from_raw(pointer as *mut EventLog);
    add_start_end_acts(&mut log_pointer);
    let _log_pointer = Box::into_raw(log_pointer);
}

/// Get attributes of (boxed) [EventLog] referenced by `pointer`
/// 
/// Attributes are converted to JSON String (encoding a [HashMap<String,String>]) 
#[jni_fn("org.processmining.alpharevisitexperiments.bridge.HelloProcessMining")]
pub unsafe fn getRustLogAttributes<'local>(
    mut _env: JNIEnv<'local>,
    _: JClass,
    pointer: jlong,
) -> JString<'local> {
    let mut log_pointer = Box::from_raw(pointer as *mut EventLog);
    log_pointer.attributes.insert(
        "__NUM_TRACES__".to_string(),
        log_pointer.traces.len().to_string(),
    );
    let attributes_json = serde_json::to_string(&log_pointer.attributes).unwrap();
    // memory of log_pointer should _not_ be destroyed!
    let _log_pointer = Box::into_raw(log_pointer);
    _env.new_string(attributes_json).unwrap()
}

/// Get the lengths of all traces in (boxed) [EventLog] referenced by `pointer`
///
/// The lengths are returned as a [JIntArray] of size of `EventLog.traces`, 
/// where each entry contains the length of the trace (i.e., the length of `Trace.events`) at the corresponding index
#[jni_fn("org.processmining.alpharevisitexperiments.bridge.HelloProcessMining")]
pub unsafe fn getRustTraceLengths<'local>(
    mut _env: JNIEnv<'local>,
    _: JClass,
    pointer: jlong,
) -> JIntArray<'local> {
    let log_pointer = Box::from_raw(pointer as *mut EventLog);
    let trace_lengths: Vec<i32> = log_pointer
        .traces
        .iter()
        .map(|t| t.events.len() as i32)
        .collect();
    let trace_lengths_j: JIntArray = _env.new_int_array(trace_lengths.len() as i32).unwrap();
    _env.set_int_array_region(&trace_lengths_j, 0, &trace_lengths)
        .unwrap();
    // memory of log_pointer should _not_ be destroyed!
    let _log_pointer = Box::into_raw(log_pointer);
    trace_lengths_j
}
