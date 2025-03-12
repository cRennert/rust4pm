use crate::dfg::DirectlyFollowsGraph;
use crate::event_log::event_log_struct::EventLogClassifier;
use crate::event_log::{Attribute, Event, Trace, XESEditableAttribute};
use crate::EventLog;
use petgraph::matrix_graph::Nullable;
use primes::PrimeSet;
use rand::rng;
use rand::seq::SliceRandom;
use rayon::prelude::*;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::ops::{BitAnd, BitAndAssign, BitOrAssign};
use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ClientKey, Config, ConfigBuilder, FheBool, FheUint, FheUint32, FheUint8, FheUint8Id, PublicKey, ServerKey};
use tqdm::tqdm;

pub fn find_activities(event_log: &EventLog) -> HashSet<String> {
    let mut result = HashSet::new();
    let classifier = EventLogClassifier::default();

    event_log.traces.iter().for_each(|trace| {
        trace.events.iter().for_each(|event| {
            result.insert(classifier.get_class_identity(event));
        })
    });

    result
}

pub fn get_timestamp(event: &Event) -> u32 {
    event
        .attributes
        .get_by_key("time:timestamp")
        .and_then(|t| t.value.try_as_date())
        .unwrap()
        .timestamp() as u32
}

pub fn encrypt_value_private(value: u32, private_key: &ClientKey) -> FheUint32 {
    FheUint32::encrypt(value, private_key)
    // FheUint32::encrypt_trivial(value)
}

pub fn encrypt_activity_private(value: u8, private_key: &ClientKey) -> FheUint8 {
    FheUint8::encrypt(value, private_key)
    // FheUint8::encrypt_trivial(value)
}

pub fn encrypt_fhe_boolean_private(bool: bool, private_key: &ClientKey) -> FheBool {
    FheBool::encrypt(bool, private_key)
    // FheBool::encrypt_trivial(bool)
}

pub fn encrypt_value(value: u32, public_key: &PublicKey) -> FheUint32 {
    FheUint32::encrypt(value, public_key)
    // FheUint32::encrypt_trivial(value)
}

pub fn encrypt_activity(value: u8, public_key: &PublicKey) -> FheUint8 {
    FheUint8::encrypt(value, public_key)
    // FheUint8::encrypt_trivial(value)
}

pub fn encrypt_fhe_boolean(bool: bool, public_key: &PublicKey) -> FheBool {
    FheBool::encrypt(bool, public_key)
    // FheBool::encrypt_trivial(bool)
}

pub fn preprocess_trace_private(
    activity_to_pos: &HashMap<String, usize>,
    private_key: &ClientKey,
    trace: &Trace,
) -> (Vec<FheUint8>, Vec<FheUint32>) {
    let mut activities: Vec<FheUint8> = Vec::with_capacity(trace.events.len());
    let mut timestamps: Vec<FheUint32> = Vec::with_capacity(trace.events.len());

    let classifier = EventLogClassifier::default();

    trace.events.iter().for_each(|event| {
        let activity: String = classifier.get_class_identity(event);
        let activity_pos: u8 =
            u8::try_from(activity_to_pos.get(&activity).unwrap().clone()).unwrap_or(0);
        activities.push(encrypt_activity_private(activity_pos, private_key));
        timestamps.push(encrypt_value_private(get_timestamp(event), private_key));
    });

    (activities, timestamps)
}

pub fn compute_case_to_trace_private(
    activity_to_pos: &HashMap<String, usize>,
    private_key: &ClientKey,
    event_log: &EventLog,
) -> HashMap<Attribute, (Vec<FheUint8>, Vec<FheUint32>)> {
    let mut result: HashMap<Attribute, (Vec<FheUint8>, Vec<FheUint32>)> = HashMap::new();

    let name_to_trace: HashMap<&Attribute, &Trace> = event_log.find_name_trace_dictionary();

    println!("Encrypt data organization A");
    tqdm(name_to_trace).into_iter().for_each(|(name, trace)| {
        result.insert(
            name.clone(),
            preprocess_trace_private(activity_to_pos, private_key, trace),
        );
    });

    result
}

pub fn preprocess_trace(
    activity_to_pos: &HashMap<String, usize>,
    public_key: &PublicKey,
    trace: &Trace,
) -> (Vec<FheUint8>, Vec<u32>) {
    let mut activities: Vec<FheUint8> = Vec::with_capacity(trace.events.len());
    let mut timestamps: Vec<u32> = Vec::with_capacity(trace.events.len());

    let classifier = EventLogClassifier::default();

    trace.events.iter().for_each(|event| {
        let activity: String = classifier.get_class_identity(event);
        let activity_pos: u8 =
            u8::try_from(activity_to_pos.get(&activity).unwrap().clone()).unwrap_or(0);
        activities.push(encrypt_activity(activity_pos, public_key));
        timestamps.push(get_timestamp(event));
    });

    (activities, timestamps)
}

pub fn compute_case_to_trace(
    activity_to_pos: &HashMap<String, usize>,
    public_key: &PublicKey,
    event_log: &EventLog,
) -> HashMap<Attribute, (Vec<FheUint8>, Vec<u32>)> {
    let mut result: HashMap<Attribute, (Vec<FheUint8>, Vec<u32>)> = HashMap::new();

    let name_to_trace: HashMap<&Attribute, &Trace> = event_log.find_name_trace_dictionary();

    println!("Encrypt data organization B");
    tqdm(name_to_trace).into_iter().for_each(|(name, trace)| {
        result.insert(
            name.clone(),
            preprocess_trace(activity_to_pos, public_key, trace),
        );
    });

    result
}

pub struct PrivateKeyOrganization<'a> {
    private_key: ClientKey,
    server_key: ServerKey,
    public_key: PublicKey,
    event_log: EventLog,
    activity_to_pos: HashMap<String, usize>,
    pos_to_activity: HashMap<usize, String>,
    dfg: DirectlyFollowsGraph<'a>,
}

impl<'a> PrivateKeyOrganization<'a> {
    pub fn new(event_log: EventLog) -> Self {
        let config: Config = ConfigBuilder::default().build();
        let (private_key, server_key): (ClientKey, ServerKey) = generate_keys(config);
        let public_key = PublicKey::new(&private_key);
        Self {
            private_key,
            server_key,
            public_key,
            event_log,
            activity_to_pos: HashMap::new(),
            pos_to_activity: HashMap::new(),
            dfg: DirectlyFollowsGraph::default(),
        }
    }

    pub fn get_dfg(&self) -> &DirectlyFollowsGraph<'a> {
        &self.dfg
    }

    pub fn recalculate_activity_counts(&mut self) -> &DirectlyFollowsGraph<'a> {
        self.dfg.recalculate_activity_counts();
        &self.dfg
    }

    fn decrypt_activity(&self, val: FheUint8) -> u8 {
        val.decrypt(&self.private_key)
    }

    fn decrypt(&self, val: FheUint32) -> u32 {
        val.decrypt(&self.private_key)
    }

    pub fn encrypt_all_data(&self) -> HashMap<Attribute, (Vec<FheUint8>, Vec<FheUint32>)> {
        compute_case_to_trace_private(&self.activity_to_pos, &self.private_key, &self.event_log)
    }

    pub fn get_public_keys(&self) -> (ServerKey, PublicKey) {
        (self.server_key.clone(), self.public_key.clone())
    }

    pub fn update_with_foreign_activities(
        &mut self,
        foreign_activities: HashSet<String>,
    ) -> HashMap<String, usize> {
        let mut activities: HashSet<String> = find_activities(&self.event_log);
        activities.extend(foreign_activities);
        let activities_len = activities.len();

        self.activity_to_pos.insert("bottom".to_string(), activities_len);
        self.activity_to_pos.insert("start".to_string(), activities_len+1);
        self.activity_to_pos.insert("end".to_string(), activities_len+2);

        activities.iter().enumerate().for_each(|(pos, act)| {
            self.activity_to_pos.insert(act.clone(), pos);
        });

        self.activity_to_pos.keys().for_each(|act| {
            if !act.eq("bottom") {
                self.dfg.add_activity(act.clone(), 0);
            }
        });

        self.activity_to_pos.iter().for_each(|(act, pos)| {
            self.pos_to_activity.insert(*pos, act.clone());
        });

        self.activity_to_pos.keys().for_each(|act| {
            if !act.eq("bottom") {
                self.dfg.add_activity(act.clone(), 0);
            }
        });

        self.activity_to_pos.clone()
    }

    pub fn evaluate_secret_to_dfg(&mut self, secret_edge: (FheUint8, FheUint8)) {
        let (from, to) = secret_edge;
        let from_pos = self.decrypt_activity(from);
        if from_pos == 0 {
            return;
        }

        let to_pos = self.decrypt_activity(to);
        if to_pos == 0 {
            return;
        }

        self.dfg.add_df_relation(
            self.pos_to_activity
                .get(&(from_pos as usize))
                .unwrap()
                .clone()
                .into(),
            self.pos_to_activity
                .get(&(to_pos as usize))
                .unwrap()
                .clone()
                .into(),
            1,
        );
    }
}

///
/// Enum declaring the different messages and data that `Organization`s can send to each other.
///
#[derive(Clone, Serialize, Debug)]
pub enum ComputationInstruction {
    FindStart(usize),
    FindEnd(usize),
    CrossingBToA(usize, usize, usize),
    CrossingAToB(usize, usize, usize),
    NonCrossingInA(usize, usize),
    NonCrossingInB(usize, usize),
}

fn find_instructions(
    case_pos: usize,
    foreign_len: usize,
    own_len: usize,
) -> Vec<ComputationInstruction> {
    let mut instructions = Vec::new();

    if own_len == 0 && foreign_len == 0 {
        return instructions;
    }

    instructions.push(ComputationInstruction::FindStart(case_pos));
    instructions.push(ComputationInstruction::FindEnd(case_pos));

    for i in 0..foreign_len.checked_sub(1).unwrap_or(0) {
        instructions.push(ComputationInstruction::NonCrossingInA(case_pos, i));
    }
    for j in 0..own_len.checked_sub(1).unwrap_or(0) {
        instructions.push(ComputationInstruction::NonCrossingInB(case_pos, j));
    }
    for i in 0..foreign_len {
        for j in 0..own_len {
            instructions.push(ComputationInstruction::CrossingAToB(case_pos, i, j));
            instructions.push(ComputationInstruction::CrossingBToA(case_pos, i, j));
        }
    }

    instructions.shuffle(&mut rng());
    instructions
}

pub struct PublicKeyOrganization {
    public_key: Option<PublicKey>,
    event_log: EventLog,
    activity_to_pos: HashMap<String, usize>,
    own_case_to_trace: HashMap<Attribute, (Vec<FheUint8>, Vec<u32>)>,
    foreign_case_to_trace: HashMap<Attribute, (Vec<FheUint8>, Vec<FheUint32>)>,
    bottom: Option<FheUint8>,
    start: Option<FheUint8>,
    end: Option<FheUint8>,
    pub instructions: Vec<ComputationInstruction>,
    all_case_names: Vec<Attribute>,
}

impl PublicKeyOrganization {
    pub fn new(event_log: EventLog) -> Self {
        Self {
            public_key: None,
            event_log,
            own_case_to_trace: HashMap::new(),
            foreign_case_to_trace: HashMap::new(),
            activity_to_pos: HashMap::new(),
            bottom: None,
            start: None,
            end: None,
            instructions: Vec::new(),
            all_case_names: Vec::new(),
        }
    }

    pub fn get_instructions_len(&self) -> usize {
        self.instructions.len()
    }

    pub fn compute_next_instruction(&mut self) -> ((FheUint8, FheUint8), bool) {
        let instruction = self.instructions.pop().unwrap();
        let unfinished = !self.instructions.is_empty();
        match instruction {
            ComputationInstruction::FindStart(case_pos) => {
                (self.compute_start(case_pos), unfinished)
            }
            ComputationInstruction::FindEnd(case_pos) => (self.compute_end(case_pos), unfinished),
            ComputationInstruction::CrossingAToB(case_pos, from, to) => {
                (self.compute_crossing(case_pos, from, to, false), unfinished)
            }
            ComputationInstruction::CrossingBToA(case_pos, from, to) => {
                (self.compute_crossing(case_pos, from, to, true), unfinished)
            }
            ComputationInstruction::NonCrossingInA(case_pos, pos) => {
                (self.compute_non_crossing_in_a(case_pos, pos), unfinished)
            }
            ComputationInstruction::NonCrossingInB(case_pos, pos) => {
                (self.compute_non_crossing_in_b(case_pos, pos), unfinished)
            }
        }
    }

    fn compute_non_crossing_in_a(&mut self, case_pos: usize, pos: usize) -> (FheUint8, FheUint8) {
        let case_name = self.all_case_names.get(case_pos).unwrap();

        let (foreign_activities, foreign_timestamps) =
            self.foreign_case_to_trace.get(case_name).unwrap();
        let (_, own_timestamps) = self.own_case_to_trace.get(case_name).unwrap();
        if own_timestamps.is_empty() {
            return (
                foreign_activities.get(pos).unwrap() + 0,
                foreign_activities.get(pos + 1).unwrap() + 0,
            );
        }

        let mut progress: FheBool;
        let timestamp1 = foreign_timestamps.get(pos).unwrap();
        let timestamp2 = foreign_timestamps.get(pos + 1).unwrap();

        progress = self.comparison_fn(timestamp2, own_timestamps.first().unwrap());
        progress
            .bitor_assign(self.reverse_comparison_fn(own_timestamps.last().unwrap(), timestamp1));

        for j in 0..own_timestamps.len() - 1 {
            let mut local_progress: FheBool =
                self.reverse_comparison_fn(own_timestamps.get(j).unwrap(), timestamp1);
            local_progress
                .bitand_assign(self.comparison_fn(timestamp2, own_timestamps.get(j + 1).unwrap()));

            progress.bitor_assign(local_progress);
        }

        (
            progress.select(
                foreign_activities.get(pos).unwrap(),
                self.bottom.as_ref().unwrap(),
            ),
            progress.select(
                foreign_activities.get(pos + 1).unwrap(),
                self.bottom.as_ref().unwrap(),
            ),
        )
    }

    fn compute_non_crossing_in_b(&mut self, case_pos: usize, pos: usize) -> (FheUint8, FheUint8) {
        let case_name = self.all_case_names.get(case_pos).unwrap();

        let (_, foreign_timestamps) = self.foreign_case_to_trace.get(case_name).unwrap();
        let (own_activities, own_timestamps) = self.own_case_to_trace.get(case_name).unwrap();
        if foreign_timestamps.is_empty() {
            return (
                own_activities.get(pos).unwrap() + 0,
                own_activities.get(pos + 1).unwrap() + 0,
            );
        }

        let mut progress: FheBool;
        let timestamp1 = own_timestamps.get(pos).unwrap();
        let timestamp2 = own_timestamps.get(pos + 1).unwrap();

        progress = self.reverse_comparison_fn(timestamp2, foreign_timestamps.first().unwrap());
        progress.bitor_assign(self.comparison_fn(foreign_timestamps.last().unwrap(), timestamp1));

        for j in 0..foreign_timestamps.len() - 1 {
            let mut local_progress: FheBool =
                self.comparison_fn(foreign_timestamps.get(j).unwrap(), timestamp1);
            local_progress.bitand_assign(
                self.reverse_comparison_fn(timestamp2, foreign_timestamps.get(j + 1).unwrap()),
            );

            progress.bitor_assign(local_progress);
        }

        (
            progress.select(
                own_activities.get(pos).unwrap(),
                self.bottom.as_ref().unwrap(),
            ),
            progress.select(
                own_activities.get(pos + 1).unwrap(),
                self.bottom.as_ref().unwrap(),
            ),
        )
    }

    fn compute_crossing(
        &mut self,
        case_pos: usize,
        pos_a: usize,
        pos_b: usize,
        reverse: bool,
    ) -> (FheUint8, FheUint8) {
        let case_name = self.all_case_names.get(case_pos).unwrap();

        let (foreign_activities, foreign_timestamps) =
            self.foreign_case_to_trace.get(case_name).unwrap();
        let (own_activities, own_timestamps) = self.own_case_to_trace.get(case_name).unwrap();
        if reverse {
            let mut cond = self.reverse_comparison_fn(
                own_timestamps.get(pos_b).unwrap(),
                foreign_timestamps.get(pos_a).unwrap(),
            );

            if pos_a > 0 {
                cond = cond.bitand(self.comparison_fn(
                    foreign_timestamps.get(pos_a - 1).unwrap(),
                    own_timestamps.get(pos_b).unwrap(),
                ));
            }

            if pos_b + 1 < own_timestamps.len() {
                cond = cond.bitand(self.comparison_fn(
                    foreign_timestamps.get(pos_a).unwrap(),
                    own_timestamps.get(pos_b + 1).unwrap(),
                ));
            }
            (
                cond.select(&own_activities[pos_b], self.bottom.as_ref().unwrap()),
                cond.select(&foreign_activities[pos_a], self.bottom.as_ref().unwrap()),
            )
        } else {
            let mut cond = self.comparison_fn(
                foreign_timestamps.get(pos_a).unwrap(),
                own_timestamps.get(pos_b).unwrap(),
            );

            if pos_b > 0 {
                cond = cond.bitand(self.reverse_comparison_fn(
                    own_timestamps.get(pos_b - 1).unwrap(),
                    foreign_timestamps.get(pos_a).unwrap(),
                ));
            }

            if pos_a + 1 < foreign_timestamps.len() {
                cond = cond.bitand(self.reverse_comparison_fn(
                    own_timestamps.get(pos_b).unwrap(),
                    foreign_timestamps.get(pos_a + 1).unwrap(),
                ));
            }
            (
                cond.select(&foreign_activities[pos_a], self.bottom.as_ref().unwrap()),
                cond.select(&own_activities[pos_b], self.bottom.as_ref().unwrap()),
            )
        }
    }

    fn compute_start(&self, case_pos: usize) -> (FheUint8, FheUint8) {
        let case_name = self.all_case_names.get(case_pos).unwrap();

        let (foreign_activities, foreign_timestamps) =
            self.foreign_case_to_trace.get(case_name).unwrap();
        let (own_activities, own_timestamps) = self.own_case_to_trace.get(case_name).unwrap();

        let successor;
        if foreign_activities.is_empty() {
            successor = own_activities.first().unwrap().clone();
        } else if own_activities.is_empty() {
            successor = foreign_activities.first().unwrap().clone();
        } else {
            successor = self
                .comparison_fn(
                    foreign_timestamps.first().unwrap(),
                    own_timestamps.first().unwrap(),
                )
                .select(
                    foreign_activities.first().unwrap(),
                    own_activities.first().unwrap(),
                );
        }

        (self.start.as_ref().unwrap().clone(), successor)
    }

    fn compute_end(&self, case_pos: usize) -> (FheUint8, FheUint8) {
        let case_name = self.all_case_names.get(case_pos).unwrap();

        let (foreign_activities, foreign_timestamps) =
            self.foreign_case_to_trace.get(case_name).unwrap();
        let (own_activities, own_timestamps) = self.own_case_to_trace.get(case_name).unwrap();

        let predecessor;
        if foreign_activities.is_empty() {
            predecessor = own_activities[own_activities.len() - 1].clone();
        } else if own_activities.is_empty() {
            predecessor = foreign_activities[foreign_activities.len() - 1].clone();
        } else {
            predecessor = self
                .comparison_fn(
                    foreign_timestamps.last().unwrap(),
                    own_timestamps.last().unwrap(),
                )
                .select(
                    own_activities.last().unwrap(),
                    foreign_activities.last().unwrap(),
                );
        }
        (predecessor, self.end.as_ref().unwrap().clone())
    }

    pub fn set_public_keys(&mut self, public_key: PublicKey, server_key: ServerKey) {
        self.public_key = Some(public_key);
        set_server_key(server_key);
    }

    pub fn find_activities(&self) -> HashSet<String> {
        find_activities(&self.event_log)
    }

    pub fn set_activity_to_pos(&mut self, activity_to_pos: HashMap<String, usize>) {
        self.activity_to_pos = activity_to_pos;
        let activities_len = u8::try_from(self.activity_to_pos.len()).unwrap();
        self.bottom = Some(encrypt_activity(
            activities_len - 3,
            self.public_key.as_ref().unwrap(),
        ));
        self.start = Some(encrypt_activity(
            activities_len - 2,
            self.public_key.as_ref().unwrap(),
        ));
        self.end = Some(encrypt_activity(
            activities_len - 1,
            self.public_key.as_ref().unwrap(),
        ));
    }

    fn comparison_fn(&self, val1: &FheUint32, val2: &u32) -> FheBool {
        val1.le(*val2)
    }

    fn reverse_comparison_fn(&self, val1: &u32, val2: &FheUint32) -> FheBool {
        val2.gt(*val1)
    }


    pub fn set_foreign_case_to_trace(
        &mut self,
        mut foreign_case_to_trace: HashMap<Attribute, (Vec<FheUint8>, Vec<FheUint32>)>,
    ) {
        println!("Sanitize activities from A in B");
        let max_activities: u8 = u8::try_from(self.activity_to_pos.len() - 3 - 1).unwrap_or(0);
        tqdm(foreign_case_to_trace.iter_mut()).for_each(|(_, (foreign_activities, _))| {
            foreign_activities.iter_mut().for_each(|act| {
                *act = act.max(max_activities);
            });
        });
        
        self.foreign_case_to_trace = foreign_case_to_trace;
    }

    pub fn compute_all_case_names(&mut self) {
        let mut all_case_names = self
            .own_case_to_trace
            .keys()
            .cloned()
            .collect::<HashSet<Attribute>>();
        all_case_names.extend(self.foreign_case_to_trace.keys().cloned());

        self.all_case_names = all_case_names.iter().cloned().collect();
    }

    pub fn find_all_instructions(&mut self) {
        self.own_case_to_trace = compute_case_to_trace(
            &self.activity_to_pos,
            self.public_key.as_ref().unwrap(),
            &self.event_log,
        );

        println!("Find all instructions");
        for (case_pos, case_name) in tqdm(self.all_case_names.iter().enumerate()) {
            let mut foreign_activities;
            (foreign_activities, _) = self
                .foreign_case_to_trace
                .get(case_name)
                .unwrap_or(&(Vec::new(), Vec::new()))
                .to_owned();

            let (own_activities, _): (Vec<FheUint8>, Vec<u32>) = self
                .own_case_to_trace
                .get(case_name)
                .unwrap_or(&(Vec::new(), Vec::new()))
                .to_owned();

            self.instructions.extend(find_instructions(
                case_pos,
                foreign_activities.len(),
                own_activities.len(),
            ));
        }
    }
}
