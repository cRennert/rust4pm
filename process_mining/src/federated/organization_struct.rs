use crate::dfg::DirectlyFollowsGraph;
use crate::event_log::event_log_struct::EventLogClassifier;
use crate::event_log::{Attribute, Event, Trace, XESEditableAttribute};
use crate::EventLog;
use petgraph::matrix_graph::Nullable;
use primes::PrimeSet;
use rand::rng;
use rand::seq::SliceRandom;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::ops::{BitAnd, BitOr, Not};
use tfhe::prelude::*;
use tfhe::{
    generate_keys, set_server_key, ClientKey, Config, ConfigBuilder, FheBool, FheUint32, FheUint8,
    PublicKey, ServerKey,
};
use tqdm::tqdm;
///
/// Enum declaring the different messages and data that `Organization`s can send to each other.
///
#[derive(Clone, Serialize, Deserialize)]
pub enum FederatedMessage {
    RequestKey,
    Okay,
    /// Sends the public and server key of the own organization with the corresponding organization
    /// name. Public key can be used for encryption by the other parties.
    SendKeys((String, (PublicKey, ServerKey))),
    /// Sends a case identifier and an encrypted timestamp that can be used to compare the next
    /// upcoming `event`'s timestamp with the encrypted timestamp.
    RequestComparison((Attribute, u32)),
    ///
    SendComparisonResult((Attribute, FheBool)),
    DeclareWinner((Attribute, String)),
}

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
    // FheUint32::encrypt(value, private_key)
    FheUint32::encrypt_trivial(value)
}

pub fn encrypt_activity_private(value: u8, private_key: &ClientKey) -> FheUint8 {
    // FheUint8::encrypt(value, private_key)
    FheUint8::encrypt_trivial(value)
}

pub fn encrypt_fhe_boolean_private(bool: bool, private_key: &ClientKey) -> FheBool {
    // FheBool::encrypt(bool, private_key)
    FheBool::encrypt_trivial(bool)
}

pub fn encrypt_value(value: u32, public_key: &PublicKey) -> FheUint32 {
    // FheUint32::encrypt(value, public_key)
    FheUint32::encrypt_trivial(value)
}

pub fn encrypt_activity(value: u8, public_key: &PublicKey) -> FheUint8 {
    // FheUint8::encrypt(value, public_key)
    FheUint8::encrypt_trivial(value)
}

pub fn encrypt_fhe_boolean(bool: bool, public_key: &PublicKey) -> FheBool {
    // FheBool::encrypt(bool, public_key)
    FheBool::encrypt_trivial(bool)
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
    for (name, trace) in tqdm(name_to_trace) {
        result.insert(
            name.clone(),
            preprocess_trace_private(activity_to_pos, private_key, trace),
        );
    }

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
    for (name, trace) in tqdm(name_to_trace) {
        result.insert(
            name.clone(),
            preprocess_trace(activity_to_pos, public_key, trace),
        );
    }

    result
}

pub struct PrivateKeyOrganization {
    private_key: ClientKey,
    server_key: ServerKey,
    public_key: PublicKey,
    event_log: EventLog,
    activity_to_pos: HashMap<String, usize>,
}

impl PrivateKeyOrganization {
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
        }
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

        self.activity_to_pos.insert("bottom".to_string(), 0);
        self.activity_to_pos.insert("start".to_string(), 1);
        self.activity_to_pos.insert("end".to_string(), 2);

        activities.iter().enumerate().for_each(|(pos, act)| {
            self.activity_to_pos.insert(act.clone(), pos + 3);
        });

        self.activity_to_pos.clone()
    }

    pub fn evaluate_secrets_to_dfg<'a>(
        &self,
        secret_edges: Vec<(FheUint8, FheUint8)>,
    ) -> DirectlyFollowsGraph<'a> {
        let mut result = DirectlyFollowsGraph::new();
        let mut found_edges_by_pos: HashMap<(u8, u8), u32> = HashMap::new();

        self.activity_to_pos.keys().for_each(|act| {
            if !act.eq("bottom") {
                result.add_activity(act.clone(), 0);
            }
        });

        for (from, to) in tqdm(secret_edges) {
            let from_pos = self.decrypt_activity(from);
            if from_pos == 0 {
                continue;
            }

            let to_pos = self.decrypt_activity(to);
            if to_pos == 0 {
                continue;
            }

            if found_edges_by_pos.contains_key(&(from_pos, to_pos)) {
                found_edges_by_pos.insert(
                    (from_pos, to_pos),
                    found_edges_by_pos.get(&(from_pos, to_pos)).unwrap() + 1,
                );
            } else {
                found_edges_by_pos.insert((from_pos, to_pos), 1);
            }
        }

        let mut pos_to_activity: HashMap<usize, String> = HashMap::new();
        self.activity_to_pos.iter().for_each(|(act, pos)| {
            pos_to_activity.insert(*pos, act.clone());
        });

        for ((from_pos, to_pos), freq) in found_edges_by_pos {
            if pos_to_activity.contains_key(&(from_pos as usize))
                & pos_to_activity.contains_key(&(to_pos as usize))
            {
                result.add_df_relation(
                    pos_to_activity
                        .get(&(from_pos as usize))
                        .unwrap()
                        .clone()
                        .into(),
                    pos_to_activity
                        .get(&(to_pos as usize))
                        .unwrap()
                        .clone()
                        .into(),
                    freq,
                )
            }
        }

        result
    }
}

pub struct PublicKeyOrganization {
    public_key: Option<PublicKey>,
    event_log: EventLog,
    activity_to_pos: HashMap<String, usize>,
}

impl PublicKeyOrganization {
    pub fn new(event_log: EventLog) -> Self {
        Self {
            public_key: None,
            event_log,
            activity_to_pos: HashMap::new(),
        }
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
    }

    fn compare_timestamps(&self, val1: &FheUint32, val2: u32) -> FheBool {
        val1.le(val2)
    }

    pub fn sanitize_activities(
        &self,
        max_activities: u8,
        enc_activity: &Vec<FheUint8>,
    ) -> Vec<FheUint8> {
        let mut result: Vec<FheUint8> = Vec::new();

        enc_activity.iter().for_each(|act| {
            //let sanitized_act = act.max(max_activities);
            let sanitized_act = act.ge(max_activities + 3).select(
                &encrypt_activity(0, self.public_key.as_ref().unwrap()),
                &act.clone(),
            );
            result.push(sanitized_act);
        });

        result
    }

    pub fn find_all_conditions(
        &mut self,
        foreign_case_to_trace: HashMap<Attribute, (Vec<FheUint8>, Vec<FheUint32>)>,
    ) -> Vec<(FheUint8, FheUint8)> {
        let own_case_to_trace: HashMap<Attribute, (Vec<FheUint8>, Vec<u32>)> =
            compute_case_to_trace(
                &self.activity_to_pos,
                self.public_key.as_ref().unwrap(),
                &self.event_log,
            );

        let max_activities: u8 = u8::try_from(self.activity_to_pos.len()).unwrap_or(0);

        let mut all_case_names = foreign_case_to_trace
            .keys()
            .cloned()
            .collect::<HashSet<Attribute>>();
        all_case_names.extend(own_case_to_trace.keys().cloned());

        let mut size_assumption = 0;
        let dummy_tuple = (Vec::new(), Vec::new());
        let dummy_tuple_encrypted = (Vec::new(), Vec::new());
        all_case_names.iter().for_each(|case_name| {
            let (own_activities, _) = own_case_to_trace.get(case_name).unwrap_or(&dummy_tuple);
            let (foreign_activities, _) = foreign_case_to_trace
                .get(case_name)
                .unwrap_or(&dummy_tuple_encrypted);

            size_assumption += (2 * own_activities.len() * foreign_activities.len())
                + own_activities.len()
                + foreign_activities.len();
        });

        let mut result: Vec<(FheUint8, FheUint8)> = Vec::with_capacity(size_assumption);

        println!("Find all conditions");
        tqdm(all_case_names.into_iter()).for_each(|case_name| {
            let mut foreign_activities;
            let foreign_timestamps;
            (foreign_activities, foreign_timestamps) = foreign_case_to_trace
                .get(&case_name)
                .unwrap_or(&(Vec::new(), Vec::new()))
                .to_owned();
            foreign_activities = self.sanitize_activities(max_activities, &foreign_activities);

            let (own_activities, own_timestamps): (Vec<FheUint8>, Vec<u32>) = own_case_to_trace
                .get(&case_name)
                .unwrap_or(&(Vec::new(), Vec::new()))
                .to_owned();

            self.find_conditions(
                foreign_activities,
                foreign_timestamps,
                own_activities,
                own_timestamps,
                &mut result,
            )
        });

        result.shuffle(&mut rng());
        result
    }

    fn find_conditions(
        &self,
        foreign_activities: Vec<FheUint8>,
        foreign_timestamps: Vec<FheUint32>,
        own_activities: Vec<FheUint8>,
        own_timestamps: Vec<u32>,
        result: &mut Vec<(FheUint8, FheUint8)>,
    ) {
        let mut comparison_foreign_to_own: HashMap<(usize, usize), FheBool> = HashMap::new();
        let mut comparison_own_to_foreign: HashMap<(usize, usize), FheBool> = HashMap::new();
        for (i, foreign_timestamp) in foreign_timestamps.iter().enumerate() {
            for (j, &own_timestamp) in own_timestamps.iter().enumerate() {
                let foreign_less_equal_own =
                    self.compare_timestamps(foreign_timestamp, own_timestamp);
                let own_less_foreign = foreign_less_equal_own.clone().not();
                comparison_foreign_to_own.insert((i, j), foreign_less_equal_own);
                comparison_own_to_foreign.insert((j, i), own_less_foreign);
            }
        }

        // Find start
        let start = encrypt_activity(1, self.public_key.as_ref().unwrap());
        result.push((
            start,
            comparison_foreign_to_own
                .get(&(0, 0))
                .unwrap_or(&encrypt_fhe_boolean(
                    !foreign_activities.is_empty(),
                    self.public_key.as_ref().unwrap(),
                ))
                .select(&foreign_activities[0], &own_activities[0]),
        ));

        // Find end
        let end = encrypt_activity(2, self.public_key.as_ref().unwrap());
        result.push((
            comparison_foreign_to_own
                .get(&(
                    foreign_activities.len().checked_sub(1).unwrap_or(0),
                    own_activities.len().checked_sub(1).unwrap_or(0),
                ))
                .unwrap_or(&encrypt_fhe_boolean(
                    !own_activities.is_empty(),
                    self.public_key.as_ref().unwrap(),
                ))
                .select(
                    &own_activities[own_activities.len() - 1],
                    &foreign_activities[foreign_activities.len() - 1],
                ),
            end,
        ));

        self.find_progress_pairs_non_crossing(
            &own_activities,
            foreign_activities.len(),
            &comparison_own_to_foreign,
            &comparison_foreign_to_own,
            result,
        );

        self.find_progress_pairs_non_crossing(
            &foreign_activities,
            own_activities.len(),
            &comparison_foreign_to_own,
            &comparison_own_to_foreign,
            result,
        );

        self.find_progress_pairs_crossing(
            &foreign_activities,
            &own_activities,
            &comparison_foreign_to_own,
            &comparison_own_to_foreign,
            result,
        );

        self.find_progress_pairs_crossing(
            &own_activities,
            &foreign_activities,
            &comparison_own_to_foreign,
            &comparison_foreign_to_own,
            result,
        );
    }

    fn find_progress_pairs_crossing(
        &self,
        activity_list_from: &Vec<FheUint8>,
        activity_list_to: &Vec<FheUint8>,
        comparison_map: &HashMap<(usize, usize), FheBool>,
        reverse_comparison_map: &HashMap<(usize, usize), FheBool>,
        result: &mut Vec<(FheUint8, FheUint8)>,
    ) {
        for i in 0..activity_list_from.len() {
            for j in 0..activity_list_to.len() {
                let bottom: FheUint8 = encrypt_activity(0, self.public_key.as_ref().unwrap());

                let mut cond = comparison_map.get(&(i, j)).unwrap().clone();
                if j > 0 {
                    cond = cond.bitand(reverse_comparison_map.get(&(j - 1, i)).unwrap());
                }
                if i + 1 < activity_list_from.len() {
                    cond = cond.bitand(reverse_comparison_map.get(&(j, i + 1)).unwrap());
                }

                result.push((
                    cond.select(&activity_list_from[i], &bottom),
                    cond.select(&activity_list_to[j], &bottom),
                ));
            }
        }
    }

    fn find_progress_pairs_non_crossing(
        &self,
        activities: &Vec<FheUint8>,
        len_other_activities: usize,
        comparison_map: &HashMap<(usize, usize), FheBool>,
        reverse_comparison_map: &HashMap<(usize, usize), FheBool>,
        result: &mut Vec<(FheUint8, FheUint8)>,
    ) {
        if activities.is_empty() {
            return;
        }

        for i in 0..activities.len() - 1 {
            let bottom: FheUint8 = encrypt_activity(0, self.public_key.as_ref().unwrap());

            let mut progress: FheBool;
            if len_other_activities > 0 {
                progress = comparison_map
                    .get(&(i + 1, 0))
                    .unwrap_or(&encrypt_fhe_boolean(
                        false,
                        self.public_key.as_ref().unwrap(),
                    ))
                    .clone();
                progress = progress.bitor(
                    reverse_comparison_map
                        .get(&(len_other_activities - 1, i))
                        .unwrap(),
                );

                for j in 0..len_other_activities - 1 {
                    let local_progress: FheBool =
                        reverse_comparison_map.get(&(j, i)).unwrap().clone()
                            & comparison_map
                                .get(&(i + 1, j + 1))
                                .unwrap_or(&encrypt_fhe_boolean(
                                    true,
                                    &self.public_key.as_ref().unwrap(),
                                ))
                                .clone();
                    progress |= local_progress;
                }
            } else {
                progress = encrypt_fhe_boolean(true, self.public_key.as_ref().unwrap());
            }

            result.push((
                progress.select(&activities[i], &bottom),
                progress.select(&activities[i + 1], &bottom),
            ));
        }
    }

    fn compute_permutations(list: Vec<FheBool>) -> (HashMap<usize, usize>, Vec<FheBool>) {
        let mut mapping: HashMap<usize, usize> = HashMap::new();
        let mut shuffled_list: Vec<FheBool> = Vec::with_capacity(list.len());

        let mut permutation: Vec<usize> = (0..list.len()).collect();
        permutation.shuffle(&mut rng());

        permutation.iter().enumerate().for_each(|(index, pos)| {
            mapping.insert(index, *pos);
            shuffled_list.push(list[*pos].clone());
        });

        (mapping, shuffled_list)
    }
}
