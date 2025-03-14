use crate::dfg::DirectlyFollowsGraph;
use crate::event_log::event_log_struct::EventLogClassifier;
use crate::event_log::{Event, Trace, XESEditableAttribute};
use crate::EventLog;
use indicatif::ProgressIterator;
use indicatif::{ParallelProgressIterator, ProgressBar, ProgressFinish, ProgressStyle};
use rand::rng;
use rand::seq::SliceRandom;
use rayon::prelude::*;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::ops::Not;
use tfhe::prelude::*;
use tfhe::{
    generate_keys, set_server_key, ClientKey, Config, ConfigBuilder, FheBool, FheUint16, FheUint32,
    PublicKey, ServerKey,
};

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

pub fn encrypt_value_private(value: u32, private_key: &ClientKey, debug: bool) -> FheUint32 {
    if debug {
        FheUint32::encrypt_trivial(value)
    } else {
        FheUint32::encrypt(value, private_key)
    }
}

pub fn encrypt_activity_private(value: u16, private_key: &ClientKey, debug: bool) -> FheUint16 {
    if debug {
        FheUint16::encrypt_trivial(value)
    } else {
        FheUint16::encrypt(value, private_key)
    }
}

pub fn encrypt_activity(value: u16, public_key: &PublicKey, debug: bool) -> FheUint16 {
    if debug {
        FheUint16::encrypt_trivial(value)
    } else {
        FheUint16::encrypt(value, public_key)
    }
}

pub fn preprocess_trace_private(
    activity_to_pos: &HashMap<String, usize>,
    private_key: &ClientKey,
    trace: &Trace,
    debug: bool,
) -> (Vec<FheUint16>, Vec<FheUint32>) {
    let mut activities: Vec<FheUint16> = Vec::with_capacity(trace.events.len());
    let mut timestamps: Vec<FheUint32> = Vec::with_capacity(trace.events.len());

    let classifier = EventLogClassifier::default();

    trace.events.iter().for_each(|event| {
        let activity: String = classifier.get_class_identity(event);
        let activity_pos: u16 =
            u16::try_from(activity_to_pos.get(&activity).unwrap().clone()).unwrap_or(0);
        activities.push(encrypt_activity_private(activity_pos, private_key, debug));
        timestamps.push(encrypt_value_private(get_timestamp(event), private_key, debug));
    });

    (activities, timestamps)
}

pub fn compute_case_to_trace_private(
    activity_to_pos: &HashMap<String, usize>,
    private_key: &ClientKey,
    event_log: &EventLog,
    debug: bool,
) -> HashMap<String, (Vec<FheUint16>, Vec<FheUint32>)> {
    let name_to_trace: HashMap<&String, &Trace> = event_log.find_name_trace_dictionary();
    let name_to_trace_vec: Vec<(&String, &Trace)> =
        name_to_trace.iter().map(|(&k, &v)| (k, v)).collect();

    let bar = ProgressBar::new(name_to_trace.len() as u64);
    bar.set_style(
        ProgressStyle::with_template(
            "[{elapsed_precise}/{eta_precise} - {per_sec}] {wide_bar} {pos}/{len}",
        )
        .unwrap(),
    );
    bar.println("Encrypt data organization A");
    let result: HashMap<String, (Vec<FheUint16>, Vec<FheUint32>)> = name_to_trace_vec
        .into_par_iter()
        .progress_with(bar)
        .with_finish(ProgressFinish::AndLeave)
        .map(|(name, trace)| {
            (
                name.clone(),
                preprocess_trace_private(activity_to_pos, private_key, trace, debug),
            )
        })
        .collect::<HashMap<String, (Vec<FheUint16>, Vec<FheUint32>)>>();

    result
}

pub fn preprocess_trace(
    activity_to_pos: &HashMap<String, usize>,
    public_key: &PublicKey,
    trace: &Trace,
    debug: bool,
) -> (Vec<FheUint16>, Vec<u32>) {
    let mut activities: Vec<FheUint16> = Vec::with_capacity(trace.events.len());
    let mut timestamps: Vec<u32> = Vec::with_capacity(trace.events.len());

    let classifier = EventLogClassifier::default();

    trace.events.iter().for_each(|event| {
        let activity: String = classifier.get_class_identity(event);
        let activity_pos: u16 =
            u16::try_from(activity_to_pos.get(&activity).unwrap().clone()).unwrap_or(0);
        activities.push(encrypt_activity(activity_pos, public_key, debug));
        timestamps.push(get_timestamp(event));
    });

    (activities, timestamps)
}

pub fn compute_case_to_trace(
    activity_to_pos: &HashMap<String, usize>,
    public_key: &PublicKey,
    event_log: &EventLog,
    debug: bool,
) -> HashMap<String, (Vec<FheUint16>, Vec<u32>)> {
    let name_to_trace: HashMap<&String, &Trace> = event_log.find_name_trace_dictionary();
    let name_to_trace_vec: Vec<(&String, &Trace)> =
        name_to_trace.iter().map(|(&k, &v)| (k, v)).collect();

    let bar = ProgressBar::new(name_to_trace.len() as u64);
    bar.set_style(
        ProgressStyle::with_template(
            "[{elapsed_precise}/{eta_precise} - {per_sec}] {wide_bar} {pos}/{len}",
        )
        .unwrap(),
    );
    bar.println("Encrypt data organization B");
    let result: HashMap<String, (Vec<FheUint16>, Vec<u32>)> = name_to_trace_vec
        .into_par_iter()
        .progress_with(bar)
        .map(|(name, trace)| {
            (
                name.clone(),
                preprocess_trace(activity_to_pos, public_key, trace, debug),
            )
        })
        .collect();
    result
}

pub struct PrivateKeyOrganization {
    private_key: ClientKey,
    server_key: ServerKey,
    public_key: PublicKey,
    event_log: EventLog,
    activity_to_pos: HashMap<String, usize>,
    pos_to_activity: HashMap<usize, String>,
    debug: bool,
}

impl PrivateKeyOrganization {
    pub fn new(event_log: EventLog, debug: bool) -> Self {
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
            debug,
        }
    }

    pub fn edges_to_dfg(&self, edges: Vec<(String, String)>) -> DirectlyFollowsGraph<'_> {
        let mut result = DirectlyFollowsGraph::default();
        self.activity_to_pos.keys().for_each(|act| {
            if !act.eq("bottom") {
                result.add_activity(act.clone(), 0);
            }
        });

        edges.into_iter().for_each(|(from, to)| {
            result.add_df_relation(Cow::from(from), Cow::from(to), 1);
        });

        result.recalculate_activity_counts();

        result
    }

    fn decrypt_activity(&self, val: FheUint16) -> u16 {
        val.decrypt(&self.private_key)
    }

    fn decrypt(&self, val: FheUint32) -> u32 {
        val.decrypt(&self.private_key)
    }

    pub fn encrypt_all_data(&self) -> HashMap<String, (Vec<FheUint16>, Vec<FheUint32>)> {
        compute_case_to_trace_private(&self.activity_to_pos, &self.private_key, &self.event_log, self.debug)
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

        self.activity_to_pos
            .insert("bottom".to_string(), activities_len);
        self.activity_to_pos
            .insert("start".to_string(), activities_len + 1);
        self.activity_to_pos
            .insert("end".to_string(), activities_len + 2);

        activities.iter().enumerate().for_each(|(pos, act)| {
            self.activity_to_pos.insert(act.clone(), pos);
        });

        self.activity_to_pos.iter().for_each(|(act, pos)| {
            self.pos_to_activity.insert(*pos, act.clone());
        });

        self.activity_to_pos.clone()
    }

    pub fn decrypt_edges(
        &self,
        secret_edges: Vec<(FheUint16, FheUint16)>,
        bar: &ProgressBar,
    ) -> Vec<(u16, u16)> {
        secret_edges
            .into_par_iter()
            .map(|(from, to)| {
                let from_pos = self.decrypt_activity(from);
                let to_pos = self.decrypt_activity(to);

                bar.inc(1);
                (from_pos, to_pos)
            })
            .collect::<Vec<(u16, u16)>>()
    }

    pub fn evaluate_decrypted_edges_to_dfg<'a>(
        &self,
        decrypted_edges: Vec<(u16, u16)>,
    ) -> DirectlyFollowsGraph<'a> {
        let mut result = DirectlyFollowsGraph::new();
        let mut found_edges_by_pos: HashMap<(u16, u16), u32> = HashMap::new();

        self.activity_to_pos.keys().for_each(|act| {
            if !act.eq("bottom") {
                result.add_activity(act.clone(), 0);
            }
        });

        let mut pos_to_activity: HashMap<usize, String> = HashMap::new();
        self.activity_to_pos.iter().for_each(|(act, pos)| {
            pos_to_activity.insert(*pos, act.clone());
        });

        let bar = ProgressBar::new(decrypted_edges.len() as u64);
        bar.set_style(
            ProgressStyle::with_template(
                "[{elapsed_precise}/{eta_precise} - {per_sec}] {wide_bar} {pos}/{len}",
            )
            .unwrap(),
        );
        bar.println("Create directly-follows graph from decrypted edges");
        decrypted_edges
            .into_iter()
            .progress_with(bar)
            .with_finish(ProgressFinish::AndLeave)
            .for_each(|(from, to)| {
                if (!pos_to_activity.get(&(from as usize)).unwrap().eq("bottom")
                    && !pos_to_activity.get(&(to as usize)).unwrap().eq("bottom"))
                {
                    if found_edges_by_pos.contains_key(&(from, to)) {
                        found_edges_by_pos
                            .insert((from, to), found_edges_by_pos.get(&(from, to)).unwrap() + 1);
                    } else {
                        found_edges_by_pos.insert((from, to), 1);
                    }
                }
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
    own_case_to_trace: HashMap<String, (Vec<FheUint16>, Vec<u32>)>,
    foreign_case_to_trace: HashMap<String, (Vec<FheUint16>, Vec<FheUint32>)>,
    start: Option<FheUint16>,
    end: Option<FheUint16>,
    bottom: Option<FheUint16>,
    all_case_names: Vec<String>,
    debug: bool,
}

impl PublicKeyOrganization {
    pub fn new(event_log: EventLog, debug: bool) -> Self {
        Self {
            public_key: None,
            event_log,
            own_case_to_trace: HashMap::new(),
            foreign_case_to_trace: HashMap::new(),
            activity_to_pos: HashMap::new(),
            start: None,
            end: None,
            bottom: None,
            all_case_names: Vec::new(),
            debug,
        }
    }

    pub fn get_cases_len(&self) -> usize {
        self.all_case_names.len()
    }

    pub fn get_secret_edges_len(&self) -> usize {
        let mut result = 0;
        self.all_case_names.iter().for_each(|case_name| {
            let (foreign_activities, _) = self
                .foreign_case_to_trace
                .get(case_name)
                .unwrap_or(&(Vec::new(), Vec::new()))
                .to_owned();

            let (own_activities, _): (Vec<FheUint16>, Vec<u32>) = self
                .own_case_to_trace
                .get(case_name)
                .unwrap_or(&(Vec::new(), Vec::new()))
                .to_owned();

            result += foreign_activities.len() + own_activities.len() + 1;
        });
        result
    }

    pub fn set_public_keys(&mut self, public_key: PublicKey, server_key: ServerKey) {
        self.public_key = Some(public_key);
        set_server_key(server_key.clone());
        rayon::broadcast(|_| set_server_key(server_key.clone()));
    }

    pub fn find_activities(&self) -> HashSet<String> {
        find_activities(&self.event_log)
    }

    pub fn set_activity_to_pos(&mut self, activity_to_pos: HashMap<String, usize>) {
        self.activity_to_pos = activity_to_pos;
        let activities_len = u16::try_from(self.activity_to_pos.len()).unwrap();
        self.bottom = Some(encrypt_activity(
            activities_len - 3,
            self.public_key.as_ref().unwrap(),
            self.debug,
        ));
        self.start = Some(encrypt_activity(
            activities_len - 2,
            self.public_key.as_ref().unwrap(),
            self.debug,
        ));
        self.end = Some(encrypt_activity(
            activities_len - 1,
            self.public_key.as_ref().unwrap(),
            self.debug,
        ));
    }

    fn comparison_fn(&self, val1: &FheUint32, val2: &u32) -> FheBool {
        val1.le(*val2)
    }

    pub fn set_foreign_case_to_trace(
        &mut self,
        mut foreign_case_to_trace: HashMap<String, (Vec<FheUint16>, Vec<FheUint32>)>,
    ) {
        let max_activities: u16 = u16::try_from(self.activity_to_pos.len() - 3).unwrap_or(0);

        let len = foreign_case_to_trace.len() as u64;
        let bar = ProgressBar::new(len);
        bar.set_style(
            ProgressStyle::with_template(
                "[{elapsed_precise}/{eta_precise} - {per_sec}] {wide_bar} {pos}/{len}",
            )
            .unwrap(),
        );
        bar.println("Sanitize activities from A in B");

        foreign_case_to_trace
            .par_iter_mut()
            .progress_with(bar)
            .with_finish(ProgressFinish::AndLeave)
            .for_each(|(_, (foreign_activities, _))| {
                foreign_activities.iter_mut().for_each(|act| {
                    *act = act
                        .ge(max_activities)
                        .select(self.start.as_ref().unwrap(), &act);
                });
            });

        self.foreign_case_to_trace = foreign_case_to_trace;
    }

    pub fn compute_all_case_names(&mut self) {
        let mut all_case_names = self
            .own_case_to_trace
            .keys()
            .cloned()
            .collect::<HashSet<String>>();
        all_case_names.extend(self.foreign_case_to_trace.keys().cloned());

        self.all_case_names = all_case_names.iter().cloned().collect();
        self.all_case_names.shuffle(&mut rand::rng());
    }

    pub(crate) fn encrypt_all_data(&mut self) {
        self.own_case_to_trace = compute_case_to_trace(
            &self.activity_to_pos,
            self.public_key.as_ref().unwrap(),
            &self.event_log,
            self.debug,
        );
    }

    pub fn find_all_secrets(
        &self,
        start_case: usize,
        upper_bound: usize,
        bar: &ProgressBar,
    ) -> Vec<(FheUint16, FheUint16)> {
        let mut result: Vec<(FheUint16, FheUint16)> = self
            .all_case_names
            .get(start_case..upper_bound)
            .unwrap()
            .par_iter()
            .flat_map(|case_name| {
                let (foreign_activities, foreign_timestamps) = self
                    .foreign_case_to_trace
                    .get(case_name)
                    .unwrap_or(&(Vec::new(), Vec::new()))
                    .to_owned();

                let (own_activities, own_timestamps): (Vec<FheUint16>, Vec<u32>) = self
                    .own_case_to_trace
                    .get(case_name)
                    .unwrap_or(&(Vec::new(), Vec::new()))
                    .to_owned();

                let intermediate_result = self.find_secrets_for_case(
                    foreign_activities,
                    foreign_timestamps,
                    own_activities,
                    own_timestamps,
                );

                bar.inc(1);
                intermediate_result
            })
            .collect();

        result.shuffle(&mut rng());
        result
    }

    fn find_secrets_for_case(
        &self,
        foreign_activities: Vec<FheUint16>,
        foreign_timestamps: Vec<FheUint32>,
        own_activities: Vec<FheUint16>,
        own_timestamps: Vec<u32>,
    ) -> Vec<(FheUint16, FheUint16)> {
        let mut result: Vec<(FheUint16, FheUint16)> = Vec::new();

        if own_activities.is_empty() {
            self.add_full_trace(&foreign_activities, &mut result);
            return result;
        } else if foreign_activities.is_empty() {
            self.add_full_trace(&own_activities, &mut result);
            return result;
        }

        let mut comparison_foreign_to_own: HashMap<(usize, usize), FheBool> = HashMap::new();
        let mut comparison_own_to_foreign: HashMap<(usize, usize), FheBool> = HashMap::new();
        for (i, foreign_timestamp) in foreign_timestamps.iter().enumerate() {
            for (j, &own_timestamp) in own_timestamps.iter().enumerate() {
                let foreign_less_equal_own = self.comparison_fn(foreign_timestamp, &own_timestamp);
                let own_less_foreign = foreign_less_equal_own.clone().not();
                comparison_foreign_to_own.insert((i, j), foreign_less_equal_own);
                comparison_own_to_foreign.insert((j, i), own_less_foreign);
            }
        }

        // Find start
        result.push((
            self.start.as_ref().unwrap().clone(),
            comparison_foreign_to_own
                .get(&(0, 0))
                .unwrap()
                .select(&foreign_activities[0], &own_activities[0]),
        ));

        result.extend(
            (0..foreign_activities.len() - 1)
                .into_par_iter()
                .map(|i| {
                    (
                        foreign_activities.get(i).unwrap() + 0,
                        self.find_following_activity(
                            i,
                            foreign_activities.get(i + 1).unwrap(),
                            &own_activities,
                            &comparison_foreign_to_own,
                            &comparison_own_to_foreign,
                        ),
                    )
                })
                .collect::<Vec<(FheUint16, FheUint16)>>(),
        );

        result.extend(
            (0..own_activities.len() - 1)
                .into_par_iter()
                .map(|j| {
                    (
                        own_activities.get(j).unwrap() + 0,
                        self.find_following_activity(
                            j,
                            own_activities.get(j + 1).unwrap(),
                            &foreign_activities,
                            &comparison_own_to_foreign,
                            &comparison_foreign_to_own,
                        ),
                    )
                })
                .collect::<Vec<(FheUint16, FheUint16)>>(),
        );

        result.push((
            foreign_activities.last().unwrap() + 0,
            self.handle_last(
                foreign_activities.len() - 1,
                &own_activities,
                &comparison_foreign_to_own,
            ),
        ));

        result.push((
            own_activities.last().unwrap() + 0,
            self.handle_last(
                own_activities.len() - 1,
                &foreign_activities,
                &comparison_own_to_foreign,
            ),
        ));

        result
    }

    fn add_full_trace(
        &self,
        activities: &Vec<FheUint16>,
        result: &mut Vec<(FheUint16, FheUint16)>,
    ) {
        if !activities.is_empty() {
            result.push((
                self.start.as_ref().unwrap().clone(),
                activities.first().unwrap().clone(),
            ));
            result.push((
                activities.last().unwrap().clone(),
                self.end.as_ref().unwrap().clone(),
            ));
        }

        for i in 0..activities.len() - 1 {
            result.push((
                activities.get(i).unwrap() + 0,
                activities.get(i + 1).unwrap() + 0,
            ));
        }
    }

    fn handle_last(
        &self,
        pos: usize,
        other_activities: &Vec<FheUint16>,
        comparison_this_to_other: &HashMap<(usize, usize), FheBool>,
    ) -> FheUint16 {
        let mut result: FheUint16 = self.end.as_ref().unwrap().clone();
        for i in (0..other_activities.len()).rev() {
            result = comparison_this_to_other
                .get(&(pos, i))
                .unwrap()
                .select(other_activities.get(i).unwrap(), &result);
        }
        result
    }

    fn find_following_activity(
        &self,
        pos: usize,
        next_activity: &FheUint16,
        other_activities: &Vec<FheUint16>,
        comparison_this_to_other: &HashMap<(usize, usize), FheBool>,
        comparison_other_to_this: &HashMap<(usize, usize), FheBool>,
    ) -> FheUint16 {
        let mut result: FheUint16 = next_activity.clone();

        for i in (0..other_activities.len()).rev() {
            let intermediate_result = comparison_other_to_this
                .get(&(i, pos + 1))
                .unwrap()
                .select(other_activities.get(i).unwrap(), next_activity);
            result = comparison_this_to_other
                .get(&(pos, i))
                .unwrap()
                .select(&intermediate_result, &result);
        }

        result
    }
}
