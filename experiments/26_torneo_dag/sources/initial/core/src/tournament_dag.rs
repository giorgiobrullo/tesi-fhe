//! Same adjacent tree with either level barriers or dependency-ready dispatch.
//! Query controls are changed only at serialized query boundaries. Every node receives
//! immutable public policy; no level settings or thread-local context are propagated.
use rayon::prelude::*;
use serde::Serialize;
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
    Mutex,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Mode {
    BarrierReference,
    DagReady,
}

impl Mode {
    pub const fn name(self) -> &'static str {
        match self {
            Self::BarrierReference => "barrier_reference",
            Self::DagReady => "dag_ready",
        }
    }
    pub fn parse(name: &str) -> Result<Self, String> {
        match name {
            "barrier_reference" => Ok(Self::BarrierReference),
            "dag_ready" => Ok(Self::DagReady),
            _ => Err(format!("unknown tournament mode: {name}")),
        }
    }
}

static ENABLED: AtomicBool = AtomicBool::new(false);
static MODE: AtomicU8 = AtomicU8::new(0);
static TRACE: AtomicBool = AtomicBool::new(false);
static FINAL_PREDICATES: AtomicUsize = AtomicUsize::new(0);
static REPORT: Mutex<Option<QueryReport>> = Mutex::new(None);

/// Call after composite::begin_query(PublicParallel, false), before evaluation.
pub fn begin_query(mode: Mode, trace: bool) {
    assert_eq!(
        crate::g4_query::query_stats()["enabled"],
        false,
        "DAG experiment requires no G4"
    );
    assert_eq!(
        crate::smallcuts::tail_cutoff(),
        0,
        "DAG experiment preserves baseline outer scheduling"
    );
    MODE.store(mode as u8, Ordering::Relaxed);
    TRACE.store(trace, Ordering::Relaxed);
    FINAL_PREDICATES.store(0, Ordering::Relaxed);
    *REPORT.lock().expect("DAG report mutex") = None;
    ENABLED.store(true, Ordering::Relaxed);
}

pub(super) fn disable() {
    ENABLED.store(false, Ordering::Relaxed);
    TRACE.store(false, Ordering::Relaxed);
    FINAL_PREDICATES.store(0, Ordering::Relaxed);
    *REPORT.lock().expect("DAG report mutex") = None;
}
pub(super) fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}
fn mode() -> Mode {
    match MODE.load(Ordering::Relaxed) {
        0 => Mode::BarrierReference,
        1 => Mode::DagReady,
        _ => unreachable!(),
    }
}
pub(super) fn final_predicate() {
    FINAL_PREDICATES.fetch_add(1, Ordering::Relaxed);
}

pub fn report() -> Value {
    let report = REPORT.lock().expect("DAG report mutex");
    let empty = QueryReport {
        schema: "tournament-dag-query.v1",
        mode: mode().name(),
        enabled: enabled(),
        trace_enabled: TRACE.load(Ordering::Relaxed),
        requested_parallel: None,
        leaf_nodes: 0,
        real_merges: 0,
        levels: 0,
        root_count: 0,
        nodes_started: 0,
        nodes_completed: 0,
        early_parent_starts: None,
        topology: Vec::new(),
        events: Vec::new(),
    };
    // JSON conversion and cloning happen only when the worker requests this snapshot,
    // after its query timer. Within evaluation we retain just typed counters/events.
    let mut value =
        serde_json::to_value(report.as_ref().unwrap_or(&empty)).expect("DAG report serializes");
    value["final_predicates"] = json!(FINAL_PREDICATES.load(Ordering::Relaxed));
    value
}

#[derive(Serialize)]
struct QueryReport {
    schema: &'static str,
    mode: &'static str,
    enabled: bool,
    trace_enabled: bool,
    requested_parallel: Option<bool>,
    leaf_nodes: usize,
    real_merges: usize,
    levels: usize,
    root_count: usize,
    nodes_started: usize,
    nodes_completed: usize,
    early_parent_starts: Option<usize>,
    topology: Vec<TopologyNode>,
    events: Vec<Event>,
}

#[derive(Serialize)]
struct TopologyNode {
    node_id: usize,
    left: usize,
    right: usize,
    level: usize,
    index: usize,
    candidates: usize,
    baseline_ready_merges: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(super) struct NodePolicy {
    pub level: usize,
    pub index: usize,
    pub candidates: usize,
    pub baseline_ready_merges: usize,
    pub requested_parallel: bool,
}

impl NodePolicy {
    pub fn final_node(level: usize, parallel: bool) -> Self {
        Self {
            level,
            index: 0,
            candidates: 2,
            baseline_ready_merges: 1,
            requested_parallel: parallel,
        }
    }
}

#[derive(Clone, Debug)]
struct Node {
    policy: NodePolicy,
    children: [usize; 2],
    parent: Option<usize>,
    dependencies: usize,
}

#[derive(Debug)]
struct Graph {
    leaves: usize,
    nodes: Vec<Node>,
    levels: Vec<Vec<usize>>,
    root: usize,
}

impl Graph {
    fn new(leaves: usize, parallel: bool) -> Self {
        assert!(leaves > 0, "a tournament must contain a leaf");
        let mut graph = Self {
            leaves,
            nodes: Vec::with_capacity(leaves - 1),
            levels: Vec::new(),
            root: 0,
        };
        let mut current: Vec<_> = (0..leaves).collect();
        while current.len() > 1 {
            let candidates = current.len();
            let level = graph.levels.len();
            let mut next = Vec::with_capacity(candidates.div_ceil(2));
            let mut at_level = Vec::with_capacity(candidates / 2);
            for (index, children) in current.chunks_exact(2).enumerate() {
                let node_index = graph.nodes.len();
                let children = [children[0], children[1]];
                let dependencies = children.iter().filter(|&&id| id >= leaves).count();
                for child in children {
                    if child >= leaves {
                        assert!(graph.nodes[child - leaves]
                            .parent
                            .replace(node_index)
                            .is_none());
                    }
                }
                graph.nodes.push(Node {
                    policy: NodePolicy {
                        level,
                        index,
                        candidates,
                        baseline_ready_merges: candidates / 2,
                        requested_parallel: parallel,
                    },
                    children,
                    parent: None,
                    dependencies,
                });
                at_level.push(node_index);
                next.push(leaves + node_index);
            }
            if candidates % 2 == 1 {
                next.push(*current.last().expect("odd carried leaf"));
            }
            graph.levels.push(at_level);
            current = next;
        }
        graph.root = current[0];
        assert_eq!(graph.nodes.len(), leaves - 1);
        graph
    }
}

#[derive(Clone, Debug, Serialize)]
struct Event {
    seq: usize,
    event: &'static str,
    node_id: usize,
    level: usize,
    index: usize,
}

struct Execution<'a, T, M, F> {
    graph: &'a Graph,
    merge: &'a F,
    values: Vec<Mutex<Option<T>>>,
    metrics: Vec<Mutex<Option<M>>>,
    pending: Vec<AtomicUsize>,
    started: AtomicUsize,
    completed: AtomicUsize,
    trace: bool,
    events: Mutex<Vec<Event>>,
}

impl<'a, T: Send, M: Send, F: Fn(NodePolicy, &[T; 2]) -> (T, M) + Sync> Execution<'a, T, M, F> {
    fn event(&self, index: usize, event: &'static str) {
        if self.trace {
            let policy = self.graph.nodes[index].policy;
            let mut events = self.events.lock().expect("DAG trace mutex");
            let seq = events.len();
            events.push(Event {
                seq,
                event,
                node_id: self.graph.leaves + index,
                level: policy.level,
                index: policy.index,
            });
        }
    }

    fn run_node(&self, index: usize) {
        let node = &self.graph.nodes[index];
        // Take each input once and release both locks before any cryptographic work.
        let inputs = node.children.map(|child| {
            self.values[child]
                .lock()
                .expect("DAG value mutex")
                .take()
                .expect("child output is ready and consumed once")
        });
        self.started.fetch_add(1, Ordering::Relaxed);
        self.event(index, "start");
        let (value, metrics) = (self.merge)(node.policy, &inputs);
        *self.values[self.graph.leaves + index]
            .lock()
            .expect("DAG output mutex") = Some(value);
        *self.metrics[index].lock().expect("DAG metrics mutex") = Some(metrics);
        self.completed.fetch_add(1, Ordering::Relaxed);
        self.event(index, "finish");
    }

    fn spawn_node<'scope>(&'scope self, scope: &rayon::Scope<'scope>, index: usize) {
        scope.spawn(move |scope| {
            self.run_node(index);
            if let Some(parent) = self.graph.nodes[index].parent {
                // Publication precedes this release; the last dependency enqueues once.
                let previous = self.pending[parent].fetch_sub(1, Ordering::AcqRel);
                assert!(previous > 0, "each dependency completes once");
                if previous == 1 {
                    self.spawn_node(scope, parent);
                }
            }
        });
    }
}

struct Reduced<T, M> {
    winner: T,
    metrics: Vec<(NodePolicy, M)>,
    report: QueryReport,
}

fn execute<T: Send, M: Send, F: Fn(NodePolicy, &[T; 2]) -> (T, M) + Sync>(
    leaves: Vec<T>,
    parallel: bool,
    mode: Mode,
    trace: bool,
    profile: bool,
    merge: &F,
) -> Reduced<T, M> {
    let graph = Graph::new(leaves.len(), parallel);
    let mut values: Vec<_> = leaves
        .into_iter()
        .map(|leaf| Mutex::new(Some(leaf)))
        .collect();
    values.extend((0..graph.nodes.len()).map(|_| Mutex::new(None)));
    let execution = Execution {
        graph: &graph,
        merge,
        values,
        metrics: (0..graph.nodes.len()).map(|_| Mutex::new(None)).collect(),
        pending: graph
            .nodes
            .iter()
            .map(|node| AtomicUsize::new(node.dependencies))
            .collect(),
        started: AtomicUsize::new(0),
        completed: AtomicUsize::new(0),
        trace,
        events: Mutex::new(Vec::new()),
    };
    if parallel && mode == Mode::DagReady {
        rayon::scope(|scope| {
            for (index, node) in graph.nodes.iter().enumerate() {
                // Test the immutable initial count, never the concurrently changing count.
                if node.dependencies == 0 {
                    execution.spawn_node(scope, index);
                }
            }
        });
    } else {
        for nodes in &graph.levels {
            let started = if profile {
                crate::smallcuts::start_timer()
            } else {
                None
            };
            if parallel {
                nodes
                    .par_iter()
                    .for_each(|&index| execution.run_node(index));
            } else {
                nodes.iter().for_each(|&index| execution.run_node(index));
            }
            if profile {
                crate::smallcuts::record_level(
                    graph.nodes[nodes[0]].policy.candidates,
                    parallel,
                    started,
                );
            }
        }
    }
    let count = graph.nodes.len();
    assert_eq!(execution.started.load(Ordering::Relaxed), count);
    assert_eq!(execution.completed.load(Ordering::Relaxed), count);
    let winner = execution.values[graph.root]
        .lock()
        .expect("DAG root mutex")
        .take()
        .expect("one completed root");
    assert!(execution
        .values
        .iter()
        .all(|slot| slot.lock().expect("DAG remaining value mutex").is_none()));
    let metrics = graph
        .nodes
        .iter()
        .zip(&execution.metrics)
        .map(|(node, slot)| {
            (
                node.policy,
                slot.lock()
                    .expect("DAG metrics mutex")
                    .take()
                    .expect("one metric per merge"),
            )
        })
        .collect();
    let events = execution.events.into_inner().expect("DAG trace mutex");
    let early = trace.then(|| {
        events
            .iter()
            .filter(|event| {
                event.event == "start"
                    && event.level > 0
                    && events.iter().any(|other| {
                        other.event == "finish"
                            && other.level + 1 == event.level
                            && other.seq > event.seq
                    })
            })
            .count()
    });
    let topology = if trace {
        graph
            .nodes
            .iter()
            .enumerate()
            .map(|(index, node)| TopologyNode {
                node_id: graph.leaves + index,
                left: node.children[0],
                right: node.children[1],
                level: node.policy.level,
                index: node.policy.index,
                candidates: node.policy.candidates,
                baseline_ready_merges: node.policy.baseline_ready_merges,
            })
            .collect()
    } else {
        Vec::new()
    };
    let report = QueryReport {
        schema: "tournament-dag-query.v1",
        mode: mode.name(),
        enabled: true,
        trace_enabled: trace,
        requested_parallel: Some(parallel),
        leaf_nodes: graph.leaves,
        real_merges: count,
        levels: graph.levels.len(),
        root_count: 1,
        nodes_started: execution.started.load(Ordering::Relaxed),
        nodes_completed: execution.completed.load(Ordering::Relaxed),
        early_parent_starts: early,
        topology,
        events,
    };
    Reduced {
        winner,
        metrics,
        report,
    }
}

pub(super) fn reduce<T: Send, M: Send, F: Fn(NodePolicy, &[T; 2]) -> (T, M) + Sync>(
    leaves: Vec<T>,
    parallel: bool,
    merge: F,
) -> (T, Vec<(NodePolicy, M)>, usize) {
    assert!(enabled());
    let result = execute(
        leaves,
        parallel,
        mode(),
        TRACE.load(Ordering::Relaxed),
        true,
        &merge,
    );
    let levels = result.report.levels;
    *REPORT.lock().expect("DAG report mutex") = Some(result.report);
    (result.winner, result.metrics, levels)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::{Condvar, Mutex};

    fn reference(mut items: Vec<String>) -> String {
        while items.len() > 1 {
            let mut next: Vec<_> = items
                .chunks_exact(2)
                .map(|pair| format!("({},{})", pair[0], pair[1]))
                .collect();
            if items.len() % 2 == 1 {
                next.push(items.last().unwrap().clone());
            }
            items = next;
        }
        items.pop().unwrap()
    }

    fn check_events(report: &Value) {
        let nodes = report["topology"].as_array().unwrap();
        let events = report["events"].as_array().unwrap();
        let mut finished = BTreeMap::new();
        let mut started = BTreeMap::new();
        let leaves = report["leaf_nodes"].as_u64().unwrap();
        for (seq, event) in events.iter().enumerate() {
            assert_eq!(event["seq"], seq);
            let id = event["node_id"].as_u64().unwrap();
            let node = &nodes[(id - leaves) as usize];
            assert_eq!(event["level"], node["level"]);
            assert_eq!(event["index"], node["index"]);
            if event["event"] == "start" {
                assert!(started.insert(id, seq).is_none());
                for child in ["left", "right"] {
                    let child = node[child].as_u64().unwrap();
                    assert!(child < leaves || finished.contains_key(&child));
                }
            } else {
                assert_eq!(event["event"], "finish");
                assert!(started.contains_key(&id));
                assert!(finished.insert(id, seq).is_none());
            }
        }
        assert_eq!(
            (started.len(), finished.len(), events.len()),
            (nodes.len(), nodes.len(), 2 * nodes.len())
        );
    }

    #[test]
    fn exact_adjacent_tree_and_public_policy_across_sizes() {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .unwrap();
        for n in [
            1, 2, 3, 5, 6, 7, 15, 17, 31, 63, 65, 127, 128, 129, 224, 225,
        ] {
            let expected = reference((0..n).map(|i| i.to_string()).collect());
            for parallel in [false, true] {
                for mode in [Mode::BarrierReference, Mode::DagReady] {
                    let result = pool.install(|| {
                        execute(
                            (0..n).map(|i| i.to_string()).collect(),
                            parallel,
                            mode,
                            true,
                            false,
                            &|policy, pair: &[String; 2]| {
                                (format!("({},{})", pair[0], pair[1]), policy)
                            },
                        )
                    });
                    assert_eq!(result.winner, expected);
                    assert_eq!(result.metrics.len(), n - 1);
                    let mut candidates = n;
                    let mut offset = 0;
                    let mut level = 0;
                    while candidates > 1 {
                        for index in 0..candidates / 2 {
                            let expected = NodePolicy {
                                level,
                                index,
                                candidates,
                                baseline_ready_merges: candidates / 2,
                                requested_parallel: parallel,
                            };
                            assert_eq!(result.metrics[offset], (expected, expected));
                            offset += 1;
                        }
                        candidates = candidates.div_ceil(2);
                        level += 1;
                    }
                    check_events(&serde_json::to_value(&result.report).unwrap());
                    if !parallel || mode == Mode::BarrierReference {
                        assert_eq!(result.report.early_parent_starts, Some(0));
                    }
                }
            }
        }
    }

    #[test]
    fn every_admitted_size_matches_interval_topology_oracle() {
        // Independent interval construction: double public block width without carrying
        // a vector of winners. Previously created interval IDs resolve short odd blocks.
        for n in 1usize..=3374 {
            let graph = Graph::new(n, true);
            let mut intervals: BTreeMap<_, _> = (0..n).map(|i| ((i, i + 1), i)).collect();
            let mut width = 1;
            let mut ordinal = 0;
            let mut level = 0;
            let mut parent_count = vec![0usize; 2 * n - 1];
            while width < n {
                let candidates = n.div_ceil(width);
                let mut index = 0;
                for start in (0..n).step_by(2 * width) {
                    let middle = start + width;
                    if middle >= n {
                        continue;
                    }
                    let end = (start + 2 * width).min(n);
                    let children = [intervals[&(start, middle)], intervals[&(middle, end)]];
                    let node = &graph.nodes[ordinal];
                    assert_eq!(
                        node.children, children,
                        "N={n}, level={level}, index={index}"
                    );
                    assert_eq!(
                        node.policy,
                        NodePolicy {
                            level,
                            index,
                            candidates,
                            baseline_ready_merges: candidates / 2,
                            requested_parallel: true,
                        }
                    );
                    for child in children {
                        parent_count[child] += 1;
                        if child >= n {
                            assert_eq!(graph.nodes[child - n].parent, Some(ordinal));
                        }
                    }
                    intervals.insert((start, end), n + ordinal);
                    ordinal += 1;
                    index += 1;
                }
                assert_eq!(graph.levels[level].len(), candidates / 2);
                assert_eq!(index, candidates / 2);
                width *= 2;
                level += 1;
            }
            assert_eq!(ordinal, n - 1);
            assert_eq!(graph.root, intervals[&(0, n)]);
            assert_eq!(graph.levels.len(), level);
            for (id, count) in parent_count.into_iter().enumerate() {
                assert_eq!(count, usize::from(id != graph.root));
            }
        }
    }

    #[test]
    fn nested_rayon_work_keeps_original_public_width_policy() {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .unwrap();
        for parallel in [false, true] {
            for mode in [Mode::BarrierReference, Mode::DagReady] {
                let result = pool.install(|| {
                    execute(
                        (0usize..33).collect(),
                        parallel,
                        mode,
                        true,
                        false,
                        &|policy, pair: &[usize; 2]| {
                            let (left, right) = rayon::join(
                                || {
                                    (0..3)
                                        .into_par_iter()
                                        .map(|lane| pair[0] + lane)
                                        .sum::<usize>()
                                },
                                || {
                                    (0..3)
                                        .into_par_iter()
                                        .map(|lane| pair[1] + lane)
                                        .sum::<usize>()
                                },
                            );
                            assert_eq!(left, 3 * pair[0] + 3);
                            assert_eq!(right, 3 * pair[1] + 3);
                            (pair[0] + pair[1], policy)
                        },
                    )
                });
                assert_eq!(result.winner, (0..33).sum::<usize>());
                assert!(result
                    .metrics
                    .iter()
                    .any(|(policy, _)| policy.baseline_ready_merges > 4));
                assert!(result
                    .metrics
                    .iter()
                    .any(|(policy, _)| policy.baseline_ready_merges <= 4));
                assert!(result
                    .metrics
                    .iter()
                    .all(|(policy, observed)| policy == observed));
                check_events(&serde_json::to_value(&result.report).unwrap());
            }
        }
    }

    #[test]
    fn nested_parallel_work_progresses_across_original_width_cutoff() {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .unwrap();
        let gate = (Mutex::new((false, false)), Condvar::new());
        let result = pool.install(|| {
            execute(
                (0usize..33).collect(),
                true,
                Mode::DagReady,
                true,
                false,
                &|policy, pair: &[usize; 2]| {
                    if policy.level == 1 && policy.index == 6 {
                        assert_eq!(policy.baseline_ready_merges, 8);
                        let mut state = gate.0.lock().unwrap();
                        state.0 = true;
                        gate.1.notify_all();
                        let (state, _) = gate
                            .1
                            .wait_timeout_while(state, std::time::Duration::from_secs(5), |state| {
                                !state.1
                            })
                            .unwrap();
                        assert!(
                            state.1,
                            "width-4 parent did not run during an unrelated width-8 merge"
                        );
                    }
                    if policy.level == 2 && policy.index == 0 {
                        assert_eq!(policy.baseline_ready_merges, 4);
                        let state = gate.0.lock().unwrap();
                        let (mut state, _) = gate
                            .1
                            .wait_timeout_while(state, std::time::Duration::from_secs(5), |state| {
                                !state.0
                            })
                            .unwrap();
                        assert!(
                            state.0,
                            "unrelated width-8 merge did not run while ready parent was active"
                        );
                        state.1 = true;
                        gate.1.notify_all();
                    }
                    // Publish the condition handshake before nested Rayon work can help a
                    // different gated node reentrantly on this worker's call stack.
                    let (left, right) = rayon::join(
                        || {
                            (0..3)
                                .into_par_iter()
                                .map(|lane| pair[0] + lane)
                                .sum::<usize>()
                        },
                        || {
                            (0..3)
                                .into_par_iter()
                                .map(|lane| pair[1] + lane)
                                .sum::<usize>()
                        },
                    );
                    assert_eq!((left, right), (3 * pair[0] + 3, 3 * pair[1] + 3));
                    (pair[0] + pair[1], policy)
                },
            )
        });
        assert_eq!(result.winner, (0..33).sum::<usize>());
        assert!(result
            .metrics
            .iter()
            .all(|(policy, observed)| policy == observed));
        check_events(&serde_json::to_value(&result.report).unwrap());
        assert!(result.report.early_parent_starts.unwrap() > 0);
    }

    #[test]
    fn stable_ties_and_odd_carries_retain_first_identity() {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .unwrap();
        for n in [1, 2, 3, 127, 128, 129, 224, 225] {
            for best in [0, n / 2, n - 1] {
                let leaves: Vec<_> = (0..n)
                    .map(|id| (if id >= best { -7 } else { 3 }, id))
                    .collect();
                for mode in [Mode::BarrierReference, Mode::DagReady] {
                    let result = pool.install(|| {
                        execute(
                            leaves.clone(),
                            true,
                            mode,
                            false,
                            false,
                            &|_, pair: &[(i32, usize); 2]| {
                                (
                                    if pair[0].0 <= pair[1].0 {
                                        pair[0]
                                    } else {
                                        pair[1]
                                    },
                                    (),
                                )
                            },
                        )
                    });
                    assert_eq!(result.winner, (-7, best));
                    assert!(result.report.events.is_empty());
                    assert!(result.report.early_parent_starts.is_none());
                }
            }
        }
    }

    #[test]
    fn ready_parent_progresses_before_unrelated_level_finishes() {
        // Two workers suffice: an unrelated level-0 merge waits until the left level-1
        // parent runs. A timeout releases the waiter if readiness regresses, avoiding
        // an indefinitely blocked test; success depends on the condition, not elapsed time.
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .unwrap();
        let gate = (Mutex::new(false), Condvar::new());
        let result = pool.install(|| {
            execute(
                (0..8).collect(),
                true,
                Mode::DagReady,
                true,
                false,
                &|policy, pair: &[usize; 2]| {
                    if policy.level == 0 && policy.index == 2 {
                        let (lock, condvar) = &gate;
                        let ready = lock.lock().unwrap();
                        let (ready, _) = condvar
                            .wait_timeout_while(ready, std::time::Duration::from_secs(5), |ready| {
                                !*ready
                            })
                            .unwrap();
                        assert!(
                            *ready,
                            "ready parent did not progress while unrelated merge waited"
                        );
                    }
                    if policy.level == 1 && policy.index == 0 {
                        *gate.0.lock().unwrap() = true;
                        gate.1.notify_all();
                    }
                    (pair[0].min(pair[1]), ())
                },
            )
        });
        assert_eq!(result.winner, 0);
        check_events(&serde_json::to_value(&result.report).unwrap());
        assert!(result.report.early_parent_starts.unwrap() > 0);
    }
}
