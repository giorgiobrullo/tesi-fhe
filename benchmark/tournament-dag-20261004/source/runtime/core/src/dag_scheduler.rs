//! Evaluate the original adjacent-pair bracket without joining whole levels.
use std::cell::Cell;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};

static ENABLED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodePolicy {
    pub ready: usize,
    pub requested_parallel: bool,
}

thread_local! {
    static POLICY: Cell<Option<NodePolicy>> = const { Cell::new(None) };
}

pub fn set_enabled(value: bool) {
    ENABLED.store(value, Ordering::Relaxed);
}

pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

pub fn current_policy() -> Option<NodePolicy> {
    POLICY.with(Cell::get)
}

// The guard belongs to the worker that executes the merge, including unwind.
struct PolicyGuard {
    previous: Option<NodePolicy>,
    _thread_bound: PhantomData<Rc<()>>,
}

impl PolicyGuard {
    fn enter(policy: NodePolicy) -> Self {
        Self {
            previous: POLICY.with(|slot| slot.replace(Some(policy))),
            _thread_bound: PhantomData,
        }
    }
}

impl Drop for PolicyGuard {
    fn drop(&mut self) {
        POLICY.with(|slot| slot.set(self.previous));
    }
}

pub struct Completed<M> {
    pub level: usize,
    pub index: usize,
    pub metrics: M,
}

enum Node<T> {
    Leaf(T),
    Merge {
        left: Box<Node<T>>,
        right: Box<Node<T>>,
        level: usize,
        index: usize,
        policy: NodePolicy,
    },
    Promote(Box<Node<T>>),
}

fn evaluate<T, M, F>(node: Node<T>, merge: &F) -> (T, Vec<Completed<M>>)
where
    T: Clone + Send,
    M: Send,
    F: Fn(usize, usize, &[T]) -> (T, M) + Sync,
{
    match node {
        Node::Leaf(value) => (value, Vec::new()),
        Node::Promote(child) => {
            let (value, completed) = evaluate(*child, merge);
            (value.clone(), completed)
        }
        Node::Merge { left, right, level, index, policy } => {
            let ((left, mut completed), (right, other)) = if policy.requested_parallel {
                rayon::join(|| evaluate(*left, merge), || evaluate(*right, merge))
            } else {
                (evaluate(*left, merge), evaluate(*right, merge))
            };
            completed.extend(other);
            let pair = [left, right];
            let (value, metrics) = {
                let _guard = PolicyGuard::enter(policy);
                merge(level, index, &pair)
            };
            completed.push(Completed { level, index, metrics });
            (value, completed)
        }
    }
}

pub fn reduce<T, M, F>(leaves: Vec<T>, requested_parallel: bool, merge: &F)
    -> (T, Vec<Completed<M>>)
where
    T: Clone + Send,
    M: Send,
    F: Fn(usize, usize, &[T]) -> (T, M) + Sync,
{
    assert!(!leaves.is_empty(), "tournament needs at least one leaf");
    let mut current: Vec<_> = leaves.into_iter().map(Node::Leaf).collect();
    let mut level = 0;
    while current.len() > 1 {
        let count = current.len();
        let ready = count / 2;
        let policy = NodePolicy { ready, requested_parallel };
        let mut nodes = current.into_iter();
        let mut next = Vec::with_capacity(ready + count % 2);
        for index in 0..ready {
            next.push(Node::Merge {
                left: Box::new(nodes.next().unwrap()),
                right: Box::new(nodes.next().unwrap()),
                level, index, policy,
            });
        }
        if let Some(tail) = nodes.next() {
            next.push(Node::Promote(Box::new(tail)));
        }
        current = next;
        level += 1;
    }
    let (winner, mut completed) = evaluate(current.pop().unwrap(), merge);
    completed.sort_by_key(|node| (node.level, node.index));
    (winner, completed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, atomic::AtomicUsize};

    #[test]
    fn reentrant_policy_restores_after_return_and_unwind() {
        assert_eq!(current_policy(), None);
        let outer = NodePolicy { ready: 60, requested_parallel: true };
        let guard = PolicyGuard::enter(outer);
        {
            let inner = NodePolicy { ready: 1, requested_parallel: false };
            let _guard = PolicyGuard::enter(inner);
            assert_eq!(current_policy(), Some(inner));
        }
        assert_eq!(current_policy(), Some(outer));
        let result = std::panic::catch_unwind(|| {
            let _guard = PolicyGuard::enter(NodePolicy { ready: 2, requested_parallel: true });
            panic!("test unwind");
        });
        assert!(result.is_err());
        assert_eq!(current_policy(), Some(outer));
        drop(guard);
        assert_eq!(current_policy(), None);
    }

    struct Tracked {
        leaves: Vec<usize>,
        clones: Arc<AtomicUsize>,
    }

    impl Clone for Tracked {
        fn clone(&self) -> Self {
            self.clones.fetch_add(1, Ordering::Relaxed);
            Self { leaves: self.leaves.clone(), clones: self.clones.clone() }
        }
    }

    #[test]
    fn n120_keeps_original_pairs_ready_counts_and_promotion_clone() {
        let ready = [60, 30, 15, 7, 4, 2, 1];
        let clones = Arc::new(AtomicUsize::new(0));
        let leaves = (0..120).map(|index| Tracked {
            leaves: vec![index], clones: clones.clone(),
        }).collect();
        let (winner, completed) = reduce(leaves, true, &|level, index, pair: &[Tracked]| {
            assert_eq!(pair.len(), 2);
            assert_eq!(current_policy(), Some(NodePolicy {
                ready: ready[level], requested_parallel: true,
            }));
            let left = &pair[0].leaves;
            let right = &pair[1].leaves;
            assert_eq!(left.last().unwrap() + 1, right[0]);
            let metrics = (left[0], *left.last().unwrap(), right[0], *right.last().unwrap());
            let start = index * (1usize << (level + 1));
            let middle = start + (1usize << level);
            assert_eq!(metrics, (start, middle - 1, middle, (start + (1usize << (level + 1)) - 1).min(119)));
            let value = Tracked {
                leaves: left.iter().chain(right).copied().collect(),
                clones: clones.clone(),
            };
            assert!(index < ready[level]);
            (value, metrics)
        });
        assert_eq!(winner.leaves, (0..120).collect::<Vec<_>>());
        assert_eq!(clones.load(Ordering::Relaxed), 1);
        assert_eq!(completed.len(), 119);
        for (level, count) in ready.into_iter().enumerate() {
            let nodes: Vec<_> = completed.iter().filter(|node| node.level == level).collect();
            assert_eq!(nodes.len(), count);
            assert_eq!(nodes.iter().map(|node| node.index).collect::<Vec<_>>(), (0..count).collect::<Vec<_>>());
        }
        assert_eq!(completed.last().unwrap().metrics, (0, 63, 64, 119));
        assert_eq!(current_policy(), None);
    }
}
