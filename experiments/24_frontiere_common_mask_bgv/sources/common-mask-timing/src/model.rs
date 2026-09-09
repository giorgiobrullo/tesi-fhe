//! Independent clear oracle and public layout/ledger; no TFHE imports.
use std::collections::BTreeMap;

pub const LANES: usize = 4;
pub const A44_DELTA: u64 = 1 << 59;
pub const CM_DELTA: u64 = 1 << 61;

#[derive(Clone, Copy, Debug)]
pub struct Layout {
    pub bit: usize,
    pub weight: u64,
    pub rescale: u64,
    pub alpha: u64,
    pub beta: u64,
}

pub const LAYOUTS: [Layout; 8] = [
    Layout {
        bit: 7,
        weight: 1,
        rescale: 4,
        alpha: 2,
        beta: 1,
    },
    Layout {
        bit: 6,
        weight: 1,
        rescale: 4,
        alpha: 2,
        beta: 1,
    },
    Layout {
        bit: 5,
        weight: 1,
        rescale: 4,
        alpha: 2,
        beta: 1,
    },
    Layout {
        bit: 4,
        weight: 1,
        rescale: 4,
        alpha: 2,
        beta: 1,
    },
    Layout {
        bit: 3,
        weight: 1,
        rescale: 4,
        alpha: 2,
        beta: 1,
    },
    Layout {
        bit: 2,
        weight: 8,
        rescale: 1,
        alpha: 1,
        beta: 2,
    },
    Layout {
        bit: 1,
        weight: 4,
        rescale: 1,
        alpha: 2,
        beta: 1,
    },
    Layout {
        bit: 0,
        weight: 2,
        rescale: 2,
        alpha: 2,
        beta: 1,
    },
];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub packing: usize,
    pub cm_ks: usize,
    pub cm_pbs: usize,
    pub ordinary_ks: usize,
    pub ordinary_pbs: usize,
    pub extraction: usize,
}

pub fn reduction_nodes(mut groups: usize) -> usize {
    assert!(groups > 0);
    let mut nodes = 0;
    while groups > 1 {
        nodes += groups / 3 + usize::from(groups % 3 == 2);
        groups = groups.div_ceil(3);
    }
    nodes
}

pub fn expected_counts(n: usize) -> Counts {
    let g = n.div_ceil(LANES);
    let r = reduction_nodes(g);
    Counts {
        packing: 2 * g + 1,
        cm_ks: 2 * g + r,
        cm_pbs: 3 * g + r,
        ordinary_ks: n + 5,
        ordinary_pbs: n + 3,
        extraction: n + 4,
    }
}

#[derive(Clone)]
pub struct Fixture {
    pub name: String,
    pub active: Vec<u64>,
    pub bits: Vec<u64>,
}

impl Fixture {
    pub fn witness(n: usize) -> Self {
        let mut bits = vec![1; n];
        bits[0] = 0;
        Self {
            name: "asymmetric_zero_first".into(),
            active: vec![1; n],
            bits,
        }
    }
    pub fn validate(&self) {
        assert!(!self.active.is_empty());
        assert_eq!(self.active.len(), self.bits.len());
        assert!(self.active.iter().chain(&self.bits).all(|&x| x <= 1));
    }
}

pub fn fixtures(suite: &str) -> Vec<Fixture> {
    match suite {
        "witness" => vec![Fixture::witness(4)],
        "smoke" => vec![
            Fixture::witness(4),
            Fixture {
                name: "all_dead".into(),
                active: vec![0; 4],
                bits: vec![0, 1, 1, 0],
            },
            Fixture {
                name: "all_one_keep".into(),
                active: vec![1; 4],
                bits: vec![1; 4],
            },
            Fixture {
                name: "inactive_zero_does_not_eliminate".into(),
                active: vec![0, 1, 1, 0],
                bits: vec![0, 1, 1, 0],
            },
        ],
        "n4-exhaustive" => (0..256)
            .map(|word| Fixture {
                name: format!("boolean_{word:03}"),
                active: (0..4).map(|i| (word >> i) & 1).collect(),
                bits: (0..4).map(|i| (word >> (4 + i)) & 1).collect(),
            })
            .collect(),
        "n127" => {
            let mut out = vec![Fixture::witness(127)];
            out.push(Fixture {
                name: "all_dead_tail".into(),
                active: vec![0; 127],
                bits: vec![0; 127],
            });
            out.push(Fixture {
                name: "all_one_keep_tail".into(),
                active: vec![1; 127],
                bits: vec![1; 127],
            });
            for &idx in &[3, 4, 62, 124, 126] {
                let mut f = Fixture::witness(127);
                f.name = format!("only_zero_{idx}");
                f.bits.fill(1);
                f.bits[idx] = 0;
                out.push(f);
            }
            let mut tie = Fixture::witness(127);
            tie.name = "tie_across_groups_and_lanes".into();
            tie.bits[4] = 0;
            tie.bits[126] = 0;
            out.push(tie);
            out
        }
        _ => panic!("unknown suite"),
    }
}

#[derive(Clone, Debug)]
pub struct Expected {
    pub values: Vec<u64>,
    pub delta: u64,
}
pub type Expectations = BTreeMap<String, Expected>;

fn put(map: &mut Expectations, tag: String, values: Vec<u64>, delta: u64) {
    assert!(map.insert(tag, Expected { values, delta }).is_none());
}

/// The final oracle directly selects zero-bit live candidates, independently of update coding.
pub fn survivor_oracle(f: &Fixture) -> Vec<u64> {
    let any = f
        .active
        .iter()
        .zip(&f.bits)
        .any(|(&a, &b)| a == 1 && b == 0);
    f.active
        .iter()
        .zip(&f.bits)
        .map(|(&a, &b)| u64::from(a == 1 && (!any || b == 0)))
        .collect()
}

pub fn expectations(f: &Fixture, layout: Layout) -> Expectations {
    f.validate();
    assert_eq!(
        layout.weight * layout.rescale * A44_DELTA,
        layout.beta * CM_DELTA
    );
    let mut map = Expectations::new();
    let n = f.active.len();
    let groups = n.div_ceil(4);
    let mut aa = f.active.clone();
    let mut bb = f.bits.clone();
    aa.resize(groups * 4, 0);
    bb.resize(groups * 4, 0);
    let zz: Vec<_> = aa.iter().zip(&bb).map(|(&a, &b)| a * (1 - b)).collect();
    let any = u64::from(zz.contains(&1));
    for i in 0..n {
        put(
            &mut map,
            format!("input_active/{i}"),
            vec![aa[i]],
            A44_DELTA,
        );
        put(
            &mut map,
            format!("input_bit/{i}"),
            vec![bb[i] * layout.weight],
            A44_DELTA,
        );
    }
    let mut roots = Vec::new();
    for g in 0..groups {
        let a = aa[4 * g..4 * g + 4].to_vec();
        let b = bb[4 * g..4 * g + 4].to_vec();
        let z = zz[4 * g..4 * g + 4].to_vec();
        for prefix in ["active_pack", "active_big"] {
            put(&mut map, format!("{prefix}/{g}"), a.clone(), CM_DELTA);
        }
        put(
            &mut map,
            format!("bit_pack/{g}"),
            b.iter().map(|b| b * layout.beta).collect(),
            CM_DELTA,
        );
        put(
            &mut map,
            format!("z_input/{g}"),
            a.iter()
                .zip(&b)
                .map(|(a, b)| a * layout.alpha + b * layout.beta)
                .collect(),
            CM_DELTA,
        );
        put(&mut map, format!("z/{g}"), z.clone(), CM_DELTA);
        roots.push(z);
        let sum: Vec<_> = a
            .iter()
            .zip(&zz[4 * g..4 * g + 4])
            .map(|(a, z)| a + z)
            .collect();
        put(&mut map, format!("update_sum/{g}"), sum.clone(), CM_DELTA);
        let code: Vec<_> = sum.iter().map(|s| s + 1 - any).collect();
        put(
            &mut map,
            format!("update_input/{g}"),
            code.clone(),
            CM_DELTA,
        );
        put(
            &mut map,
            format!("next/{g}"),
            code.iter().map(|&x| u64::from(x == 2)).collect(),
            CM_DELTA,
        );
    }
    let mut level = 0;
    while roots.len() > 1 {
        let mut next = Vec::new();
        for (node, chunk) in roots.chunks(3).enumerate() {
            if chunk.len() == 1 {
                next.push(chunk[0].clone());
                continue;
            }
            let sums: Vec<u64> = (0..4)
                .map(|lane| chunk.iter().map(|row| row[lane]).sum())
                .collect();
            put(
                &mut map,
                format!("reduce_input/{level}/{node}"),
                sums.clone(),
                CM_DELTA,
            );
            let value: Vec<_> = sums.iter().map(|&s| u64::from(s != 0)).collect();
            put(
                &mut map,
                format!("reduce/{level}/{node}"),
                value.clone(),
                CM_DELTA,
            );
            next.push(value);
        }
        roots = next;
        level += 1;
    }
    let roots = &roots[0];
    for lane in 0..4 {
        put(
            &mut map,
            format!("root_bridge/{lane}"),
            vec![roots[lane]],
            CM_DELTA,
        );
    }
    let mut pair_flags = Vec::new();
    for pair in 0..2 {
        let sum = roots[2 * pair] + roots[2 * pair + 1];
        put(&mut map, format!("pair_input/{pair}"), vec![sum], CM_DELTA);
        let flag = u64::from(sum != 0);
        pair_flags.push(flag);
        put(&mut map, format!("pair/{pair}"), vec![flag], A44_DELTA);
    }
    put(
        &mut map,
        "any_input".into(),
        vec![pair_flags.iter().sum()],
        A44_DELTA,
    );
    put(&mut map, "any".into(), vec![any], A44_DELTA);
    put(&mut map, "broadcast".into(), vec![any; 4], CM_DELTA);
    let final_values = survivor_oracle(f);
    for (i, &value) in final_values.iter().enumerate() {
        put(&mut map, format!("egress_small/{i}"), vec![value], CM_DELTA);
        put(&mut map, format!("output/{i}"), vec![value], A44_DELTA);
    }
    map
}
