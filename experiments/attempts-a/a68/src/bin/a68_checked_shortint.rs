use std::env;
use std::error::Error;

use a68_checked_shortint::{
    clear_reference_identity, decrypt_identity, encrypt_query, evaluate_exact_identity,
    worst_case_checked_gate_calls, GalleryEntry, DIMENSION, MAX_GALLERY_SIZE,
};
use tfhe::integer::gen_keys_radix;
use tfhe::shortint::parameters::V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

const SMALL_N_MAX: usize = 8;

#[derive(Clone, Copy)]
enum RunCase {
    N1,
    Small(usize),
}

struct Options {
    run: bool,
    case: Option<RunCase>,
}

fn usage() -> &'static str {
    "usage:\n  a68-checked-shortint [--dry-plan]\n  a68-checked-shortint --run --case=n1\n  a68-checked-shortint --run --case=small [--small-n=2..8]"
}

fn parse_usize(raw: &str, flag: &str) -> Result<usize, String> {
    raw.parse::<usize>()
        .map_err(|_| format!("{flag} expects an unsigned integer, got {raw}"))
}

fn parse_options() -> Result<Options, String> {
    let mut run = false;
    let mut dry_plan = false;
    let mut case_name: Option<String> = None;
    let mut small_n = 4_usize;
    let mut arguments = env::args().skip(1);

    while let Some(argument) = arguments.next() {
        if argument == "--run" {
            run = true;
        } else if argument == "--dry-plan" {
            dry_plan = true;
        } else if argument == "--case" {
            case_name = Some(
                arguments
                    .next()
                    .ok_or_else(|| "--case requires n1 or small".to_owned())?,
            );
        } else if let Some(value) = argument.strip_prefix("--case=") {
            case_name = Some(value.to_owned());
        } else if argument == "--small-n" {
            let raw = arguments
                .next()
                .ok_or_else(|| "--small-n requires a value".to_owned())?;
            small_n = parse_usize(&raw, "--small-n")?;
        } else if let Some(value) = argument.strip_prefix("--small-n=") {
            small_n = parse_usize(value, "--small-n")?;
        } else if argument == "--help" || argument == "-h" {
            return Err(usage().to_owned());
        } else {
            return Err(format!("unknown argument {argument}\n{}", usage()));
        }
    }

    if run && dry_plan {
        return Err("choose either --run or --dry-plan".to_owned());
    }
    if !run {
        if case_name.is_some() {
            return Err("--case is accepted only with --run".to_owned());
        }
        return Ok(Options {
            run: false,
            case: None,
        });
    }

    let case = match case_name.as_deref() {
        Some("n1") => {
            if small_n != 4 {
                return Err("--small-n is not meaningful for --case=n1".to_owned());
            }
            RunCase::N1
        }
        Some("small") => {
            if !(2..=SMALL_N_MAX).contains(&small_n) {
                return Err(format!(
                    "small harness restricts N to 2..={SMALL_N_MAX}, got {small_n}"
                ));
            }
            RunCase::Small(small_n)
        }
        Some(other) => return Err(format!("unknown case {other}; expected n1 or small")),
        None => {
            return Err(format!(
                "--run requires an explicit --case filter\n{}",
                usage()
            ))
        }
    };

    Ok(Options {
        run: true,
        case: Some(case),
    })
}

fn print_dry_plan() {
    println!("A68 checked-only dry plan; no key generation or FHE evaluation performed");
    println!("fixed geometry: D={DIMENSION}, 1 <= N <= {MAX_GALLERY_SIZE}");
    println!("input: 512 x 7 fresh encrypt_bool selectors, one radix block each");
    println!("output: eight encrypted little-endian bits; 0=reject, i+1=identity");
    println!("ledger: M(N)=24,029+18,984*N possible checked-gate PBS events");
    for gallery_size in [1_usize, 4, 8, 128] {
        println!(
            "  N={gallery_size:>3}: M={}",
            worst_case_checked_gate_calls(gallery_size)
        );
    }
    println!("FHE is opt-in only: pass --run with --case=n1 or --case=small");
}

fn make_case(case: RunCase) -> Result<(Vec<i8>, Vec<GalleryEntry>, u8), Box<dyn Error>> {
    let query = vec![0_i8; DIMENSION];
    let gallery_size = match case {
        RunCase::N1 => 1,
        RunCase::Small(size) => size,
    };

    let mut gallery = Vec::with_capacity(gallery_size);
    for index in 0..gallery_size {
        let mut template = vec![0_i8; DIMENSION];
        if gallery_size > 1 && index + 1 < gallery_size {
            template[0] = 1;
        }
        gallery.push(GalleryEntry::new(template, 0)?);
    }
    let expected = clear_reference_identity(&query, &gallery)?;
    Ok((query, gallery, expected))
}

fn run_filtered_case(case: RunCase) -> Result<(), Box<dyn Error>> {
    let (query, gallery, expected) = make_case(case)?;
    println!(
        "explicit FHE run selected: D={DIMENSION}, N={}, expected ID={expected}",
        gallery.len()
    );
    println!("warning: this reference executes tens of thousands of checked gates even at N=1");

    let (client_key, server_key) =
        gen_keys_radix(V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64, 1);
    let encrypted_query = encrypt_query(&query, &client_key, &server_key)?;
    let evaluation = evaluate_exact_identity(&encrypted_query, &gallery, &server_key)?;
    let actual = decrypt_identity(&evaluation.identity, &client_key)?;

    if actual != expected {
        return Err(format!("FHE result {actual} did not match clear result {expected}").into());
    }
    if evaluation.checked_gate_calls > evaluation.worst_case_checked_gate_calls {
        return Err("checked-gate count exceeded its fail-closed ledger".into());
    }
    println!(
        "PASS: ID={actual}, checked calls={}, ledger upper bound={}",
        evaluation.checked_gate_calls, evaluation.worst_case_checked_gate_calls
    );
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let options = parse_options().map_err(|message| format!("{message}"))?;
    if !options.run {
        print_dry_plan();
        return Ok(());
    }
    let case = options
        .case
        .ok_or_else(|| "run mode lost its mandatory case filter".to_owned())?;
    run_filtered_case(case)
}
