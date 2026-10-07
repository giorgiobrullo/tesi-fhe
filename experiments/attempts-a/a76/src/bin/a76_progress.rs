use std::env;
use std::error::Error;
use std::time::Instant;

use a76_a68_progress::{
    clear_reference_identity, encrypt_query, evaluate_exact_identity_with_progress,
    worst_case_checked_gate_calls, GalleryEntry, ProgressConfig, ProtocolError, DIMENSION,
};
use tfhe::integer::gen_keys_radix;
use tfhe::shortint::parameters::V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64;

const DEFAULT_REPORT_EVERY: u64 = 256;

struct Options {
    run: bool,
    prefix_gates: Option<u64>,
    report_every: u64,
}

fn usage() -> &'static str {
    "usage:\n  a76-a68-progress --dry-plan\n  a76-a68-progress --run --case=n1 --prefix-gates=N [--report-every=N]"
}

fn parse_u64(raw: &str, flag: &str) -> Result<u64, String> {
    raw.parse::<u64>()
        .map_err(|_| format!("{flag} expects an unsigned integer, got {raw}"))
}

fn parse_options() -> Result<Options, String> {
    let mut run = false;
    let mut dry_plan = false;
    let mut case_name: Option<String> = None;
    let mut prefix_gates: Option<u64> = None;
    let mut report_every = DEFAULT_REPORT_EVERY;
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
                    .ok_or_else(|| "--case requires n1".to_owned())?,
            );
        } else if let Some(value) = argument.strip_prefix("--case=") {
            case_name = Some(value.to_owned());
        } else if argument == "--prefix-gates" {
            let raw = arguments
                .next()
                .ok_or_else(|| "--prefix-gates requires a value".to_owned())?;
            prefix_gates = Some(parse_u64(&raw, "--prefix-gates")?);
        } else if let Some(value) = argument.strip_prefix("--prefix-gates=") {
            prefix_gates = Some(parse_u64(value, "--prefix-gates")?);
        } else if argument == "--report-every" {
            let raw = arguments
                .next()
                .ok_or_else(|| "--report-every requires a value".to_owned())?;
            report_every = parse_u64(&raw, "--report-every")?;
        } else if let Some(value) = argument.strip_prefix("--report-every=") {
            report_every = parse_u64(value, "--report-every")?;
        } else {
            return Err(format!("unknown argument {argument}\n{}", usage()));
        }
    }

    if run && dry_plan {
        return Err("choose either --run or --dry-plan".to_owned());
    }
    if !run {
        if case_name.is_some() || prefix_gates.is_some() {
            return Err("case/prefix filters require --run".to_owned());
        }
        return Ok(Options {
            run: false,
            prefix_gates: None,
            report_every,
        });
    }
    if case_name.as_deref() != Some("n1") {
        return Err("instrumented runs require exactly --case=n1".to_owned());
    }
    let prefix = prefix_gates.ok_or_else(|| "--run requires --prefix-gates=N".to_owned())?;
    let full_bound = worst_case_checked_gate_calls(1);
    if prefix == 0 || prefix >= full_bound {
        return Err(format!(
            "prefix must be in 1..{full_bound}; full evaluation is deliberately disabled"
        ));
    }
    if report_every == 0 {
        return Err("--report-every must be positive".to_owned());
    }
    Ok(Options {
        run: true,
        prefix_gates: Some(prefix),
        report_every,
    })
}

fn main() -> Result<(), Box<dyn Error>> {
    let options = parse_options().map_err(|message| format!("{message}"))?;
    if !options.run {
        println!("A76 instrumentation dry plan; no key generation or FHE evaluation performed");
        println!(
            "fixed case: D={DIMENSION}, N=1; full ledger={}",
            worst_case_checked_gate_calls(1)
        );
        println!("run mode requires an exact checked-gate prefix below the full ledger");
        return Ok(());
    }

    let started = Instant::now();
    let query = vec![0_i8; DIMENSION];
    let gallery = vec![GalleryEntry::new(vec![0_i8; DIMENSION], 0)?];
    let expected = clear_reference_identity(&query, &gallery)?;
    let prefix = options.prefix_gates.ok_or("missing checked prefix")?;
    eprintln!(
        "A76_CHECKPOINT fixture_complete elapsed_ms={} D={DIMENSION} N=1 expected_id={expected}",
        started.elapsed().as_millis()
    );

    eprintln!(
        "A76_CHECKPOINT keygen_start elapsed_ms={} parameter=V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64 radix_blocks=1",
        started.elapsed().as_millis()
    );
    let (client_key, server_key) =
        gen_keys_radix(V0_11_PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M64, 1);
    eprintln!(
        "A76_CHECKPOINT keygen_complete elapsed_ms={}",
        started.elapsed().as_millis()
    );

    eprintln!(
        "A76_CHECKPOINT encryption_start elapsed_ms={} selectors={}",
        started.elapsed().as_millis(),
        DIMENSION * 7
    );
    let encrypted_query = encrypt_query(&query, &client_key, &server_key)?;
    eprintln!(
        "A76_CHECKPOINT encryption_complete elapsed_ms={}",
        started.elapsed().as_millis()
    );

    eprintln!(
        "A76_CHECKPOINT evaluation_start elapsed_ms={} prefix_gates={prefix} report_every={}",
        started.elapsed().as_millis(),
        options.report_every
    );
    match evaluate_exact_identity_with_progress(
        &encrypted_query,
        &gallery,
        &server_key,
        ProgressConfig::bounded(prefix, options.report_every),
    ) {
        Err(ProtocolError::InstrumentationStop {
            completed_calls,
            stage,
        }) if completed_calls == prefix => {
            eprintln!(
                "A76_PREFIX_STOP elapsed_ms={} stage={stage} checked_calls={completed_calls} full_ledger={} status=EXPECTED_BOUNDED_STOP",
                started.elapsed().as_millis(),
                worst_case_checked_gate_calls(1)
            );
            Ok(())
        }
        Err(error) => Err(error.into()),
        Ok(_) => Err("instrumented prefix unexpectedly completed the full circuit".into()),
    }
}
