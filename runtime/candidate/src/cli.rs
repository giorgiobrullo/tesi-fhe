//! Validate the complete command line before initializing the numerical runtime.
use crate::profile::QueryProfile;
use crate::protocol::PROBE_DIM;
use crate::{client_commands, diagnostics, dispatch, http, keygen, metadata, rebind, runtime};
use pfks_core::service::{self, ExecutionMode};
use std::path::Path;

const USAGE: &str = "uso: varco_demo_composite_v9 keygen <dir> | encrypt <dir> <probe.txt> <out> head51 | decrypt <dir> <esito.ct> | serve <porta> [dim] [T_default] | plan-json <fixture> | counts-base <n> <mode> [sentinel] | rebind-v8 <source> <destination> | rebind-probe-v8 <source> <destination> | export-phase-key <dir> <destination> | mutate-bundle <source> <destination> <mutation>";

#[derive(Debug)]
enum Command<'a> {
    Help,
    Keygen(&'a str),
    Encrypt {
        directory: &'a str,
        probe: &'a str,
        output: &'a str,
        profile: QueryProfile,
    },
    Decrypt {
        directory: &'a str,
        ciphertext: &'a str,
    },
    Serve {
        port: u16,
        dimension: usize,
        threshold: i64,
    },
    Plan(&'a str),
    Counts {
        gallery_size: usize,
        mode: ExecutionMode,
    },
    RebindKeys {
        source: &'a str,
        destination: &'a str,
    },
    RebindProbe {
        source: &'a str,
        destination: &'a str,
    },
    ExportPhaseKey {
        directory: &'a str,
        destination: &'a str,
    },
    MutateBundle {
        source: &'a str,
        destination: &'a str,
        mutation: &'a str,
    },
}

fn parse(arguments: &[String]) -> Result<Command<'_>, String> {
    let args: Vec<&str> = arguments.iter().map(String::as_str).collect();
    match args.as_slice() {
        ["--help"] | ["-h"] => Ok(Command::Help),
        ["keygen", directory] => Ok(Command::Keygen(directory)),
        ["encrypt", directory, probe, output, profile] => Ok(Command::Encrypt {
            directory,
            probe,
            output,
            profile: QueryProfile::from_cli(profile)?,
        }),
        ["decrypt", directory, ciphertext] => Ok(Command::Decrypt {
            directory,
            ciphertext,
        }),
        ["serve", port, optional @ ..] if optional.len() <= 2 => {
            let port = port
                .parse()
                .map_err(|_| "la porta deve essere un intero in 0..65535")?;
            let dimension = optional
                .first()
                .unwrap_or(&"512")
                .parse::<usize>()
                .map_err(|_| "dim deve essere un intero")?;
            if dimension != PROBE_DIM {
                return Err(format!("varco_demo supporta dim={PROBE_DIM}"));
            }
            let threshold = optional
                .get(1)
                .unwrap_or(&"0")
                .parse()
                .map_err(|_| "T_default deve essere un intero i64")?;
            Ok(Command::Serve {
                port,
                dimension,
                threshold,
            })
        }
        ["plan-json", source] => Ok(Command::Plan(source)),
        ["counts-base", n, name, optional @ ..] if optional.len() <= 1 => {
            let gallery_size = n.parse().map_err(|_| "gallery size must be an integer")?;
            let mode = dispatch::mode_from_cli(name, optional.first().copied())?;
            service::operation_counts(gallery_size, mode)
                .ok_or("valid gallery size and mode required")?;
            Ok(Command::Counts { gallery_size, mode })
        }
        ["rebind-v8", source, destination] => Ok(Command::RebindKeys {
            source,
            destination,
        }),
        ["rebind-probe-v8", source, destination] => Ok(Command::RebindProbe {
            source,
            destination,
        }),
        ["export-phase-key", directory, destination] => Ok(Command::ExportPhaseKey {
            directory,
            destination,
        }),
        ["mutate-bundle", source, destination, mutation] => Ok(Command::MutateBundle {
            source,
            destination,
            mutation,
        }),
        _ => Err(format!(
            "comando sconosciuto o argomenti incompleti\n{USAGE}"
        )),
    }
}

pub(crate) fn run(arguments: Vec<String>) -> Result<(), String> {
    let command = parse(&arguments)?;
    if matches!(command, Command::Help) {
        println!("{USAGE}");
        return Ok(());
    }
    runtime::initialize_process()?;
    match command {
        Command::Help => unreachable!("help returns before numerical initialization"),
        Command::Keygen(directory) => keygen::generate(Path::new(directory)),
        Command::Encrypt {
            directory,
            probe,
            output,
            profile,
        } => client_commands::encrypt(directory, probe, output, profile),
        Command::Decrypt {
            directory,
            ciphertext,
        } => client_commands::decrypt(directory, ciphertext),
        Command::Serve {
            port,
            dimension,
            threshold,
        } => http::serve(port, dimension, threshold)?,
        Command::Plan(source) => println!("{}", rebind::plan(Path::new(source))?),
        Command::Counts { gallery_size, mode } => print_counts(gallery_size, mode)?,
        Command::RebindKeys {
            source,
            destination,
        } => println!(
            "{}",
            rebind::keys(Path::new(source), Path::new(destination))?
        ),
        Command::RebindProbe {
            source,
            destination,
        } => println!(
            "{}",
            rebind::probe(Path::new(source), Path::new(destination))?
        ),
        Command::ExportPhaseKey {
            directory,
            destination,
        } => diagnostics::export_phase_key(Path::new(directory), Path::new(destination)),
        Command::MutateBundle {
            source,
            destination,
            mutation,
        } => diagnostics::mutate_bundle(source, Path::new(destination), mutation),
    }
    Ok(())
}

fn print_counts(n: usize, mode: ExecutionMode) -> Result<(), String> {
    let mut receipt = metadata::counts_json(
        service::operation_counts(n, mode).ok_or("valid gallery size and mode required")?,
    );
    let fields = receipt.as_object_mut().expect("count object");
    fields.insert("scope".into(), serde_json::json!("baseline before public threshold/digit savings; use plan-json for an actual template ledger"));
    fields.insert("n".into(), serde_json::json!(n));
    fields.insert(
        "execution_mode".into(),
        serde_json::json!(dispatch::mode_name(mode)),
    );
    fields.insert(
        "sentinel_score".into(),
        serde_json::json!(dispatch::sentinel_score(mode)),
    );
    fields.insert(
        "endpoint".into(),
        serde_json::json!(dispatch::endpoint_name(mode)),
    );
    fields.insert("structural_only".into(), serde_json::json!(true));
    println!("{receipt}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).into()).collect()
    }

    #[test]
    fn every_command_rejects_missing_and_excess_arguments_without_panicking() {
        for command in [
            "keygen",
            "encrypt",
            "decrypt",
            "serve",
            "plan-json",
            "counts-base",
            "rebind-v8",
            "rebind-probe-v8",
            "export-phase-key",
            "mutate-bundle",
        ] {
            assert!(parse(&args(&[command])).is_err(), "{command}");
            assert!(
                parse(&args(&[command, "a", "b", "c", "d", "e", "f"])).is_err(),
                "{command}"
            );
        }
        assert!(parse(&[]).is_err());
        assert!(parse(&args(&["unknown"])).is_err());
    }

    #[test]
    fn invalid_numeric_arguments_and_profiles_are_rejected_before_runtime_setup() {
        for values in [
            vec!["serve", "no"],
            vec!["serve", "65536"],
            vec!["serve", "9005", "1"],
            vec!["serve", "9005", "512", "no"],
            vec!["counts-base", "x", "mixed_winner_threshold"],
            vec!["counts-base", "1", "uniform_sentinel"],
            vec!["encrypt", "keys", "probe", "out", "head52"],
        ] {
            assert!(parse(&args(&values)).is_err(), "{values:?}");
        }
    }

    #[test]
    fn documented_server_defaults_and_explicit_threshold_are_preserved() {
        assert!(matches!(
            parse(&args(&["serve", "9005"])).unwrap(),
            Command::Serve {
                port: 9005,
                dimension: 512,
                threshold: 0
            }
        ));
        assert!(matches!(
            parse(&args(&["serve", "9005", "512", "-4"])).unwrap(),
            Command::Serve { threshold: -4, .. }
        ));
        assert!(matches!(
            parse(&args(&["decrypt", "keys", "result"])).unwrap(),
            Command::Decrypt {
                directory: "keys",
                ciphertext: "result"
            }
        ));
        assert!(matches!(parse(&args(&["--help"])).unwrap(), Command::Help));
    }
}
