//! Local exact 0/ID service. The trusted client validates inputs and decodes output.
#![recursion_limit = "256"]

mod cli;
mod client_commands;
mod diagnostics;
mod dispatch;
mod evaluation;
mod gallery;
mod http;
mod http_request;
mod keygen;
mod keys;
mod metadata;
mod profile;
mod protocol;
mod rebind;
mod routes;
mod runtime;
mod supplement;
mod wire;

fn main() -> std::process::ExitCode {
    match cli::run(std::env::args().skip(1).collect()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod profile_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod threshold_tests;
