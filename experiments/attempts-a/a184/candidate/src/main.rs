#![recursion_limit = "256"]

mod diagnostic;

fn main() {
    if let Err(error) = diagnostic::run() {
        eprintln!("A175_ERROR: {error}");
        std::process::exit(1);
    }
}
