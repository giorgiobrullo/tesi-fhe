mod diagnostic;

fn main() {
    if let Err(error) = diagnostic::run() {
        eprintln!("A169_ERROR: {error}");
        std::process::exit(1);
    }
}
