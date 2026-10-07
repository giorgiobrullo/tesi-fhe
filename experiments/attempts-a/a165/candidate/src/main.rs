mod diagnostic;

fn main() {
    if let Err(error) = diagnostic::run() {
        eprintln!("A165_ERROR: {error}");
        std::process::exit(1);
    }
}
