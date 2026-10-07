mod diagnostic;

fn main() {
    if let Err(error) = diagnostic::run() {
        eprintln!("A125_ERROR: {error}");
        std::process::exit(1);
    }
}
