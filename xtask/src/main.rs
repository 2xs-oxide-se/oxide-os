fn main() {
    if let Err(error) = xtask::main_entry() {
        eprintln!("----- repporting error -----");
        eprintln!("{error}");
        eprintln!("----- end of repport -----");
        std::process::exit(1);
    }
}
