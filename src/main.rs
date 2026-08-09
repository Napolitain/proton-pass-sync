use clap::Parser;
use proton_pass_sync::cli::Cli;

fn main() {
    let cli = Cli::parse();
    if let Err(error) = proton_pass_sync::run(cli) {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}
