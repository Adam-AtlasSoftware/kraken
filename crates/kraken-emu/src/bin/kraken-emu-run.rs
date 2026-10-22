//! The confined emulation runner: started by `kraken_emu::confined::run_program_confined` under
//! the sandbox, it reads one run request from the socket on fd 0, emulates the program and
//! writes the outcome back.

use std::process::ExitCode;

#[cfg(not(unix))]
fn main() -> ExitCode {
    eprintln!("kraken-emu-run: the emulation sandbox runs on Unix only");
    ExitCode::FAILURE
}

#[cfg(unix)]
fn main() -> ExitCode {
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream;

    let fd = match std::io::stdin().as_fd().try_clone_to_owned() {
        Ok(fd) => fd,
        Err(e) => {
            eprintln!("kraken-emu-run: fd 0: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut sock = UnixStream::from(fd);
    match kraken_emu::confined::serve(&mut sock) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("kraken-emu-run: {e}");
            ExitCode::FAILURE
        }
    }
}
