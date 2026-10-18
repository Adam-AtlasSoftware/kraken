//! Whole-program emulation inside the sandbox child (`kraken-emu-run` under kraken-sidecar's
//! spawner: Landlock, seccomp, network namespace).

mod common;

use common::*;
use kraken_emu::confined::{read_message, run_program_confined, write_message};
use kraken_emu::{Exit, RunSpec};
use kraken_sidecar::ConfinementOptions;

#[test]
fn messages_round_trip_and_oversized_ones_are_refused() {
    let mut buf = Vec::new();
    write_message(&mut buf, b"{\"a\":1}").expect("write");
    let got = read_message(&mut buf.as_slice()).expect("read");
    assert_eq!(got, b"{\"a\":1}");
    let mut huge = (u64::MAX).to_le_bytes().to_vec();
    huge.extend_from_slice(b"x");
    assert!(read_message(&mut huge.as_slice()).is_err());
}

#[test]
#[ignore = "needs Ghidra processor sources for the SLEIGH specs and Landlock"]
fn a_program_runs_in_the_confined_runner() {
    let _ = specs(kraken_emu::Arch::Riscv32);
    let work = tempfile::tempdir().expect("tmp");
    let mut spec = RunSpec::new(bin("riscv32", "switch_vm-riscv32-O2"));
    spec.workdir = Some(work.path().to_path_buf());
    let runner = std::path::PathBuf::from(env!("CARGO_BIN_EXE_kraken-emu-run"));
    let (out, report) =
        run_program_confined(&spec, &runner, ConfinementOptions::default()).expect("confined run");
    eprintln!("confinement: {report}");
    assert!(report.is_confined(), "{report}");
    assert!(report.network_blocked(), "{report}");
    assert_eq!(out.exit, Exit::Code { code: 0 });
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        want_stdout("riscv32", "switch_vm")
    );
}
