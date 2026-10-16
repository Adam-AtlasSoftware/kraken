//! The scripted demo pipeline, driven through the real registry commands and job machinery.

use std::time::Duration;

use tokio::runtime::Runtime;

use super::*;
use crate::ViewModel;
use crate::backend::JobState;

const WAIT: Duration = Duration::from_secs(20);

#[test]
fn the_demo_pipeline_runs_through_the_real_commands() {
    let rt = Runtime::new().expect("runtime");
    let demo = {
        let _g = rt.enter();
        crate::demo::demo_project_with(crate::demo::demo_fixture(), Duration::ZERO).expect("demo")
    };
    let mut vm = ViewModel::new(demo.backend.clone(), rt.handle().clone());
    vm.create_project(
        demo.binary.to_string_lossy(),
        demo.project_dir.to_string_lossy(),
    );
    assert!(vm.block_until_idle(WAIT));
    vm.rewrite.availability = Availability::Unknown;
    vm.rewrite_refresh();
    assert!(vm.block_until_idle(WAIT));
    let st = &vm.rewrite;
    assert_eq!(st.rows.len(), 13);
    assert_eq!(st.rows[0].name, "FUN_00401440");
    assert_eq!(
        (
            st.counts.accepted,
            st.counts.verified,
            st.counts.failed,
            st.counts.translated
        ),
        (1, 1, 1, 1)
    );

    // checksum failed twice; its stored versions carry the Rust and a counterexample.
    vm.rewrite_select(0x401240);
    assert!(vm.block_until_idle(WAIT));
    let d = vm.rewrite.selected_detail().expect("detail");
    assert!(d.c.as_ref().is_some_and(|c| c.text().contains("checksum")));
    assert_eq!(d.versions().len(), 2);
    assert!(
        d.current()
            .is_some_and(|v| v.counterexample.is_some() && v.rust.is_some())
    );

    // Retry: the script gets it right on the third try, and it can be accepted.
    vm.rewrite_retry(0x401240);
    assert!(vm.block_until(WAIT, |vm| vm.rewrite.acceptable_unit(0x401240).is_some()));
    assert!(vm.block_until_idle(WAIT));
    assert_eq!(vm.rewrite.jobs[0].state, JobState::Succeeded);
    vm.rewrite_accept(0x401240);
    assert!(vm.block_until(WAIT, |vm| vm.rewrite.counts.accepted == 2));
    assert!(vm.rewrite.coverage_line().starts_with("Accepted 2 of 13"));

    // Specs and the export come from the same script.
    vm.rewrite_write_spec(Some(0x401240));
    assert!(vm.block_until(WAIT, |vm| vm.rewrite.spec_for(Some(0x401240)).is_some()));
    assert!(
        vm.rewrite
            .spec_for(Some(0x401240))
            .is_some_and(|s| s.cited().contains(&0x4011a0))
    );
    vm.rewrite_export_open();
    vm.rewrite_export_start();
    assert!(vm.block_until(WAIT, |vm| vm.rewrite.export.result.is_some()));
    let s = vm.rewrite.export.result.clone().expect("summary");
    assert_eq!(s.symbols, ["FUN_00401440", "checksum"]);
}
