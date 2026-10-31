//! The coverage overlay: the Listing's Coverage switch and the Emulate menu action.

use egui_kittest::kittest::Queryable;
use kraken_proto::Hex64;
use kraken_proto::trace::CoverageBlock;
use kraken_viewmodel::AppAction;

use super::shell::{Kit, kit};
use crate::workspace::Tab;

fn ready(k: &mut Kit) {
    super::shots::ready_demo(k);
    super::shots::select_first_instruction(k);
    k.h.run_steps(4);
}

fn shown(k: &mut Kit) -> (bool, bool) {
    let vm = k.h.state_mut().view_model_mut().expect("vm");
    (vm.tools.coverage.show, vm.tools.coverage.active())
}

#[test]
fn the_coverage_switch_shades_and_unshades_the_listing() {
    let mut k = kit(true);
    ready(&mut k);
    k.h.state_mut().bring_to_front(Tab::Listing);
    k.h.run_steps(4);
    let first = {
        let vm = k.h.state_mut().view_model_mut().expect("vm");
        let first = vm.views.listing.rows[0].address;
        vm.tools.coverage.set_blocks(&[CoverageBlock {
            start: Hex64(first),
            size: 4,
            hits: 3,
        }]);
        vm.tools.coverage.loaded = true;
        first
    };
    assert_eq!(shown(&mut k), (false, false), "off until asked");

    k.h.get_by_label("Coverage").click();
    k.h.run_steps(3);
    assert_eq!(shown(&mut k), (true, true), "the switch turns it on");
    let vm = k.h.state_mut().view_model_mut().expect("vm");
    assert_eq!(vm.tools.coverage.hits_at(first), Some(3));

    k.h.get_by_label("Coverage").click();
    k.h.run_steps(3);
    assert_eq!(shown(&mut k), (false, false), "and off again");
}

#[test]
fn the_emulate_menu_action_toggles_the_overlay() {
    let mut k = kit(true);
    ready(&mut k);
    {
        let vm = k.h.state_mut().view_model_mut().expect("vm");
        vm.tools.coverage.set_blocks(&[CoverageBlock {
            start: Hex64(0x1000),
            size: 8,
            hits: 1,
        }]);
        vm.tools.coverage.loaded = true;
    }
    let ctx = k.h.ctx.clone();
    k.h.state_mut().dispatch(AppAction::ToggleCoverage, &ctx);
    k.h.run_steps(2);
    assert_eq!(shown(&mut k), (true, true));
    k.h.state_mut().dispatch(AppAction::ToggleCoverage, &ctx);
    k.h.run_steps(2);
    assert_eq!(shown(&mut k), (false, false));
}
