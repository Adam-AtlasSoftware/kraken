//! The Original/Patched toggle: the Listing and Decompiler show the file as it is on disk until
//! the user asks for the program as the byte patches would leave it.

use serde_json::json;

use crate::errors::plain_error;
use crate::state::{Decompiled, Load, ToastLevel};
use crate::vm::{ViewModel, hex, parse};
use crate::wire::DecompileWire;

/// The patched decompile of one function.
#[derive(Debug, Clone, Default)]
pub struct PatchedDecompile {
    /// Function it belongs to.
    pub function: Option<u64>,
    /// The result, once asked for.
    pub state: Load<Decompiled>,
    pub(crate) req: u64,
}

impl ViewModel {
    /// True when at least one byte patch is staged (as far as the Patches list has loaded).
    pub fn has_patches(&self) -> bool {
        !self.tools.patches.items.is_empty()
    }

    /// Switches the Listing and Decompiler between the file on disk and the patched program.
    pub fn set_patched_view(&mut self, patched: bool) {
        if self.views.patched == patched {
            return;
        }
        self.ensure_patches();
        if patched && self.tools.patches.loaded && !self.has_patches() {
            self.toast(
                ToastLevel::Info,
                "No byte patches yet, so the patched view is the same as the original.",
            );
        }
        self.views.patched = patched;
        self.views.listing.stale = true;
    }

    /// Decompiles the current function in a copy with the byte patches applied.
    pub fn decompile_patched_current(&mut self) {
        let Some((addr, name)) = self.current.as_ref().map(|c| (c.address, c.name.clone())) else {
            return;
        };
        let req = self.views.next_seq();
        let d = &mut self.views.patched_decompile;
        d.function = Some(addr);
        d.state = Load::Loading;
        d.req = req;
        self.call(
            "decompile_patched",
            json!({ "address": hex(addr) }),
            move |vm, res| {
                if vm.views.patched_decompile.req != req {
                    return;
                }
                let state = match res.and_then(parse::<DecompileWire>) {
                    Ok(w) => Load::Ready(vm.build_decompiled(addr, &name, w)),
                    Err(e) => Load::Failed(plain_error(&e)),
                };
                vm.views.patched_decompile.state = state;
            },
        );
    }

    /// Forgets the patched decompile and reloads the patched listing: the patches changed.
    pub(crate) fn patches_changed(&mut self) {
        self.views.patched_decompile = PatchedDecompile::default();
        self.views.listing.stale = true;
    }
}
