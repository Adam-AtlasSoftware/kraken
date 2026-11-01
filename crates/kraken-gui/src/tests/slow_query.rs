//! The window keeps drawing while a query is slow: with every answer of the backend held back,
//! no frame takes as long as one answer, whatever the person does meanwhile. A frame that waited
//! for a reply on the UI thread would.

use std::time::{Duration, Instant};

use super::*;

/// How long each query takes. A frame of the debug build is well under this.
const DELAY: Duration = Duration::from_millis(900);

/// The longest frame allowed.
const LIMIT: Duration = Duration::from_millis(600);

impl Harness {
    /// Draws frames for `time`, returns the longest, and says whether a query was out meanwhile.
    fn frames_for(&mut self, time: Duration) -> (Duration, bool) {
        let end = Instant::now() + time;
        let (mut longest, mut waited) = (Duration::ZERO, false);
        while Instant::now() < end {
            let t = Instant::now();
            self.step_with(vec![Event::PointerMoved(pos2(420.0, 250.0))]);
            longest = longest.max(t.elapsed());
            waited |= self.app.view_model().is_some_and(|vm| vm.busy());
            std::thread::sleep(Duration::from_millis(4));
        }
        (longest, waited)
    }

    fn slow_step(&mut self, what: &str, time: Duration) -> Duration {
        let (longest, waited) = self.frames_for(time);
        assert!(waited, "{what}: no query was out, so this shows nothing");
        assert!(longest < LIMIT, "{what}: a frame took {longest:?}");
        longest
    }
}

#[test]
fn no_frame_waits_for_a_slow_query() {
    let mut h = Harness::new(false);
    let ctx = h.ctx.clone();
    h.app.start_slow_demo(&ctx, DELAY);
    // the first frames lay the fonts out and are not about queries
    h.step();
    h.step();
    let mut worst = h.slow_step("opening", Duration::from_secs(2));
    let opened = Instant::now();
    while !h
        .app
        .view_model()
        .is_some_and(|vm| vm.connection == Connection::Open && !vm.functions.items.is_empty())
    {
        assert!(opened.elapsed() < WAIT, "the demo opens");
        worst = worst.max(h.slow_step("opening", Duration::from_secs(1)));
    }

    let first = h.app.view_model().unwrap().functions.items[0].address;
    h.app.view_model_mut().unwrap().select_function(first);
    worst = worst.max(h.slow_step("decompiling a function", DELAY / 2));
    h.app.bring_to_front(Tab::Listing);
    h.key(Key::PageDown, Modifiers::NONE);
    worst = worst.max(h.slow_step("the listing", DELAY / 2));
    h.app.set_dock(workspace::graph_dock());
    h.app.bring_to_front(Tab::Graph);
    h.step();
    h.app.view_model_mut().unwrap().ensure_graph();
    worst = worst.max(h.slow_step("the graph", DELAY / 2));
    h.app.bring_to_front(Tab::Strings);
    worst = worst.max(h.slow_step("the strings", DELAY / 2));
    println!("longest frame with every query taking {DELAY:?}: {worst:?}");
}
