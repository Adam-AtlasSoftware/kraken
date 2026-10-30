//! A small framework for step-by-step dialogs: the steps, which one is current, why Next is
//! disabled, and the CLI commands that do the same. The window draws it (`kraken-gui`'s
//! `wizard.rs`); the Import wizard is the first flow on it.

/// A wizard's content and rules. The window never decides anything a flow can: which steps exist,
/// when one may be left, and what the finished choices come to.
pub trait WizardFlow {
    /// The steps; a small `Copy` enum.
    type Step: Copy + Eq + 'static;

    /// The wizard's id (`import`), reported to tests and the palette.
    const ID: &'static str;

    /// The steps that apply now, in order. A flow may leave a step out (loader options are only
    /// needed for a raw file), and the list can change as choices are made.
    fn steps(&self) -> Vec<Self::Step>;

    /// The step on show.
    fn current(&self) -> Self::Step;

    /// Moves to `step` (the framework only passes steps from [`steps`](Self::steps)).
    fn set_current(&mut self, step: Self::Step);

    /// The step's short name, for the stepper.
    fn title(&self, step: Self::Step) -> &'static str;

    /// One or two sentences saying what this step is for.
    fn explain(&self, step: Self::Step) -> &'static str;

    /// Why Next (or Finish) is disabled on the current step; `None` when it may be pressed.
    fn blocker(&self) -> Option<String>;

    /// Called when the person leaves `step` forward; a flow starts its work here (reading the
    /// file chosen on the first step).
    fn leave(&mut self, _step: Self::Step) {}

    /// The label of the last step's button.
    fn finish_label(&self) -> &'static str {
        "Finish"
    }

    /// The CLI commands that do what the wizard will do, one per line, for the closing box.
    fn commands(&self) -> Vec<String> {
        Vec::new()
    }
}

/// What pressing Next did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WizardNav {
    /// Moved to the next step.
    Moved,
    /// The last step is done: the flow should act now.
    Finish,
    /// Not allowed; the reason.
    Blocked(String),
}

/// Where the current step sits: (1-based position, how many steps).
pub fn position<F: WizardFlow>(flow: &F) -> (usize, usize) {
    let steps = flow.steps();
    let at = steps.iter().position(|s| *s == flow.current()).unwrap_or(0);
    (at + 1, steps.len())
}

/// Whether the current step is the last.
pub fn is_last<F: WizardFlow>(flow: &F) -> bool {
    let (at, n) = position(flow);
    at == n
}

/// Whether Back does anything.
pub fn can_back<F: WizardFlow>(flow: &F) -> bool {
    position(flow).0 > 1
}

/// Goes to the next step, or says the wizard is finished, or why neither is allowed.
pub fn next<F: WizardFlow>(flow: &mut F) -> WizardNav {
    if let Some(why) = flow.blocker() {
        return WizardNav::Blocked(why);
    }
    let here = flow.current();
    flow.leave(here);
    let steps = flow.steps();
    match steps.iter().position(|s| *s == flow.current()) {
        Some(i) if i + 1 < steps.len() => {
            flow.set_current(steps[i + 1]);
            WizardNav::Moved
        }
        _ => WizardNav::Finish,
    }
}

/// Goes back one step; false on the first.
pub fn back<F: WizardFlow>(flow: &mut F) -> bool {
    let steps = flow.steps();
    match steps.iter().position(|s| *s == flow.current()) {
        Some(i) if i > 0 => {
            flow.set_current(steps[i - 1]);
            true
        }
        _ => false,
    }
}

/// Jumps to an earlier step (a click on a finished step of the stepper); never forward.
pub fn jump_back<F: WizardFlow>(flow: &mut F, step: F::Step) -> bool {
    let steps = flow.steps();
    let (Some(to), Some(at)) = (
        steps.iter().position(|s| *s == step),
        steps.iter().position(|s| *s == flow.current()),
    ) else {
        return false;
    };
    if to < at {
        flow.set_current(step);
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum S {
        A,
        B,
        C,
    }

    struct Toy {
        at: S,
        ready: bool,
        skip_b: bool,
        left: Vec<S>,
    }

    impl WizardFlow for Toy {
        type Step = S;
        const ID: &'static str = "toy";
        fn steps(&self) -> Vec<S> {
            if self.skip_b {
                vec![S::A, S::C]
            } else {
                vec![S::A, S::B, S::C]
            }
        }
        fn current(&self) -> S {
            self.at
        }
        fn set_current(&mut self, s: S) {
            self.at = s;
        }
        fn title(&self, _: S) -> &'static str {
            "step"
        }
        fn explain(&self, _: S) -> &'static str {
            "explain"
        }
        fn blocker(&self) -> Option<String> {
            (!self.ready && self.at == S::A).then(|| "Fill in A first.".to_string())
        }
        fn leave(&mut self, s: S) {
            self.left.push(s);
        }
    }

    fn toy() -> Toy {
        Toy {
            at: S::A,
            ready: false,
            skip_b: false,
            left: Vec::new(),
        }
    }

    #[test]
    fn next_waits_for_the_blocker_and_finishes_on_the_last_step() {
        let mut t = toy();
        assert_eq!(next(&mut t), WizardNav::Blocked("Fill in A first.".into()));
        assert_eq!(t.at, S::A);
        assert!(t.left.is_empty(), "a blocked step is not left");
        t.ready = true;
        assert_eq!(next(&mut t), WizardNav::Moved);
        assert_eq!(next(&mut t), WizardNav::Moved);
        assert_eq!(position(&t), (3, 3));
        assert!(is_last(&t));
        assert_eq!(next(&mut t), WizardNav::Finish);
        assert_eq!(t.left, [S::A, S::B, S::C]);
    }

    #[test]
    fn back_and_jumps_go_only_backwards_and_skipped_steps_are_not_visited() {
        let mut t = toy();
        t.ready = true;
        t.skip_b = true;
        assert!(!can_back(&t));
        next(&mut t);
        assert_eq!(t.at, S::C, "step B is not part of this run");
        assert!(can_back(&t));
        assert!(back(&mut t));
        assert_eq!(t.at, S::A);
        assert!(!back(&mut t));
        next(&mut t);
        assert!(!jump_back(&mut t, S::C), "the current step is not earlier");
        assert!(jump_back(&mut t, S::A));
    }
}
