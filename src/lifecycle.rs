//! Staged patch lifecycle.
//!
//! Port of `PatchLifecycle.h` from the fork (`2aa0d3e`). The state machine
//! serializes install and unload without blocking a game callback behind an
//! installer: a call made in the wrong state returns `false` at once. A failed
//! rollback is terminal, because retrying over partially restored hooks is
//! unsafe.
//!
//! The steps themselves live behind [`Operations`], so this module is pure and
//! tested with a fake.

use std::sync::atomic::{AtomicU8, Ordering};

/// Where the patch is in its lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum State {
    Idle = 0,
    Installing = 1,
    Active = 2,
    Unloading = 3,
    Failed = 4,
}

impl State {
    const fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Idle,
            1 => Self::Installing,
            2 => Self::Active,
            3 => Self::Unloading,
            _ => Self::Failed,
        }
    }
}

/// The install stages, in the order [`Lifecycle::install`] runs them, and the rollback.
pub trait Operations {
    /// Applies the Arxan bypass, resolves the game and creates the hooks, which stay disabled.
    ///
    /// # Errors
    ///
    /// Returns the reason the game or the hooking library could not be prepared.
    fn prepare(&mut self) -> Result<(), String>;
    /// Installs the exception dispatcher hook.
    ///
    /// # Errors
    ///
    /// Returns the reason the dispatcher could not be installed.
    fn install_dispatcher(&mut self) -> Result<(), String>;
    /// Installs the protection writes and memory patches.
    ///
    /// # Errors
    ///
    /// Returns the reason a write failed; earlier writes stay recorded for [`Operations::rollback`].
    fn install_protection(&mut self) -> Result<(), String>;
    /// Raises the process priority, applies the VMT hook and enables the detours.
    ///
    /// # Errors
    ///
    /// Returns the reason enabling failed; hooks enabled before the failure may stay live until [`Operations::rollback`].
    fn activate(&mut self) -> Result<(), String>;
    /// Starts the background settings worker.
    ///
    /// # Errors
    ///
    /// Returns the reason the worker could not be started.
    fn start_worker(&mut self) -> Result<(), String>;
    /// Undoes whatever the stages applied. Must be safe after a failure at any stage.
    ///
    /// # Errors
    ///
    /// Returns every restoration that failed. The state those failures leave behind is retained, and further lifecycle transitions are refused.
    fn rollback(&mut self) -> Result<(), String>;
    /// Reports the error that aborted an install.
    fn report_failure(&mut self, message: &str);
}

/// Port of `patch_runtime::Lifecycle`.
pub struct Lifecycle {
    state: AtomicU8,
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl Lifecycle {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: AtomicU8::new(State::Idle as u8),
        }
    }

    pub fn state(&self) -> State {
        State::from_u8(self.state.load(Ordering::Acquire))
    }

    fn transition(&self, from: State, to: State) -> bool {
        self.state
            .compare_exchange(from as u8, to as u8, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn settle(&self, restored: bool) {
        let state = if restored { State::Idle } else { State::Failed };
        self.state.store(state as u8, Ordering::Release);
    }

    /// Runs every install stage from `Idle`. On a failed stage, reports it and rolls back,
    /// ending in `Idle` (or `Failed` if the rollback fails). Returns `true` only when the
    /// patch ends up `Active`.
    pub fn install(&self, ops: &mut impl Operations) -> bool {
        if !self.transition(State::Idle, State::Installing) {
            return false;
        }
        let result = ops
            .prepare()
            .and_then(|()| ops.install_dispatcher())
            .and_then(|()| ops.install_protection())
            .and_then(|()| ops.activate())
            .and_then(|()| ops.start_worker());
        match result {
            Ok(()) => {
                self.state.store(State::Active as u8, Ordering::Release);
                true
            }
            Err(message) => {
                ops.report_failure(&message);
                let restored = ops.rollback();
                if let Err(message) = &restored {
                    ops.report_failure(message);
                }
                self.settle(restored.is_ok());
                false
            }
        }
    }

    /// Rolls an `Active` patch back to `Idle` (or `Failed`). Returns `true` when restored.
    pub fn unload(&self, ops: &mut impl Operations) -> bool {
        if !self.transition(State::Active, State::Unloading) {
            return false;
        }
        let restored = ops.rollback();
        if let Err(message) = &restored {
            ops.report_failure(message);
        }
        self.settle(restored.is_ok());
        restored.is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STAGES: [&str; 5] = [
        "prepare",
        "install_dispatcher",
        "install_protection",
        "activate",
        "start_worker",
    ];

    #[derive(Default)]
    struct Fake {
        calls: Vec<&'static str>,
        fail_at: Option<&'static str>,
        rollback_fails: bool,
        reports: Vec<String>,
    }

    impl Fake {
        fn step(&mut self, name: &'static str) -> Result<(), String> {
            self.calls.push(name);
            if self.fail_at == Some(name) {
                Err(format!("{name} failed"))
            } else {
                Ok(())
            }
        }
    }

    impl Operations for Fake {
        fn prepare(&mut self) -> Result<(), String> {
            self.step("prepare")
        }
        fn install_dispatcher(&mut self) -> Result<(), String> {
            self.step("install_dispatcher")
        }
        fn install_protection(&mut self) -> Result<(), String> {
            self.step("install_protection")
        }
        fn activate(&mut self) -> Result<(), String> {
            self.step("activate")
        }
        fn start_worker(&mut self) -> Result<(), String> {
            self.step("start_worker")
        }
        fn rollback(&mut self) -> Result<(), String> {
            self.calls.push("rollback");
            if self.rollback_fails {
                Err("rollback failed".to_owned())
            } else {
                Ok(())
            }
        }
        fn report_failure(&mut self, message: &str) {
            self.reports.push(message.to_owned());
        }
    }

    #[test]
    fn install_runs_every_stage_in_order() {
        let lifecycle = Lifecycle::new();
        let mut ops = Fake::default();
        assert!(lifecycle.install(&mut ops));
        assert_eq!(ops.calls, STAGES);
        assert_eq!(ops.reports, Vec::<String>::new());
        assert_eq!(lifecycle.state(), State::Active);
    }

    #[test]
    fn failure_at_each_stage_rolls_back_to_idle() {
        for (index, stage) in STAGES.iter().enumerate() {
            let lifecycle = Lifecycle::new();
            let mut ops = Fake {
                fail_at: Some(stage),
                ..Fake::default()
            };
            assert!(!lifecycle.install(&mut ops));
            let mut expected = STAGES[..=index].to_vec();
            expected.push("rollback");
            assert_eq!(ops.calls, expected);
            assert_eq!(ops.reports, [format!("{stage} failed")]);
            assert_eq!(lifecycle.state(), State::Idle);

            // A retry from Idle is allowed and can succeed.
            let mut retry = Fake::default();
            assert!(lifecycle.install(&mut retry));
            assert_eq!(lifecycle.state(), State::Active);
        }
    }

    #[test]
    fn failed_rollback_is_terminal() {
        let lifecycle = Lifecycle::new();
        let mut ops = Fake {
            fail_at: Some("activate"),
            rollback_fails: true,
            ..Fake::default()
        };
        assert!(!lifecycle.install(&mut ops));
        assert_eq!(lifecycle.state(), State::Failed);
        assert_eq!(ops.reports, ["activate failed", "rollback failed"]);

        let mut again = Fake::default();
        assert!(!lifecycle.install(&mut again));
        assert!(!lifecycle.unload(&mut again));
        assert_eq!(again.calls, Vec::<&str>::new());
        assert_eq!(lifecycle.state(), State::Failed);
    }

    #[test]
    fn second_install_while_active_is_refused() {
        let lifecycle = Lifecycle::new();
        assert!(lifecycle.install(&mut Fake::default()));
        let mut second = Fake::default();
        assert!(!lifecycle.install(&mut second));
        assert_eq!(second.calls, Vec::<&str>::new());
        assert_eq!(lifecycle.state(), State::Active);
    }

    #[test]
    fn unload_before_install_is_refused() {
        let lifecycle = Lifecycle::new();
        let mut ops = Fake::default();
        assert!(!lifecycle.unload(&mut ops));
        assert_eq!(ops.calls, Vec::<&str>::new());
        assert_eq!(lifecycle.state(), State::Idle);
    }

    #[test]
    fn unload_rolls_back_to_idle_and_allows_reinstall() {
        let lifecycle = Lifecycle::new();
        assert!(lifecycle.install(&mut Fake::default()));
        let mut ops = Fake::default();
        assert!(lifecycle.unload(&mut ops));
        assert_eq!(ops.calls, ["rollback"]);
        assert_eq!(lifecycle.state(), State::Idle);
        assert!(lifecycle.install(&mut Fake::default()));
    }

    #[test]
    fn failed_unload_rollback_is_terminal() {
        let lifecycle = Lifecycle::new();
        assert!(lifecycle.install(&mut Fake::default()));
        let mut ops = Fake {
            rollback_fails: true,
            ..Fake::default()
        };
        assert!(!lifecycle.unload(&mut ops));
        assert_eq!(lifecycle.state(), State::Failed);
        assert!(!lifecycle.unload(&mut Fake::default()));
        assert!(!lifecycle.install(&mut Fake::default()));
    }
}
