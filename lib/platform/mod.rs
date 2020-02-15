//! Modelling of Platforms (Execution environments, e.g. the Linux Operating System)

use crate::error::*;
use crate::executor::{State, Successor};
use falcon::il;
use std::any::Any;
use std::fmt::Debug;

pub mod linux;

/// Functionality required by all Platforms
pub trait Platform: Debug {
    /// Execute an intrinsic instruction
    fn get_intrinsic_handler(
        &self,
    ) -> fn(state: State, intrinsic: &il::Intrinsic) -> Result<Vec<Successor>>;

    /// Merge the other state into this state.
    ///
    /// Returns true if states were successfully merged, false if states could
    /// not be merged
    fn merge(&mut self, other: &dyn Platform, constraints: &il::Expression) -> Result<bool>;

    /// Clone this `Platform` into a `Box<Platform>`
    fn box_clone(&self) -> Box<dyn Platform>;

    fn as_any(&self) -> &dyn Any;
    fn any_mut(&mut self) -> &mut dyn Any;
}

/// A Dummy platform that does nothing.
///
/// The Dummy Platform will throw an error everytime an `il::Intrinsic` is
/// encountered.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Dummy {}

impl Dummy {
    /// Create a new `Dummy` `Platform`.
    pub fn new() -> Dummy {
        Dummy {}
    }

    fn dummy_intrinsic(_state: State, intrinsic: &il::Intrinsic) -> Result<Vec<Successor>> {
        Err(format!("Unhandled intrinsic {}", intrinsic).into())
    }
}

impl Platform for Dummy {
    fn get_intrinsic_handler(
        &self,
    ) -> fn(state: State, intrinsic: &il::Intrinsic) -> Result<Vec<Successor>> {
        return Dummy::dummy_intrinsic;
    }

    fn merge(&mut self, _: &dyn Platform, _: &il::Expression) -> Result<bool> {
        Ok(true)
    }

    fn box_clone(&self) -> Box<dyn Platform> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn any_mut(&mut self) -> &mut dyn Any {
        self
    }
}
