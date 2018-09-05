//! Modelling of Platforms (Execution environments, e.g. the Linux Operating System)

use error::*;
use executor::{State, Successor};
use falcon::il;
use std::fmt::Debug;

pub mod linux;


/// Functionality required by all Platforms
pub trait Platform<P: Platform<P>>: Debug {
    /// Execute an intrinsic instruction
    fn intrinsic(state: State<P>, intrinsic: &il::Intrinsic)
        -> Result<Vec<Successor<P>>>;

    /// Merge the other state into this state.
    ///
    /// Returns true if states were successfully merged, false if states could
    /// not be merged
    fn merge(&mut self, other: &P, constraints: &il::Expression) -> Result<bool>;

    /// Clone this `Platform` into a `Box<Platform>`
    fn box_clone(&self) -> Box<P>;
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
}


impl Platform<Dummy> for Dummy {
    fn intrinsic(_: State<Dummy>, intrinsic: &il::Intrinsic)
        -> Result<Vec<Successor<Dummy>>> {

        Err(format!("Unhandled intrinsic {}", intrinsic).into())
    }

    fn merge(&mut self, _: &Dummy, _: &il::Expression) -> Result<bool> {

        Ok(true)
    }

    fn box_clone(&self) -> Box<Dummy> {
        Box::new(self.clone())
    }
}