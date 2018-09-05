//! A successor after symbolic evaluation of a Falcon IL Instruction.

use executor::State;
use falcon::il;
use platform::Platform;


/// A representation of the successor location in an `il::Program` after
/// execution of an `il::Operation`.
#[derive(Clone, Debug)]
pub enum SuccessorType {
    FallThrough,
    Branch(u64),
    Raise(il::Expression)
}


/// The result of executing an `il::Operation` over a `State`.
#[derive(Clone, Debug)]
pub struct Successor<P: Platform<P>> {
    state: State<P>,
    type_: SuccessorType
}


impl<P: Platform<P>> Successor<P> {
    pub(crate) fn new(state: State<P>, type_: SuccessorType) -> Successor<P> {
        Successor {
            state: state,
            type_: type_
        }
    }

    /// Get the `SuccessorType` of this `Successor`.
    pub fn type_(&self) -> &SuccessorType {
        &self.type_
    }


    /// Get the `State` of this `Successor`.
    pub fn state(&self) -> &State<P> {
        &self.state
    }
}


/// Turn this `Successor` into its `State`, discarding the `SuccessorType`.
impl<P: Platform<P>> Into<State<P>> for Successor<P> {
    fn into(self) -> State<P> {
        self.state
    }
}