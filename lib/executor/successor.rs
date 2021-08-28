//! A successor after symbolic evaluation of a Falcon IL Instruction.

use crate::executor::State;
use falcon::il;

/// A representation of the successor location in an `il::Program` after
/// execution of an `il::Operation`.
#[derive(Clone, Debug)]
pub enum SuccessorType {
    FallThrough,
    Branch(u64),
    Raise(il::Expression),
}

/// The result of executing an `il::Operation` over a `State`.
#[derive(Clone, Debug)]
pub struct Successor {
    state: State,
    type_: SuccessorType,
}

impl Successor {
    pub(crate) fn new(state: State, type_: SuccessorType) -> Successor {
        Successor {
            state,
            type_,
        }
    }

    /// Get the `SuccessorType` of this `Successor`.
    pub fn type_(&self) -> &SuccessorType {
        &self.type_
    }

    /// Get the `State` of this `Successor`.
    pub fn state(&self) -> &State {
        &self.state
    }
}

impl From<Successor> for State {
    fn from(successor: Successor) -> State {
        successor.state
    }
}
