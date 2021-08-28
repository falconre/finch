//! An implementation of the `TranslationMemory` trait for symbolic `State`.

use crate::executor::State;
use falcon::memory::MemoryPermissions;
use falcon::translator::TranslationMemory;
use std::cell::RefCell;

/// A wrapper around a symbolic `State` which implements the `TranslationMemory`
/// trait.
pub struct StateTranslator {
    state: RefCell<State>,
}

impl StateTranslator {
    /// Create a new `StateTranslator` from the given `State`.
    pub fn new(state: State) -> StateTranslator {
        StateTranslator {
            state: RefCell::new(state),
        }
    }
}

impl TranslationMemory for StateTranslator {
    fn permissions(&self, address: u64) -> Option<MemoryPermissions> {
        self.state.borrow().memory().permissions(address)
    }

    fn get_u8(&self, address: u64) -> Option<u8> {
        let value = self.state.borrow().memory().load(address, 8).unwrap();

        match value {
            Some(value) => self
                .state
                .borrow_mut()
                .eval_and_concretize(&value)
                .unwrap()
                .map(|c| c.value_u64().unwrap() as u8),
            None => None,
        }
    }
}

impl From<StateTranslator> for State {
    fn from(state_translator: StateTranslator) -> State {
        state_translator.state.into_inner()
    }
}
