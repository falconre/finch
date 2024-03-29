//! A convenience struct for maintaining state of symbolic strings.

use crate::executor::*;

#[derive(Clone, Debug)]
pub struct SymbolicString {
    bytes: Vec<ExpressionHash>,
}

impl SymbolicString {
    pub fn new(bytes: Vec<ExpressionHash>) -> SymbolicString {
        SymbolicString { bytes }
    }
}
