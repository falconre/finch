//! A Symbolic Executor for Falcon IL

use error::*;
use falcon::architecture::Endian;
use falcon::executor::eval;
use falcon::il;
use falcon::memory::{paged, backing};
use falcon::RC;
use std::collections::HashMap;

mod state;
mod driver;
mod hash_expression;
mod memory;
mod state_translator;
mod successor;
mod symbolic_string;
mod trace;

pub use self::state::*;
pub use self::driver::*;
pub(crate) use self::hash_expression::*;
pub use self::memory::*;
pub use self::state_translator::*;
pub use self::successor::*;
pub(crate) use self::symbolic_string::*;
pub use self::trace::*;


#[derive(Clone, Debug)]
pub struct SymbolicMemory(paged::Memory<il::Expression>);

impl SymbolicMemory {
    pub fn new(endian: Endian) -> SymbolicMemory {
        SymbolicMemory(paged::Memory::new(endian))
    }

    pub fn endian(&self) -> Endian {
        self.0.endian()
    }

    pub fn new_with_backing(endian: Endian, backing: RC<backing::Memory>)
        -> SymbolicMemory {

        SymbolicMemory(paged::Memory::new_with_backing(endian, backing))
    }


    pub fn pages(&self) -> &HashMap<u64, RC<paged::Page<il::Expression>>> {
        self.0.pages()
    }


    pub fn load(&self, address: u64, bits: usize)
        -> Result<Option<il::Expression>> {

        Ok(self.memory().load(address, bits)?)
    }

    pub fn store(&mut self, address: u64, value: il::Expression) -> Result<()> {
        Ok(self.memory_mut().store(address, simplify(&value)?)?)
    }

    pub fn memory(&self) -> &paged::Memory<il::Expression> {
        &self.0
    }

    pub fn memory_mut(&mut self)
        -> &mut paged::Memory<il::Expression> {
        &mut self.0
    }
}

use falcon::memory::MemoryPermissions;
use falcon::translator;

impl translator::TranslationMemory for SymbolicMemory {
    fn get_u8(&self, address: u64) -> Option<u8> {
        match self.load(address, 8).unwrap() {
            Some(expr) =>
                eval(&expr).ok().map(|c| c.value_u64().unwrap() as u8),
            None => None
        }
    }


    fn permissions(&self, address: u64) -> Option<MemoryPermissions> {
        self.memory().permissions(address)
    }
}


pub fn expression_complexity(expression: &il::Expression) -> usize {
    match expression {
        il::Expression::Scalar(_) |
        il::Expression::Constant(_) => 0,
        il::Expression::Add(lhs, rhs) |
        il::Expression::Sub(lhs, rhs) |
        il::Expression::Mul(lhs, rhs) |
        il::Expression::Divu(lhs, rhs) |
        il::Expression::Modu(lhs, rhs) |
        il::Expression::Divs(lhs, rhs) |
        il::Expression::Mods(lhs, rhs) |
        il::Expression::And(lhs, rhs) |
        il::Expression::Or(lhs, rhs) |
        il::Expression::Xor(lhs, rhs) |
        il::Expression::Shl(lhs, rhs) |
        il::Expression::Shr(lhs, rhs) |
        il::Expression::Cmpeq(lhs, rhs) |
        il::Expression::Cmpneq(lhs, rhs) |
        il::Expression::Cmplts(lhs, rhs) |
        il::Expression::Cmpltu(lhs, rhs) =>
            1 + expression_complexity(lhs) + expression_complexity(rhs),
        il::Expression::Trun(_, rhs) |
        il::Expression::Sext(_, rhs) |
        il::Expression::Zext(_, rhs) => 1 + expression_complexity(rhs),
        il::Expression::Ite(cond, then, else_) =>
            1 + 
            expression_complexity(cond) + 
            expression_complexity(then) + 
            expression_complexity(else_)
    }
}



pub fn simplify(expression: &il::Expression) -> Result<il::Expression> {

    fn simplify_zext(bits: usize, expression: &il::Expression)
        -> Result<il::Expression> {

        // Get rid of nested zext(zext())
        match expression {
            il::Expression::Zext(_, expression) =>
                return Ok(il::Expression::zext(bits, simplify(expression)?)?),
            _ => {}
        };

        Ok(il::Expression::zext(bits, simplify(expression)?)?)
    }

    fn simplify_trun(bits: usize, expression: &il::Expression)
        -> Result<il::Expression> {

        // Get rid of nested trun(zext()) patterns
        match expression {
            il::Expression::Zext(_, expression) =>
                if expression.bits() == bits {
                    return simplify(expression);
                },
            _ => {}
        };

        Ok(il::Expression::trun(bits, simplify(expression)?)?)
    }


    if expression.all_constants() {
        Ok(eval(expression)?.into())
    }
    else {
        Ok(match *expression {
            il::Expression::Scalar(_) => expression.clone(),
            il::Expression::Constant(_) => expression.clone(),
            il::Expression::Add(ref lhs, ref rhs) =>
                il::Expression::add(simplify(lhs)?, simplify(rhs)?)?,
            il::Expression::Sub(ref lhs, ref rhs) =>
                il::Expression::sub(simplify(lhs)?, simplify(rhs)?)?,
            il::Expression::Mul(ref lhs, ref rhs) =>
                il::Expression::mul(simplify(lhs)?, simplify(rhs)?)?,
            il::Expression::Divu(ref lhs, ref rhs) =>
                il::Expression::divu(simplify(lhs)?, simplify(rhs)?)?,
            il::Expression::Modu(ref lhs, ref rhs) =>
                il::Expression::modu(simplify(lhs)?, simplify(rhs)?)?,
            il::Expression::Divs(ref lhs, ref rhs) =>
                il::Expression::divs(simplify(lhs)?, simplify(rhs)?)?,
            il::Expression::Mods(ref lhs, ref rhs) =>
                il::Expression::mods(simplify(lhs)?, simplify(rhs)?)?,
            il::Expression::And(ref lhs, ref rhs) =>
                il::Expression::and(simplify(lhs)?, simplify(rhs)?)?,
            il::Expression::Or(ref lhs, ref rhs) =>
                il::Expression::or(simplify(lhs)?, simplify(rhs)?)?,
            il::Expression::Xor(ref lhs, ref rhs) =>
                il::Expression::xor(simplify(lhs)?, simplify(rhs)?)?,
            il::Expression::Shl(ref lhs, ref rhs) =>
                il::Expression::shl(simplify(lhs)?, simplify(rhs)?)?,
            il::Expression::Shr(ref lhs, ref rhs) =>
                il::Expression::shr(simplify(lhs)?, simplify(rhs)?)?,
            il::Expression::Cmpeq(ref lhs, ref rhs) =>
                il::Expression::cmpeq(simplify(lhs)?, simplify(rhs)?)?,
            il::Expression::Cmpneq(ref lhs, ref rhs) =>
                il::Expression::cmpneq(simplify(lhs)?, simplify(rhs)?)?,
            il::Expression::Cmplts(ref lhs, ref rhs) =>
                il::Expression::cmplts(simplify(lhs)?, simplify(rhs)?)?,
            il::Expression::Cmpltu(ref lhs, ref rhs) =>
                il::Expression::cmpltu(simplify(lhs)?, simplify(rhs)?)?,
            il::Expression::Trun(bits, ref rhs) => simplify_trun(bits, rhs)?,
            il::Expression::Sext(bits, ref rhs) =>
                il::Expression::sext(bits, simplify(rhs)?)?,
            il::Expression::Zext(bits, ref rhs) => simplify_zext(bits, rhs)?,
            il::Expression::Ite(ref cond, ref then, ref else_) =>
                il::Expression::ite(simplify(cond)?,
                                    simplify(then)?,
                                    simplify(else_)?)?,
        })
    }
}