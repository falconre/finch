//! A Symbolic Executor for Falcon IL

use crate::error::*;
use falcon::architecture::Endian;
use falcon::executor::eval;
use falcon::il;
use falcon::memory::{backing, paged};
use falcon::RC;
use std::collections::HashMap;

mod driver;
mod hash_expression;
mod memory;
mod state;
mod state_translator;
mod successor;
mod symbolic_string;
mod trace;

pub use self::driver::*;
pub(crate) use self::hash_expression::*;
pub use self::memory::*;
pub use self::state::*;
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

    pub fn new_with_backing(endian: Endian, backing: RC<backing::Memory>) -> SymbolicMemory {
        SymbolicMemory(paged::Memory::new_with_backing(endian, backing))
    }

    pub fn pages(&self) -> &HashMap<u64, RC<paged::Page<il::Expression>>> {
        self.0.pages()
    }

    pub fn load(&self, address: u64, bits: usize) -> Result<Option<il::Expression>> {
        Ok(self.memory().load(address, bits)?)
    }

    pub fn store(&mut self, address: u64, value: il::Expression) -> Result<()> {
        Ok(self.memory_mut().store(address, simplify(&value)?)?)
    }

    pub fn memory(&self) -> &paged::Memory<il::Expression> {
        &self.0
    }

    pub fn memory_mut(&mut self) -> &mut paged::Memory<il::Expression> {
        &mut self.0
    }
}

use falcon::memory::MemoryPermissions;
use falcon::translator;

impl translator::TranslationMemory for SymbolicMemory {
    fn get_u8(&self, address: u64) -> Option<u8> {
        match self.load(address, 8).unwrap() {
            Some(expr) => eval(&expr).ok().map(|c| c.value_u64().unwrap() as u8),
            None => None,
        }
    }

    fn permissions(&self, address: u64) -> Option<MemoryPermissions> {
        self.memory().permissions(address)
    }
}

pub fn simplify(expression: &il::Expression) -> Result<il::Expression> {
    // We have reached an optimization that allows us to safely eliminate lower
    // bits in some circumstances. For example (0xFFFFFF00:32 & zext.32(e:8))
    // can be simplified to 0:32
    fn eliminate_lower_bits(bits: usize, e: il::Expression) -> Result<il::Expression> {
        fn zext_eliminate(bits: usize, e: il::Expression) -> il::Expression {
            let e_bits = e.bits();
            match e {
                il::Expression::Zext(_, ref ze) => {
                    if ze.bits() <= bits {
                        return il::expr_const(0, e_bits);
                    }
                }
                _ => {}
            };
            e
        }

        match e {
            il::Expression::Or(lhs, rhs) => {
                let lhs = zext_eliminate(bits, *lhs);
                let rhs = zext_eliminate(bits, *rhs);
                Ok(il::Expression::or(lhs.clone(), rhs.clone())?)
            }
            _ => Ok(e.clone()),
        }
    }

    // We have reached an optimization that allows us to safely eliminate upper
    // bits in some circumstances. For example trun.8(0xFFFFFF00:32 | e:32) can be
    // simplified to trun.8(e:32)
    fn eliminate_upper_bits(bits: usize, e: il::Expression) -> Result<il::Expression> {
        // Returns true if this side of an or statement can be safely eliminated
        fn or_eliminate(bits: usize, e: &il::Expression) -> bool {
            let mask: u64 = (1 << (bits as u64)) - 1;

            match e {
                il::Expression::Constant(c) => {
                    c.value_u64().map(|v| v & mask == 0).unwrap_or(false)
                }
                _ => false,
            }
        }

        Ok(match e {
            il::Expression::Or(lhs, rhs) => {
                if or_eliminate(bits, &lhs) {
                    *rhs
                } else if or_eliminate(bits, &rhs) {
                    *lhs
                } else {
                    il::Expression::or(*lhs, *rhs)?
                }
            }
            _ => e,
        })
    }

    fn simplify_and(lhs: &il::Expression, rhs: &il::Expression) -> Result<il::Expression> {
        let lhs = simplify(lhs)?;
        let rhs = simplify(rhs)?;

        fn and_bitmask(expression: &il::Expression) -> usize {
            match expression {
                il::Expression::Constant(c) => {
                    if let Some(v) = c.value_u64() {
                        v.trailing_zeros() as usize
                    } else {
                        0
                    }
                }
                _ => 0,
            }
        }

        let lhs_bitmask = and_bitmask(&lhs);
        let rhs_bitmask = and_bitmask(&rhs);

        Ok(if lhs_bitmask > 0 {
            eliminate_lower_bits(lhs_bitmask, rhs)?
        } else if rhs_bitmask > 0 {
            eliminate_lower_bits(rhs_bitmask, lhs)?
        } else {
            il::Expression::and(lhs, rhs)?
        })
    }

    fn simplify_or(lhs: &il::Expression, rhs: &il::Expression) -> Result<il::Expression> {
        let lhs = simplify(lhs)?;
        let rhs = simplify(rhs)?;

        Ok(
            if lhs.get_constant().map(|c| c.is_zero()).unwrap_or(false) {
                rhs
            } else if rhs.get_constant().map(|c| c.is_zero()).unwrap_or(false) {
                lhs
            } else {
                il::Expression::or(lhs, rhs)?
            },
        )
    }

    fn simplify_zext(bits: usize, expression: &il::Expression) -> Result<il::Expression> {
        let expression = simplify(expression)?;

        // Get rid of nested zext(zext())
        match expression {
            il::Expression::Zext(_, expression) => {
                return Ok(il::Expression::zext(bits, *expression)?)
            }
            _ => {}
        };

        Ok(il::Expression::zext(bits, expression)?)
    }

    fn simplify_trun(bits: usize, expression: &il::Expression) -> Result<il::Expression> {
        let expression = simplify(expression)?;
        let expression = eliminate_upper_bits(bits, expression)?;

        // Get rid of nested trun(zext()) patterns
        match expression {
            il::Expression::Zext(zbits, expression) => {
                if expression.bits() == bits {
                    Ok(*expression)
                } else {
                    Ok(il::Expression::trun(
                        bits,
                        il::Expression::zext(zbits, *expression)?,
                    )?)
                }
            }
            _ => Ok(il::Expression::trun(bits, expression)?),
        }
    }

    Ok(if expression.all_constants() {
        eval(expression)?.into()
    } else {
        match *expression {
            il::Expression::Scalar(_) => expression.clone(),
            il::Expression::Constant(_) => expression.clone(),
            il::Expression::Add(ref lhs, ref rhs) => {
                il::Expression::add(simplify(lhs)?, simplify(rhs)?)?
            }
            il::Expression::Sub(ref lhs, ref rhs) => {
                il::Expression::sub(simplify(lhs)?, simplify(rhs)?)?
            }
            il::Expression::Mul(ref lhs, ref rhs) => {
                il::Expression::mul(simplify(lhs)?, simplify(rhs)?)?
            }
            il::Expression::Divu(ref lhs, ref rhs) => {
                il::Expression::divu(simplify(lhs)?, simplify(rhs)?)?
            }
            il::Expression::Modu(ref lhs, ref rhs) => {
                il::Expression::modu(simplify(lhs)?, simplify(rhs)?)?
            }
            il::Expression::Divs(ref lhs, ref rhs) => {
                il::Expression::divs(simplify(lhs)?, simplify(rhs)?)?
            }
            il::Expression::Mods(ref lhs, ref rhs) => {
                il::Expression::mods(simplify(lhs)?, simplify(rhs)?)?
            }
            il::Expression::And(ref lhs, ref rhs) => simplify_and(lhs, rhs)?,
            il::Expression::Or(ref lhs, ref rhs) => simplify_or(lhs, rhs)?,
            il::Expression::Xor(ref lhs, ref rhs) => {
                il::Expression::xor(simplify(lhs)?, simplify(rhs)?)?
            }
            il::Expression::Shl(ref lhs, ref rhs) => {
                il::Expression::shl(simplify(lhs)?, simplify(rhs)?)?
            }
            il::Expression::Shr(ref lhs, ref rhs) => {
                il::Expression::shr(simplify(lhs)?, simplify(rhs)?)?
            }
            il::Expression::Cmpeq(ref lhs, ref rhs) => {
                il::Expression::cmpeq(simplify(lhs)?, simplify(rhs)?)?
            }
            il::Expression::Cmpneq(ref lhs, ref rhs) => {
                il::Expression::cmpneq(simplify(lhs)?, simplify(rhs)?)?
            }
            il::Expression::Cmplts(ref lhs, ref rhs) => {
                il::Expression::cmplts(simplify(lhs)?, simplify(rhs)?)?
            }
            il::Expression::Cmpltu(ref lhs, ref rhs) => {
                il::Expression::cmpltu(simplify(lhs)?, simplify(rhs)?)?
            }
            il::Expression::Trun(bits, ref rhs) => simplify_trun(bits, rhs)?,
            il::Expression::Sext(bits, ref rhs) => il::Expression::sext(bits, simplify(rhs)?)?,
            il::Expression::Zext(bits, ref rhs) => simplify_zext(bits, rhs)?,
            il::Expression::Ite(ref cond, ref then, ref else_) => {
                il::Expression::ite(simplify(cond)?, simplify(then)?, simplify(else_)?)?
            }
        }
    })
}

pub fn expression_complexity(e: &il::Expression) -> usize {
    match e {
        il::Expression::Scalar(_) | il::Expression::Constant(_) => 1,
        il::Expression::Add(lhs, rhs)
        | il::Expression::Sub(lhs, rhs)
        | il::Expression::Mul(lhs, rhs)
        | il::Expression::Divu(lhs, rhs)
        | il::Expression::Modu(lhs, rhs)
        | il::Expression::Divs(lhs, rhs)
        | il::Expression::Mods(lhs, rhs)
        | il::Expression::And(lhs, rhs)
        | il::Expression::Or(lhs, rhs)
        | il::Expression::Xor(lhs, rhs)
        | il::Expression::Shl(lhs, rhs)
        | il::Expression::Shr(lhs, rhs)
        | il::Expression::Cmpeq(lhs, rhs)
        | il::Expression::Cmpneq(lhs, rhs)
        | il::Expression::Cmplts(lhs, rhs)
        | il::Expression::Cmpltu(lhs, rhs) => {
            expression_complexity(lhs) + expression_complexity(rhs) + 1
        }
        il::Expression::Trun(_, e) | il::Expression::Zext(_, e) | il::Expression::Sext(_, e) => {
            expression_complexity(e) + 1
        }
        il::Expression::Ite(cond, then, else_) => {
            expression_complexity(cond)
                + expression_complexity(then)
                + expression_complexity(else_)
                + 1
        }
    }
}
