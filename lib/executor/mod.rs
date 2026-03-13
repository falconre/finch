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
            if let il::Expression::Zext(_, ref ze) = e {
                if ze.bits() <= bits {
                    return il::expr_const(0, e_bits);
                }
            };
            e
        }

        match e {
            il::Expression::Or(lhs, rhs) => {
                let lhs = zext_eliminate(bits, *lhs);
                let rhs = zext_eliminate(bits, *rhs);
                Ok(il::Expression::or(lhs, rhs)?)
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
        if let il::Expression::Zext(_, expression) = expression {
            return Ok(il::Expression::zext(bits, *expression)?);
        }

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
            il::Expression::AShr(ref lhs, ref rhs) => {
                il::Expression::ashr(simplify(lhs)?, simplify(rhs)?)?
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
        | il::Expression::AShr(lhs, rhs)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expression_complexity_scalar() {
        let s = il::expr_scalar("x", 32);
        assert_eq!(expression_complexity(&s), 1);
    }

    #[test]
    fn test_expression_complexity_constant() {
        let c = il::expr_const(42, 32);
        assert_eq!(expression_complexity(&c), 1);
    }

    #[test]
    fn test_expression_complexity_binary_op() {
        let expr = il::Expression::add(il::expr_scalar("x", 32), il::expr_const(1, 32)).unwrap();
        assert_eq!(expression_complexity(&expr), 3);
    }

    #[test]
    fn test_expression_complexity_nested() {
        let inner = il::Expression::add(il::expr_scalar("x", 32), il::expr_const(1, 32)).unwrap();
        let outer = il::Expression::mul(inner, il::expr_const(2, 32)).unwrap();
        // (x + 1) * 2 => complexity = (1 + 1 + 1) + 1 + 1 = 5
        assert_eq!(expression_complexity(&outer), 5);
    }

    #[test]
    fn test_simplify_constant_folding() {
        let expr = il::Expression::add(il::expr_const(1, 32), il::expr_const(2, 32)).unwrap();
        let result = simplify(&expr).unwrap();
        assert_eq!(result, il::expr_const(3, 32));
    }

    #[test]
    fn test_simplify_or_with_zero() {
        let x = il::expr_scalar("x", 32);
        let zero = il::expr_const(0, 32);
        let expr = il::Expression::or(zero, x.clone()).unwrap();
        let result = simplify(&expr).unwrap();
        assert_eq!(result, x);
    }

    #[test]
    fn test_simplify_nested_zext() {
        let x = il::expr_scalar("x", 8);
        let inner = il::Expression::zext(16, x.clone()).unwrap();
        let outer = il::Expression::zext(32, inner).unwrap();
        let result = simplify(&outer).unwrap();
        let expected = il::Expression::zext(32, x).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_simplify_trun_zext_same_bits() {
        let x = il::expr_scalar("x", 8);
        let zext = il::Expression::zext(32, x.clone()).unwrap();
        let trun = il::Expression::trun(8, zext).unwrap();
        let result = simplify(&trun).unwrap();
        assert_eq!(result, x);
    }

    #[test]
    fn test_simplify_identity() {
        let x = il::expr_scalar("x", 32);
        let result = simplify(&x).unwrap();
        assert_eq!(result, x);
    }

    #[test]
    fn test_symbolic_memory_store_load_little_endian() {
        let mut mem = SymbolicMemory::new(Endian::Little);
        let val = il::expr_const(0x42, 8);
        mem.store(0x1000, val.clone()).unwrap();
        let loaded = mem.load(0x1000, 8).unwrap().unwrap();
        assert_eq!(eval(&loaded).unwrap().value_u64().unwrap(), 0x42);
    }

    #[test]
    fn test_symbolic_memory_store_load_32bit_little_endian() {
        let mut mem = SymbolicMemory::new(Endian::Little);
        let val = il::expr_const(0xDEADBEEF, 32);
        mem.store(0x1000, val).unwrap();
        let loaded = mem.load(0x1000, 32).unwrap().unwrap();
        assert_eq!(eval(&loaded).unwrap().value_u64().unwrap(), 0xDEADBEEF);
    }

    #[test]
    fn test_symbolic_memory_store_load_32bit_big_endian() {
        let mut mem = SymbolicMemory::new(Endian::Big);
        let val = il::expr_const(0xDEADBEEF, 32);
        mem.store(0x1000, val).unwrap();
        let loaded = mem.load(0x1000, 32).unwrap().unwrap();
        assert_eq!(eval(&loaded).unwrap().value_u64().unwrap(), 0xDEADBEEF);
    }

    #[test]
    fn test_symbolic_memory_load_uninitialized() {
        let mem = SymbolicMemory::new(Endian::Little);
        let loaded = mem.load(0x2000, 8).unwrap();
        assert!(loaded.is_none());
    }

    // --- Simplify edge-case tests ---

    #[test]
    fn test_simplify_and_bitmask_eliminates_zext() {
        // and(0xFFFFFF00:32, or(zext(32, x:8), zext(32, y:8))) → 0:32
        // Because 0xFFFFFF00 has 8 trailing zeros, and both zext operands have <=8 bits
        // eliminate_lower_bits only applies to Or expressions
        let x = il::expr_scalar("x", 8);
        let y = il::expr_scalar("y", 8);
        let zext_x = il::Expression::zext(32, x).unwrap();
        let zext_y = il::Expression::zext(32, y).unwrap();
        let or_expr = il::Expression::or(zext_x, zext_y).unwrap();
        let mask = il::expr_const(0xFFFFFF00, 32);
        let expr = il::Expression::and(mask, or_expr).unwrap();
        let result = simplify(&expr).unwrap();
        // Both zext operands eliminated to 0, result is or(0,0) which evaluates to 0
        assert!(result.all_constants());
        assert_eq!(eval(&result).unwrap().value_u64().unwrap(), 0);
    }

    #[test]
    fn test_simplify_and_bitmask_preserves_wider_zext() {
        // and(0xFFFFFF00:32, zext(32, x:16)) → NOT eliminated (16 > 8 trailing zeros)
        let x = il::expr_scalar("x", 16);
        let zext = il::Expression::zext(32, x.clone()).unwrap();
        let mask = il::expr_const(0xFFFFFF00, 32);
        let expr = il::Expression::and(mask, zext).unwrap();
        let result = simplify(&expr).unwrap();
        // Should not be simplified to zero since 16-bit value extends beyond 8 trailing zeros
        assert_ne!(result, il::expr_const(0, 32));
    }

    #[test]
    fn test_simplify_trun_eliminates_upper_or_bits() {
        // trun(8, or(0xFFFFFF00:32, x:32)) → trun(8, x:32)
        let x = il::expr_scalar("x", 32);
        let mask = il::expr_const(0xFFFFFF00, 32);
        let or_expr = il::Expression::or(mask, x.clone()).unwrap();
        let trun = il::Expression::trun(8, or_expr).unwrap();
        let result = simplify(&trun).unwrap();
        let expected = il::Expression::trun(8, x).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_simplify_trun_zext_different_bits_no_collapse() {
        // trun(16, zext(32, x:8)) → doesn't collapse to x (inner 8 != trun 16)
        let x = il::expr_scalar("x", 8);
        let zext = il::Expression::zext(32, x.clone()).unwrap();
        let trun = il::Expression::trun(16, zext).unwrap();
        let result = simplify(&trun).unwrap();
        // Should NOT collapse to just x since 8 != 16
        assert_ne!(result, x);
    }

    #[test]
    fn test_simplify_or_zero_right() {
        // or(x:32, 0:32) → x:32
        let x = il::expr_scalar("x", 32);
        let zero = il::expr_const(0, 32);
        let expr = il::Expression::or(x.clone(), zero).unwrap();
        let result = simplify(&expr).unwrap();
        assert_eq!(result, x);
    }

    #[test]
    fn test_simplify_idempotent() {
        // simplify(simplify(expr)) == simplify(expr)
        let x = il::expr_scalar("x", 32);
        let inner = il::Expression::add(x.clone(), il::expr_const(0, 32)).unwrap();
        let outer = il::Expression::or(inner, il::expr_const(0, 32)).unwrap();
        let once = simplify(&outer).unwrap();
        let twice = simplify(&once).unwrap();
        assert_eq!(once, twice);
    }

    // --- State edge-case tests ---

    fn make_state(endian: Endian) -> State {
        State::new(Memory::new(endian), Box::new(crate::platform::Dummy::new()))
    }

    #[test]
    fn test_state_scalar_not_set_returns_none() {
        let state = make_state(Endian::Little);
        assert!(state.scalar("nonexistent").is_none());
    }

    #[test]
    fn test_symbolize_replaces_nested_scalars() {
        let mut state = make_state(Endian::Little);
        state.set_scalar("y", &il::expr_const(10, 32)).unwrap();
        let y_scalar = il::expr_scalar("y", 32);
        let expr = il::Expression::add(y_scalar, il::expr_const(1, 32)).unwrap();
        state.set_scalar("x", &expr).unwrap();

        // symbolize_expression does one level of substitution, then we need
        // to symbolize again to resolve nested scalars
        let first = state
            .symbolize_expression(&il::expr_scalar("x", 32))
            .unwrap();
        let second = state.symbolize_expression(&first).unwrap();
        assert!(second.all_constants());
        assert_eq!(eval(&second).unwrap().value_u64().unwrap(), 11);
    }

    #[test]
    fn test_eval_constant_fast_path() {
        let state = make_state(Endian::Little);
        let expr = il::Expression::add(il::expr_const(3, 32), il::expr_const(4, 32)).unwrap();
        let result = state.eval(&expr).unwrap().unwrap();
        assert_eq!(result.value_u64().unwrap(), 7);
    }

    #[test]
    fn test_eval_unsatisfiable_returns_none() {
        let mut state = make_state(Endian::Little);
        let x = il::expr_scalar("x", 32);
        // x == 5
        state
            .add_path_constraint(&il::Expression::cmpeq(x.clone(), il::expr_const(5, 32)).unwrap())
            .unwrap();
        // x == 10 (contradicts)
        state
            .add_path_constraint(&il::Expression::cmpeq(x.clone(), il::expr_const(10, 32)).unwrap())
            .unwrap();
        let result = state.eval(&x).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_eval_and_concretize_adds_constraint() {
        let mut state = make_state(Endian::Little);
        let x = il::expr_scalar("x", 32);
        state.set_scalar("x", &x).unwrap();

        let constraints_before = state.path_constraints().len();
        let _result = state
            .eval_and_concretize(&il::expr_scalar("x", 32))
            .unwrap();
        let constraints_after = state.path_constraints().len();
        // Should have added a cmpeq constraint since x is symbolic
        assert!(constraints_after > constraints_before);
    }

    #[test]
    fn test_eval_and_concretize_constant_skips_constraint() {
        let mut state = make_state(Endian::Little);
        state.set_scalar("x", &il::expr_const(42, 32)).unwrap();

        let constraints_before = state.path_constraints().len();
        let result = state
            .eval_and_concretize(&il::expr_scalar("x", 32))
            .unwrap()
            .unwrap();
        let constraints_after = state.path_constraints().len();

        assert_eq!(result.value_u64().unwrap(), 42);
        // Should NOT add constraint for a constant
        assert_eq!(constraints_before, constraints_after);
    }

    #[test]
    fn test_symbolize_and_assert_satisfiable() {
        let state = make_state(Endian::Little);
        let x = il::expr_scalar("x", 32);
        let constraint = il::Expression::cmpeq(x, il::expr_const(5, 32)).unwrap();
        assert!(state.symbolize_and_assert(&constraint).unwrap());
    }

    #[test]
    fn test_symbolize_and_assert_unsatisfiable() {
        let mut state = make_state(Endian::Little);
        let x = il::expr_scalar("x", 32);
        state
            .add_path_constraint(&il::Expression::cmpeq(x.clone(), il::expr_const(5, 32)).unwrap())
            .unwrap();
        // Assert x == 10, but x is constrained to 5
        let constraint = il::Expression::cmpeq(x, il::expr_const(10, 32)).unwrap();
        assert!(!state.symbolize_and_assert(&constraint).unwrap());
    }

    #[test]
    fn test_symbolize_and_assert_constant_true() {
        let state = make_state(Endian::Little);
        // cmpeq(5, 5) → all constants → evaluates to true
        let constraint =
            il::Expression::cmpeq(il::expr_const(5, 32), il::expr_const(5, 32)).unwrap();
        assert!(state.symbolize_and_assert(&constraint).unwrap());
    }

    #[test]
    fn test_symbolize_and_assert_constant_false() {
        let state = make_state(Endian::Little);
        let constraint =
            il::Expression::cmpeq(il::expr_const(5, 32), il::expr_const(6, 32)).unwrap();
        assert!(!state.symbolize_and_assert(&constraint).unwrap());
    }

    #[test]
    fn test_execute_assign() {
        let state = make_state(Endian::Little);
        let op = il::Operation::assign(il::scalar("x", 32), il::expr_const(42, 32));
        let successors = state.execute(&op).unwrap();
        assert_eq!(successors.len(), 1);
        let succ_state = successors[0].state();
        assert_eq!(
            eval(&succ_state.scalar("x").unwrap())
                .unwrap()
                .value_u64()
                .unwrap(),
            42
        );
        assert!(matches!(successors[0].type_(), SuccessorType::FallThrough));
    }

    #[test]
    fn test_execute_store_concrete() {
        let mut state = make_state(Endian::Little);
        state
            .set_scalar("addr", &il::expr_const(0x1000, 32))
            .unwrap();
        state
            .memory_mut()
            .set_permissions(0x0, PAGE_SIZE, Some(MemoryPermissions::ALL))
            .unwrap();

        let op = il::Operation::store(il::expr_const(0x1000, 32), il::expr_const(0xBEEF, 16));
        let successors = state.execute(&op).unwrap();
        assert_eq!(successors.len(), 1);
        let loaded = successors[0]
            .state()
            .memory()
            .load(0x1000, 16)
            .unwrap()
            .unwrap();
        assert_eq!(eval(&loaded).unwrap().value_u64().unwrap(), 0xBEEF);
    }

    #[test]
    fn test_execute_load_uninitialized_empty_successors() {
        let state = make_state(Endian::Little);
        // Load from uninitialized address → empty successors
        let op = il::Operation::load(il::scalar("dst", 32), il::expr_const(0x9999, 32));
        let successors = state.execute(&op).unwrap();
        assert!(successors.is_empty());
    }

    #[test]
    fn test_execute_load_undefined_scalar_in_index() {
        let state = make_state(Endian::Little);
        // Index references undefined scalar "addr" → empty Vec (early guard)
        let op = il::Operation::load(il::scalar("dst", 32), il::expr_scalar("addr", 32));
        let successors = state.execute(&op).unwrap();
        assert!(successors.is_empty());
    }

    #[test]
    fn test_execute_branch() {
        let state = make_state(Endian::Little);
        let op = il::Operation::branch(il::expr_const(0xDEAD, 32));
        let successors = state.execute(&op).unwrap();
        assert_eq!(successors.len(), 1);
        assert!(matches!(
            successors[0].type_(),
            SuccessorType::Branch(0xDEAD)
        ));
    }

    #[test]
    fn test_execute_nop() {
        let state = make_state(Endian::Little);
        let op = il::Operation::nop();
        let successors = state.execute(&op).unwrap();
        assert_eq!(successors.len(), 1);
        assert!(matches!(successors[0].type_(), SuccessorType::FallThrough));
    }

    #[test]
    fn test_execute_intrinsic_dummy_errors() {
        let state = make_state(Endian::Little);
        let intrinsic = il::Intrinsic::new(
            "test_intrinsic",
            "test_intrinsic",
            Vec::new(),
            None,
            None,
            Vec::new(),
        );
        let op = il::Operation::Intrinsic {
            intrinsic: intrinsic.clone(),
        };
        let result = state.execute(&op);
        assert!(result.is_err());
    }

    #[test]
    fn test_make_symbolic_buffer() {
        let mut state = make_state(Endian::Little);
        let (addr, exprs) = state.make_symbolic_buffer("buf", 4).unwrap();
        assert_eq!(addr, 0x8000_0000);
        assert_eq!(exprs.len(), 4);
        // Each expression should be a scalar
        for (i, expr) in exprs.iter().enumerate() {
            if let il::Expression::Scalar(s) = expr {
                assert_eq!(s.name(), &format!("buf_{}", i));
                assert_eq!(s.bits(), 8);
            } else {
                panic!("Expected scalar expression");
            }
        }
        // Next buffer should start at 0x8000_0004
        let (addr2, _) = state.make_symbolic_buffer("buf2", 2).unwrap();
        assert_eq!(addr2, 0x8000_0004);
    }

    #[test]
    fn test_make_symbolic_string_null_terminated() {
        let mut state = make_state(Endian::Little);
        let addr = state.make_symbolic_string("str", 4).unwrap();
        assert_eq!(addr, 0x8000_0000);
        // 3 symbolic bytes + 1 null terminator
        // Check null terminator at offset 3
        let null_byte = state.memory().load(addr + 3, 8).unwrap().unwrap();
        assert_eq!(eval(&null_byte).unwrap().value_u64().unwrap(), 0);
        // First 3 bytes should be symbolic (scalars)
        for i in 0..3u64 {
            let byte = state.memory().load(addr + i, 8).unwrap().unwrap();
            assert!(!byte.all_constants());
        }
    }

    #[test]
    fn test_get_string_reads_null_terminated() {
        let mut state = make_state(Endian::Little);
        // Store "Hi\0"
        state
            .memory_mut()
            .store(0x1000, &il::expr_const(b'H' as u64, 8))
            .unwrap();
        state
            .memory_mut()
            .store(0x1001, &il::expr_const(b'i' as u64, 8))
            .unwrap();
        state
            .memory_mut()
            .store(0x1002, &il::expr_const(0, 8))
            .unwrap();
        let s = state.get_string(0x1000).unwrap().unwrap();
        assert_eq!(s, "Hi");
    }

    #[test]
    fn test_get_string_uninitialized_returns_none() {
        let state = make_state(Endian::Little);
        let result = state.get_string(0x5000).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_merge_differing_scalars_ite() {
        let mut state_a = make_state(Endian::Little);
        state_a.set_scalar("x", &il::expr_const(1, 32)).unwrap();

        let mut state_b = make_state(Endian::Little);
        let cond = il::expr_scalar("cond", 1);
        state_b
            .add_path_constraint(&il::Expression::cmpeq(cond, il::expr_const(1, 1)).unwrap())
            .unwrap();
        state_b.set_scalar("x", &il::expr_const(2, 32)).unwrap();

        let merged = state_a.merge(&state_b).unwrap();
        let x = merged.scalar("x").unwrap();
        // Should be an ITE, not a plain constant
        assert!(!x.all_constants());
    }

    #[test]
    fn test_merge_same_scalars_unchanged() {
        let mut state_a = make_state(Endian::Little);
        state_a.set_scalar("x", &il::expr_const(5, 32)).unwrap();

        let mut state_b = make_state(Endian::Little);
        state_b.set_scalar("x", &il::expr_const(5, 32)).unwrap();

        let merged = state_a.merge(&state_b).unwrap();
        let x = merged.scalar("x").unwrap();
        assert_eq!(eval(&x).unwrap().value_u64().unwrap(), 5);
    }

    #[test]
    fn test_merge_other_has_extra_scalar() {
        let state_a = make_state(Endian::Little);

        let mut state_b = make_state(Endian::Little);
        state_b.set_scalar("y", &il::expr_const(10, 32)).unwrap();

        let merged = state_a.merge(&state_b).unwrap();
        let y = merged.scalar("y").unwrap();
        // y should be ite(constraint, 10, 0) — not all constants since constraint is const(1,1)
        // Actually with empty path constraints, constraint = const(1,1), so ite(1, 10, 0) = 10
        assert_eq!(eval(&y).unwrap().value_u64().unwrap(), 10);
    }

    #[test]
    fn test_ecv_creates_constraint_and_increments() {
        let mut state = make_state(Endian::Little);
        let expr = il::Expression::add(il::expr_scalar("a", 32), il::expr_const(1, 32)).unwrap();

        let constraints_before = state.path_constraints().len();
        let ecv0 = state.expression_complexity_variable(expr).unwrap();
        let constraints_after = state.path_constraints().len();

        // Should have added a cmpeq constraint
        assert_eq!(constraints_after, constraints_before + 1);
        // Should be ecv_0
        if let il::Expression::Scalar(s) = &ecv0 {
            assert_eq!(s.name(), "ecv_0");
        } else {
            panic!("Expected scalar");
        }

        // Next call increments to ecv_1
        let expr2 = il::Expression::add(il::expr_scalar("b", 32), il::expr_const(2, 32)).unwrap();
        let ecv1 = state.expression_complexity_variable(expr2).unwrap();
        if let il::Expression::Scalar(s) = &ecv1 {
            assert_eq!(s.name(), "ecv_1");
        } else {
            panic!("Expected scalar");
        }
    }
}
