#![allow(dead_code)]

use error::*;
use executor::simplify;
use falcon::il;
use std::collections::HashMap;
use std::sync::RwLock;


lazy_static!{
    pub static ref HASH_EXPRESSION_STORE: RwLock<HashExpressionStore>
        = RwLock::new(HashExpressionStore::new());
}


#[derive(Clone, Debug, Deserialize, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ExpressionHash(u32, u16);


// ehbinop = expression_hash_binop
fn ehbinop<F: FnOnce(ExpressionHash, ExpressionHash) -> HashExpression>(
    lhs: ExpressionHash,
    rhs: ExpressionHash,
    op: F
) -> ExpressionHash {
    HASH_EXPRESSION_STORE.write().unwrap().get_hash_(&op(lhs, rhs))
}

impl ExpressionHash {
    pub fn bits(&self) -> usize {
        self.1 as usize
    }

    pub fn constant(value: u64, bits: usize) -> ExpressionHash {
        HASH_EXPRESSION_STORE.write().unwrap().get_hash_(
            &HashExpression::Constant(il::const_(value, bits)))
    }

    pub fn add(self, other: ExpressionHash) -> ExpressionHash {
        ehbinop(self, other, |lhs, rhs| HashExpression::Add(lhs, rhs))
    }

    pub fn sub(self, other: ExpressionHash) -> ExpressionHash {
        ehbinop(self, other, |lhs, rhs| HashExpression::Sub(lhs, rhs))
    }

    pub fn mul(self, other: ExpressionHash) -> ExpressionHash {
        ehbinop(self, other, |lhs, rhs| HashExpression::Mul(lhs, rhs))
    }

    pub fn divu(self, other: ExpressionHash) -> ExpressionHash {
        ehbinop(self, other, |lhs, rhs| HashExpression::Divu(lhs, rhs))
    }

    pub fn modu(self, other: ExpressionHash) -> ExpressionHash {
        ehbinop(self, other, |lhs, rhs| HashExpression::Modu(lhs, rhs))
    }

    pub fn divs(self, other: ExpressionHash) -> ExpressionHash {
        ehbinop(self, other, |lhs, rhs| HashExpression::Divs(lhs, rhs))
    }

    pub fn mods(self, other: ExpressionHash) -> ExpressionHash {
        ehbinop(self, other, |lhs, rhs| HashExpression::Mods(lhs, rhs))
    }

    pub fn and(self, other: ExpressionHash) -> ExpressionHash {
        ehbinop(self, other, |lhs, rhs| HashExpression::And(lhs, rhs))
    }

    pub fn or(self, other: ExpressionHash) -> ExpressionHash {
        ehbinop(self, other, |lhs, rhs| HashExpression::Or(lhs, rhs))
    }

    pub fn xor(self, other: ExpressionHash) -> ExpressionHash {
        ehbinop(self, other, |lhs, rhs| HashExpression::Xor(lhs, rhs))
    }

    pub fn shl(self, other: ExpressionHash) -> ExpressionHash {
        ehbinop(self, other, |lhs, rhs| HashExpression::Shl(lhs, rhs))
    }

    pub fn shl_const(self, bits: u64) -> ExpressionHash {
        let bits = ExpressionHash::constant(bits, self.bits());
        ehbinop(self, bits, |lhs, rhs| HashExpression::Shl(lhs, rhs))
    }

    pub fn shr(self, other: ExpressionHash) -> ExpressionHash {
        ehbinop(self, other, |lhs, rhs| HashExpression::Shr(lhs, rhs))
    }

    pub fn shr_const(self, bits: u64) -> ExpressionHash {
        let bits = ExpressionHash::constant(bits, self.bits());
        ehbinop(self, bits, |lhs, rhs| HashExpression::Shr(lhs, rhs))
    }

    pub fn cmpeq(self, other: ExpressionHash) -> ExpressionHash {
        ehbinop(self, other, |lhs, rhs| HashExpression::Cmpeq(lhs, rhs))
    }

    pub fn cmpneq(self, other: ExpressionHash) -> ExpressionHash {
        ehbinop(self, other, |lhs, rhs| HashExpression::Cmpneq(lhs, rhs))
    }

    pub fn cmplts(self, other: ExpressionHash) -> ExpressionHash {
        ehbinop(self, other, |lhs, rhs| HashExpression::Cmplts(lhs, rhs))
    }

    pub fn cmpltu(self, other: ExpressionHash) -> ExpressionHash {
        ehbinop(self, other, |lhs, rhs| HashExpression::Cmpltu(lhs, rhs))
    }

    pub fn zext(self, bits: usize) -> ExpressionHash {
        HASH_EXPRESSION_STORE.write().unwrap().get_hash_(
            &HashExpression::Zext(bits, self))
    }

    pub fn sext(self, bits: usize) -> ExpressionHash {
        HASH_EXPRESSION_STORE.write().unwrap().get_hash_(
            &HashExpression::Sext(bits, self))
    }

    pub fn trun(self, bits: usize) -> ExpressionHash {
        HASH_EXPRESSION_STORE.write().unwrap().get_hash_(
            &HashExpression::Trun(bits, self))
    }
}



#[derive(Clone, Debug, Deserialize, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize)]
enum HashExpression {
    Scalar(il::Scalar),
    Constant(il::Constant),
    Add(ExpressionHash, ExpressionHash),
    Sub(ExpressionHash, ExpressionHash),
    Mul(ExpressionHash, ExpressionHash),
    Divu(ExpressionHash, ExpressionHash),
    Modu(ExpressionHash, ExpressionHash),
    Divs(ExpressionHash, ExpressionHash),
    Mods(ExpressionHash, ExpressionHash),
    And(ExpressionHash, ExpressionHash),
    Or(ExpressionHash, ExpressionHash),
    Xor(ExpressionHash, ExpressionHash),
    Shl(ExpressionHash, ExpressionHash),
    Shr(ExpressionHash, ExpressionHash),
    Cmpeq(ExpressionHash, ExpressionHash),
    Cmpneq(ExpressionHash, ExpressionHash),
    Cmpltu(ExpressionHash, ExpressionHash),
    Cmplts(ExpressionHash, ExpressionHash),
    Zext(usize, ExpressionHash),
    Sext(usize, ExpressionHash),
    Trun(usize, ExpressionHash),
    Ite(ExpressionHash, ExpressionHash, ExpressionHash),
}


impl HashExpression {
    pub fn bits(&self)
        -> usize {

        match *self {
            HashExpression::Scalar(ref scalar) => scalar.bits(),
            HashExpression::Constant(ref constant) => constant.bits(),
            HashExpression::Add(ref lhs, _) |
            HashExpression::Sub(ref lhs, _) |
            HashExpression::Mul(ref lhs, _) |
            HashExpression::Divu(ref lhs, _) |
            HashExpression::Modu(ref lhs, _) |
            HashExpression::Divs(ref lhs, _) |
            HashExpression::Mods(ref lhs, _) |
            HashExpression::And(ref lhs, _) |
            HashExpression::Or(ref lhs, _) |
            HashExpression::Xor(ref lhs, _) |
            HashExpression::Shl(ref lhs, _) |
            HashExpression::Shr(ref lhs, _) => lhs.bits(),
            HashExpression::Cmpeq(_, _) |
            HashExpression::Cmpneq(_, _) |
            HashExpression::Cmpltu(_, _) |
            HashExpression::Cmplts(_, _) => 1,
            HashExpression::Zext(bits, _) |
            HashExpression::Sext(bits, _) |
            HashExpression::Trun(bits, _) => bits,
            HashExpression::Ite(_, ref then, _) => then.bits()
        }
    }
}


#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HashExpressionStore {
    expr_to_hash: HashMap<HashExpression, ExpressionHash>,
    hash_to_expr: HashMap<ExpressionHash, HashExpression>,
    next_id: u32
}


impl HashExpressionStore {
    pub fn new() -> HashExpressionStore {
        HashExpressionStore {
            expr_to_hash: HashMap::new(),
            hash_to_expr: HashMap::new(),
            next_id: 0
        }
    }


    pub fn bits(&self, expression_hash: &ExpressionHash) -> Result<usize> {
        match self.hash_to_expr[&expression_hash] {
            HashExpression::Scalar(ref scalar) => Ok(scalar.bits()),
            HashExpression::Constant(ref constant) => Ok(constant.bits()),
            HashExpression::Add(ref lhs, _) |
            HashExpression::Sub(ref lhs, _) |
            HashExpression::Mul(ref lhs, _) |
            HashExpression::Divu(ref lhs, _) |
            HashExpression::Modu(ref lhs, _) |
            HashExpression::Divs(ref lhs, _) |
            HashExpression::Mods(ref lhs, _) |
            HashExpression::And(ref lhs, _) |
            HashExpression::Or(ref lhs, _) |
            HashExpression::Xor(ref lhs, _) |
            HashExpression::Shl(ref lhs, _) |
            HashExpression::Shr(ref lhs, _) => self.bits(lhs),
            HashExpression::Cmpeq(_, _) |
            HashExpression::Cmpneq(_, _) |
            HashExpression::Cmpltu(_, _) |
            HashExpression::Cmplts(_, _) => Ok(1),
            HashExpression::Zext(bits, _) |
            HashExpression::Sext(bits, _) |
            HashExpression::Trun(bits, _) => Ok(bits),
            HashExpression::Ite(_, ref then, _) => self.bits(then)
        }
    }


    pub fn expression(&self, expression_hash: &ExpressionHash)
        -> Result<il::Expression> {

        Ok(match self.hash_to_expr[&expression_hash] {
            HashExpression::Scalar(ref scalar) => scalar.clone().into(),
            HashExpression::Constant(ref constant) => constant.clone().into(),
            HashExpression::Add(ref lhs, ref rhs) =>
                il::Expression::add(self.expression(lhs)?,
                                    self.expression(rhs)?)?,
            HashExpression::Sub(ref lhs, ref rhs) =>
                il::Expression::sub(self.expression(lhs)?,
                                    self.expression(rhs)?)?,
            HashExpression::Mul(ref lhs, ref rhs) =>
                il::Expression::mul(self.expression(lhs)?,
                                    self.expression(rhs)?)?,
            HashExpression::Divu(ref lhs, ref rhs) =>
                il::Expression::divu(self.expression(lhs)?,
                                     self.expression(rhs)?)?,
            HashExpression::Modu(ref lhs, ref rhs) =>
                il::Expression::modu(self.expression(lhs)?,
                                     self.expression(rhs)?)?,
            HashExpression::Divs(ref lhs, ref rhs) =>
                il::Expression::divs(self.expression(lhs)?,
                                     self.expression(rhs)?)?,
            HashExpression::Mods(ref lhs, ref rhs) =>
                il::Expression::mods(self.expression(lhs)?,
                                     self.expression(rhs)?)?,
            HashExpression::And(ref lhs, ref rhs) =>
                il::Expression::and(self.expression(lhs)?,
                                    self.expression(rhs)?)?,
            HashExpression::Or(ref lhs, ref rhs) =>
                il::Expression::or(self.expression(lhs)?,
                                   self.expression(rhs)?)?,
            HashExpression::Xor(ref lhs, ref rhs) =>
                il::Expression::xor(self.expression(lhs)?,
                                    self.expression(rhs)?)?,
            HashExpression::Shl(ref lhs, ref rhs) =>
                il::Expression::shl(self.expression(lhs)?,
                                    self.expression(rhs)?)?,
            HashExpression::Shr(ref lhs, ref rhs) =>
                il::Expression::shr(self.expression(lhs)?,
                                    self.expression(rhs)?)?,
            HashExpression::Cmpeq(ref lhs, ref rhs) =>
                il::Expression::cmpeq(self.expression(lhs)?,
                                      self.expression(rhs)?)?,
            HashExpression::Cmpneq(ref lhs, ref rhs) =>
                il::Expression::cmpneq(self.expression(lhs)?,
                                       self.expression(rhs)?)?,
            HashExpression::Cmpltu(ref lhs, ref rhs) =>
                il::Expression::cmpltu(self.expression(lhs)?,
                                       self.expression(rhs)?)?,
            HashExpression::Cmplts(ref lhs, ref rhs) =>
                il::Expression::cmplts(self.expression(lhs)?,
                                       self.expression(rhs)?)?,
            HashExpression::Zext(bits, ref rhs) =>
                il::Expression::zext(bits, self.expression(rhs)?)?,
            HashExpression::Sext(bits, ref rhs) =>
                il::Expression::sext(bits, self.expression(rhs)?)?,
            HashExpression::Trun(bits, ref rhs) =>
                il::Expression::trun(bits, self.expression(rhs)?)?,
            HashExpression::Ite(ref cond, ref then, ref else_) =>
                il::Expression::ite(self.expression(cond)?,
                                    self.expression(then)?,
                                    self.expression(else_)?)?
        })
    }


    pub fn get_hash(&mut self, expression: &il::Expression) ->
        Result<ExpressionHash> {

        let expression = simplify(expression)?;

        fn gh(
            hes: &mut HashExpressionStore,
            expression: &il::Expression
        ) -> ExpressionHash {
            let hash_expression = match *expression {
                il::Expression::Scalar(ref scalar) =>
                    HashExpression::Scalar(scalar.clone()), 
                il::Expression::Constant(ref constant) =>
                    HashExpression::Constant(constant.clone()),
                il::Expression::Add(ref lhs, ref rhs) =>
                    HashExpression::Add(gh(hes, lhs), gh(hes, rhs)),
                il::Expression::Sub(ref lhs, ref rhs) =>
                    HashExpression::Sub(gh(hes, lhs), gh(hes, rhs)),
                il::Expression::Mul(ref lhs, ref rhs) =>
                    HashExpression::Mul(gh(hes, lhs), gh(hes, rhs)),
                il::Expression::Divu(ref lhs, ref rhs) =>
                    HashExpression::Divu(gh(hes, lhs), gh(hes, rhs)),
                il::Expression::Modu(ref lhs, ref rhs) =>
                    HashExpression::Modu(gh(hes, lhs), gh(hes, rhs)),
                il::Expression::Divs(ref lhs, ref rhs) =>
                    HashExpression::Divs(gh(hes, lhs), gh(hes, rhs)),
                il::Expression::Mods(ref lhs, ref rhs) =>
                    HashExpression::Mods(gh(hes, lhs), gh(hes, rhs)),
                il::Expression::And(ref lhs, ref rhs) =>
                    HashExpression::And(gh(hes, lhs), gh(hes, rhs)),
                il::Expression::Or(ref lhs, ref rhs) =>
                    HashExpression::Or(gh(hes, lhs), gh(hes, rhs)),
                il::Expression::Xor(ref lhs, ref rhs) =>
                    HashExpression::Xor(gh(hes, lhs), gh(hes, rhs)),
                il::Expression::Shl(ref lhs, ref rhs) =>
                    HashExpression::Shl(gh(hes, lhs), gh(hes, rhs)),
                il::Expression::Shr(ref lhs, ref rhs) =>
                    HashExpression::Shr(gh(hes, lhs), gh(hes, rhs)),
                il::Expression::Cmpeq(ref lhs, ref rhs) =>
                    HashExpression::Cmpeq(gh(hes, lhs), gh(hes, rhs)),
                il::Expression::Cmpneq(ref lhs, ref rhs) =>
                    HashExpression::Cmpneq(gh(hes, lhs), gh(hes, rhs)),
                il::Expression::Cmpltu(ref lhs, ref rhs) =>
                    HashExpression::Cmpltu(gh(hes, lhs), gh(hes, rhs)),
                il::Expression::Cmplts(ref lhs, ref rhs) =>
                    HashExpression::Cmplts(gh(hes, lhs), gh(hes, rhs)),
                il::Expression::Zext(bits, ref rhs) =>
                    HashExpression::Zext(bits, gh(hes, rhs)),
                il::Expression::Sext(bits, ref rhs) =>
                    HashExpression::Sext(bits, gh(hes, rhs)),
                il::Expression::Trun(bits, ref rhs) =>
                    HashExpression::Trun(bits, gh(hes, rhs)),
                il::Expression::Ite(ref cond, ref then, ref else_) =>
                    HashExpression::Ite(gh(hes, cond),
                                        gh(hes, then),
                                        gh(hes, else_))
            };
            hes.get_hash_(&hash_expression)
        }

        Ok(gh(self, &expression))
    }


    fn get_hash_(&mut self, hash_expression: &HashExpression)
        -> ExpressionHash {

        if let Some(hash) = self.expr_to_hash.get(&hash_expression) {
            return hash.clone();
        }

        let expression_hash =
            ExpressionHash(self.next_id, hash_expression.bits() as u16);
        self.expr_to_hash.insert(hash_expression.clone(), expression_hash.clone());
        self.hash_to_expr.insert(expression_hash.clone(), hash_expression.clone());
        self.next_id += 1;
        expression_hash
    }
}


#[test]
fn test() {
    let expression =
        il::Expression::add(
            il::Expression::or(
                il::expr_scalar("test", 32).into(),
                il::expr_scalar("test2", 32).into()).unwrap(),
            il::expr_const(32, 32).into()).unwrap();

    let mut hes = HashExpressionStore::new();
    let expression_hash = hes.get_hash(&expression).unwrap();
    let hashed_expression = hes.expression(&expression_hash).unwrap();

    assert_eq!(expression, hashed_expression);


    let expression =
        il::Expression::trun(
            8,
            il::Expression::shr(
                il::expr_const(0xaabbccdd, 32),
                il::expr_const(8, 32)).unwrap()).unwrap();

    let expression_hash = hes.get_hash(&expression).unwrap();
    let _ = hes.expression(&expression_hash).unwrap();
}