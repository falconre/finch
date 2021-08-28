//! A symbolic state for execution over Falcon IL.

use crate::executor::successor::*;
use crate::executor::*;
use crate::platform::Platform;
use falcon_z3::il::solve;
use std::collections::HashMap;

const DEFAULT_SYMBOLIC_MEMORY_ADDRESS: u64 = 0x8000_0000;

/// A symbolic `State`.
#[derive(Debug)]
pub struct State {
    /// scalar variables in this current state
    scalars: HashMap<String, ExpressionHash>,
    /// path constraints for this state
    path_constraints: Vec<ExpressionHash>,
    /// constraints for merged states
    merged_constraints: Vec<Vec<ExpressionHash>>,
    /// the memory model for this state
    pub(crate) memory: Memory,
    /// the platform for this state
    pub(crate) platform: Box<dyn Platform>,
    /// all symbolic scalars that have been created for this state
    symbolic_strings: HashMap<String, SymbolicString>,
    /// the next address to create a symbolic value in memory
    symbolic_memory_address: u64,
    /// the index for the next expression_complexity variable
    next_expression_complexity_variable: usize,
}

impl State {
    /// Create a new `State` from the given memory model.
    pub fn new(memory: Memory, platform: Box<dyn Platform>) -> State {
        State {
            scalars: HashMap::new(),
            path_constraints: Vec::new(),
            merged_constraints: Vec::new(),
            memory,
            platform,
            symbolic_strings: HashMap::new(),
            symbolic_memory_address: DEFAULT_SYMBOLIC_MEMORY_ADDRESS,
            next_expression_complexity_variable: 0,
        }
    }

    /// Print debug information for this `State`.
    ///
    /// This prints _a lot_ of information.
    pub fn debug(&self) {
        println!("scalars");
        for (name, expression_hash) in &self.scalars {
            println!(
                "{} = {}",
                name,
                HASH_EXPRESSION_STORE
                    .read()
                    .unwrap()
                    .expression(expression_hash)
                    .unwrap()
            );
        }

        println!("path_constraints");
        for path_constraint in &self.path_constraints {
            println!(
                "{}",
                HASH_EXPRESSION_STORE
                    .read()
                    .unwrap()
                    .expression(path_constraint)
                    .unwrap()
            );
        }

        println!("merged_constraints");
        for merged_constraint in &self.merged_constraints {
            println!(
                "{}",
                merged_constraint
                    .iter()
                    .map(|mc| {
                        let mc = HASH_EXPRESSION_STORE
                            .read()
                            .unwrap()
                            .expression(mc)
                            .unwrap();
                        format!("{}", mc)
                    })
                    .collect::<Vec<String>>()
                    .join(",")
            );
        }
    }

    /// Add the expression to constraints, and return a scalar expression to use
    /// in its place
    pub fn expression_complexity_variable(
        &mut self,
        expression: il::Expression,
    ) -> Result<il::Expression> {
        let scalar_expression = il::expr_scalar(
            format!("ecv_{}", self.next_expression_complexity_variable),
            expression.bits(),
        );

        self.next_expression_complexity_variable += 1;

        self.add_path_constraint(&il::Expression::cmpeq(
            scalar_expression.clone(),
            expression,
        )?)?;

        Ok(scalar_expression)
    }

    /// Retrieve the `Memory` associated with this `State`.
    pub fn memory(&self) -> &Memory {
        &self.memory
    }

    /// Retrieve a mutable reference to the `Memory` associated with this
    /// `State`.
    pub fn memory_mut(&mut self) -> &mut Memory {
        &mut self.memory
    }

    /// Set the symbolic value of the given scalar.
    pub fn set_scalar<S: Into<String>>(&mut self, name: S, value: &il::Expression) -> Result<()> {
        let expression_hash = HASH_EXPRESSION_STORE.write().unwrap().get_hash(value)?;
        self.scalars.insert(name.into(), expression_hash);
        Ok(())
    }

    /// Get the symbolic value of the given scalar.
    pub fn scalar(&self, name: &str) -> Option<il::Expression> {
        self.scalars.get(name).map(|expression_hash| {
            HASH_EXPRESSION_STORE
                .read()
                .unwrap()
                .expression(expression_hash)
                .unwrap()
        })
    }

    /// Get the names of the scalars in this `State`.
    pub fn scalars(&self) -> Vec<String> {
        self.scalars
            .iter()
            .map(|(name, _)| name.to_string())
            .collect::<Vec<String>>()
    }

    /// Add a path constraint to this state
    pub fn add_path_constraint(&mut self, constraint: &il::Expression) -> Result<()> {
        assert!(constraint.bits() == 1);

        let expression_hash = HASH_EXPRESSION_STORE
            .write()
            .unwrap()
            .get_hash(constraint)?;
        self.path_constraints.push(expression_hash);
        Ok(())
    }

    /// Get the path constraints for this `State`.
    pub fn path_constraints(&self) -> Vec<il::Expression> {
        self.path_constraints
            .iter()
            .map(|path_constraint| {
                HASH_EXPRESSION_STORE
                    .read()
                    .unwrap()
                    .expression(path_constraint)
                    .unwrap()
            })
            .collect::<Vec<il::Expression>>()
    }

    /// Get the merged constraints for this `State`.
    pub fn merged_constraints(&self) -> Vec<Vec<il::Expression>> {
        self.merged_constraints
            .iter()
            .map(|merged_constraints| {
                merged_constraints
                    .iter()
                    .map(|mc| {
                        HASH_EXPRESSION_STORE
                            .read()
                            .unwrap()
                            .expression(mc)
                            .unwrap()
                    })
                    .collect::<Vec<il::Expression>>()
            })
            .collect::<Vec<Vec<il::Expression>>>()
    }

    fn add_merged_constraints(&mut self, constraints: Vec<il::Expression>) -> Result<()> {
        constraints
            .iter()
            .for_each(|constraint| assert!(constraint.bits() == 1));

        let constraints = constraints
            .into_iter()
            .map(|constraint| {
                HASH_EXPRESSION_STORE
                    .write()
                    .unwrap()
                    .get_hash(&constraint)
                    .unwrap()
            })
            .collect::<Vec<ExpressionHash>>();

        self.merged_constraints.push(constraints);

        Ok(())
    }

    /// Get the `Platform` for this `State`.
    pub fn platform(&self) -> &dyn Platform {
        self.platform.as_ref()
    }

    /// Get a mutable reference to the `Platform` for this `State`.
    pub fn platform_mut(&mut self) -> &mut dyn Platform {
        self.platform.as_mut()
    }

    /// Symbolize an expression, replacing all scalars with the values
    /// stored in this `State`.
    pub fn symbolize_expression(&self, expression: &il::Expression) -> Result<il::Expression> {
        Ok(match *expression {
            il::Expression::Scalar(ref scalar) => match self.scalars.get(scalar.name()) {
                Some(expression_hash) => HASH_EXPRESSION_STORE
                    .read()
                    .unwrap()
                    .expression(expression_hash)?,
                None => il::Expression::Scalar(scalar.clone()),
            },
            il::Expression::Constant(_) => expression.clone(),
            il::Expression::Add(ref lhs, ref rhs) => il::Expression::add(
                self.symbolize_expression(lhs)?,
                self.symbolize_expression(rhs)?,
            )?,
            il::Expression::Sub(ref lhs, ref rhs) => il::Expression::sub(
                self.symbolize_expression(lhs)?,
                self.symbolize_expression(rhs)?,
            )?,
            il::Expression::Mul(ref lhs, ref rhs) => il::Expression::mul(
                self.symbolize_expression(lhs)?,
                self.symbolize_expression(rhs)?,
            )?,
            il::Expression::Divu(ref lhs, ref rhs) => il::Expression::divu(
                self.symbolize_expression(lhs)?,
                self.symbolize_expression(rhs)?,
            )?,
            il::Expression::Modu(ref lhs, ref rhs) => il::Expression::modu(
                self.symbolize_expression(lhs)?,
                self.symbolize_expression(rhs)?,
            )?,
            il::Expression::Divs(ref lhs, ref rhs) => il::Expression::divs(
                self.symbolize_expression(lhs)?,
                self.symbolize_expression(rhs)?,
            )?,
            il::Expression::Mods(ref lhs, ref rhs) => il::Expression::mods(
                self.symbolize_expression(lhs)?,
                self.symbolize_expression(rhs)?,
            )?,
            il::Expression::And(ref lhs, ref rhs) => il::Expression::and(
                self.symbolize_expression(lhs)?,
                self.symbolize_expression(rhs)?,
            )?,
            il::Expression::Or(ref lhs, ref rhs) => il::Expression::or(
                self.symbolize_expression(lhs)?,
                self.symbolize_expression(rhs)?,
            )?,
            il::Expression::Xor(ref lhs, ref rhs) => il::Expression::xor(
                self.symbolize_expression(lhs)?,
                self.symbolize_expression(rhs)?,
            )?,
            il::Expression::Shl(ref lhs, ref rhs) => il::Expression::shl(
                self.symbolize_expression(lhs)?,
                self.symbolize_expression(rhs)?,
            )?,
            il::Expression::Shr(ref lhs, ref rhs) => il::Expression::shr(
                self.symbolize_expression(lhs)?,
                self.symbolize_expression(rhs)?,
            )?,
            il::Expression::Cmpeq(ref lhs, ref rhs) => il::Expression::cmpeq(
                self.symbolize_expression(lhs)?,
                self.symbolize_expression(rhs)?,
            )?,
            il::Expression::Cmpneq(ref lhs, ref rhs) => il::Expression::cmpneq(
                self.symbolize_expression(lhs)?,
                self.symbolize_expression(rhs)?,
            )?,
            il::Expression::Cmplts(ref lhs, ref rhs) => il::Expression::cmplts(
                self.symbolize_expression(lhs)?,
                self.symbolize_expression(rhs)?,
            )?,
            il::Expression::Cmpltu(ref lhs, ref rhs) => il::Expression::cmpltu(
                self.symbolize_expression(lhs)?,
                self.symbolize_expression(rhs)?,
            )?,
            il::Expression::Zext(bits, ref src) => {
                il::Expression::zext(bits, self.symbolize_expression(src)?)?
            }
            il::Expression::Sext(bits, ref src) => {
                il::Expression::sext(bits, self.symbolize_expression(src)?)?
            }
            il::Expression::Trun(bits, ref src) => {
                il::Expression::trun(bits, self.symbolize_expression(src)?)?
            }
            il::Expression::Ite(ref cond, ref then, ref else_) => il::Expression::ite(
                self.symbolize_expression(cond)?,
                self.symbolize_expression(then)?,
                self.symbolize_expression(else_)?,
            )?,
        })
    }

    /// Symbolize the given expression, replacing all scalars with the symbolic
    /// values held in this state, and evaluate the expression to a single
    /// concrete value.
    pub fn symbolize_and_eval(&self, expression: &il::Expression) -> Result<Option<il::Constant>> {
        let expression = self.symbolize_expression(expression)?;

        self.eval(&expression)
    }

    /// Evaluates the expression to a single, concrete value
    pub fn eval(&self, expression: &il::Expression) -> Result<Option<il::Constant>> {
        if expression.all_constants() {
            Ok(Some(eval(expression)?))
        } else if self.merged_constraints.is_empty() {
            Ok(solve(&self.path_constraints(), expression)?)
        }
        // If we have merged constraints, we need to assert that at least one
        // set of merged constraints is true
        else {
            let path_constraints = self
                .path_constraints()
                .into_iter()
                .fold(il::expr_const(1, 1), |sum, constraint| {
                    il::Expression::and(sum, constraint).unwrap()
                });
            let merged_constraints =
                self.merged_constraints()
                    .into_iter()
                    .fold(path_constraints, |ite, constraints| {
                        let constraints = constraints
                            .into_iter()
                            .fold(il::expr_const(1, 1), |sum, constraint| {
                                il::Expression::and(sum, constraint).unwrap()
                            });
                        il::Expression::ite(constraints, il::expr_const(1, 1), ite).unwrap()
                    });

            Ok(solve(&[merged_constraints], expression)?)
        }
    }

    /// Symbolize and evaluate the given expression. If the expression is
    /// symbolic, add a path constraint that sets the expression equal to its
    /// evaluated value.
    pub fn eval_and_concretize(
        &mut self,
        expression: &il::Expression,
    ) -> Result<Option<il::Constant>> {
        let expression = self.symbolize_expression(expression)?;

        if expression.all_constants() {
            Ok(Some(eval(&expression)?))
        } else {
            let constant = self.symbolize_and_eval(&expression)?;
            if let Some(ref constant) = constant {
                self.add_path_constraint(&il::Expression::cmpeq(
                    expression,
                    constant.clone().into(),
                )?)?;
            }
            Ok(constant)
        }
    }

    /// Symbolize the given expression, replacing all scalars with the symbolic
    /// values held in this state, and evaluate whether the given constraint is
    /// true/satisfiable
    pub fn symbolize_and_assert(&self, constraint: &il::Expression) -> Result<bool> {
        let expression = self.symbolize_expression(constraint)?;

        if expression.all_constants() {
            Ok(eval(&expression)?.is_one())
        } else if self.merged_constraints.is_empty() {
            let mut constraints = self.path_constraints();
            constraints.push(expression);

            Ok(solve(&constraints, &il::expr_scalar("asisjelisf", 1))?.is_some())
        }
        // If we have merged constraints, we need to assert that at least one
        // set of merged constraints is true
        else {
            let path_constraints = self
                .path_constraints()
                .into_iter()
                .fold(il::expr_const(1, 1), |sum, constraint| {
                    il::Expression::and(sum, constraint).unwrap()
                });
            let merged_constraints =
                self.merged_constraints()
                    .into_iter()
                    .fold(path_constraints, |ite, constraints| {
                        let constraints = constraints
                            .into_iter()
                            .fold(il::expr_const(1, 1), |sum, constraint| {
                                il::Expression::and(sum, constraint).unwrap()
                            });
                        il::Expression::ite(constraints, il::expr_const(1, 1), ite).unwrap()
                    });

            let merged_constraints = il::Expression::and(expression, merged_constraints)?;

            Ok(solve(&[merged_constraints], &il::expr_scalar("lsdkfjsoeifjs", 1))?.is_some())
        }
    }

    /// Execute an `il::Operation`, returning the post-execution `Successor`.
    pub fn execute(mut self, operation: &il::Operation) -> Result<Vec<Successor>> {
        Ok(match *operation {
            il::Operation::Assign { ref dst, ref src } => {
                let src = self.symbolize_expression(src)?;
                let src = if expression_complexity(&src) > 256 {
                    self.expression_complexity_variable(src)?
                } else {
                    src
                };
                self.set_scalar(dst.name(), &src)?;
                // if dst.name().len() >= 3 {
                //     println!("{} = {}", dst, simplify(&src)?);
                // }
                vec![Successor::new(self, SuccessorType::FallThrough)]
            }
            il::Operation::Store { ref index, ref src } => {
                let src = self.symbolize_expression(src)?;
                let index = self.symbolize_and_eval(index)?;
                match index {
                    Some(index) => {
                        self.memory
                            .store(index.value_u64().ok_or("Too many address bits")?, &src)?;
                        vec![Successor::new(self, SuccessorType::FallThrough)]
                    }
                    None => Vec::new(),
                }
            }
            il::Operation::Load { ref dst, ref index } => {
                if index
                    .scalars()
                    .into_iter()
                    .any(|scalar| self.scalar(scalar.name()).is_none())
                {
                    return Ok(Vec::new());
                }
                let index = self.symbolize_and_eval(index)?;
                match index {
                    Some(index) => {
                        let value = self.memory.load(
                            index.value_u64().ok_or("Too many address bits")?,
                            dst.bits(),
                        )?;
                        match value {
                            Some(v) => {
                                self.set_scalar(dst.name(), &v)?;
                                vec![Successor::new(self, SuccessorType::FallThrough)]
                            }
                            None => Vec::new(),
                        }
                    }
                    None => Vec::new(),
                }
            }
            il::Operation::Branch { ref target } => {
                let target = self.symbolize_and_eval(target)?;
                match target {
                    Some(target) => vec![Successor::new(
                        self,
                        SuccessorType::Branch(target.value_u64().ok_or("Too many address bits")?),
                    )],
                    None => Vec::new(),
                }
            }
            il::Operation::Intrinsic { ref intrinsic } => {
                self.platform.get_intrinsic_handler()(self, intrinsic)?
            }
            il::Operation::Nop { .. } => vec![Successor::new(self, SuccessorType::FallThrough)],
        })
    }

    /// Combine the constraints for this state into one expression combined with
    /// `il::Expression::And`
    fn constraints_as_expression(&self) -> Result<il::Expression> {
        let path_constraints = self.path_constraints();

        Ok(if path_constraints.is_empty() {
            il::expr_const(1, 1)
        } else if path_constraints.len() == 1 {
            path_constraints[0].clone()
        } else {
            let mut expr = path_constraints[0].clone();
            for path_constraint in path_constraints.iter().skip(1) {
                expr = il::Expression::and(expr, path_constraint.clone())?;
            }
            expr
        })
    }

    /// Merge this `State` with another `State`
    pub fn merge(mut self, other: &State) -> Result<State> {
        let other_constraints = other.constraints_as_expression()?;
        // merge memory
        self.memory = self.memory.merge(&other.memory, &other_constraints)?;

        // merge all scalars
        for (name, scalar) in other
            .scalars
            .iter()
            .map(|(name, _)| (name, other.scalar(name).unwrap()))
        {
            let e = if let Some(self_scalar) = self.scalar(name) {
                if !self_scalar.all_constants() || self_scalar != scalar {
                    Some(il::Expression::ite(
                        other_constraints.clone(),
                        scalar.clone(),
                        self_scalar.clone(),
                    )?)
                } else {
                    None
                }
            } else {
                Some(il::Expression::ite(
                    other_constraints.clone(),
                    scalar.clone(),
                    il::expr_const(0, scalar.bits()),
                )?)
            };
            if let Some(e) = e {
                self.set_scalar(name.to_string(), &e)?;
            }
        }

        if !self.platform.merge(other.platform(), &other_constraints)? {
            bail!("Platforms did not merge correctly");
        }

        // add constraints to merged constraints
        self.add_merged_constraints(other.path_constraints())?;

        // Choose the higher of the next symbolic memory addresses
        if self.symbolic_memory_address < other.symbolic_memory_address {
            self.symbolic_memory_address = other.symbolic_memory_address;
        }

        Ok(self)
    }

    /// Receive the next byte for symbolic memory addresses, and increment
    /// the symbolic memory address counter
    fn next_symbolic_memory_address(&mut self) -> u64 {
        let address = self.symbolic_memory_address;
        self.symbolic_memory_address += 1;
        address
    }

    /// Create a symbolic memory buffer in this `State`.
    ///
    /// Returns the address of the symbolic buffer
    pub fn make_symbolic_buffer(
        &mut self,
        name: &str,
        length: usize,
    ) -> Result<(u64, Vec<il::Expression>)> {
        let buffer_address = self.symbolic_memory_address;
        let mut expressions = Vec::new();

        for i in 0..length {
            let address = self.next_symbolic_memory_address();
            let name = format!("{}_{}", name, i);
            let expr = il::expr_scalar(name, 8);
            expressions.push(expr.clone());
            self.memory.store(address, &expr)?;
        }

        Ok((buffer_address, expressions))
    }

    /// Create a symbolic string in this `State`.
    ///
    /// This is a null-terminated symbolic buffer.
    pub fn make_symbolic_string(&mut self, name: &str, length: usize) -> Result<u64> {
        let (address, expressions) = self.make_symbolic_buffer(name, length - 1)?;

        let null_byte_address = self.next_symbolic_memory_address();
        self.memory
            .store(null_byte_address, &il::expr_const(0, 8))?;

        let mut expression_hashes = Vec::new();

        for expression in expressions {
            expression_hashes.push(
                HASH_EXPRESSION_STORE
                    .write()
                    .unwrap()
                    .get_hash(&expression)?,
            );
        }

        let symbolic_string = SymbolicString::new(expression_hashes);

        self.symbolic_strings
            .insert(name.to_string(), symbolic_string);

        Ok(address)
    }

    /// Attempts to read a constant string from a given address
    pub fn get_string(&self, address: u64) -> Result<Option<String>> {
        let mut bytes = Vec::new();

        for i in 0..256 {
            let byte = self.memory.load(address + i, 8)?;
            let byte = match byte {
                Some(byte) => byte,
                None => {
                    return Ok(None);
                }
            };
            let byte = match self.symbolize_and_eval(&byte)? {
                Some(byte) => byte,
                None => {
                    return Ok(None);
                }
            };
            if byte.is_zero() {
                break;
            }
            bytes.push(byte.value_u64().unwrap() as u8);
        }

        Ok(String::from_utf8(bytes).map(Some).unwrap_or(None))
    }
}

impl Clone for State {
    fn clone(&self) -> State {
        State {
            scalars: self.scalars.clone(),
            path_constraints: self.path_constraints.clone(),
            merged_constraints: self.merged_constraints.clone(),
            memory: self.memory.clone(),
            platform: self.platform.box_clone(),
            symbolic_strings: self.symbolic_strings.clone(),
            symbolic_memory_address: self.symbolic_memory_address,
            next_expression_complexity_variable: self.next_expression_complexity_variable,
        }
    }
}
