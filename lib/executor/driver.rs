//! A `Driver`, "Driver," `State` over an `il::Program`.

use crate::error::*;
use crate::executor::successor::*;
use crate::executor::{State, StateTranslator, Trace};
use falcon::architecture::Architecture;
use falcon::{il, RC};

/// A `Driver` to driver `State` over an `il::Program`.
#[derive(Clone, Debug)]
pub struct Driver {
    program: il::Program,
    location: il::ProgramLocation,
    state: State,
    architecture: RC<Box<dyn Architecture>>,
    trace: Trace,
}

impl Driver {
    /// Create a new `Driver` for symbolic execution over Falcon IL.
    pub fn new(
        program: il::Program,
        location: il::ProgramLocation,
        state: State,
        architecture: RC<Box<dyn Architecture>>,
    ) -> Driver {
        Driver {
            program: program,
            location: location,
            state: state,
            architecture: architecture,
            trace: Trace::new(),
        }
    }

    fn new_full(
        program: il::Program,
        location: il::ProgramLocation,
        state: State,
        architecture: RC<Box<dyn Architecture>>,
        trace: Trace,
    ) -> Driver {
        Driver {
            program: program,
            location: location,
            state: state,
            architecture: architecture,
            trace: trace,
        }
    }

    /// Step the underlying `State` forward over this `Driver`'s `il::Program`.
    pub fn step(mut self) -> Result<Vec<Driver>> {
        // Go ahead and set the trace location
        let index = {
            let location = self.location.apply(&self.program()).unwrap();

            let index: Option<il::Expression> =
                if let Some(operation) = location.instruction().map(|i| i.operation()) {
                    match operation {
                        il::Operation::Load { index, .. } | il::Operation::Store { index, .. } => {
                            Some(index.clone())
                        }
                        il::Operation::Assign { .. }
                        | il::Operation::Branch { .. }
                        | il::Operation::Intrinsic { .. }
                        | il::Operation::Nop { .. } => None,
                    }
                } else {
                    None
                };

            index
        };

        let address = match index {
            Some(index) => {
                let address = self
                    .state
                    .eval_and_concretize(&index)?
                    .ok_or("Failed to concretize address while running trace")?;
                let address = address
                    .value_u64()
                    .ok_or("value_u64 failed on address for trace")?;
                Some(address)
            }
            None => None,
        };

        let program_location = self.location.clone();

        self.trace.push(program_location, address);

        let location = self.location.apply(&self.program).unwrap();

        let mut drivers = Vec::new();
        match *location.function_location() {
            il::RefFunctionLocation::Instruction(_, instruction) => {
                for successor in self.state.execute(instruction.operation())? {
                    match successor.type_().clone() {
                        SuccessorType::FallThrough => {
                            // we are going to gather successor locations first, because if only
                            // one location is a valid successor, we can avoid cloning state.
                            let mut locations = Vec::new();
                            for location in location.forward()? {
                                if let Some(edge) = location.function_location().edge() {
                                    if edge.condition().is_some() {
                                        if successor
                                            .state()
                                            .symbolize_and_assert(edge.condition().unwrap())?
                                        {
                                            locations.push(location.clone());
                                        }
                                    } else {
                                        locations.push(location.clone());
                                    }
                                } else {
                                    locations.push(location.clone());
                                }
                            }

                            if locations.len() == 1 {
                                drivers.push(Driver::new_full(
                                    self.program.clone(),
                                    locations[0].clone().into(),
                                    successor.into(),
                                    self.architecture.clone(),
                                    self.trace.clone(),
                                ));
                            } else {
                                // every location should be an edge
                                for location in locations {
                                    let edge = location.function_location().edge().unwrap();
                                    let mut state = successor.state().clone();
                                    let constraint =
                                        state.symbolize_expression(edge.condition().unwrap())?;
                                    // println!("Satisfied conditional edge {} {}",
                                    //     edge.condition().unwrap(), constraint);
                                    if !constraint.all_constants() {
                                        state.add_path_constraint(&constraint)?;
                                    }
                                    drivers.push(Driver::new_full(
                                        self.program.clone(),
                                        location.clone().into(),
                                        state,
                                        self.architecture.clone(),
                                        self.trace.clone(),
                                    ));
                                }
                            }
                        }
                        SuccessorType::Branch(address) => {
                            match il::RefProgramLocation::from_address(&self.program, address) {
                                Some(location) => drivers.push(Driver::new_full(
                                    self.program.clone(),
                                    location.into(),
                                    successor.into(),
                                    self.architecture.clone(),
                                    self.trace.clone(),
                                )),
                                None => {
                                    let state: State = successor.into();
                                    let state_translator = StateTranslator::new(state);
                                    let function = self
                                        .architecture
                                        .clone()
                                        .translator()
                                        .translate_function(&state_translator, address)
                                        .expect(&format!(
                                            "Failed to lift function at 0x{:x}",
                                            address
                                        ));
                                    let mut program = self.program.clone();
                                    program.add_function(function);
                                    let location =
                                        il::RefProgramLocation::from_address(&program, address)
                                            .expect(&format!(
                                                "Unable to get program location for address 0x{:x}",
                                                address
                                            ));
                                    drivers.push(Driver::new_full(
                                        program.clone(),
                                        location.into(),
                                        state_translator.into(),
                                        self.architecture.clone(),
                                        self.trace.clone(),
                                    ));
                                }
                            }
                        }
                        SuccessorType::Raise(ref expression) => {
                            bail!(format!("Raise is unimplemented, {}", expression));
                        }
                    }
                }
            }
            il::RefFunctionLocation::Edge(_) => {
                let locations = location.forward()?;
                drivers.push(Driver::new_full(
                    self.program.clone(),
                    locations[0].clone().into(),
                    self.state,
                    self.architecture,
                    self.trace,
                ));
            }
            il::RefFunctionLocation::EmptyBlock(_) => {
                let mut locations = Vec::new();
                for location in location.forward()? {
                    if let Some(edge) = location.function_location().edge() {
                        if edge.condition().is_some() {
                            if self.state.symbolize_and_assert(edge.condition().unwrap())? {
                                locations.push(location.clone());
                            }
                        } else {
                            locations.push(location.clone());
                        }
                    } else {
                        locations.push(location.clone());
                    }
                }

                if locations.len() == 1 {
                    drivers.push(Driver::new_full(
                        self.program.clone(),
                        locations[0].clone().into(),
                        self.state,
                        self.architecture.clone(),
                        self.trace,
                    ));
                } else {
                    for location in locations {
                        if let il::RefFunctionLocation::Edge(edge) = *location.function_location() {
                            if self
                                .state
                                .symbolize_and_eval(&edge.condition().clone().unwrap())?
                                .map(|constant| constant.is_one())
                                .unwrap_or(false)
                            {
                                drivers.push(Driver::new_full(
                                    self.program.clone(),
                                    location.clone().into(),
                                    self.state.clone(),
                                    self.architecture.clone(),
                                    self.trace.clone(),
                                ));
                            }
                        }
                    }
                }
            }
        }
        Ok(drivers)
    }

    /// Retrieve the Falcon IL program associated with this driver.
    pub fn program(&self) -> &il::Program {
        &self.program
    }

    /// Set the Falcon IL program associated with this driver.
    pub fn set_program(&mut self, program: il::Program, program_location: il::ProgramLocation) {
        self.program = program;
        self.location = program_location;
    }

    /// Retrieve the RefProgramLocation for this Driver
    pub fn ref_program_location(&self) -> il::RefProgramLocation {
        self.location.apply(&self.program).unwrap()
    }

    /// Retrieve the `il::ProgramLocation` associated with this driver.
    pub fn location(&self) -> &il::ProgramLocation {
        &self.location
    }

    /// Jump the driver to another address
    pub fn set_location(&mut self, location: il::ProgramLocation) {
        self.location = location;
    }

    /// Retrieve the address of the instruction this driver is currently on
    pub fn address(&self) -> Option<u64> {
        self.location
            .apply(&self.program)
            .ok()
            .and_then(|rpl| rpl.address())
    }

    /// Retrieve the instruction for this driver, if this driver is currently
    /// execution an instruction
    pub fn instruction(&self) -> Option<il::Instruction> {
        self.location
            .apply(&self.program)
            .ok()
            .and_then(|rpl| rpl.instruction().cloned())
    }

    /// Retrieve the `State` associated with this driver.
    pub fn state(&self) -> &State {
        &self.state
    }

    /// Retrieve a mutable reference to the `State`.
    pub fn state_mut(&mut self) -> &mut State {
        &mut self.state
    }

    /// Get a trace of instructions executed by this driver
    pub fn trace(&self) -> &Trace {
        &self.trace
    }

    /// Merge two drivers together, if they are at the same program location
    pub fn merge(&self, other: &Driver) -> Result<Option<Driver>> {
        if self.location == other.location {
            Ok(Some(Driver::new(
                self.program.clone(),
                self.location.clone(),
                self.state.clone().merge(&other.state)?,
                self.architecture.clone(),
            )))
        } else {
            Ok(None)
        }
    }
}

impl Into<State> for Driver {
    fn into(self) -> State {
        self.state
    }
}
