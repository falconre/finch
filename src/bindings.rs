use executor;
use falcon_z3;
use gluon;
use gluon::vm::api::{Userdata, VmType};
use gluon::vm::thread::{Traverseable};
use osprey;
use platform;
use platform::Platform;
use std::sync::Arc;


#[macro_use]
macro_rules! finch_type_wrapper {
    ($p: path, $n: ident) => {
        #[derive(Clone, Debug)] pub struct $n { pub x: $p }
        impl VmType for $n { type Type = $n; }
        impl Traverseable for $n {}
        impl Userdata for $n {}
    }
}

#[macro_use]
macro_rules! finch_type_wrapper_generic {
    ($g: ident, $type: path, $p: path, $n: ident) => {
        #[derive(Clone, Debug)] pub struct $n<$g: $type> { pub x: $p }
        impl<$g: $type + 'static> VmType for $n<$g> { type Type = $n<$g>; }
        impl<$g: $type> Traverseable for $n<$g> {}
        impl<$g: $type + 'static> Userdata for $n<$g> {}
    }
}


fn solve<'vm>(
    constraints: &osprey::il::IlExpression,
    value: &osprey::il::IlExpression
) -> Option<osprey::il::IlConstant> {
    falcon_z3::il::solve(&[constraints.x.clone()], &value.x)
        .ok()?
        .map(|c| osprey::il::IlConstant { x: c })
}


finch_type_wrapper_generic!(P, Platform, executor::State<P>, ExecutorState);

// #[derive(Clone, Debug)] pub struct ExecutorState<P: Platform> { pub x: executor::State<P> }
// impl<P: Platform> VmType for ExecutorState<P> { type Type = executor::State<P>; }
// impl<P: Platform> Traverseable for ExecutorState<P> {}
// impl<P: Platform> Userdata for ExecutorState<P> {}


fn state_new<P: Platform>(executor_memory: &ExecutorMemory) -> ExecutorState<P> {
    ExecutorState { x: executor::State::new(executor_memory.x.clone(), None) }
}

fn state_memory<P: Platform>(state: &ExecutorState<P>) -> ExecutorMemory {
    ExecutorMemory { x: state.x.memory().clone() }
}

fn state_set_scalar<P: Platform>(
    state: &ExecutorState<P>,
    name: String,
    value: &osprey::il::IlExpression
) -> ExecutorState<P> {
    let mut state: ExecutorState<P> = ExecutorState { x: state.x.clone() };
    state.x.set_scalar(name, &value.x).unwrap();
    state
}

fn state_scalar<P: Platform>(state: &ExecutorState<P>, name: String)
    -> Option<osprey::il::IlExpression> {

    state.x.scalar(&name).map(|expr|
        osprey::il::IlExpression{ x: expr.clone() } )
}

fn state_add_path_constraint<P: Platform>(
    state: &ExecutorState<P>,
    constraint: &osprey::il::IlExpression
) -> ExecutorState<P> {
    let mut state = state.clone();
    state.x.add_path_constraint(&constraint.x).unwrap();
    *state
}

fn state_symbolize_expression<P: Platform>(
    state: &ExecutorState<P>,
    expression: &osprey::il::IlExpression
) -> osprey::il::IlExpression {
    osprey::il::IlExpression {
        x: state.x.symbolize_expression(&expression.x).unwrap()
    }
}

fn state_symbolize_and_eval<P: Platform>(
    state: &ExecutorState<P>,
    expression: &osprey::il::IlExpression
) -> Option<osprey::il::IlConstant> {
    state.x.symbolize_and_eval(&expression.x).unwrap().map(|constant|
        osprey::il::IlConstant{ x: constant })
}

fn state_execute<P: Platform>(
    state: &ExecutorState<P>,
    operation: &osprey::il::IlOperation
) -> Vec<ExecutorSuccessor<P>> {
    state.x.clone().execute(&operation.x)
        .unwrap()
        .into_iter()
        .map(|successor| ExecutorSuccessor { x: successor })
        .collect::<Vec<ExecutorSuccessor<P>>>()
}

fn state_debug<P: Platform>(state: &ExecutorState<P>) {
    state.x.debug();
}



finch_type_wrapper!(executor::Memory, ExecutorMemory);

fn executor_memory_new(endian: &osprey::architecture::ArchitectureEndian)
    -> ExecutorMemory {

    ExecutorMemory { x: executor::Memory::new(endian.x.clone()) }
}

fn executor_memory_new_with_backing(
    endian: &osprey::architecture::ArchitectureEndian,
    backing: &osprey::memory::BackingMemory
) -> ExecutorMemory {
    ExecutorMemory { x: executor::Memory::new_with_backing(
        endian.x.clone(), Arc::new(backing.x.clone())) }
}

fn executor_memory_load(
    executor_memory: &ExecutorMemory,
    address: u64,
    bits: usize
) -> Option<osprey::il::IlExpression> {
    executor_memory.x.load(address, bits).unwrap().map(|expression|
        osprey::il::IlExpression { x: expression })
}

fn executor_memory_store(
    executor_memory: &ExecutorMemory,
    address: u64,
    value: &osprey::il::IlExpression
) -> ExecutorMemory {
    let mut executor_memory = executor_memory.clone();
    executor_memory.x.store(address, &value.x).unwrap();
    executor_memory
}



finch_type_wrapper_generic!(P, Platform, executor::Driver<P>, ExecutorDriver);

fn driver_new<P: Platform>(
    program: &osprey::il::IlProgram,
    location: &osprey::il::IlProgramLocation,
    state: &ExecutorState<P>,
    architecture: &osprey::architecture::ArchitectureArchitecture
) -> ExecutorDriver<P> {
    let program = Arc::new(program.x.clone());
    let location = location.x.clone();
    let state = state.x.clone();
    let architecture = architecture.x.clone();
    ExecutorDriver {
        x: executor::Driver::new(program, location, state, architecture)
    }
}

fn driver_step<P: Platform>(driver: &ExecutorDriver<P>) -> Vec<ExecutorDriver<P>> {
    driver.x
        .clone()
        .step()
        .unwrap()
        .into_iter()
        .map(|driver| ExecutorDriver { x: driver })
        .collect::<Vec<ExecutorDriver<P>>>()
}

fn driver_program<P: Platform>(driver: &ExecutorDriver<P>) -> osprey::il::IlProgram {
    osprey::il::IlProgram { x: driver.x.program().clone() }
}

fn driver_location<P: Platform>(driver: &ExecutorDriver<P>) -> osprey::il::IlProgramLocation {
    osprey::il::IlProgramLocation { x: driver.x.location().clone() }
}

fn driver_address<P: Platform>(driver: &ExecutorDriver<P>) -> Option<u64> {
    driver.x.address()
}

fn driver_state<P: Platform>(driver: &ExecutorDriver<P>) -> ExecutorState<P> {
    ExecutorState { x: driver.x.state().clone() }
}

fn driver_store<P: Platform>(
    driver: &ExecutorDriver<P>,
    address: u64,
    value: &osprey::il::IlExpression
) -> ExecutorDriver<P> {
    let mut driver = ExecutorDriver { x: driver.x.clone() };
    driver.x.state_mut().memory_mut().store(address, &value.x).unwrap();
    driver
}

fn driver_load<P: Platform>(
    driver: &ExecutorDriver<P>,
    address: u64,
    bits: usize
) -> Option<osprey::il::IlExpression> {
    driver.x
        .state()
        .memory()
        .load(address, bits)
        .unwrap()
        .map(|expression| osprey::il::IlExpression { x: expression })
}

fn driver_set_scalar<P: Platform>(
    driver: &ExecutorDriver<P>,
    name: String,
    value: &osprey::il::IlExpression
) -> ExecutorDriver<P> {
    let mut driver = ExecutorDriver { x: driver.x.clone() };
    driver.x.state_mut().set_scalar(name, &value.x).unwrap();
    driver
}

fn driver_set_location<P: Platform>(
    driver: &ExecutorDriver<P>,
    location: &osprey::il::IlProgramLocation
) -> ExecutorDriver<P> {
    let mut driver = ExecutorDriver { x: driver.x.clone() };
    driver.x.set_location(location.x.clone());
    driver
}

fn driver_merge<P: Platform>(driver: &ExecutorDriver<P>, other: &ExecutorDriver<P>)
    -> Option<ExecutorDriver<P>> {

    driver.x.merge(&other.x).unwrap().map(|driver| ExecutorDriver { x: driver })
}

fn driver_add_path_constraint<P: Platform>(
    driver: &ExecutorDriver<P>,
    constraint: &osprey::il::IlExpression
) -> ExecutorDriver<P> {
    let mut driver = ExecutorDriver { x: driver.x.clone() };
    driver.x.state_mut().add_path_constraint(&constraint.x).unwrap();
    driver
}


finch_type_wrapper_generic!(P, Platform, executor::Successor<P>, ExecutorSuccessor);


fn platform_mips_standard_load<P: Platform>(filename: String) -> ExecutorDriver<P> {
    ExecutorDriver {
        x: platform::mips_linux::standard_load(&filename).unwrap()
    }
}


fn platform_mips_linux_initialize<P: Platform>(
    state: &ExecutorState<P>,
    elf_linker: &osprey::loader::LoaderElfLinker)
 -> ExecutorState<P> {

    let state = state.x.clone();
    let state = platform::mips_linux::initialize(state, &elf_linker.x).unwrap();
    ExecutorState { x: state }
}


fn drive_and_merge<P: Platform>(
    driver: &ExecutorDriver<P>,
    target_address: u64,
    max_steps: usize
) -> Option<ExecutorDriver<P>> {
    use driver;
    let drivers = driver::drive_to_address(driver.x.clone(),
                                           target_address,
                                           max_steps).unwrap();
    if drivers.is_empty() {
        None
    }
    else {
        Some(ExecutorDriver { x: driver::merge_drivers(drivers).unwrap() })
    }
}


pub fn bindings(vm: gluon::RootedThread) -> gluon::RootedThread {

    fn finch_prim_loader(vm: &gluon::Thread)
        -> gluon::vm::Result<gluon::vm::ExternModule> {

        vm.register_type::<ExecutorDriver<P=platform::linux::mips::Mips>>("ExecutorDriver", &[]).unwrap();
        vm.register_type::<ExecutorMemory>("ExecutorMemory", &[]).unwrap();
        vm.register_type::<ExecutorState>("ExecutorState", &[]).unwrap();
        vm.register_type::<ExecutorSuccessor>("ExecutorSuccessor", &[]).unwrap();
        gluon::vm::ExternModule::new(vm, record! {
            drive_and_merge => primitive!(3 drive_and_merge),

            driver_add_path_constraint => primitive!(2 driver_add_path_constraint),
            driver_address => primitive!(1 driver_address),
            driver_load => primitive!(3 driver_load),
            driver_location => primitive!(1 driver_location),
            driver_merge => primitive!(2 driver_merge),
            driver_new => primitive!(4 driver_new),
            driver_program => primitive!(1 driver_program),
            driver_set_location => primitive!(2 driver_set_location),
            driver_set_scalar => primitive!(3 driver_set_scalar),
            driver_state => primitive!(1 driver_state),
            driver_step => primitive!(1 driver_step),
            driver_store => primitive!(3 driver_store),
            platform_mips_linux_initialize =>
                primitive!(2 platform_mips_linux_initialize),
            platform_mips_standard_load =>
                primitive!(1 platform_mips_standard_load),
            solve => primitive!(2 solve),
            state_add_path_constraint =>
                primitive!(2 state_add_path_constraint),
            state_debug => primitive!(1 state_debug),
            state_execute => primitive!(2 state_execute),
            state_memory => primitive!(1 state_memory),
            state_new => primitive!(1 state_new),
            state_scalar => primitive!(2 state_scalar),
            state_set_scalar => primitive!(3 state_set_scalar),
            state_symbolize_and_eval => primitive!(2 state_symbolize_and_eval),
            state_symbolize_expression =>
                primitive!(2 state_symbolize_expression),
            memory_load => primitive!(3 executor_memory_load),
            memory_new => primitive!(1 executor_memory_new),
            memory_new_with_backing =>
                primitive!(2 executor_memory_new_with_backing),
            memory_store => primitive!(3 executor_memory_store)
        })
    }
    
    gluon::import::add_extern_module(&vm, "finch_prim", finch_prim_loader);

    vm
}