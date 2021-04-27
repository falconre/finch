//! A basic model of the Linux Operating System for MIPS.

use crate::error::*;
use crate::executor::{Driver, Memory, State, Successor, SuccessorType};
use crate::platform::linux::{Constants, Environment, EnvironmentString, Linux};
use crate::platform::Platform;
use byteorder::{BigEndian, WriteBytesExt};
use falcon::loader::{ElfLinker, ElfLinkerBuilder, Loader};
use falcon::{il, RC};
use log::trace;
use std::any::Any;
use std::path::PathBuf;

// const ARGV_STRING_LEN: u64 = 256;
const TLS_ADDRESS: u64 = 0xc000_0000;
const STACK_BASE: u64 = 0xbff0_0000;

const DEFAULT_PID: u64 = 512;

// System call information
const SYSCALL_ACCESS: u64 = 0xFC1;
const SYSCALL_BRK: u64 = 0xFCD;
const SYSCALL_CLOSE: u64 = 0xFA6;
const SYSCALL_EXIT_GROUP: u64 = 0x1096;
const SYSCALL_FSTAT64: u64 = 0x1077;
const SYSCALL_FUTEX: u64 = 0x108E;
const SYSCALL_GETPID: u64 = 0xFB4;
const SYSCALL_GETRLIMIT: u64 = 0xFEC;
const SYSCALL_LSEEK: u64 = 0xFB3;
const SYSCALL_MMAP: u64 = 0xFFA;
const SYSCALL_MPROTECT: u64 = 0x101D;
const SYSCALL_OPEN: u64 = 0xFA5;
const SYSCALL_READ: u64 = 0xFA3;
const SYSCALL_RT_SIGACTION: u64 = 0x1062;
const SYSCALL_RT_SIGPROCMASK: u64 = 0x1063;
const SYSCALL_SET_ROBUST_LIST: u64 = 0x10D5;
const SYSCALL_SET_THREAD_AREA: u64 = 0x10BB;
const SYSCALL_SET_TID_ADDRESS: u64 = 0x109C;
const SYSCALL_STAT64: u64 = 0x1075;
const SYSCALL_UNAME: u64 = 0x101A;
const SYSCALL_WRITE: u64 = 0xFA4;
const SYSCALL_WRITEV: u64 = 0x1032;

const MIPS_LINUX_CONSTANTS: Constants = Constants {
    PAGE_SIZE: 0x1000,

    MAP_SHARED: 0x1,
    MAP_PRIVATE: 0x2,
    MAP_FIXED: 0x10,
    MAP_LOCAL: 0x80,
    MAP_ANONYMOUS: 0x800,
    O_CREAT: 0x100,
    PROT_READ: 0x1,
    PROT_WRITE: 0x2,
    PROT_EXEC: 0x4,
    SEEK_SET: 0x0,
    SEEK_CUR: 0x1,
    SEEK_END: 0x2,
};

/// A `Platform` for Linux on MIPS.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Mips {
    linux: Linux,
    fake_ino: u64,
}

impl Mips {
    /// Create a standard driver, set up with a MIPS Platform, and everything
    /// initialized.
    pub fn standard_load(filename: &str, base_path: Option<PathBuf>) -> Result<Driver> {
        let mut elf_linker = ElfLinkerBuilder::new(filename.into())
            .do_relocations(false)
            .just_interpreter(true);
        if let Some(ref base_path) = base_path {
            let paths = vec![base_path.to_path_buf()];
            elf_linker = elf_linker.ld_paths(Some(paths));
        }

        let elf_linker = elf_linker.link()?;

        let architecture = elf_linker.architecture();
        let endian = architecture.endian();

        // To figure out where we start, we need to check and see if this ELF
        // has an interpreter entry. If it does, we use that as the address for
        // program entry. Otherwise, we start at the designated binary's entry
        // point.
        let entry = elf_linker
            .get_interpreter()?
            .map(|elf| elf.base_address() + elf.elf().header.e_entry)
            .unwrap_or(elf_linker.program_entry());

        let mut program = il::Program::new();
        let function = elf_linker.function(entry)?;
        program.add_function(function);

        let program_location = {
            let program_location = il::RefProgramLocation::from_address(&program, entry)
                .ok_or(format!("Failed  to get program location for 0x{:x}", entry))?;
            let program_location: il::ProgramLocation = program_location.into();
            program_location
        };

        let mips_linux = Mips {
            linux: Linux::new(&elf_linker, base_path, &MIPS_LINUX_CONSTANTS)?,
            fake_ino: 0,
        };
        let backing = elf_linker.memory()?;
        let memory = Memory::new_with_backing(endian, RC::new(backing));
        let state = State::new(memory, Box::new(mips_linux));

        let state = Mips::initialize(state, &elf_linker)?;

        Ok(Driver::new(
            program,
            program_location,
            state,
            RC::new(architecture.box_clone()),
        ))
    }

    fn initialize(mut state: State, elf_linker: &ElfLinker) -> Result<State> {
        let environment = Environment::new()
            .command_line_argument(EnvironmentString::new_concrete("application_filename"))
            // .environment_variable(
            //     EnvironmentString::new_concrete("LD_DEBUG=bindings"))
            .environment_variable(EnvironmentString::new_concrete("LD_BIND_NOW=1"))
            .environment_variable(EnvironmentString::new_concrete(
                "LD_LIBRARY_PATH=/usr/lib:/lib",
            ))
            .environment_variable(EnvironmentString::new_concrete("LOCALDOMAIN=localdomain"))
            .environment_variable(EnvironmentString::new_environment_variable(
                "SCRIPT_NAME",
                128,
            ));

        environment.initialize_process32(&mut state.memory_mut(), STACK_BASE, elf_linker)?;

        for i in 0..0x8000 {
            state
                .memory_mut()
                .store(TLS_ADDRESS + i, &il::expr_const(0, 8))?;
        }

        // Writing to create some stack space, which is good for qemu
        for i in 1..0x10000 {
            state
                .memory_mut()
                .store(STACK_BASE - i, &il::expr_const(0, 8))?;
        }

        state.set_scalar("$ra", &il::expr_const(0, 32))?;
        state.set_scalar("$v0", &il::expr_const(0, 32))?;
        state.set_scalar("$sp", &il::expr_const(STACK_BASE, 32))?;
        state.set_scalar("$s0", &il::expr_const(0, 32))?;
        state.set_scalar("$s1", &il::expr_const(0, 32))?;
        state.set_scalar("$s2", &il::expr_const(0, 32))?;
        state.set_scalar("$s3", &il::expr_const(0, 32))?;
        state.set_scalar("$s4", &il::expr_const(0, 32))?;
        state.set_scalar("$s5", &il::expr_const(0, 32))?;
        state.set_scalar("$s6", &il::expr_const(0, 32))?;
        state.set_scalar("$s7", &il::expr_const(0, 32))?;
        state.set_scalar("$fp", &il::expr_const(0, 32))?;

        Ok(state)
    }

    /// Handle an intrinsic instruction.
    pub fn intrinsic(mut state: State, intrinsic: &il::Intrinsic) -> Result<Vec<Successor>> {
        if intrinsic.mnemonic() == "rdhwr" {
            if intrinsic.arguments()[1].get_scalar().unwrap().name() == "$sp" {
                state.set_scalar(
                    intrinsic.arguments()[0].get_scalar().unwrap().name(),
                    &il::expr_const(TLS_ADDRESS + 0x8000, 32),
                )?;
                Ok(vec![Successor::new(state, SuccessorType::FallThrough)])
            } else {
                bail!("Expected first argument for rdhwr to be $sp");
            }
        } else if intrinsic.mnemonic() == "syscall" {
            Mips::syscall(state)
        } else {
            Err(ErrorKind::UnhandledIntrinsic(format!("{}", intrinsic)).into())
        }
    }

    // create a fake stat64 buf
    fn fake_stat64(&mut self, size: usize) -> Result<Vec<u8>> {
        const S_IFREG: u32 = 0o0100000;

        let mut buf = Vec::new();
        buf.write_u32::<BigEndian>(0x4f)?; // 0x0  4 st_dev
        buf.write_u32::<BigEndian>(0)?;
        buf.write_u32::<BigEndian>(0)?;
        buf.write_u32::<BigEndian>(0)?;
        buf.write_u64::<BigEndian>(self.fake_ino)?; // 0x10 8 st_ino
        buf.write_u32::<BigEndian>(0o100755 | S_IFREG)?; // 0x18 4 st_mode
        buf.write_u32::<BigEndian>(1)?; // 0x1c 4 st_nlink
        buf.write_u32::<BigEndian>(0)?; // 0x20 4 st_uid
        buf.write_u32::<BigEndian>(0)?; // 0x24 4 st_gid
        buf.write_u32::<BigEndian>(0)?; // 0x28 4 st_rdev
        buf.write_u32::<BigEndian>(0)?; // 0x2c
        buf.write_u32::<BigEndian>(0)?; // 0x30
        buf.write_u32::<BigEndian>(0)?; // 0x34
        buf.write_u64::<BigEndian>(size as u64)?; // 0x38 8 st_size
        buf.write_u32::<BigEndian>(100000)?; // 0x40 4 st_atime
        buf.write_u32::<BigEndian>(1)?; // 0x44 4 st_atime_nsec
        buf.write_u32::<BigEndian>(100000)?; // 0x48 4 st_mtime
        buf.write_u32::<BigEndian>(1)?; // 0x4c 4 st_mtime_nsec
        buf.write_u32::<BigEndian>(100000)?; // 0x50 4 st_ctime
        buf.write_u32::<BigEndian>(1)?; // 0x54 4 st_ctime_nsec
        buf.write_u32::<BigEndian>(512)?; // 0x58 4 st_blksize
        buf.write_u32::<BigEndian>(1)?;
        buf.write_u64::<BigEndian>((size / 512 + if size & (512 - 1) > 0 { 1 } else { 0 }) as u64)?; // 0x60 8 st_blocks

        self.fake_ino += 1;

        Ok(buf)
    }

    fn get_register(state: &mut State, name: &str) -> Result<u64> {
        Ok(state
            .eval_and_concretize(&il::expr_scalar(name, 32))?
            .ok_or(format!("Failed to get {}", name))?
            .value_u64()
            .ok_or(format!("Failed to get value for {}", name))?)
    }

    fn get_stack_arg(state: &mut State, offset: i64) -> Result<u64> {
        let sp = Mips::get_register(state, "$sp")? as i64;
        let address = (sp + offset) as u64;
        let value = state.memory().load(address, 32)?.ok_or(format!(
            "Failed to get stack arg at address 0x{:x}",
            address
        ))?;
        Ok(state
            .eval_and_concretize(&value)?
            .ok_or(format!("Failed to get stack argument at offset {}", offset))?
            .value_u64()
            .ok_or(format!("Failed to get stack argument at offset {}", offset))?)
    }

    /// Handle a system call.
    pub fn syscall(mut state: State) -> Result<Vec<Successor>> {
        let syscall_num = state
            .eval_and_concretize(&il::expr_scalar("$v0", 32))?
            .ok_or("Failed to get syscall num in $v0")?;

        fn platform_mut(state: &mut State) -> &mut Mips {
            state.platform.as_mut().any_mut().downcast_mut().unwrap()
        }

        match syscall_num.value_u64().unwrap() {
            SYSCALL_ACCESS => {
                let a0 = state
                    .eval_and_concretize(&il::expr_scalar("$a0", 32))?
                    .ok_or("Failed to get a0 for access")?
                    .value_u64()
                    .ok_or("Could not get value for a0")?;
                let a1 = state
                    .eval_and_concretize(&il::expr_scalar("$a1", 32))?
                    .ok_or("Failed to get a0 for access")?
                    .value_u64()
                    .ok_or("Could not get value for a1")?;

                let filename = match state.get_string(a0)? {
                    Some(filename) => filename,
                    None => {
                        bail!("Could not get filename for access");
                    }
                };

                let result = platform_mut(&mut state).linux.access(&filename, a1);

                trace!("access for \"{}\" was {}", filename, result as i64);

                state.set_scalar("$v0", &il::expr_const(result, 32))?;
                if result == 0 {
                    state.set_scalar("$a3", &il::expr_const(0, 32))?;
                } else {
                    state.set_scalar("$a3", &il::expr_const(1, 32))?;
                }

                Ok(vec![Successor::new(state, SuccessorType::FallThrough)])
            }
            SYSCALL_BRK => {
                let a0 = state
                    .eval_and_concretize(&il::expr_scalar("$a0", 32))?
                    .ok_or("Failed to get $a0 for brk systemcall")?;

                let a0 = (state.platform.any_mut().downcast_mut().unwrap() as &mut Mips)
                    .linux
                    .brk(a0.value_u64().unwrap(), &mut state.memory)?;

                state.set_scalar("$v0", &il::expr_const(a0, 32))?;
                state.set_scalar("$a3", &il::expr_const(0, 32))?;
                Ok(vec![Successor::new(state, SuccessorType::FallThrough)])
            }
            SYSCALL_CLOSE => {
                let a0 = Mips::get_register(&mut state, "$a0")?;
                if platform_mut(&mut state)
                    .linux
                    .file_system_mut()
                    .close_fd(a0 as usize)
                {
                    trace!("close {} = 0", a0);
                    state.set_scalar("$v0", &il::expr_const(0, 32))?;
                    state.set_scalar("$a3", &il::expr_const(0, 32))?;
                } else {
                    trace!("close {} = -1", a0);
                    state.set_scalar("$v0", &il::expr_const(-1i64 as u64, 32))?;
                    state.set_scalar("$a3", &il::expr_const(1, 32))?;
                }
                Ok(vec![Successor::new(state, SuccessorType::FallThrough)])
            }
            SYSCALL_EXIT_GROUP => {
                let a0 = state
                    .eval_and_concretize(&il::expr_scalar("$a0", 32))?
                    .ok_or("Failed to get $a0 for exit_group")?;
                trace!("exit_group: {}", a0);
                Ok(Vec::new())
            }
            SYSCALL_FSTAT64 => {
                let a0 = Mips::get_register(&mut state, "$a0")?;
                let a1 = Mips::get_register(&mut state, "$a1")?;

                match platform_mut(&mut state)
                    .linux
                    .file_system()
                    .size_fd(a0 as usize)
                {
                    Some(size) => {
                        let buf = platform_mut(&mut state).fake_stat64(size)?;
                        for i in 0..buf.len() {
                            state
                                .memory_mut()
                                .store(a1 + i as u64, &il::expr_const(buf[i] as u64, 8))?;
                        }
                        trace!("fstat64 for {} = 0, {}", a0, size);
                        state.set_scalar("$v0", &il::expr_const(0, 32))?;
                        state.set_scalar("$a3", &il::expr_const(0, 32))?;
                    }
                    None => {
                        trace!("fstat64 for {} = -1", a0);
                        state.set_scalar("$v0", &il::expr_const(-1i64 as u64, 32))?;
                        state.set_scalar("$a3", &il::expr_const(1, 32))?;
                    }
                }

                Ok(vec![Successor::new(state, SuccessorType::FallThrough)])
            }
            SYSCALL_FUTEX => {
                trace!("futex");
                state.set_scalar("$v0", &il::expr_const(DEFAULT_PID, 32))?;
                state.set_scalar("$a3", &il::expr_const(1, 32))?;
                Ok(vec![Successor::new(state, SuccessorType::FallThrough)])
            }
            SYSCALL_GETPID => {
                trace!("getpid");
                state.set_scalar("$v0", &il::expr_const(DEFAULT_PID, 32))?;
                state.set_scalar("$a3", &il::expr_const(0, 32))?;
                Ok(vec![Successor::new(state, SuccessorType::FallThrough)])
            }
            SYSCALL_GETRLIMIT => {
                let a0 = Mips::get_register(&mut state, "$a0")?;
                let a1 = Mips::get_register(&mut state, "$a1")?;

                // https://github.com/angr/angr/blob/master/angr/procedures/linux_kernel/getrlimit.py
                if a0 == 3 {
                    // This is RLIMIT_STACK according to angr
                    state
                        .memory_mut()
                        .store(a1, &il::expr_const(1024 * 8 * 8, 32))?;
                    state
                        .memory_mut()
                        .store(a1 + 4, &il::expr_const(1024 * 8 * 16, 32))?;
                    trace!("getrlimit {}", a0);
                } else {
                    trace!("getrlimit skipping");
                }
                state.set_scalar("$v0", &il::expr_const(DEFAULT_PID, 32))?;
                state.set_scalar("$a3", &il::expr_const(0, 32))?;
                Ok(vec![Successor::new(state, SuccessorType::FallThrough)])
            }
            SYSCALL_LSEEK => {
                let a0 = Mips::get_register(&mut state, "$a0")?;
                let a1 = Mips::get_register(&mut state, "$a1")?;
                let a2 = Mips::get_register(&mut state, "$a2")?;

                let result = platform_mut(&mut state)
                    .linux
                    .lseek(a0, (a1 as i32) as isize, a2)?;

                state.set_scalar("$v0", &il::expr_const(result as u64, 32))?;
                if result as i64 >= 0 {
                    state.set_scalar("$a3", &il::expr_const(0, 32))?;
                } else {
                    state.set_scalar("$a3", &il::expr_const(1, 32))?;
                }
                trace!("lseek 0x{:x} 0x{:x} 0x{:x} is {}", a0, a1, a2, result);
                Ok(vec![Successor::new(state, SuccessorType::FallThrough)])
            }
            SYSCALL_MMAP => {
                let a0 = Mips::get_register(&mut state, "$a0")?;
                let a1 = Mips::get_register(&mut state, "$a1")?;
                let a2 = Mips::get_register(&mut state, "$a2")?;
                let a3 = Mips::get_register(&mut state, "$a3")?;
                let stack0 = Mips::get_stack_arg(&mut state, 0x10)?;
                let stack1 = Mips::get_stack_arg(&mut state, 0x14)?;

                let address = (state.platform.any_mut().downcast_mut().unwrap() as &mut Mips)
                    .linux
                    .mmap(&mut state.memory, a0, a1, a2, a3, stack0, stack1)?;

                state.set_scalar("$v0", &il::expr_const(address as u64, 32))?;
                state.set_scalar("$a3", &il::expr_const(0, 32))?;

                trace!(
                    "mmap(0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}, 0x{:x} = 0x{:x}",
                    a0,
                    a1,
                    a2,
                    a3,
                    stack0,
                    stack1,
                    address
                );

                Ok(vec![Successor::new(state, SuccessorType::FallThrough)])
            }
            SYSCALL_MPROTECT => {
                let a0 = Mips::get_register(&mut state, "$a0")?;
                let a1 = Mips::get_register(&mut state, "$a1")?;
                let a2 = Mips::get_register(&mut state, "$a2")?;

                let result = (state.platform.any_mut().downcast_mut().unwrap() as &mut Mips)
                    .linux
                    .mprotect(&mut state.memory, a0, a1, a2)?;

                state.set_scalar("$v0", &il::expr_const(result as u64, 32))?;

                if result == 0 {
                    state.set_scalar("$a3", &il::expr_const(0, 32))?;
                } else {
                    state.set_scalar("$a3", &il::expr_const(1, 32))?;
                }

                trace!(
                    "mprotect(0x{:x}, 0x{:x}, 0x{:x}) = 0x{:x}",
                    a0,
                    a1,
                    a2,
                    result
                );

                Ok(vec![Successor::new(state, SuccessorType::FallThrough)])
            }
            SYSCALL_OPEN => {
                let a0 = Mips::get_register(&mut state, "$a0")?;
                let a1 = Mips::get_register(&mut state, "$a1")?;
                let a2 = Mips::get_register(&mut state, "$a2")?;

                let filename = match state.get_string(a0)? {
                    Some(filename) => filename,
                    None => {
                        bail!("Could not get filename for open");
                    }
                };

                let result = platform_mut(&mut state).linux.open(&filename, a1, a2)?;

                trace!("open for \"{}\" was {}", filename, result as i64);

                state.set_scalar("$v0", &il::expr_const(result, 32))?;
                if result as i64 >= 0 {
                    state.set_scalar("$a3", &il::expr_const(0, 32))?;
                } else {
                    state.set_scalar("$a3", &il::expr_const(1, 32))?;
                }
                state.set_scalar("$v0", &il::expr_const(3, 32))?;

                Ok(vec![Successor::new(state, SuccessorType::FallThrough)])
            }
            SYSCALL_READ => {
                let a0 = state
                    .eval_and_concretize(&il::expr_scalar("$a0", 32))?
                    .ok_or("Failed to get a0 for open")?
                    .value_u64()
                    .ok_or("Could not get value for a0")?;
                let a1 = state
                    .eval_and_concretize(&il::expr_scalar("$a1", 32))?
                    .ok_or("Failed to get a0 for open")?
                    .value_u64()
                    .ok_or("Could not get value for a1")?;
                let a2 = state
                    .eval_and_concretize(&il::expr_scalar("$a2", 32))?
                    .ok_or("Failed to get a2 for open")?
                    .value_u64()
                    .ok_or("Could not get value for a2")?;

                let result = platform_mut(&mut state).linux.read(a0, a2)?;

                if let Some(bytes) = result {
                    for (i, byte) in bytes.iter().enumerate() {
                        state.memory_mut().store(a1 + (i as u64), byte)?;
                    }
                    state.set_scalar("$v0", &il::expr_const(bytes.len() as u64, 32))?;
                    state.set_scalar("$a3", &il::expr_const(0, 32))?;
                } else {
                    state.set_scalar("$v0", &il::expr_const(-1i64 as u64, 32))?;
                    state.set_scalar("$a3", &il::expr_const(-1i64 as u64, 32))?;
                }

                trace!(
                    "read for {},0x{:x},0x{:x} was {}",
                    a0,
                    a1,
                    a2,
                    state.scalar("$v0").unwrap()
                );

                Ok(vec![Successor::new(state, SuccessorType::FallThrough)])
            }
            SYSCALL_RT_SIGACTION => {
                let _a0 = Mips::get_register(&mut state, "$a0")?;

                trace!("rt_sigaction skipping");

                state.set_scalar("$v0", &il::expr_const(0_u64, 32))?;
                state.set_scalar("$a3", &il::expr_const(0_u64, 32))?;

                Ok(vec![Successor::new(state, SuccessorType::FallThrough)])
            }
            SYSCALL_RT_SIGPROCMASK => {
                let _a0 = Mips::get_register(&mut state, "$a0")?;

                trace!("rt_sigprocmask skipping");

                state.set_scalar("$v0", &il::expr_const(0_u64, 32))?;
                state.set_scalar("$a3", &il::expr_const(0_u64, 32))?;

                Ok(vec![Successor::new(state, SuccessorType::FallThrough)])
            }
            SYSCALL_SET_ROBUST_LIST => {
                let _a0 = Mips::get_register(&mut state, "$a0")?;

                trace!("set_robust_list skipping");

                state.set_scalar("$v0", &il::expr_const(0_u64, 32))?;
                state.set_scalar("$a3", &il::expr_const(1_u64, 32))?;

                Ok(vec![Successor::new(state, SuccessorType::FallThrough)])
            }
            SYSCALL_SET_THREAD_AREA => {
                let _a0 = Mips::get_register(&mut state, "$a0")?;

                trace!("set_thread_area skipping");

                state.set_scalar("$v0", &il::expr_const(0_u64, 32))?;
                state.set_scalar("$a3", &il::expr_const(0_u64, 32))?;

                Ok(vec![Successor::new(state, SuccessorType::FallThrough)])
            }
            SYSCALL_SET_TID_ADDRESS => {
                let _a0 = Mips::get_register(&mut state, "$a0")?;

                trace!("set_tid_address skipping");

                state.set_scalar("$v0", &il::expr_const(0_u64, 32))?;
                state.set_scalar("$a3", &il::expr_const(0_u64, 32))?;

                Ok(vec![Successor::new(state, SuccessorType::FallThrough)])
            }
            SYSCALL_STAT64 => {
                let a0 = state
                    .eval_and_concretize(&il::expr_scalar("$a0", 32))?
                    .ok_or("Failed to get a0")?
                    .value_u64()
                    .ok_or("Could not get value for a0")?;
                // let a1 = state.eval_and_concretize(&il::expr_scalar("$a1", 32))?
                //     .ok_or("Failed to get a0")?
                //     .value_u64()
                //     .ok_or("Could not get value for a1")?;

                let path = match state.get_string(a0)? {
                    Some(path) => path,
                    None => {
                        bail!("Could not get path");
                    }
                };

                trace!("stat64 for {}, always returning -1", path);

                state.set_scalar("$v0", &il::expr_const(-1i64 as u64, 32))?;
                state.set_scalar("$a3", &il::expr_const(1, 32))?;

                Ok(vec![Successor::new(state, SuccessorType::FallThrough)])
            }
            SYSCALL_UNAME => {
                trace!("uname");
                // Just zero everything out
                let a0 = state
                    .eval_and_concretize(&il::expr_scalar("$a0", 32))?
                    .ok_or("Failed to get a0 for uname")?
                    .value_u64()
                    .ok_or("Could not get value for a0")?;

                for i in 0..(65 * 5) {
                    state.memory_mut().store(a0 + i, &il::expr_const(0, 8))?;
                }

                // This fakes a linux kernel 3 something
                state
                    .memory_mut()
                    .store(a0 + (65 * 2), &il::expr_const(0x33, 8))?;

                state.set_scalar("$v0", &il::expr_const(0, 32))?;
                state.set_scalar("$a3", &il::expr_const(0, 32))?;

                Ok(vec![Successor::new(state, SuccessorType::FallThrough)])
            }
            SYSCALL_WRITE => {
                let a0 = Mips::get_register(&mut state, "$a0")?;
                let a1 = Mips::get_register(&mut state, "$a1")?;
                let a2 = Mips::get_register(&mut state, "$a2")?;

                if a0 == 1 || a0 == 2 {
                    let bytes = state
                        .memory()
                        .load_buf(a1, a2 as usize)?
                        .ok_or("Failed to load buf for printing to stdout/stderr")?;

                    let byte_string = bytes
                        .iter()
                        .map(|b| {
                            state
                                .eval_and_concretize(b)
                                .unwrap()
                                .unwrap()
                                .value_u64()
                                .unwrap() as u8
                        })
                        .filter(|b| *b <= 0x7f)
                        .collect::<Vec<u8>>();

                    let byte_string: String = String::from_utf8(byte_string).chain_err(|| {
                        "Failed to convert bytes to string for \
                                       write to stdout/stderr"
                    })?;

                    trace!("write {} 0x{:x} {}: {}", a0, a1, a2, byte_string);
                }

                // We need to read all the bytes we are writing
                let bytes: ::std::result::Result<Vec<il::Expression>, Error> = (0..a2)
                    .into_iter()
                    .try_fold(Vec::new(), |mut bytes, offset| {
                        fn get(state: &State, address: u64) -> Result<il::Expression> {
                            state.memory().load(address, 8)?.ok_or_else(|| {
                                format!(
                                    "Value for write was None \
                                                    address=0x{:08x}",
                                    address
                                )
                                .into()
                            })
                        }

                        bytes.push(get(&state, a1 + offset)?);
                        Ok(bytes)
                    });

                let bytes = match bytes {
                    Ok(bytes) => bytes,
                    Err(_) => bail!("Failed to get bytes for write system call"),
                };

                let result = platform_mut(&mut state).linux.write(a0, bytes)?;

                state.set_scalar("$v0", &il::expr_const(result, 32))?;
                if result as i64 >= 0 {
                    state.set_scalar("$a3", &il::expr_const(0, 32))?;
                } else {
                    state.set_scalar("$a3", &il::expr_const(1, 32))?;
                }

                Ok(vec![Successor::new(state, SuccessorType::FallThrough)])
            }
            SYSCALL_WRITEV => {
                let a0 = state
                    .eval_and_concretize(&il::expr_scalar("$a0", 32))?
                    .ok_or("Failed to get a0 for writev")?;
                let a1 = state
                    .eval_and_concretize(&il::expr_scalar("$a1", 32))?
                    .ok_or("Failed to get a1 for writev")?;
                let a2 = state
                    .eval_and_concretize(&il::expr_scalar("$a2", 32))?
                    .ok_or("Failed to get a2 for writev")?;

                let iovec_base = a1.value_u64().unwrap();

                let mut bytes_written = 0;

                let mut output_string = String::new();

                for i in 0..a2.value_u64().unwrap() {
                    let iovec_address = iovec_base + (i * 8);
                    let iovec_length = iovec_base + (i * 8) + 4;

                    let iovec_address = state.memory().load(iovec_address, 32)?.ok_or(format!(
                        "Failed to get iovec_address at 0x{:x}",
                        iovec_address
                    ))?;
                    let iovec_length = state.memory().load(iovec_length, 32)?.ok_or(format!(
                        "Failed to get iovec_length at 0x{:x}",
                        iovec_length
                    ))?;

                    let iovec_address = state
                        .eval_and_concretize(&iovec_address)?
                        .ok_or(format!(
                            "Failed to concretize iovec_address {}",
                            iovec_address
                        ))?
                        .value_u64()
                        .unwrap();
                    let iovec_length = state
                        .eval_and_concretize(&iovec_length)?
                        .ok_or(format!(
                            "Failed to concretize iovec_length {}",
                            iovec_length
                        ))?
                        .value_u64()
                        .unwrap();

                    let bytes = state
                        .memory()
                        .load_buf(iovec_address, iovec_length as usize)?
                        .ok_or(format!(
                            "Failed to load bytes for writev syscall at 0x{:x}, len={}",
                            iovec_address, iovec_length
                        ))?;

                    let byte_string = bytes
                        .iter()
                        .map(|b| {
                            state
                                .eval_and_concretize(b)
                                .unwrap()
                                .unwrap()
                                .value_u64()
                                .unwrap() as u8
                        })
                        .filter(|b| *b <= 0x7f)
                        .collect::<Vec<u8>>();

                    let byte_string: String = String::from_utf8(byte_string)
                        .chain_err(|| "Failed to convert bytes to string for writev")?;

                    output_string += &byte_string;

                    // trace!("WRITEV {} 0x{:x} {} {}", a0, iovec_address, iovec_length, byte_string);

                    bytes_written += iovec_length;
                }

                trace!("WRITEV {}: {}", a0, output_string);

                state.set_scalar("$v0", &il::expr_const(bytes_written, 32))?;
                state.set_scalar("$a3", &il::expr_const(0, 32))?;

                Ok(vec![Successor::new(state, SuccessorType::FallThrough)])
            }
            _ => Err(format!("Unhandled system call {}", syscall_num).into()),
        }
    }
}

impl Platform for Mips {
    fn get_intrinsic_handler(
        &self,
    ) -> fn(state: State, intrinsic: &il::Intrinsic) -> Result<Vec<Successor>> {
        Mips::intrinsic
    }

    fn merge(&mut self, other: &dyn Platform, _: &il::Expression) -> Result<bool> {
        if self == other.as_any().downcast_ref().unwrap() {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn box_clone(&self) -> Box<dyn Platform> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn any_mut(&mut self) -> &mut dyn Any {
        self
    }
}
