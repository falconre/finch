//! A basic model of the Linux Operating System for MIPS.

use byteorder::{BigEndian, WriteBytesExt};
use error::*;
use executor::{Driver, Memory, State, Successor, SuccessorType};
use falcon::{il, RC};
use falcon::loader::{ElfLinker, ElfLinkerBuilder, Loader};
use platform::linux::{Constants, Environment, EnvironmentString, Linux};
use platform::Platform;
use std::path::PathBuf;


// const ARGV_STRING_LEN: u64 = 256;
const TLS_ADDRESS: u64 = 0xc000_0000_0000;
const STACK_BASE: u64 = 0xbff0_0000_0000;

const DEFAULT_PID: u64 = 512;

// System call information
const SYSCALL_ACCESS: u64          = 21;
const SYSCALL_BRK: u64             = 12;
const SYSCALL_CLOSE: u64           = 3;
const SYSCALL_EXIT_GROUP: u64      = 231;
const SYSCALL_FSTAT: u64           = 5;
const SYSCALL_FUTEX: u64           = 202;
const SYSCALL_GETPID: u64          = 39;
const SYSCALL_GETRLIMIT: u64       = 97;
const SYSCALL_LSEEK: u64           = 8;
const SYSCALL_MMAP: u64            = 9;
const SYSCALL_MPROTECT: u64        = 10;
const SYSCALL_OPEN: u64            = 2;
const SYSCALL_READ: u64            = 0;
const SYSCALL_RT_SIGACTION: u64    = 13;
const SYSCALL_RT_SIGPROCMASK: u64  = 14;
const SYSCALL_SET_ROBUST_LIST: u64 = 273;
const SYSCALL_SET_THREAD_AREA: u64 = 205;
const SYSCALL_SET_TID_ADDRESS: u64 = 218;
const SYSCALL_STAT: u64            = 4;
const SYSCALL_UNAME: u64           = 63;
const SYSCALL_WRITE: u64           = 1;
const SYSCALL_WRITEV: u64          = 20;


const AMD64_LINUX_CONSTANTS: Constants = Constants {
    PAGE_SIZE:     0x1000,

    MAP_SHARED:    0x1,
    MAP_PRIVATE:   0x2,
    MAP_FIXED:     0x10,
    MAP_LOCAL:     0xffffffff,
    MAP_ANONYMOUS: 0x20,
    O_CREAT:       0x40,
    PROT_READ:     0x1,
    PROT_WRITE:    0x2,
    PROT_EXEC:     0x4,
    SEEK_SET:      0x0,
    SEEK_CUR:      0x1,
    SEEK_END:      0x2
};


/// A `Platform` for Linux on Amd64.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Amd64 {
    linux: Linux,
    fake_ino: u64,
}


impl Amd64 {
    /// Create a standard driver, set up with a Amd64 Platform, and everything
    /// initialized.
    pub fn standard_load(filename: &str, base_path: Option<PathBuf>)
        -> Result<Driver<Amd64>> {

        let mut elf_linker =
            ElfLinkerBuilder::new(filename.into())
                .do_relocations(false)
                .just_interpreter(true);

        if let Some(ref base_path) = base_path {
            let mut paths = vec![base_path.to_path_buf()];
            elf_linker = elf_linker.ld_paths(Some(paths));
        }

        let elf_linker = elf_linker.link()?;

        let architecture = elf_linker.architecture();
        let endian = architecture.endian();

        // To figure out where we start, we need to check and see if this ELF
        // has an interpreter entry. If it does, we use that as the address for
        // program entry. Otherwise, we start at the designated binary's entry
        // point.
        let entry = elf_linker.get_interpreter()?
            .map(|elf| elf.base_address() + elf.elf().header.e_entry)
            .unwrap_or(elf_linker.program_entry());

        let mut program = il::Program::new();
        let function = elf_linker.function(entry)?;
        program.add_function(function);

        let program_location = {
            let program_location =
                il::RefProgramLocation::from_address(&program, entry)
                    .ok_or(format!("Failed  to get program location for 0x{:x}",
                                   entry))?;
            let program_location: il::ProgramLocation = program_location.into();
            program_location
        };

        let amd64_linux = Amd64 {
            linux: Linux::new(&elf_linker, base_path, &AMD64_LINUX_CONSTANTS)?,
            fake_ino: 0
        };
        let backing = elf_linker.memory()?;
        let memory = Memory::new_with_backing(endian, RC::new(backing));
        let state = State::new(memory, Box::new(amd64_linux));

        let state = Amd64::initialize(state, &elf_linker)?;

        Ok(Driver::new(
            program,
            program_location,
            state,
            RC::new(architecture.box_clone())
        ))
    }


    fn initialize(mut state: State<Amd64>, elf_linker: &ElfLinker)
        -> Result<State<Amd64>> {

        let environment = Environment::new()
            .command_line_argument(
                EnvironmentString::new_concrete("application_filename"))
            // .environment_variable(
            //     EnvironmentString::new_concrete("LD_DEBUG=bindings"))
            .environment_variable(
                EnvironmentString::new_concrete(
                    "LD_BIND_NOW=1"))
            .environment_variable(
                EnvironmentString::new_concrete(
                    "LD_DEBUG=all"))
            .environment_variable(
                EnvironmentString::new_concrete(
                    "LD_LIBRARY_PATH=/usr/lib:/lib64"))
            .environment_variable(
                EnvironmentString::new_concrete(
                    "LOCALDOMAIN=localdomain"));

        environment.initialize_process64(
            &mut state.memory_mut(),
            STACK_BASE,
            elf_linker)?;

        for i in 0..0x8000 {
            state.memory_mut().store(TLS_ADDRESS + i, &il::expr_const(0, 8))?;
        }

        // Writing to create some stack space, which is good for qemu
        for i in 1..0x10000 {
            state.memory_mut().store(STACK_BASE - i, &il::expr_const(0, 8))?;
        }

        state.set_scalar("DF", &il::expr_const(0, 1))?;
        state.set_scalar("CF", &il::expr_const(0, 1))?;
        state.set_scalar("PF", &il::expr_const(0, 1))?;
        state.set_scalar("AF", &il::expr_const(0, 1))?;
        state.set_scalar("ZF", &il::expr_const(0, 1))?;
        state.set_scalar("SF", &il::expr_const(0, 1))?;
        state.set_scalar("OF", &il::expr_const(0, 1))?;

        state.set_scalar("rax", &il::expr_const(0, 64))?;
        state.set_scalar("rbx", &il::expr_const(0, 64))?;
        state.set_scalar("rcx", &il::expr_const(0, 64))?;
        state.set_scalar("rdx", &il::expr_const(0, 64))?;
        state.set_scalar("rdi", &il::expr_const(0, 64))?;
        state.set_scalar("rsi", &il::expr_const(0, 64))?;
        state.set_scalar("r8", &il::expr_const(0, 64))?;
        state.set_scalar("r9", &il::expr_const(0, 64))?;
        state.set_scalar("r10", &il::expr_const(0, 64))?;
        state.set_scalar("r11", &il::expr_const(0, 64))?;
        state.set_scalar("r12", &il::expr_const(0, 64))?;
        state.set_scalar("r13", &il::expr_const(0, 64))?;
        state.set_scalar("r14", &il::expr_const(0, 64))?;
        state.set_scalar("r15", &il::expr_const(0, 64))?;
        state.set_scalar("rbp", &il::expr_const(0, 64))?;
        state.set_scalar("rsp", &il::expr_const(STACK_BASE, 64))?;

        Ok(state)
    }


    /// Handle an intrinsic instruction.
    pub fn intrinsic(mut state: State<Amd64>, intrinsic: &il::Intrinsic)
        -> Result<Vec<Successor<Amd64>>> {

        if intrinsic.mnemonic() == "syscall" {
            Amd64::syscall(state)
        }
        else if intrinsic.mnemonic() == "cpuid" {
            let rax = state.eval_and_concretize(&il::expr_scalar("rax", 64))?
                .and_then(|constant| constant.value_u64())
                .ok_or("Failed to get syscall num in rax")?;

            match rax {
                0 => {
                    state.set_scalar("rax", &il::expr_const(0, 64))?;
                    state.set_scalar("rbx", &il::expr_const(0x756e6547, 64))?;
                    state.set_scalar("rcx", &il::expr_const(0x6c65746e, 64))?;
                    state.set_scalar("rdx", &il::expr_const(0x49656e69, 64))?;
                },
                1 => {
                    // this says essentially that the cpu supports nothing.
                    state.set_scalar("rax", &il::expr_const(0b0000_00000000_0000_00_00_0000_0000_0000, 64))?;
                    state.set_scalar("rbx", &il::expr_const(0b00000000_00000001_00000001_00000000, 64))?;
                    state.set_scalar("rcx", &il::expr_const(0, 64))?;
                    state.set_scalar("rdx", &il::expr_const(0, 64))?;
                }
                _ => {
                    bail!("Unhandled cpuid rax={}", rax)
                }
            };
            Ok(vec![Successor::new(state, SuccessorType::FallThrough)])
        }
        else if intrinsic.mnemonic() == "rdtsc" {
            state.set_scalar("rax", &il::expr_scalar("rdtsc-rax", 64))?;
            state.set_scalar("rdx", &il::expr_scalar("rdtsc-rdx", 64))?;
            Ok(vec![Successor::new(state, SuccessorType::FallThrough)])
        }
        else {
            Err(ErrorKind::UnhandledIntrinsic(format!("{}", intrinsic)).into())
        }

    }


    // create a fake stat64 buf
    fn fake_stat64(&mut self, size: usize) -> Result<Vec<u8>> {
        const S_IFREG: u32 = 0o0100000;

        let mut buf = Vec::new();
        buf.write_u32::<BigEndian>(0x4f)?;    // 0x0  4 st_dev
        buf.write_u32::<BigEndian>(0)?;
        buf.write_u32::<BigEndian>(0)?;
        buf.write_u32::<BigEndian>(0)?;
        buf.write_u64::<BigEndian>(self.fake_ino)?;    // 0x10 8 st_ino
        buf.write_u32::<BigEndian>(0o100755 | S_IFREG)?; // 0x18 4 st_mode
        buf.write_u32::<BigEndian>(1)?;    // 0x1c 4 st_nlink
        buf.write_u32::<BigEndian>(0)?;    // 0x20 4 st_uid
        buf.write_u32::<BigEndian>(0)?;    // 0x24 4 st_gid
        buf.write_u32::<BigEndian>(0)?;    // 0x28 4 st_rdev
        buf.write_u32::<BigEndian>(0)?;    // 0x2c
        buf.write_u32::<BigEndian>(0)?;    // 0x30
        buf.write_u32::<BigEndian>(0)?;    // 0x34
        buf.write_u64::<BigEndian>(size as u64)?; // 0x38 8 st_size
        buf.write_u32::<BigEndian>(100000)?;    // 0x40 4 st_atime
        buf.write_u32::<BigEndian>(1)?;    // 0x44 4 st_atime_nsec
        buf.write_u32::<BigEndian>(100000)?;    // 0x48 4 st_mtime
        buf.write_u32::<BigEndian>(1)?;    // 0x4c 4 st_mtime_nsec
        buf.write_u32::<BigEndian>(100000)?;    // 0x50 4 st_ctime
        buf.write_u32::<BigEndian>(1)?;    // 0x54 4 st_ctime_nsec
        buf.write_u32::<BigEndian>(512)?;    // 0x58 4 st_blksize
        buf.write_u32::<BigEndian>(1)?;
        buf.write_u64::<BigEndian>((size / 512 + if size & (512 - 1) > 0 { 1 } else { 0 }) as u64)?; // 0x60 8 st_blocks

        self.fake_ino += 1;

        Ok(buf)
    }


    fn get_arg(state: &mut State<Amd64>, index: usize) -> Result<u64> {
        let register = match index {
            0 => il::expr_scalar("rdi", 64),
            1 => il::expr_scalar("rsi", 64),
            2 => il::expr_scalar("rdx", 64),
            3 => il::expr_scalar("r10", 64),
            4 => il::expr_scalar("r8", 64),
            5 => il::expr_scalar("r9", 64),
            _ => bail!("Invalid system call argument index")
        };

        Ok(state.eval_and_concretize(&register)?
            .and_then(|constant| constant.value_u64())
            .ok_or(format!("Failed to get system call argument {}", index))?)
    }


    /// Handle a system call.
    pub fn syscall(mut state: State<Amd64>)
        -> Result<Vec<Successor<Amd64>>> {

        let syscall_num = state.eval_and_concretize(&il::expr_scalar("rax", 64))?
            .ok_or("Failed to get syscall num in rax")?;

        println!("syscall_num is {}", syscall_num);

        match syscall_num.value_u64().unwrap() {
            SYSCALL_ACCESS => {
                let filename_address = Amd64::get_arg(&mut state, 0)?;
                let mode = Amd64::get_arg(&mut state, 1)?;

                let filename = match state.get_string(filename_address)? {
                    Some(filename) => filename,
                    None => { bail!("Could not get filename for access"); }
                };

                let result =
                    state.platform()
                        .linux
                        .access(&filename, mode);

                trace!("access for \"{}\" was {}", filename, result as i64);
                state.set_scalar("rax", &il::expr_const(result, 64))?;
                Ok(vec![Successor::new(state, SuccessorType::FallThrough)])
            },
            SYSCALL_BRK => {
                let brk = Amd64::get_arg(&mut state, 0)?;
                let result = state.platform_mut().linux.brk(brk);
                trace!("brk set to 0x{:x}", result);
                state.set_scalar("rax", &il::expr_const(result, 64))?;
                Ok(vec![Successor::new(state, SuccessorType::FallThrough)])
            },
            SYSCALL_CLOSE => {
                let fd = Amd64::get_arg(&mut state, 0)?;
                if state.platform_mut()
                        .linux
                        .file_system_mut()
                        .close_fd(fd as usize) {
                    trace!("close {} = 0", fd);
                    state.set_scalar("rax", &il::expr_const(0, 64))?;
                }
                else {
                    trace!("close {} = -1", fd);
                    state.set_scalar("rax", &il::expr_const(-1i64 as u64, 64))?;
                }
                Ok(vec![Successor::new(state, SuccessorType::FallThrough)])
            },
            SYSCALL_EXIT_GROUP => {
                let error_code = Amd64::get_arg(&mut state, 0)?;
                trace!("exit_group: {}", error_code);
                Ok(Vec::new())
            },
            SYSCALL_FSTAT => {
                let fd = Amd64::get_arg(&mut state, 0)?;
                let statbuf = Amd64::get_arg(&mut state, 1)?;

                match state.platform()
                           .linux
                           .file_system()
                           .size_fd(fd as usize) {
                    Some(size) => {
                        let buf =
                            state.platform_mut().fake_stat64(size)?;
                        for i in 0..buf.len() {
                            state.memory_mut().store(
                                statbuf + i as u64,
                                &il::expr_const(buf[i] as u64, 8))?;
                        }
                        trace!("fstat for {} = 0, {}", fd, statbuf);
                        state.set_scalar("rax", &il::expr_const(0, 64))?;
                    },
                    None => {
                        trace!("fstat64 for {} = -1", fd);
                        state.set_scalar("rax", &il::expr_const(-1i64 as u64, 64))?;
                    }
                }

                Ok(vec![Successor::new(state, SuccessorType::FallThrough)])
            },
            SYSCALL_FUTEX => {
                trace!("futex");
                state.set_scalar("rax", &il::expr_const(0, 64))?;
                Ok(vec![Successor::new(state, SuccessorType::FallThrough)])
            },
            SYSCALL_GETPID => {
                trace!("getpid");
                state.set_scalar("rax", &il::expr_const(DEFAULT_PID, 64))?;
                Ok(vec![Successor::new(state, SuccessorType::FallThrough)])
            },
            SYSCALL_GETRLIMIT => {
                let resource = Amd64::get_arg(&mut state, 0)?;
                let rlim = Amd64::get_arg(&mut state, 1)?;

                // https://github.com/angr/angr/blob/master/angr/procedures/linux_kernel/getrlimit.py
                if resource == 3 { // This is RLIMIT_STACK according to angr
                    state.memory_mut().store(rlim, &il::expr_const(1024*8*8, 64))?;
                    state.memory_mut().store(rlim + 4, &il::expr_const(1024*8*16, 64))?;
                    trace!("getrlimit {}", resource);
                }
                else {
                    trace!("getrlimit skipping");
                }
                state.set_scalar("rax", &il::expr_const(0, 64))?;
                Ok(vec![Successor::new(state, SuccessorType::FallThrough)])
            },
            SYSCALL_LSEEK => {
                let fd = Amd64::get_arg(&mut state, 0)?;
                let offset = Amd64::get_arg(&mut state, 1)?;
                let origin = Amd64::get_arg(&mut state, 2)?;

                let result =
                    state.platform_mut()
                        .linux
                        .lseek(fd, offset as isize, origin)?;

                state.set_scalar("rax", &il::expr_const(result as u64, 64))?;
                trace!("lseek 0x{:x} 0x{:x} 0x{:x} is {}", fd, offset, origin, result);
                Ok(vec![Successor::new(state, SuccessorType::FallThrough)])
            },
            SYSCALL_MMAP => {
                let addr  = Amd64::get_arg(&mut state, 0)?;
                let len   = Amd64::get_arg(&mut state, 1)?;
                let prot  = Amd64::get_arg(&mut state, 2)?;
                let flags = Amd64::get_arg(&mut state, 3)?;
                let fd    = Amd64::get_arg(&mut state, 4)?;
                let off   = Amd64::get_arg(&mut state, 5)?;

                let address =
                    state.platform
                        .as_mut()
                        .linux
                        .mmap(&mut state.memory, addr, len, prot, flags, fd, off)?;

                state.set_scalar("rax", &il::expr_const(address as u64, 64))?;

                trace!("mmap(0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}, 0x{:x} = 0x{:x}",
                    addr, len, prot, flags, fd, off, address);

                Ok(vec![Successor::new(state, SuccessorType::FallThrough)])
            },
            SYSCALL_MPROTECT => {
                let addr = Amd64::get_arg(&mut state, 0)?;
                let len = Amd64::get_arg(&mut state, 1)?;
                let prot = Amd64::get_arg(&mut state, 2)?;

                let result =
                    state.platform
                        .as_mut()
                        .linux
                        .mprotect(&mut state.memory, addr, len, prot)?;

                state.set_scalar("rax", &il::expr_const(result as u64, 64))?;

                trace!("mprotect(0x{:x}, 0x{:x}, 0x{:x}) = 0x{:x}",
                    addr, len, prot, result);

                Ok(vec![Successor::new(state, SuccessorType::FallThrough)])
            },
            SYSCALL_OPEN => {
                let filename_address = Amd64::get_arg(&mut state, 0)?;
                let flags = Amd64::get_arg(&mut state, 1)?;
                let mode = Amd64::get_arg(&mut state, 2)?;

                let filename =
                    state.get_string(filename_address)?
                        .ok_or("Could not get filename for open")?;

                let result =
                    state.platform_mut()
                        .linux
                        .open(&filename, flags, mode)?;

                trace!("open for \"{}\" was {}", filename, result as i64);

                state.set_scalar("rax", &il::expr_const(result, 64))?;

                Ok(vec![Successor::new(state, SuccessorType::FallThrough)])
            },
            SYSCALL_READ => {
                let fd = Amd64::get_arg(&mut state, 0)?;
                let buf = Amd64::get_arg(&mut state, 1)?;
                let count = Amd64::get_arg(&mut state, 2)?;

                let result =
                    state.platform_mut()
                        .linux
                        .read(fd, count)?;

                if let Some(bytes) = result {
                    for i in 0..bytes.len() {
                        state.memory_mut().store(buf + (i as u64), &bytes[i])?;
                    }
                    state.set_scalar("rax", &il::expr_const(0, 64))?;
                }
                else {
                    state.set_scalar("rax", &il::expr_const(-1i64 as u64, 64))?;
                }

                trace!("read for {},0x{:x},0x{:x} was {}",
                    fd, buf, count,
                    state.scalar("rax").unwrap());

                Ok(vec![Successor::new(state, SuccessorType::FallThrough)])
            },
            SYSCALL_RT_SIGACTION => {
                trace!("rt_sigaction skipping");
                state.set_scalar("rax", &il::expr_const(0 as u64, 64))?;
                Ok(vec![Successor::new(state, SuccessorType::FallThrough)])
            },
            SYSCALL_RT_SIGPROCMASK => {
                trace!("rt_sigprocmask skipping");
                state.set_scalar("rax", &il::expr_const(0 as u64, 64))?;
                Ok(vec![Successor::new(state, SuccessorType::FallThrough)])
            },
            SYSCALL_SET_ROBUST_LIST => {
                trace!("set_robust_list skipping");
                state.set_scalar("rax", &il::expr_const(0 as u64, 64))?;
                Ok(vec![Successor::new(state, SuccessorType::FallThrough)])

            },
            SYSCALL_SET_THREAD_AREA => {
                trace!("set_thread_area skipping");
                state.set_scalar("rax", &il::expr_const(0 as u64, 64))?;
                Ok(vec![Successor::new(state, SuccessorType::FallThrough)])

            },
            SYSCALL_SET_TID_ADDRESS => {
                trace!("set_tid_address skipping");
                state.set_scalar("$rax", &il::expr_const(0 as u64, 64))?;
                Ok(vec![Successor::new(state, SuccessorType::FallThrough)])

            },
            SYSCALL_STAT => {
                let filename_address = Amd64::get_arg(&mut state, 0)?;
                let path = state.get_string(filename_address)?
                    .ok_or("Could not get path")?;

                trace!("stat for {}, always returning -1", path);

                state.set_scalar("rax", &il::expr_const(-1i64 as u64, 64))?;
                Ok(vec![Successor::new(state, SuccessorType::FallThrough)])
            },
            SYSCALL_UNAME => {
                trace!("uname");
                // Just zero everything out
                let buf = Amd64::get_arg(&mut state, 0)?;

                for i in 0..(65*5) {
                    state.memory_mut().store(buf + i, &il::expr_const(0, 8))?;
                }

                // This fakes a linux kernel 3 something
                state.memory_mut().store(buf + (65 * 2), &il::expr_const(0x33, 8))?;

                state.set_scalar("rax", &il::expr_const(0, 64))?;

                Ok(vec![Successor::new(state, SuccessorType::FallThrough)])
            },
            SYSCALL_WRITE => {
                let fd = Amd64::get_arg(&mut state, 0)?;
                let buf = Amd64::get_arg(&mut state, 1)?;
                let len = Amd64::get_arg(&mut state, 2)?;

                if fd == 1 || fd == 2 {
                    let bytes = state.memory()
                        .load_buf(buf, len as usize)?
                        .ok_or("Failed to load buf for printing to stdout/stderr")?;

                    let byte_string =
                        bytes.iter()
                            .map(|b| state.eval_and_concretize(b)
                                          .unwrap()
                                          .unwrap()
                                          .value_u64()
                                          .unwrap() as u8)
                            .filter(|b| *b <= 0x7f)
                            .collect::<Vec<u8>>();

                    let byte_string: String = String::from_utf8(byte_string)
                        .chain_err(|| "Failed to convert bytes to string for \
                                       write to stdout/stderr")?;

                    trace!("write {} 0x{:x} {}: {}", fd, buf, len, byte_string);
                }

                // We need to read all the bytes we are writing
                let bytes: ::std::result::Result<Vec<il::Expression>, Error> =
                    (0..len).into_iter()
                        .try_fold(Vec::new(), |mut bytes, offset| {
                            fn get<P: Platform<P>>(state: &State<P>, address: u64)
                                -> Result<il::Expression> {

                                state.memory().load(address, 8)?
                                    .ok_or(format!("Value for write was None \
                                                    address=0x{:08x}",
                                                    address).into())
                            }

                            bytes.push(get(&state, buf + offset)?);
                            Ok(bytes)
                        });

                let bytes = match bytes {
                    Ok(bytes) => bytes,
                    Err(_) => bail!("Failed to get bytes for write system call")
                };

                let result = state.platform_mut()
                    .linux
                    .write(fd, bytes)?;

                state.set_scalar("rax", &il::expr_const(result, 64))?;

                Ok(vec![Successor::new(state, SuccessorType::FallThrough)])
            },
            SYSCALL_WRITEV => {
                let fd = Amd64::get_arg(&mut state, 0)?;
                let vec = Amd64::get_arg(&mut state, 1)?;
                let vlen = Amd64::get_arg(&mut state, 2)?;

                trace!("writev: 0x{:x} 0x{:x} 0x{:x}", fd, vec, vlen);

                let iovec_base = vec;

                let mut bytes_written = 0;

                let mut output_string = String::new();

                for i in 0..vlen {
                    let iovec_address = iovec_base + (i * 16);
                    let iovec_length = iovec_base + (i * 16) + 8;

                    let iovec_address =
                        state.memory().load(iovec_address, 64)?
                            .ok_or(format!("Failed to get iovec_address at 0x{:x}", iovec_address))?;
                    let iovec_length =
                        state.memory().load(iovec_length, 64)?
                            .ok_or(format!("Failed to get iovec_length at 0x{:x}", iovec_length))?;

                    let iovec_address = state.eval_and_concretize(&iovec_address)?
                        .ok_or(format!("Failed to concretize iovec_address {}", iovec_address))?
                        .value_u64()
                        .unwrap();
                    let iovec_length = state.eval_and_concretize(&iovec_length)?
                        .ok_or(format!("Failed to concretize iovec_length {}", iovec_length))?
                        .value_u64()
                        .unwrap();

                    println!("iovec_address: 0x{:x}, iovec_length: 0x{:x}", iovec_address, iovec_length);

                    let bytes =
                        state.memory()
                            .load_buf(iovec_address, iovec_length as usize)?
                            .ok_or(format!(
                                "Failed to load bytes for writev syscall at 0x{:x}, len={}",
                                iovec_address,
                                iovec_length))?;

                    let byte_string =
                        bytes.iter()
                            .map(|b|
                                state.eval_and_concretize(b)
                                    .unwrap()
                                    .unwrap()
                                    .value_u64()
                                    .unwrap() as u8)
                            .filter(|b| *b <= 0x7f)
                            .collect::<Vec<u8>>();

                    let byte_string: String = String::from_utf8(byte_string)
                        .chain_err(|| "Failed to convert bytes to string for writev")?;

                    output_string += &byte_string;

                    // trace!("WRITEV {} 0x{:x} {} {}", a0, iovec_address, iovec_length, byte_string);

                    bytes_written += iovec_length;
                }

                trace!("WRITEV {}: {}", fd, output_string);

                state.set_scalar("rax", &il::expr_const(bytes_written, 64))?;
                Ok(vec![Successor::new(state, SuccessorType::FallThrough)])
            },
            _ => Err(format!("Unhandled system call {}", syscall_num).into())
        }
    }
}



impl Platform<Amd64> for Amd64 {
    fn intrinsic(state: State<Amd64>, intrinsic: &il::Intrinsic)
        -> Result<Vec<Successor<Amd64>>> {

        Amd64::intrinsic(state, intrinsic)
    }

    fn merge(&mut self, other: &Amd64, _: &il::Expression)
        -> Result<bool> {

        if self == other {
            Ok(true)
        }
        else {
            Ok(false)
        }
    }


    fn box_clone(&self) -> Box<Amd64> {
        Box::new(self.clone())
    }
}