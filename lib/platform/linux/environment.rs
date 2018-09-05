//! Modelling of the Linux Userland Environment.
//!
//! This deals primarily with configuring the environment for a userland process
//! as it is loaded and initialized by the Linux Kernel.

use error::*;
use executor::Memory;
use falcon::il;
use falcon::loader::{ElfLinker, Loader};


/// A string to be used in the `Environment`.
///
/// **Note**: `EnvironmentString` is used for more purposes than just
/// environment variables.
pub enum EnvironmentString {
    Concrete {
        string: String
    },
    Symbolic {
        name: String,
        length: usize
    },
    EnvironmentVariable {
        name: String,
        length: usize
    }
}


impl EnvironmentString {
    /// Create a new concrete string.
    pub fn new_concrete<S: Into<String>>(string: S) -> EnvironmentString {
        EnvironmentString::Concrete { string: string.into() }
    }

    /// Create a new symbolic string.
    pub fn new_symbolic<S: Into<String>>(name: S, length: usize)
        -> EnvironmentString {

        EnvironmentString::Symbolic { name: name.into(), length: length }
    }

    /// Create a new environment variable.
    ///
    /// The name of the string will be concrete, and the value will be symbolic.
    /// I.E. `NAME={SYMBOLIC_BYTES}`, where `NAME=` is concrete.
    pub fn new_environment_variable<S:Into<String>>(name: S, length: usize)
        -> EnvironmentString {

        EnvironmentString::EnvironmentVariable { name: name.into(), length }
    }
}


/// A Linux Environment during process initialization.
pub struct Environment {
    command_line_arguments: Vec<EnvironmentString>,
    environment_variables: Vec<EnvironmentString>
}


impl Environment {
    /// Create a new Linux Environment.
    pub fn new() -> Environment {
        Environment {
            command_line_arguments: Vec::new(),
            environment_variables: Vec::new()
        }
    }


    /// Add a new command line argument to the environment, utilizing the
    /// builder pattern.
    pub fn command_line_argument(
        mut self,
        environment_string: EnvironmentString
    ) -> Environment {
        self.command_line_arguments.push(environment_string);
        self
    }


    /// Add a new environment variable to the environment, utilizing the
    /// builder pattern.
    pub fn environment_variable(
        mut self,
        environment_string: EnvironmentString
    ) -> Environment {
        self.environment_variables.push(environment_string);
        self
    }


    /// Initialize a 32-bit Linux userland process.
    ///
    /// This is currently only tested for the MIPS userland environment. This
    /// will configure hte process in the passed memory, which should be blank.
    pub fn initialize_process32(
        &self,
        mut memory: &mut Memory,
        stack_address: u64,
        elf_linker: &ElfLinker
    ) -> Result<()> {

        fn push(
            memory: &mut Memory,
            stack_address: &mut u64,
            value: &il::Expression
        ) -> Result<()> {
            memory.store(*stack_address, &value)?;
            *stack_address += 4;
            Ok(())
        }

        fn set_string(
            memory: &mut Memory,
            address: &mut u64,
            environment_string: &EnvironmentString,
        ) -> Result<()> {
            match *environment_string {
                EnvironmentString::Concrete { ref string } => {
                    for i in 0..string.len() {
                        memory.store(
                            *address,
                            &il::expr_const(string.as_bytes()[i] as u64, 8)
                        )?;
                        *address += 1;
                    }
                    memory.store(*address, &il::expr_const(0, 8))?;
                    *address += 1;
                },
                EnvironmentString::Symbolic { ref name, length } => {
                    for i in 0..length {
                        memory.store(
                            *address,
                            &il::expr_scalar(format!("{}_{}", name, i), 8)
                        )?;
                        *address += 1;
                    }
                    memory.store(*address, &il::expr_const(0, 8))?;
                    *address += 1;
                },
                EnvironmentString::EnvironmentVariable { ref name, length } => {
                    for i in 0..name.len() {
                        memory.store(
                            *address,
                            &il::expr_const(name.as_bytes()[i] as u64, 8)
                        )?;
                        *address += 1;
                    }
                    memory.store(*address, &il::expr_const('=' as u64, 8))?;
                    *address += 1;
                    for i in 0..length {
                        memory.store(
                            *address,
                            &il::expr_scalar(format!("{}_{}", name, i), 8)
                        )?;
                        *address += 1;
                    }
                    memory.store(*address, &il::expr_const(0, 8))?;
                    *address += 1;
                }
            }
            Ok(())
        }

        // first we need to find out how many bytes are needed to store command
        // line arguments, environment variables, and elf auxiliary table
        // entries.
        let mut initial_stack_size = self.command_line_arguments.len();
        initial_stack_size += self.environment_variables.len();
        initial_stack_size += 1; // argc
        initial_stack_size += 1; // null word after argv
        initial_stack_size += 1; // null word after environment variables
        initial_stack_size += 8 * 2; // 8 elf auxiliary table entries
        initial_stack_size *= 4; // multiply by word size

        // a little padding never hurt anyone.
        let strings_offset = initial_stack_size + 16;

        let mut stack_address = stack_address;
        let mut strings_address = stack_address + strings_offset as u64;

        // push argc
        push(&mut memory,
             &mut stack_address,
             &il::expr_const(self.command_line_arguments.len() as u64, 32))?;

        // push argv
        for command_line_argument in &self.command_line_arguments {
            push(&mut memory,
                 &mut stack_address,
                 &il::expr_const(strings_address, 32))?;
            set_string(&mut memory,
                       &mut strings_address,
                       command_line_argument)?;
        }

        // null word separates argv from environment variables
        push(&mut memory, &mut stack_address, &il::expr_const(0, 32))?;

        // push a null word if there are no environment variables
        if self.environment_variables.is_empty() {
            push(&mut memory,
                 &mut stack_address,
                 &il::expr_const(0, 32))?;   
        }
        // otherwise push environment variables
        else {
            for environment_variable in &self.environment_variables {
                push(&mut memory,
                     &mut stack_address,
                     &il::expr_const(strings_address, 32))?;
                set_string(&mut memory,
                           &mut strings_address,
                           environment_variable)?;
            }
        }

        // null word terminates environment variables
        push(&mut memory, &mut stack_address, &il::expr_const(0, 32))?;


        // We need some information from the Elf for the Elf Auxiliary Table
        // entries
        let loaded = elf_linker.loaded();
        let filename = elf_linker.filename()
            .file_name()
            .and_then(|filename| filename.to_str())
            .ok_or("Could not get filename for ElfLinker's primary program")?;

        let elf = loaded.get(filename)
            .ok_or(format!("Could not get {} from ElfLinker", filename))?;

        // we need to find the address where PHDRs are loaded into memory.
        // find the lowest address of a PT_LOAD phdr
        let mut base_address = 0x100000000;
        for phdr in elf.elf().program_headers {
            if phdr.p_type == ::goblin::elf::program_header::PT_LOAD {
                if phdr.p_vaddr < base_address {
                    base_address = phdr.p_vaddr;
                }
            }
        }

        // add in the base address from ElfLinker. This should be 0
        base_address += elf.base_address();

        // and add in e_phoff from elf header
        let phdr_address = base_address + elf.elf().header.e_phoff;

        let ehdr = elf.elf().header;
        
        // 0xbff00028 AT_PHDR (0x3) is beginning of PHDR for this binary
        push(&mut memory, &mut stack_address, &il::expr_const(3, 32))?;
        push(&mut memory, &mut stack_address, &il::expr_const(phdr_address, 32))?;
        // state.memory_mut().store(0xbff00028, &il::expr_const(3, 32))?;
        // state.memory_mut().store(0xbff0002c, &il::expr_const(phdr_address, 32))?;

        // 0xbff00030 AT_PHENT (0x4)
        push(&mut memory, &mut stack_address, &il::expr_const(4, 32))?;
        push(&mut memory, &mut stack_address, &il::expr_const(ehdr.e_phentsize as u64, 32))?;
        // state.memory_mut().store(0xbff00030, &il::expr_const(4, 32))?;
        // state.memory_mut().store(0xbff00034, &il::expr_const(ehdr.e_phentsize as u64, 32))?;

        // 0xbff00038 AT_PHNUM (0x5)
        push(&mut memory, &mut stack_address, &il::expr_const(5, 32))?;
        push(&mut memory, &mut stack_address, &il::expr_const(ehdr.e_phnum as u64, 32))?;
        // state.memory_mut().store(0xbff00038, &il::expr_const(5, 32))?;
        // state.memory_mut().store(0xbff0003c, &il::expr_const(ehdr.e_phnum as u64, 32))?;

        // 0xbff00040 AT_PAGESZ (0x6)
        push(&mut memory, &mut stack_address, &il::expr_const(6, 32))?;
        push(&mut memory, &mut stack_address, &il::expr_const(0x1000, 32))?;
        // state.memory_mut().store(0xbff00040, &il::expr_const(6, 32))?;
        // state.memory_mut().store(0xbff00044, &il::expr_const(0x1000, 32))?;

        // now we need the address where our interpreter is loaded
        let interpreter_base_address =
            elf_linker.get_interpreter()?
                .map(|elf| elf.base_address())
                .unwrap_or(0);

        // 0xbff00048 AT_BASE (0x7)
        push(&mut memory, &mut stack_address, &il::expr_const(7, 32))?;
        push(&mut memory, &mut stack_address, &il::expr_const(interpreter_base_address as u64, 32))?;
        // state.memory_mut().store(0xbff00048, &il::expr_const(7, 32))?;
        // state.memory_mut().store(0xbff0004c, &il::expr_const(interpreter_base_address, 32))?;

        // 0xbff00050 AT_BASE (0x8)
        push(&mut memory, &mut stack_address, &il::expr_const(8, 32))?;
        push(&mut memory, &mut stack_address, &il::expr_const(0, 32))?;
        // state.memory_mut().store(0xbff00050, &il::expr_const(8, 32))?;
        // state.memory_mut().store(0xbff00054, &il::expr_const(0, 32))?;

        // 0xbff00058 AT_ENTRY (0x9)
        push(&mut memory, &mut stack_address, &il::expr_const(9, 32))?;
        push(&mut memory, &mut stack_address, &il::expr_const(elf.program_entry(), 32))?;
        // state.memory_mut().store(0xbff00058, &il::expr_const(9, 32))?;
        // state.memory_mut().store(0xbff0005c, &il::expr_const(elf.program_entry(), 32))?;

        // 0xbff00060 AT_NULL (0x0)
        push(&mut memory, &mut stack_address, &il::expr_const(0, 32))?;
        push(&mut memory, &mut stack_address, &il::expr_const(0, 32))?;
        // state.memory_mut().store(0xbff00060, &il::expr_const(0, 32))?;
        // state.memory_mut().store(0xbff00064, &il::expr_const(0, 32))?;

        Ok(())
    }
}