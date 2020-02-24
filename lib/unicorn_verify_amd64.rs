//! Verify Finch's execution and semantics against Unicorn.

use crate::error::*;
use crate::executor::{Driver, State, StateTranslator};
use falcon::il;
use falcon::translator::TranslationMemory;
use std::collections::HashSet;
use unicorn;
use unicorn::{Cpu, CpuX86};

struct RegisterMapping {
    register: unicorn::RegisterX86,
    name: &'static str,
}

const REGISTER_MAPPINGS: &[RegisterMapping] = &[
    RegisterMapping {
        register: unicorn::RegisterX86::RAX,
        name: "rax",
    },
    RegisterMapping {
        register: unicorn::RegisterX86::RBX,
        name: "rbx",
    },
    RegisterMapping {
        register: unicorn::RegisterX86::RCX,
        name: "rcx",
    },
    RegisterMapping {
        register: unicorn::RegisterX86::RDX,
        name: "rdx",
    },
    RegisterMapping {
        register: unicorn::RegisterX86::RDI,
        name: "rdi",
    },
    RegisterMapping {
        register: unicorn::RegisterX86::RSI,
        name: "rsi",
    },
    RegisterMapping {
        register: unicorn::RegisterX86::R8,
        name: "r8",
    },
    RegisterMapping {
        register: unicorn::RegisterX86::R9,
        name: "r9",
    },
    RegisterMapping {
        register: unicorn::RegisterX86::R10,
        name: "r10",
    },
    RegisterMapping {
        register: unicorn::RegisterX86::R11,
        name: "r11",
    },
    RegisterMapping {
        register: unicorn::RegisterX86::R12,
        name: "r12",
    },
    RegisterMapping {
        register: unicorn::RegisterX86::R13,
        name: "r13",
    },
    RegisterMapping {
        register: unicorn::RegisterX86::R14,
        name: "r14",
    },
    RegisterMapping {
        register: unicorn::RegisterX86::R15,
        name: "r15",
    },
    RegisterMapping {
        register: unicorn::RegisterX86::RBP,
        name: "rbp",
    },
    RegisterMapping {
        register: unicorn::RegisterX86::RSP,
        name: "rsp",
    },
];

fn make_emu(mut driver: Driver) -> Result<(Driver, CpuX86)> {
    // create the emu emulator
    let mode = unicorn::Mode::MODE_64 as i32;
    let mode = unsafe { ::std::mem::transmute::<i32, unicorn::Mode>(mode) };
    let emu = CpuX86::new(mode).expect("Failed to initialize unicorn engine");

    trace!("Unicorn engine created");

    // We need to track the pages we map, because we can't map a page twice
    let mut mapped_pages: HashSet<u64> = HashSet::new();

    let page_addresses: HashSet<u64> = driver
        .state()
        .memory()
        .pages()
        .into_iter()
        .map(|(address, _)| address)
        .collect::<HashSet<u64>>();

    // set up memory
    for address in &page_addresses {
        if mapped_pages.contains(address) {
            continue;
        }
        mapped_pages.insert(*address);

        let mut length = crate::executor::PAGE_SIZE as u64;
        loop {
            if page_addresses.contains(&(address + length))
                && !mapped_pages.contains(&(address + length))
            {
                mapped_pages.insert(*address + length);
                length += crate::executor::PAGE_SIZE as u64;
            } else {
                break;
            }
        }

        emu.mem_map(*address, length as usize, unicorn::Protection::ALL)
            .expect(&format!("Failed to map memory 0x{:x}", address));
    }

    // println!("memory pages mapped");

    if let Some(backing) = driver.state().memory().backing() {
        for (address, section) in backing.sections() {
            let length = if section.len() % 0x1000 > 0 {
                (section.len() + 0x1000) & (!0xfff)
            } else {
                section.len()
            };

            let mut map_address = *address;
            let mut map_length = length;

            if map_address % 0x1000 > 0 {
                map_address = map_address & (!0xfff);
                map_length += 0x1000;
            }

            // Mapping lots of 0x1000 pages is slow, so we're going to first
            // try 0x10000 increments, and default back to 0x1000
            let mut i: u64 = 0;
            while i < map_length as u64 {
                let large_increment = !(0..16)
                    .into_iter()
                    .any(|j| mapped_pages.contains(&(map_address + i + (j * 0x1000))));

                if large_increment {
                    emu.mem_map(map_address + i, 0x10000, unicorn::Protection::ALL)
                        .expect("Failed to map memory");
                    for j in 0..16 {
                        mapped_pages.insert(map_address + i + (j * 0x1000));
                    }
                } else {
                    for j in 0..16 {
                        if mapped_pages.contains(&(map_address + i + (j * 0x1000))) {
                            continue;
                        }
                        emu.mem_map(
                            map_address + i + (j * 0x1000),
                            0x1000,
                            unicorn::Protection::ALL,
                        )
                        .expect(&format!(
                            "Failed to map memory 0x{:x}",
                            map_address + i + (j * 0x1000)
                        ));
                        mapped_pages.insert(map_address + i + (j * 0x1000));
                    }
                }
                i = i + 0x10000;
            }

            // println!("Write at 0x{:08x}, len=0x{:x}", address, section.data().len());
            emu.mem_write(*address, section.data())
                .expect(&format!("Failed to write memory at 0x{:x}", address));
        }
    }

    trace!("memory backing mapped");

    let state = driver.state().clone();
    let state_translator = StateTranslator::new(state);

    for (address, _) in driver.state().memory().pages() {
        for i in 0..crate::executor::PAGE_SIZE {
            if let Some(byte) = state_translator.get_u8(address + i as u64) {
                emu.mem_write(address + i as u64, &[byte]).expect(&format!(
                    "Failed to write 0x{:02x} at 0x{:x}",
                    byte, address
                ));
            }
        }
    }

    let mut state: State = state_translator.into();

    // initialize all our registers
    for register_mapping in REGISTER_MAPPINGS {
        let value = state.eval_and_concretize(&il::expr_scalar(register_mapping.name, 64))?;
        match value {
            Some(value) => emu
                .reg_write(
                    register_mapping.register.clone(),
                    value.value_u64().unwrap(),
                )
                .expect("Failed to write register"),
            None => emu
                .reg_write(register_mapping.register.clone(), 0)
                .expect("Failed to write register"),
        };
    }

    // including the pc register
    emu.reg_write(
        unicorn::RegisterX86::RIP,
        driver
            .instruction()
            .expect("Failed to get instruction to start unicorn stepping")
            .address()
            .expect("Failed to get address of instruction to start unicorn stepping"),
    )
    .expect("Failed to write PC register");

    // driver takes this state
    *driver.state_mut() = state;

    trace!("make emu complete");

    Ok((driver, emu))
}

fn panic_step(emu: &mut CpuX86, steps: usize) {
    let pc = emu
        .reg_read(unicorn::RegisterX86::RIP)
        .expect("Failed to get PC register");

    // println!("panic_step: 0x{:08x}", pc);

    match emu.emu_start(pc, 0, 0, steps) {
        Ok(_) => {}
        Err(err) => match err {
            unicorn::Error::OK => panic!("Qemu Error OK {}", err as i32),
            _ => panic!("Qemu error {:?}", err),
        },
    }
}

pub fn step_with_unicorn(driver: Driver, steps: usize) -> Result<()> {
    let (mut driver, mut emu) = make_emu(driver)?;

    let debug = false;

    // Dump the initial stack
    // for i in 0..(0x200 / 16) {
    //     let line_address = 0xBFF000000000 + (i * 16);
    //     println!(
    //         "0x{:016x}: {} {}",
    //         line_address,
    //         crate::executor::simplify(&driver.state().memory().load(line_address, 64)?.unwrap())?,
    //         crate::executor::simplify(
    //             &driver.state().memory().load(line_address + 8, 64)?.unwrap()
    //         )?
    //     );
    // }

    for step in 0..steps {
        panic_step(&mut emu, 1);

        // if driver.address().unwrap_or(0) == 0x4001a6c5 {
        //     let driver = driver.step()?.pop().unwrap();
        //     panic!("{}", driver.state().scalar("temp_0.0").unwrap());
        // }

        let mut step_over = false;
        if let Some(instruction) = driver.instruction() {
            match instruction.operation() {
                il::Operation::Intrinsic { intrinsic } => {
                    if intrinsic.mnemonic() == "cpuid"
                        || intrinsic.mnemonic() == "rdtsc"
                        || intrinsic.mnemonic() == "syscall"
                    {
                        step_over = true;
                    }
                }
                _ => {}
            }
        }

        if step_over {
            let mut drivers = driver.step()?;
            driver = drivers.pop().unwrap();
            let (d, e) = make_emu(driver)?;
            driver = d;
            emu = e;
            continue;
        }

        // get the new pc
        let pc = emu
            .reg_read(unicorn::RegisterX86::RIP)
            .expect("Failed to get PC register");

        if debug {
            println!("pc=0x{:08x}, step={}", pc, step);
        }

        // step the driver until it hits this address
        for _ in 0..256 {
            let mut drivers = driver.step()?;
            if drivers.len() != 1 {
                bail!("Drivers len != 1");
            }
            driver = drivers.pop().unwrap();

            if debug {
                println!("{}", driver.location().apply(driver.program())?);
            }

            if let Some(instruction) = driver.instruction() {
                match instruction.operation() {
                    il::Operation::Branch { .. } => {
                        // println!("Branch");
                    }
                    _ => {}
                }
            }
            if driver
                .address()
                .map(|address| address == pc)
                .unwrap_or(false)
            {
                break;
            }
        }

        // make sure address matches
        if !driver
            .address()
            .map(|address| address == pc)
            .unwrap_or(false)
        {
            println!(
                "unicorn-pc=0x{:08x}, driver-address={:?}, step={}",
                pc,
                driver.address(),
                step
            );
            println!("{}", driver.location().apply(driver.program())?);
            panic!("Driver address does not match");
        }

        // verify registers
        for register_mapping in REGISTER_MAPPINGS {
            if let Some(value) = driver
                .state()
                .scalar(register_mapping.name)
                .and_then(|expr| driver.state().symbolize_and_eval(&expr).unwrap())
            {
                let unicorn_value = emu
                    .reg_read(register_mapping.register)
                    .expect("Failed to read x86 register");
                if debug {
                    println!(
                        "  {} unicorn=0x{:08x} finch=0x{:08x}",
                        register_mapping.name,
                        unicorn_value,
                        value.value_u64().unwrap()
                    );
                }
                if value.value_u64().unwrap() != unicorn_value {
                    panic!("Register mismatch, step={}", step);
                }
            }
        }
        // println!(
        //     "  ZF={} CF={} SF={} OF={}",
        //     driver.state().scalar("ZF").unwrap_or(il::expr_const(0, 1)),
        //     driver.state().scalar("CF").unwrap_or(il::expr_const(0, 1)),
        //     driver.state().scalar("SF").unwrap_or(il::expr_const(0, 1)),
        //     driver.state().scalar("OF").unwrap_or(il::expr_const(0, 1))
        // );
    }

    Ok(())
}
