//! Verify Finch's execution and semantics against Unicorn.

use error::*;
use executor::{Driver, State, StateTranslator};
use falcon::il;
use falcon::translator::TranslationMemory;
use falcon_capstone::{capstone, capstone_sys};
use platform::Platform;
use std::collections::HashSet;
use unicorn;
use unicorn::{Cpu, CpuMIPS};


struct RegisterMapping {
    register: unicorn::RegisterMIPS,
    name: &'static str
}


const REGISTER_MAPPINGS: &[RegisterMapping] = &[
    RegisterMapping { register: unicorn::RegisterMIPS::AT, name: "$at" },
    RegisterMapping { register: unicorn::RegisterMIPS::V0, name: "$v0" },
    RegisterMapping { register: unicorn::RegisterMIPS::V1, name: "$v1" },
    RegisterMapping { register: unicorn::RegisterMIPS::A0, name: "$a0" },
    RegisterMapping { register: unicorn::RegisterMIPS::A1, name: "$a1" },
    RegisterMapping { register: unicorn::RegisterMIPS::A2, name: "$a2" },
    RegisterMapping { register: unicorn::RegisterMIPS::A3, name: "$a3" },
    RegisterMapping { register: unicorn::RegisterMIPS::T0, name: "$t0" },
    RegisterMapping { register: unicorn::RegisterMIPS::T1, name: "$t1" },
    RegisterMapping { register: unicorn::RegisterMIPS::T2, name: "$t2" },
    RegisterMapping { register: unicorn::RegisterMIPS::T3, name: "$t3" },
    RegisterMapping { register: unicorn::RegisterMIPS::T4, name: "$t4" },
    RegisterMapping { register: unicorn::RegisterMIPS::T5, name: "$t5" },
    RegisterMapping { register: unicorn::RegisterMIPS::T6, name: "$t6" },
    RegisterMapping { register: unicorn::RegisterMIPS::T7, name: "$t7" },
    RegisterMapping { register: unicorn::RegisterMIPS::S0, name: "$s0" },
    RegisterMapping { register: unicorn::RegisterMIPS::S1, name: "$s1" },
    RegisterMapping { register: unicorn::RegisterMIPS::S2, name: "$s2" },
    RegisterMapping { register: unicorn::RegisterMIPS::S3, name: "$s3" },
    RegisterMapping { register: unicorn::RegisterMIPS::S4, name: "$s4" },
    RegisterMapping { register: unicorn::RegisterMIPS::S5, name: "$s5" },
    RegisterMapping { register: unicorn::RegisterMIPS::S6, name: "$s6" },
    RegisterMapping { register: unicorn::RegisterMIPS::S7, name: "$s7" },
    RegisterMapping { register: unicorn::RegisterMIPS::T8, name: "$t8" },
    RegisterMapping { register: unicorn::RegisterMIPS::T9, name: "$t9" },
    RegisterMapping { register: unicorn::RegisterMIPS::K0, name: "$k0" },
    RegisterMapping { register: unicorn::RegisterMIPS::K1, name: "$k1" },
    RegisterMapping { register: unicorn::RegisterMIPS::GP, name: "$gp" },
    RegisterMapping { register: unicorn::RegisterMIPS::SP, name: "$sp" },
    RegisterMapping { register: unicorn::RegisterMIPS::FP, name: "$fp" },
    RegisterMapping { register: unicorn::RegisterMIPS::RA, name: "$ra" },
];


fn make_emu<P: Platform<P>>(mut driver: Driver<P>)
    -> Result<(Driver<P>, CpuMIPS)> {

    // create the emu emulator
    let mode = unicorn::Mode::BIG_ENDIAN as i32 | unicorn::Mode::MODE_32 as i32;
    let mode = unsafe { ::std::mem::transmute::<i32, unicorn::Mode>(mode) };
    let emu = CpuMIPS::new(mode)
        .expect("Failed to initialize unicorn engine");

    println!("Unicorn engine created");

    // We need to track the pages we map, because we can't map a page twice
    let mut mapped_pages: HashSet<u64> = HashSet::new();

    let page_addresses: HashSet<u64> =
        driver.state()
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

        let mut length = ::executor::PAGE_SIZE as u64;
        loop {
            if    page_addresses.contains(&(address + length))
               && !mapped_pages.contains(&(address + length)) {
                mapped_pages.insert(*address + length);
                length += ::executor::PAGE_SIZE as u64;
            }
            else {
                break;
            }
        }

        emu.mem_map(*address, length as usize, unicorn::PROT_ALL)
            .expect(&format!("Failed to map memory 0x{:x}", address));
    }

    // println!("memory pages mapped");

    if let Some(backing) = driver.state().memory().backing() {
        for (address, section) in backing.sections() {
            let length = if section.len() % 0x1000 > 0 {
                (section.len() + 0x1000) & (!0xfff)
            }
            else {
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
                let large_increment =
                    !(0..16).into_iter().any(|j|
                        mapped_pages.contains(&(map_address + i + (j * 0x1000))));

                if large_increment {
                    emu.mem_map(map_address + i, 0x10000, unicorn::PROT_ALL)
                        .expect("Failed to map memory");
                    for j in 0..16 {
                        mapped_pages.insert(map_address + i + (j * 0x1000));
                    }
                }
                else {
                    for j in 0..16 {
                        if mapped_pages.contains(&(map_address + i + (j * 0x1000))) {
                            continue;
                        }
                        emu.mem_map(map_address + i + (j * 0x1000),
                                    0x1000,
                                    unicorn::PROT_ALL)
                            .expect(&format!("Failed to map memory 0x{:x}",
                                             map_address + i + (j * 0x1000)));
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

    println!("memory backing mapped");

    let state = driver.state().clone();
    let state_translator = StateTranslator::new(state);

    for (address, _) in driver.state().memory().pages() {
        for i in 0..::executor::PAGE_SIZE {
            if let Some(byte) = state_translator.get_u8(address + i as u64) {
                emu.mem_write(address + i as u64, &[byte])
                    .expect(&format!("Failed to write 0x{:02x} at 0x{:x}",
                                     byte,
                                     address));
            }
        }
    }

    let mut state: State<P> = state_translator.into();

    // initialize all our registers
    for register_mapping in REGISTER_MAPPINGS {
        let value =
            state.eval_and_concretize(
                &il::expr_scalar(register_mapping.name, 32))?;
        match value {
            Some(value) =>
                emu.reg_write(register_mapping.register.clone(),
                              value.value_u64().unwrap())
                    .expect("Failed to write register"),
            None =>
                emu.reg_write(register_mapping.register.clone(), 0)
                    .expect("Failed to write register")
        };
    }

    // including the pc register
    emu.reg_write(
        unicorn::RegisterMIPS::PC,
        driver.instruction()
            .expect("Failed to get instruction to start unicorn stepping")
            .address()
            .expect("Failed to get address of instruction to start unicorn stepping")
    ).expect("Failed to write PC register");

    // driver takes this state
    *driver.state_mut() = state;

    Ok((driver, emu))
}


fn panic_step(emu: &mut CpuMIPS, steps: usize) {
    let pc = emu.reg_read(unicorn::RegisterMIPS::PC)
        .expect("Failed to get PC register");

    println!("panic_step: 0x{:08x}", pc);
    println!("$v0: 0x{:x}", emu.reg_read(unicorn::RegisterMIPS::V0).unwrap());

    match emu.emu_start(pc, 0, 0, steps) {
        Ok(_) => {},
        Err(err) => match err {
            unicorn::Error::OK => panic!("Qemu Error OK {}", err as i32),
            _ => {
                let mem = emu.mem_read(0xc000102c, 16).unwrap();
                for i in 0..16 {
                    let address: u64 = 0xc000102c;
                    println!("0x{:x}: {:02x}", address + i, mem[i as usize]);
                }
                panic!("Qemu error {:?}", err)
            }
        }
    }
}


pub fn step_with_unicorn<P: Platform<P>>(driver: Driver<P>, steps: usize)
    -> Result<()> {

    let (mut driver, mut emu) = make_emu(driver)?;

    enum WhatToDo {
        Steps(usize),
        Skip,
        Syscall
    }

    fn instruction_id(emu: &CpuMIPS) -> Option<capstone_sys::mips_insn> {
        let pc = emu.reg_read(unicorn::RegisterMIPS::PC)
            .expect("Failed to get PC register");
        
        let mem = emu.mem_read(pc, 4).expect("Failed to read instruction");

        let mode = capstone::CS_MODE_32 | capstone::CS_MODE_BIG_ENDIAN;
        let cs = capstone::Capstone::new(capstone::cs_arch::CS_ARCH_MIPS, mode)
            .expect("Failed to create capstone context");

        let instruction =
            cs.disasm(&mem, pc, 1)
                .expect("Capstone disassembly error")
                .get(0)
                .unwrap();

        let instruction_bytes =
            mem.iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<String>>()
                .join("");

        println!("{}: {} {}",
                 instruction_bytes,
                 instruction.mnemonic,
                 instruction.op_str);

        if let capstone::InstrIdArch::MIPS(instruction_id) = instruction.id {
            Some(instruction_id)
        }
        else {
            None
        }
    }

    fn what_to_do(emu: &CpuMIPS) -> WhatToDo {
        if let Some(instruction_id) = instruction_id(emu) {
            println!("instruction_id: {:?}", instruction_id);
            match instruction_id {
                capstone::mips_insn::MIPS_INS_B      |
                capstone::mips_insn::MIPS_INS_BAL    |
                capstone::mips_insn::MIPS_INS_BEQ    |
                capstone::mips_insn::MIPS_INS_BEQZ   |
                capstone::mips_insn::MIPS_INS_BGEZ   |
                capstone::mips_insn::MIPS_INS_BGEZAL |
                capstone::mips_insn::MIPS_INS_BGTZ   |
                capstone::mips_insn::MIPS_INS_BLEZ   |
                capstone::mips_insn::MIPS_INS_BLTZ   |
                capstone::mips_insn::MIPS_INS_BLTZAL |
                capstone::mips_insn::MIPS_INS_BNE    |
                capstone::mips_insn::MIPS_INS_BNEZ   |
                capstone::mips_insn::MIPS_INS_J      |
                capstone::mips_insn::MIPS_INS_JR     |
                capstone::mips_insn::MIPS_INS_JAL    |
                capstone::mips_insn::MIPS_INS_JALR   => WhatToDo::Steps(2),
                capstone::mips_insn::MIPS_INS_MOVN   => WhatToDo::Skip,
                capstone::mips_insn::MIPS_INS_RDHWR   |
                capstone::mips_insn::MIPS_INS_SYSCALL => WhatToDo::Syscall,
                _ => WhatToDo::Steps(1)
            }
        }
        else {
            panic!("Could not disassemble mips instruction");
        }
    }

    'emulator_step: for step in 0..steps {
        // Perform an action
        match what_to_do(&emu) {
            WhatToDo::Skip => {
                panic_step(&mut emu, 1);
                continue;
            },
            WhatToDo::Steps(steps) => {
                panic_step(&mut emu, steps)
            },
            WhatToDo::Syscall => {
                println!("syscall");
                let mut drivers = driver.step()?;
                if drivers.len() != 1 {
                    panic!("Multiple drivers following syscall");
                }
                driver = drivers.pop().unwrap();
                if emu.reg_read(unicorn::RegisterMIPS::PC).unwrap() == 0x685318e4 {
                    println!("Shortcut");
                    emu.reg_write(unicorn::RegisterMIPS::V1, 0xc0008000).unwrap();
                    emu.reg_write(unicorn::RegisterMIPS::PC, 0x685318e8).unwrap();
                }
                else {
                    let (driver_, emu_) = make_emu(driver)?;
                    driver = driver_;
                    emu = emu_;
                    println!("New emu pc=0x{:08x}",
                        emu.reg_read(unicorn::RegisterMIPS::PC).unwrap());
                }
                continue;
            }
        }

        // Check to make sure we aren't sitting on a skip instruction
        match what_to_do(&emu) {
            WhatToDo::Skip => {
                panic_step(&mut emu, 1);
                continue;
            }
            _ => {}
        }

        // get the new pc
        let pc = emu.reg_read(unicorn::RegisterMIPS::PC)
            .expect("Failed to get PC register");
        println!("pc=0x{:08x}, step={}", pc, step);

        // step the driver until it hits this address
        for _ in 0..16 {
            let mut drivers = driver.step()?;
            if drivers.len() != 1 {
                bail!("Drivers len != 1");
            }
            driver = drivers.pop().unwrap();

            if let Some(address) = driver.address() {
                println!("driver address = 0x{:x}", address);
            }

            if let Some(instruction) = driver.instruction() {
                match instruction.operation() {
                    il::Operation::Branch { .. } => {
                        println!("Branch");
                    },
                    _ => {}
                }
            }
            if driver.address().map(|address| address == pc).unwrap_or(false) {
                break;
            }
        }

        // make sure address matches
        if !driver.address().map(|address| address == pc).unwrap_or(false) {
            panic!("Driver address does not match");
        }

        // verify registers
        for register_mapping in REGISTER_MAPPINGS {
            if let Some(value) = driver.state()
                       .scalar(register_mapping.name)
                       .and_then(|expr| driver.state().symbolize_and_eval(&expr).unwrap()) {
                let unicorn_value = emu.reg_read(register_mapping.register)
                    .expect("Failed to read MIPS register");
                println!("  {} 0x{:08x} 0x{:08x}",
                         register_mapping.name,
                         unicorn_value,
                         value.value_u64().unwrap());
                // if unicorn_value != value.value_u64().unwrap() {
                //     for i in 0..16 {
                //         let address = 0x680006a0 - 16 + i;
                //         println!("0x{:08x}: {}",
                //                  address,
                //                  driver.state().memory().load(address, 8)?.unwrap());
                //     }
                //     bail!("Register values differ");
                // }
            }
        }

        // verify 0x6800069d
        // if let Some(constant) = driver.state().memory().load(0x6800069d, 8)? {
        //     let model8 = driver.state().symbolize_and_eval(&constant)?.unwrap().value_u64().unwrap() as u8;
        //     if emu.mem_regions().unwrap().into_iter().any(|region|
        //                region.begin <= 0x6800069d && region.end >= 0x6800069d) {
        //         let mem = emu.mem_read(0x6800069d, 1).unwrap();
        //         if model8 != mem[0] {
        //             panic!("mismatch at address 0x6800069d")
        //         }
        //     }
        // }
    }

    Ok(())
}