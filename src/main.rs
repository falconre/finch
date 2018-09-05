#![recursion_limit="128"]


extern crate clap;
#[macro_use] extern crate error_chain;
extern crate falcon;
extern crate falcon_capstone;
extern crate finch;
#[macro_use] extern crate log;
#[macro_use] extern crate nom;
extern crate rayon;
extern crate rustyline;
extern crate simplelog;


// mod bindings;
pub mod debugger;
pub mod driver;
pub mod hooks;
pub mod interpreter;


pub mod error {
    error_chain! {
        types {
            Error, ErrorKind, ResultExt, Result;
        }

        foreign_links {
            Finch(::finch::error::Error);
            IoError(::std::io::Error);
            ReadLineError(::rustyline::error::ReadlineError);
        }
    }
}


use error::*;
use finch::executor;
use finch::platform;
use std::path::{Path, PathBuf};


fn quick(filename: &str, base_path: Option<PathBuf>) -> Result<()> {
    let driver = platform::linux::Mips::standard_load(filename, base_path)?;
    driver::drive_to_address(driver, 0x40107c, 4000000)?;
    Ok(())
}


fn run() -> Result<()> {
    let matches = clap::App::new("finch")
        .version("0.1.0")
        .about("Falcon Symbolic Executor")
        .author("Alex Eubanks")
        .arg(clap::Arg::with_name("filename")
            .short("f")
            .value_name("FILE")
            .help("Binary to symbolically execute")
            .required(true))
        .arg(clap::Arg::with_name("base_path")
            .short("b")
            .value_name("BASE_PATH")
            .help("Base path of filesystem")
            .required(true))
        .arg(clap::Arg::with_name("debugger")
            .short("d")
            .help("Start the interactive debugger"))
        .arg(clap::Arg::with_name("debugger_script")
            .short("x")
            .long("debugger_script")
            .value_name("DEBUGGER_SCRIPT")
            .conflicts_with("debugger")
            .help("Give a file filled with debugger command"))
        .arg(clap::Arg::with_name("log")
            .short("l")
            .long("log")
            .value_name("LOG_LEVEL")
            .help("Log level"))
        .get_matches();

    let filename = matches.value_of("filename").unwrap();

    let base_path: Option<PathBuf> = match matches.value_of("base_path") {
        Some(base_path) => Some(base_path.into()),
        None => None
    };

    if let Some(log_level) = matches.value_of("log") {
        let level_filter =
            match log_level {
                "debug" => Some(simplelog::LevelFilter::Debug),
                "info" => Some(simplelog::LevelFilter::Info),
                "trace" => Some(simplelog::LevelFilter::Trace),
                "warn" => Some(simplelog::LevelFilter::Warn),
                _ => Some(simplelog::LevelFilter::Error)
            };
        if let Some(level_filter) = level_filter {
            simplelog::TermLogger::init(
                level_filter,
                simplelog::Config::default()
            ).expect("Failed to initialize logging");
        }
    }

    if matches.is_present("debugger") {
        let driver = platform::linux::Mips::standard_load(filename, base_path)?;
        let debugger = debugger::Debugger::new(vec![driver]);
        let mut interpreter = interpreter::Interpreter::new(debugger);
        interpreter.interactive()
    }
    else if let Some(debugger_script) = matches.value_of("debugger_script") {
        let driver = platform::linux::Mips::standard_load(filename, base_path)?;
        let debugger = debugger::Debugger::new(vec![driver]);
        let mut interpreter = interpreter::Interpreter::new(debugger);
        interpreter.script(Path::new(debugger_script))
    }
    else {
        quick(filename, base_path)
    }
}


fn main() {
    match run() {
        Ok(_) => {},
        Err(e) => {
            eprintln!("error: {}", e);
            for e in e.iter().skip(1) {
                eprintln!("caused by: {}", e);
            }
            if let Some(backtrace) = e.backtrace() {
                eprintln!("backtrace: {:?}", backtrace);
            }
        }
    }
}