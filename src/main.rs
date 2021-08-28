#![recursion_limit = "128"]

#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate log;

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
            Falcon(::falcon::error::Error);
            Finch(::finch::error::Error);
            IoError(::std::io::Error);
            ReadLineError(::rustyline::error::ReadlineError);
        }
    }
}

use error::*;
use falcon::loader::Loader;
use finch::executor::Driver;
use finch::platform;
use std::path::{Path, PathBuf};

fn run2(driver: Driver, matches: &clap::ArgMatches) -> Result<()> {
    if matches.is_present("debugger") {
        let debugger = debugger::Debugger::new(vec![driver]);
        let mut interpreter = interpreter::Interpreter::new(debugger);
        interpreter.interactive()
    } else if let Some(debugger_script) = matches.value_of("debugger_script") {
        let debugger = debugger::Debugger::new(vec![driver]);
        let mut interpreter = interpreter::Interpreter::new(debugger);
        interpreter.script(Path::new(debugger_script))
    } else {
        unimplemented!("Unicorn testing");
        // let driver = driver::drive_to_address(driver, 0x1000, 1000000)?
        //     .get(0)
        //     .unwrap()
        //     .clone();
        // unimplemented!("unicorn testing");
        // info!("Being unicorn testing");
        // Ok(finch::unicorn_verify_amd64::step_with_unicorn(
        //     driver, 100000,
        // )?)
    }
}

fn run() -> Result<()> {
    let matches = clap::App::new("finch")
        .version("0.1.0")
        .about("Falcon Symbolic Executor")
        .author("Alex Eubanks")
        .arg(
            clap::Arg::with_name("filename")
                .short("f")
                .value_name("FILE")
                .help("Binary to symbolically execute")
                .required(true),
        )
        .arg(
            clap::Arg::with_name("base_path")
                .short("b")
                .value_name("BASE_PATH")
                .help("Base path of filesystem")
                .required(true),
        )
        .arg(
            clap::Arg::with_name("debugger")
                .short("d")
                .help("Start the interactive debugger"),
        )
        .arg(
            clap::Arg::with_name("debugger_script")
                .short("x")
                .long("debugger_script")
                .value_name("DEBUGGER_SCRIPT")
                .conflicts_with("debugger")
                .help("Give a file filled with debugger command"),
        )
        .arg(
            clap::Arg::with_name("log")
                .short("l")
                .long("log")
                .value_name("LOG_LEVEL")
                .help("Log level"),
        )
        .get_matches();

    let filename = matches.value_of("filename").unwrap();

    let base_path: Option<PathBuf> = matches
        .value_of("base_path")
        .map(|base_path| base_path.into());

    if let Some(log_level) = matches.value_of("log") {
        let level_filter = match log_level {
            "debug" => Some(simplelog::LevelFilter::Debug),
            "info" => Some(simplelog::LevelFilter::Info),
            "trace" => Some(simplelog::LevelFilter::Trace),
            "warn" => Some(simplelog::LevelFilter::Warn),
            "error" => Some(simplelog::LevelFilter::Error),
            _ => bail!("Invalid log level"),
        };
        if let Some(level_filter) = level_filter {
            simplelog::TermLogger::init(
                level_filter,
                simplelog::Config::default(),
                simplelog::TerminalMode::Mixed,
                simplelog::ColorChoice::Auto,
            )
            .expect("Failed to initialize logging");
        }
    }

    // let's determine the architecture of the target binary
    let elf = falcon::loader::Elf::from_file(Path::new(filename))?;

    match elf.architecture().name() {
        "amd64" => run2(
            platform::linux::Amd64::standard_load(filename, base_path)?,
            &matches,
        ),
        "mips" => run2(
            platform::linux::Mips::standard_load(filename, base_path)?,
            &matches,
        ),
        _ => bail!("Unhandled architecture: {}", elf.architecture().name()),
    }
}

fn main() {
    run().unwrap();
    // match run() {
    //     Ok(_) => {},
    //     Err(e) => {
    //         eprintln!("error: {}", e);
    //         for e in e.iter().skip(1) {
    //             eprintln!("caused by: {}", e);
    //         }
    //         if let Some(backtrace) = e.backtrace() {
    //             eprintln!("backtrace: {:?}", backtrace);
    //         }
    //     }
    // }
}
