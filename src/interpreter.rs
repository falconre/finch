use crate::debugger::Debugger;
use crate::error::*;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use nom::{alt, map_res, named, tag, take_while1, tuple};

#[derive(Clone, Debug)]
pub enum Command {
    AddBreakpoint(u64),
    AddKillPoint(u64),
    Continue(usize),
    CullDrivers,
    DeleteBreakpoints,
    // A placeholder for empty or comment lines when reading from a file
    Empty,
    Flatten,
    Help,
    InfoBreakpoints,
    InfoDrivers,
    InfoKillPoints,
    Quit,
}

fn map_address(input: &str) -> ::std::result::Result<u64, ::std::num::ParseIntError> {
    u64::from_str_radix(input, 16)
}

fn map_decimal_u64(input: &str) -> ::std::result::Result<u64, ::std::num::ParseIntError> {
    input.parse::<u64>()
}

fn is_hex_digit(c: char) -> bool {
    matches!(c, '0'..='9' | 'a'..='f' | 'A'..='F')
}

fn is_decimal_digit(c: char) -> bool {
    matches!(c, '0'..='9')
}

named!(parse_hex_u64<&str, u64>, alt!(
    tuple!(
        tag!("0x"),
        map_res!(take_while1!(is_hex_digit), map_address)
    ) => { |(_, value)| value }
));

named!(parse_decimal_u64<&str, u64>,
    map_res!(take_while1!(is_decimal_digit), map_decimal_u64)
);

named!(parse_u64<&str, u64>, alt!(
    parse_hex_u64 |
    parse_decimal_u64
));

fn is_space(c: char) -> bool {
    matches!(c, ' ' | '\t')
}

named!(parse_info<&str, Command>, alt!(
    alt!(tag!("breakpoints") | tag!("b")) => {|_| Command::InfoBreakpoints} |
    alt!(tag!("drivers") | tag!("d")) => {|_| Command::InfoDrivers} |
    alt!(tag!("killpoints") | tag!("k")) => {|_| Command::InfoKillPoints}
));

named!(parse_delete<&str, Command>, alt!(
    alt!(tag!("breakpoints") | tag!("b")) => { |_| Command::DeleteBreakpoints }
));

named!(parse_command <&str, Command>, alt!(
    tuple!(
        alt!(tag!("breakpoint") | tag!("b")),
        take_while1!(is_space),
        parse_u64
    ) => { |(_, _, address)|
        Command::AddBreakpoint(address)
    } |

    tuple!(
        alt!( tag!("continue") | tag!("c")),
        take_while1!(is_space),
        parse_u64
    ) => { |(_, _, address)|
        Command::Continue(address as usize)
    } |

    tag!("cull") => { |_| Command::CullDrivers } |

    tuple!(
        alt!(tag!("delete") | tag!("d")),
        take_while1!(is_space),
        parse_delete
    ) => {|(_, _, command)| command } |

    tag!("flatten") => { |_| Command::Flatten } |

    alt!(tag!("help") | tag!("h")) => { |_| Command::Help } |

    tuple!(
        alt!(tag!("info") | tag!("i")),
        take_while1!(is_space),
        parse_info
    ) => { |(_, _, command)| command } |

    tuple!(
        alt!(tag!("killpoint") | tag!("k")),
        take_while1!(is_space),
        parse_u64
    ) => { |(_, _, address)|
        Command::AddKillPoint(address)
    } |

    alt!(tag!("quit") | tag!("q")) => { |_| Command::Quit }
));

pub struct Interpreter {
    debugger: Debugger,
}

impl Interpreter {
    pub fn new(debugger: Debugger) -> Interpreter {
        Interpreter { debugger }
    }

    pub fn script(&mut self, filename: &Path) -> Result<()> {
        let mut file = File::open(filename)?;

        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        for line in contents.lines() {
            if line.is_empty() {
                continue;
            }
            let command = match parse_command(line) {
                Ok(command) => command.1,
                Err(e) => {
                    eprintln!("{}", e);
                    continue;
                }
            };

            match command {
                Command::Quit => break,
                _ => self.execute(command)?,
            }
        }

        Ok(())
    }

    pub fn interactive(&mut self) -> Result<()> {
        let mut rl = rustyline::Editor::<()>::new();

        'debugger_loop: loop {
            let line = rl.readline("> ")?;
            rl.add_history_entry(&line);

            let command = match parse_command(&line) {
                Ok(command) => command.1,
                Err(e) => {
                    eprintln!("{}", e);
                    continue 'debugger_loop;
                }
            };

            match command {
                Command::Quit => break 'debugger_loop,
                _ => self.execute(command)?,
            }
        }

        Ok(())
    }

    pub fn execute(&mut self, command: Command) -> Result<()> {
        match command {
            Command::AddBreakpoint(address) => {
                self.debugger.push_breakpoint(address);
                println!("Breakpoint 0x{:x} added", address);
            }
            Command::AddKillPoint(address) => {
                self.debugger.push_killpoint(address);
                println!("Killpoint 0x{:x} added", address);
            }
            Command::Continue(steps) => {
                println!("Continuing {} steps", steps);
                self.debugger.continue_(steps)?
            }
            Command::CullDrivers => {
                println!("Drivers culled");
                self.debugger.cull_drivers()
            }
            Command::DeleteBreakpoints => {
                self.debugger.delete_breakpoints();
                self.debugger.unbreak_drivers();
                println!("All breakpoints deleted");
            }
            Command::Flatten => {
                self.debugger.flatten()?;
            }
            Command::Help => {
                println!("commands: help, quit");
            }
            Command::InfoBreakpoints => {
                println!("{} breakpoints", self.debugger.breakpoints().len());
                for breakpoint in self.debugger.breakpoints() {
                    println!("  0x{:x}", breakpoint);
                }
            }
            Command::InfoDrivers => {
                println!(
                    "There are {} regular drivers",
                    self.debugger.drivers().len()
                );
                println!(
                    "There are {} breaked drivers",
                    self.debugger.breaked_drivers().len()
                );
                println!(
                    "There are {} merged drivers",
                    self.debugger.merged_drivers().len()
                )
            }
            Command::InfoKillPoints => {
                println!("{} killpoints", self.debugger.killpoints().len());
                for killpoint in self.debugger.killpoints() {
                    println!("  0x{:x}", killpoint);
                }
            }
            Command::Empty | Command::Quit => {}
        }

        Ok(())
    }
}
