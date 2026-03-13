use crate::debugger::Debugger;
use crate::error::*;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use nom::{
    branch::alt,
    bytes::complete::{tag, take_while1},
    combinator::map_res,
    IResult, Parser,
};

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
    c.is_ascii_hexdigit()
}

fn is_decimal_digit(c: char) -> bool {
    c.is_ascii_digit()
}

fn parse_hex_u64(input: &str) -> IResult<&str, u64> {
    let (input, (_, value)) =
        (tag("0x"), map_res(take_while1(is_hex_digit), map_address)).parse(input)?;
    Ok((input, value))
}

fn parse_decimal_u64(input: &str) -> IResult<&str, u64> {
    map_res(take_while1(is_decimal_digit), map_decimal_u64).parse(input)
}

fn parse_u64(input: &str) -> IResult<&str, u64> {
    alt((parse_hex_u64, parse_decimal_u64)).parse(input)
}

fn is_space(c: char) -> bool {
    matches!(c, ' ' | '\t')
}

fn parse_info(input: &str) -> IResult<&str, Command> {
    alt((
        |i| {
            alt((tag("breakpoints"), tag("b")))
                .parse(i)
                .map(|(r, _)| (r, Command::InfoBreakpoints))
        },
        |i| {
            alt((tag("drivers"), tag("d")))
                .parse(i)
                .map(|(r, _)| (r, Command::InfoDrivers))
        },
        |i| {
            alt((tag("killpoints"), tag("k")))
                .parse(i)
                .map(|(r, _)| (r, Command::InfoKillPoints))
        },
    ))
    .parse(input)
}

fn parse_delete(input: &str) -> IResult<&str, Command> {
    let (input, _) = alt((tag("breakpoints"), tag("b"))).parse(input)?;
    Ok((input, Command::DeleteBreakpoints))
}

fn parse_command(input: &str) -> IResult<&str, Command> {
    alt((
        |i| {
            let (i, (_, _, address)) = (
                alt((tag("breakpoint"), tag("b"))),
                take_while1(is_space),
                parse_u64,
            )
                .parse(i)?;
            Ok((i, Command::AddBreakpoint(address)))
        },
        |i| {
            let (i, (_, _, address)) = (
                alt((tag("continue"), tag("c"))),
                take_while1(is_space),
                parse_u64,
            )
                .parse(i)?;
            Ok((i, Command::Continue(address as usize)))
        },
        |i| {
            let (i, _) = tag("cull").parse(i)?;
            Ok((i, Command::CullDrivers))
        },
        |i| {
            let (i, (_, _, command)) = (
                alt((tag("delete"), tag("d"))),
                take_while1(is_space),
                parse_delete,
            )
                .parse(i)?;
            Ok((i, command))
        },
        |i| {
            let (i, _) = tag("flatten").parse(i)?;
            Ok((i, Command::Flatten))
        },
        |i| {
            let (i, _) = alt((tag("help"), tag("h"))).parse(i)?;
            Ok((i, Command::Help))
        },
        |i| {
            let (i, (_, _, command)) = (
                alt((tag("info"), tag("i"))),
                take_while1(is_space),
                parse_info,
            )
                .parse(i)?;
            Ok((i, command))
        },
        |i| {
            let (i, (_, _, address)) = (
                alt((tag("killpoint"), tag("k"))),
                take_while1(is_space),
                parse_u64,
            )
                .parse(i)?;
            Ok((i, Command::AddKillPoint(address)))
        },
        |i| {
            let (i, _) = alt((tag("quit"), tag("q"))).parse(i)?;
            Ok((i, Command::Quit))
        },
    ))
    .parse(input)
}

pub struct Interpreter {
    debugger: Debugger,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex_u64() {
        let (_, val) = parse_hex_u64("0xff").unwrap();
        assert_eq!(val, 255);
        let (_, val) = parse_hex_u64("0xDEAD").unwrap();
        assert_eq!(val, 0xDEAD);
    }

    #[test]
    fn test_parse_decimal_u64() {
        let (_, val) = parse_decimal_u64("42").unwrap();
        assert_eq!(val, 42);
        let (_, val) = parse_decimal_u64("0").unwrap();
        assert_eq!(val, 0);
    }

    #[test]
    fn test_parse_u64_hex_and_decimal() {
        let (_, val) = parse_u64("0x10").unwrap();
        assert_eq!(val, 16);
        let (_, val) = parse_u64("10").unwrap();
        assert_eq!(val, 10);
    }

    #[test]
    fn test_parse_command_breakpoint() {
        let (_, cmd) = parse_command("b 0x1000").unwrap();
        assert!(matches!(cmd, Command::AddBreakpoint(0x1000)));
    }

    #[test]
    fn test_parse_command_continue() {
        let (_, cmd) = parse_command("c 10").unwrap();
        assert!(matches!(cmd, Command::Continue(10)));
    }

    #[test]
    fn test_parse_command_quit() {
        let (_, cmd) = parse_command("q").unwrap();
        assert!(matches!(cmd, Command::Quit));
        let (_, cmd) = parse_command("quit").unwrap();
        assert!(matches!(cmd, Command::Quit));
    }

    #[test]
    fn test_parse_command_help() {
        let (_, cmd) = parse_command("h").unwrap();
        assert!(matches!(cmd, Command::Help));
        let (_, cmd) = parse_command("help").unwrap();
        assert!(matches!(cmd, Command::Help));
    }

    #[test]
    fn test_parse_command_info() {
        let (_, cmd) = parse_command("i breakpoints").unwrap();
        assert!(matches!(cmd, Command::InfoBreakpoints));
        let (_, cmd) = parse_command("i d").unwrap();
        assert!(matches!(cmd, Command::InfoDrivers));
    }

    #[test]
    fn test_parse_command_cull() {
        let (_, cmd) = parse_command("cull").unwrap();
        assert!(matches!(cmd, Command::CullDrivers));
    }

    #[test]
    fn test_parse_command_flatten() {
        let (_, cmd) = parse_command("flatten").unwrap();
        assert!(matches!(cmd, Command::Flatten));
    }
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
        let mut rl = rustyline::Editor::<(), rustyline::history::DefaultHistory>::new()?;

        'debugger_loop: loop {
            let line = rl.readline("> ")?;
            let _ = rl.add_history_entry(&line);

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
