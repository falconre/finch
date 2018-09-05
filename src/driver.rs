use error::*;
use executor::{Driver, State, Memory};
use platform::Platform;


const MAX_DRIVER_MERGE: usize = 16;
const DRIVER_CULL_SIZE: usize = 32;


/// Drive the given driver until it hits the given driver, or until max_steps
/// has been hit.
///
/// Collects drivers once they hit the desired address
pub fn drive_to_address<P: Platform<P>>(
    driver: Driver<P>,
    target_address: u64,
    max_steps: usize
) -> Result<Vec<Driver<P>>> {
    let mut drivers = vec![driver];
    let mut final_drivers = Vec::new();

    for _step in 0..max_steps {
        if (_step & 0xfff) == 0 {
            println!("drive_to_address step={} drivers.len()={} final_drivers.len()={}",
                     _step,
                     drivers.len(),
                     final_drivers.len());
        }
        let mut step_drivers = Vec::new();
        for driver in drivers {

            // if _step > 3579904 {
            //     if let Some(instruction) =
            //             driver.location()
            //                 .apply(driver.program())
            //                 .unwrap()
            //                 .instruction() {
            //         let sp = driver.state().symbolize_and_eval(&driver.state().scalar("$sp").unwrap())?.unwrap();
            //         println!("{}, sp={}", instruction, sp);
            //     }
            // }

            // if driver.address().map(|address| address > 0x684aea00).unwrap_or(false) {
            //     println!("Address is 0x{:x}", driver.address().unwrap());

            //     println!("ra={}",
            //         driver.state().symbolize_and_eval(
            //             &driver.state().scalar("$ra").unwrap())?.unwrap());
            // }

            if driver.address().map(|address| address == 0x684e2b10).unwrap_or(false) {
                let a0 =
                    driver.state()
                        .symbolize_and_eval(
                            &driver.state().scalar("$a0").unwrap())?
                        .unwrap();

                let string = driver.state().get_string(a0.value_u64().unwrap())?.unwrap();

                println!("getenv {}, ra={}", string,
                    driver.state().symbolize_and_eval(
                        &driver.state().scalar("$ra").unwrap())?.unwrap());
            }

            if driver.address().map(|address| address == 0x685c56e8).unwrap_or(false) {
                println!("__res_maybe_init, ra={}",
                    driver.state().symbolize_and_eval(
                        &driver.state().scalar("$ra").unwrap())?.unwrap());
            }

            if driver.address().map(|address| address == 0x685c7870).unwrap_or(false) {
                println!("__nss_hostname_digits_dots, ra={}",
                    driver.state().symbolize_and_eval(
                        &driver.state().scalar("$ra").unwrap())?.unwrap());
            }

            if driver.address().map(|address| address == 0x685b4860).unwrap_or(false) {
                println!("sub_105e60 a0={} ra={}",
                    driver.state().symbolize_and_eval(
                        &driver.state().scalar("$a0").unwrap())?.unwrap(),
                    driver.state().symbolize_and_eval(
                        &driver.state().scalar("$ra").unwrap())?.unwrap());
            }

            if driver.address().map(|address| address == 0x685b3f30).unwrap_or(false) {
                let a0 =
                    driver.state()
                        .symbolize_and_eval(
                            &driver.state().scalar("$a0").unwrap())?
                        .unwrap();

                let string = driver.state().get_string(a0.value_u64().unwrap())?.unwrap();

                println!("gethostbyname(\"{}\"), ra={}",
                    string,
                    driver.state().symbolize_and_eval(
                        &driver.state().scalar("$ra").unwrap())?.unwrap());
            }
            
            // if _step > 5701632 {
            //     if let Some(instruction) = driver.ref_program_location().instruction() {
            //         println!("{} {}", _step, instruction);
            //     }
            // }

            if driver.address().map(|address| address == 0x46006e30).unwrap_or(false) {
                let a0 =
                    driver.state()
                        .symbolize_and_eval(
                            &driver.state().scalar("$a0").unwrap())?
                        .unwrap();
                let a1 =
                    driver.state()
                        .symbolize_and_eval(
                            &driver.state().scalar("$a1").unwrap())?
                        .unwrap();
                let a2 =
                    driver.state()
                        .symbolize_and_eval(
                            &driver.state().scalar("$a2").unwrap())?
                        .unwrap();

                println!("open_verify {}, {}, {}",
                    driver.state().get_string(a0.value_u64().unwrap())?.unwrap(),
                    a1, a2);
            }

            if driver.address().map(|address| address == 0x4600764c).unwrap_or(false) {
                let v0 =
                    driver.state()
                        .symbolize_and_eval(
                            &driver.state().scalar("$v0").unwrap())?
                        .unwrap();

                println!("open_verify result {}", v0);
            }

            let close_addresses = &[0x46005978, 0x46005b00, 0x460064ec, 0x46006f80];

            for address in close_addresses {
                if driver.address().map(|a| a == *address).unwrap_or(false) {
                    println!("hit close on 0x{:x}", address);
                }
            }


            if driver.address().map(|address| address == 0x46005af8).unwrap_or(false) {
                let v0 =
                    driver.state()
                        .symbolize_and_eval(
                            &driver.state().scalar("$v0").unwrap())?
                        .unwrap();
                let a2 =
                    driver.state()
                        .symbolize_and_eval(
                            &driver.state().scalar("$a2").unwrap())?
                        .unwrap();
                let s0 =
                    driver.state()
                        .symbolize_and_eval(
                            &driver.state().scalar("$s0").unwrap())?
                        .unwrap();

                // for i in 0..256 {
                //     let address = 0x68000000 + (i * 4);
                //     println!("0x{:x} {}", address,
                //         driver.state().memory().load(address, 32)?
                //             .map(|e| ::falcon::executor::eval(&e).unwrap())
                //             .map(|e| format!("{}", e))
                //             .unwrap_or(String::new()));
                // }

                println!("0x46005af8 {}, {}, {}", v0, a2, s0);
            }


            // for scalar in driver.state().scalars() {
            //     if let Some(value) = driver.state().symbolize_and_eval(&::falcon::il::expr_scalar(scalar.clone(), 32))? {
            //         if value.value_u64().unwrap() == 0x400054 {
            //             println!("scalar: {}", scalar);
            //             panic!("Found value");
            //         }
            //     }
            // }

            for driver in driver.step()? {
                if driver.address()
                    .map(|address| address == target_address)
                    .unwrap_or(false) {
                    final_drivers.push(driver);
                }
                else {
                    step_drivers.push(driver);
                }
            }
        }
        drivers = step_drivers;
        if drivers.len() > DRIVER_CULL_SIZE {
            let mut i = 2;
            // keep the last handful of drivers
            while i < drivers.len() - 2 {
                drivers.remove(i);
                i += 1;
            }
        }
        if final_drivers.len() > DRIVER_CULL_SIZE {
            let mut i = 2;
            // keep the last handful of drivers
            while i < final_drivers.len() - 2 {
                final_drivers.remove(i);
                i += 1;
            }
        }
        if drivers.len() == 0 {
            break;
        }
    }

    // TODO HACK for debugging
    if final_drivers.len() == 0 {
        Ok(drivers)
    }
    else {
        Ok(final_drivers)
    }
}


pub fn merge_drivers<P: Platform<P>>(drivers: Vec<Driver<P>>)
    -> Result<Driver<P>> {

    if drivers.is_empty() {
        bail!("Tried to merge an empty vector of drivers");
    }
    let location = drivers[0].location().clone();
    if drivers.iter().any(|driver| *driver.location() != location) {
        bail!("Driver locations are not consistent.");
    }

    let mut driver = drivers[0].clone();
    if drivers.len() < MAX_DRIVER_MERGE {
        let memory = Memory::new(driver.state().memory().endian());
        let sum = State::new(
            memory,
            drivers[0].state().platform().map(|d| d.box_clone())
        );
        let state = drivers.into_iter().fold(sum, |sum, driver|
            sum.merge(driver.state()).unwrap());

        *driver.state_mut() = state;
    }
    else {
        // Merge the first driver, the last driver, and some intermediate
        // drivers
        let state = drivers[0].state().clone();
        let mut state = state.merge(drivers[drivers.len() - 1].state())?;

        let step = drivers.len() / MAX_DRIVER_MERGE;
        for i in 0..(MAX_DRIVER_MERGE - 2) {
            if (i * step) + step == drivers.len() {
                break;
            }
            state = state.merge(drivers[i].state())?;
        }

        *driver.state_mut() = state;
    }

    Ok(driver)
}