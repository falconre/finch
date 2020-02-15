use crate::error::*;
use finch::executor::{Driver, Memory, State};

const MAX_DRIVER_MERGE: usize = 16;
const DRIVER_CULL_SIZE: usize = 32;

/// Drive the given driver until it hits the given driver, or until max_steps
/// has been hit.
///
/// Collects drivers once they hit the desired address
pub fn drive_to_address(
    driver: Driver,
    target_address: u64,
    max_steps: usize,
) -> Result<Vec<Driver>> {
    let mut drivers = vec![driver];
    let mut final_drivers = Vec::new();

    for _step in 0..max_steps {
        if (_step & 0xfff) == 0 {
            println!(
                "drive_to_address step={} drivers.len()={} final_drivers.len()={}",
                _step,
                drivers.len(),
                final_drivers.len()
            );
        }
        let mut step_drivers = Vec::new();
        for driver in drivers {
            for driver in driver.step()? {
                if driver
                    .address()
                    .map(|address| address == target_address)
                    .unwrap_or(false)
                {
                    final_drivers.push(driver);
                } else {
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
    } else {
        Ok(final_drivers)
    }
}

pub fn merge_drivers(drivers: Vec<Driver>) -> Result<Driver> {
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
        let sum = State::new(memory, drivers[0].state().platform().box_clone());
        let state = drivers
            .into_iter()
            .fold(sum, |sum, driver| sum.merge(driver.state()).unwrap());

        *driver.state_mut() = state;
    } else {
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
