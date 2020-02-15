use crate::error::*;
use finch::executor::Driver;
use finch::platform::Platform;
use std::collections::HashMap;

const MAX_DRIVERS: usize = 256;

pub struct Debugger<P: Platform<P>> {
    breakpoints: Vec<u64>,
    breaked_drivers: Vec<Driver<P>>,
    drivers: Vec<Driver<P>>,
    killpoints: Vec<u64>,
    merge_points: Vec<u64>,
    merged_drivers: HashMap<u64, Driver<P>>,
}

impl<P: Platform<P>> Debugger<P> {
    pub fn new(drivers: Vec<Driver<P>>) -> Debugger<P> {
        Debugger {
            breakpoints: Vec::new(),
            breaked_drivers: Vec::new(),
            drivers: drivers,
            killpoints: Vec::new(),
            merge_points: Vec::new(),
            merged_drivers: HashMap::new(),
        }
    }

    pub fn cull_drivers(&mut self) {
        self.drivers = Vec::new();
    }

    pub fn breakpoints(&self) -> &[u64] {
        &self.breakpoints
    }

    pub fn breaked_drivers(&self) -> &[Driver<P>] {
        &self.breaked_drivers
    }

    pub fn unbreak_drivers(&mut self) {
        self.drivers.append(&mut self.breaked_drivers);
    }

    pub fn delete_breakpoints(&mut self) {
        self.breakpoints = Vec::new();
    }

    pub fn drivers(&self) -> &[Driver<P>] {
        &self.drivers
    }

    pub fn killpoints(&self) -> &[u64] {
        &self.killpoints
    }

    pub fn merge_points(&self) -> &[u64] {
        &self.merge_points
    }

    pub fn merged_drivers(&self) -> &HashMap<u64, Driver<P>> {
        &self.merged_drivers
    }

    pub fn flatten(&mut self) -> Result<()> {
        // self.drivers.iter_mut()
        //     .chain(self.breaked_drivers.iter_mut())
        //     .chain(self.merged_drivers.iter_mut().map(|(_, driver)| driver))
        //     .try_for_each(|driver| {
        //         driver.state_mut().memory_mut().flatten()?;
        //         Ok(())
        //     })
        for driver in self.drivers.iter_mut() {
            driver.state_mut().memory_mut().flatten()?;
        }

        Ok(())
    }

    /// Apply a filter to this Debugger's drivers, and return a new Debugger
    /// with only those Debuggers
    pub fn filter<F>(&self, filter: F) -> Debugger<P>
    where
        F: Fn(&Driver<P>) -> bool,
    {
        Debugger {
            breakpoints: self.breakpoints.clone(),
            breaked_drivers: self.breaked_drivers.clone(),
            drivers: self
                .drivers
                .iter()
                .filter(|driver| filter(driver))
                .cloned()
                .collect::<Vec<Driver<P>>>(),
            killpoints: self.killpoints.clone(),
            merge_points: self.merge_points.clone(),
            merged_drivers: self.merged_drivers.clone(),
        }
    }

    pub fn push_breakpoint(&mut self, breakpoint_address: u64) {
        self.breakpoints.push(breakpoint_address);
    }

    pub fn push_killpoint(&mut self, killpoint_address: u64) {
        self.killpoints.push(killpoint_address);
    }

    pub fn push_merge_point(&mut self, merge_point_address: u64) {
        self.merge_points.push(merge_point_address);
    }

    pub fn continue_(&mut self, steps: usize) -> Result<()> {
        fn bin_drivers<P: Platform<P>>(
            drivers: Vec<Driver<P>>,
            breakpoints: &[u64],
            merge_points: &[u64],
            killpoints: &[u64],
            breaked: &mut Vec<Driver<P>>,
            merged: &mut HashMap<u64, Driver<P>>,
        ) -> Result<Vec<Driver<P>>> {
            let mut step_drivers = Vec::new();
            for driver in drivers {
                if let Some(address) = driver.address() {
                    if breakpoints.contains(&address) {
                        info!("Driver hit breakpoint 0x{:x}", address);
                        breaked.push(driver);
                        continue;
                    } else if merge_points.contains(&address) {
                        info!("Driver hit merge point 0x{:x}", address);
                        if let Some(merged_driver) = merged.get_mut(&address) {
                            *merged_driver = match merged_driver.merge(&driver)? {
                                Some(driver) => driver,
                                None => bail!(
                                    "Failed to merge drivers at \
                                               merge point"
                                ),
                            };
                            continue;
                        }
                        merged.insert(address, driver);
                        continue;
                    } else if killpoints.contains(&address) {
                        info!("Driver hit kill point 0x{:x}", address);
                        continue;
                    }
                }
                step_drivers.push(driver);
            }
            Ok(step_drivers)
        }

        let mut drivers: Vec<Driver<P>> = self.drivers.clone();

        let mut last_step_drivers_len = drivers.len();

        for _i in 0..steps {
            let temp_drivers = bin_drivers(
                drivers,
                &self.breakpoints,
                &self.merge_points,
                &self.killpoints,
                &mut self.breaked_drivers,
                &mut self.merged_drivers,
            )?;

            // let drivers_ =
            //     temp_drivers.into_par_iter()
            //         .try_fold(|| Vec::new(), |mut v, d| {
            //             v.append(&mut d.step()?);
            //             Ok(v)
            //         })
            //         .try_reduce(|| Vec::new(), |mut v, mut d| {
            //             v.append(&mut d);
            //             Ok(v)
            //         });

            let drivers_ = temp_drivers.into_iter().try_fold(Vec::new(), |mut v, d| {
                v.append(&mut d.step()?);
                Ok(v)
            });

            drivers = match drivers_ {
                Ok(drivers) => drivers,
                Err(e) => return Err(e),
            };

            let address = drivers.get(0).unwrap().address().unwrap_or(0);

            // if _i == 1645 {
            if address == 0x4000b343 {
                use falcon::il;
                let driver = drivers.get(0).unwrap();
                let trace = driver.trace();
                let sliced_trace =
                    trace.slice_backwards(&il::scalar("r14", 64), driver.program())?;

                for trace_item in sliced_trace.items() {
                    let location = trace_item.program_location().apply(driver.program())?;
                    println!("{}", location);
                }
                println!("Trace is {} items", driver.trace().items().len());
                println!("Sliced trace is {} items", sliced_trace.items().len());
                println!("r14: {}", driver.state().scalar("r14").unwrap());
                println!("{}", driver.instruction().unwrap());
                // panic!("11213");
            }

            if let Some(driver) = drivers.get(0) {
                println!("{}", driver.location().apply(driver.program())?);
                // use falcon::il;
                // if let Some(instruction) = driver.instruction() {
                //     match instruction.operation() {
                //         il::Operation::Branch { target } => {
                //             let target = driver.state().clone().eval_and_concretize(target)?.unwrap();
                //             let target = target.value_u64().unwrap();
                //             let target = target + 0x4000a03000 - 0x40000000;
                //             println!("b *0x{:x}", target);
                //         },
                //         _ => {}
                //     }
                // }
            }

            if drivers.len() > last_step_drivers_len {
                debug!(
                    "Had {} drivers, now have {} drivers",
                    last_step_drivers_len,
                    drivers.len()
                );
                last_step_drivers_len = drivers.len();
            }

            if drivers.len() > MAX_DRIVERS {
                warn!(
                    "Debugger has {} drivers, which is {} more than max of \
                       {}. Deleting half of the drivers",
                    drivers.len(),
                    drivers.len() - MAX_DRIVERS,
                    MAX_DRIVERS
                );
                for i in 0..drivers.len() / 2 {
                    drivers.remove(i);
                }
                last_step_drivers_len = drivers.len();
            }
        }

        self.drivers = bin_drivers(
            drivers,
            &self.breakpoints,
            &self.merge_points,
            &self.killpoints,
            &mut self.breaked_drivers,
            &mut self.merged_drivers,
        )?;

        Ok(())
    }
}
