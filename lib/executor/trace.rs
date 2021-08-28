use crate::error::*;
use falcon::il;
use std::collections::HashSet;

#[derive(Clone, Debug)]
pub struct TraceItem {
    index: usize,
    program_location: il::ProgramLocation,
    address: Option<u64>,
}

impl TraceItem {
    pub fn new(
        index: usize,
        program_location: il::ProgramLocation,
        address: Option<u64>,
    ) -> TraceItem {
        TraceItem {
            index,
            program_location,
            address,
        }
    }

    pub fn index(&self) -> usize {
        self.index
    }
    pub fn program_location(&self) -> &il::ProgramLocation {
        &self.program_location
    }
    pub fn address(&self) -> Option<u64> {
        self.address
    }
}

#[derive(Clone, Debug)]
pub struct Trace {
    next_index: usize,
    items: Vec<TraceItem>,
}

impl Trace {
    pub fn new() -> Trace {
        Trace {
            next_index: 0,
            items: Vec::new(),
        }
    }

    pub fn items(&self) -> &[TraceItem] {
        &self.items
    }

    fn get_next_index(&mut self) -> usize {
        let index = self.next_index;
        self.next_index += 1;
        index
    }

    pub fn push(&mut self, program_location: il::ProgramLocation, address: Option<u64>) {
        let index = self.get_next_index();
        self.items
            .push(TraceItem::new(index, program_location, address));
    }

    /// Starting from the last item in this slice, slice backwards over a
    /// scalar
    pub fn slice_backwards(&self, scalar: &il::Scalar, program: &il::Program) -> Result<Trace> {
        let mut items: Vec<TraceItem> = Vec::new();

        // scalars read
        let mut scalars_read: HashSet<il::Scalar> = HashSet::new();

        // addresses that are read. An entry that is made for each byte, so a
        // 4-byte read of write will correspond to 4-bytes in this HashSet.
        let mut addresses_read: HashSet<u64> = HashSet::new();

        scalars_read.insert(scalar.clone());

        for item in self.items().iter().rev() {
            let rpl = item.program_location().apply(program)?;
            if let Some(operation) = rpl.instruction().map(|i| i.operation()) {
                match operation {
                    il::Operation::Assign { dst, src } => {
                        if scalars_read.contains(dst) {
                            scalars_read.remove(dst);
                            for scalar in src.scalars() {
                                scalars_read.insert(scalar.clone());
                            }
                            items.push(item.clone());
                        }
                    }
                    il::Operation::Load { dst, .. } => {
                        if scalars_read.contains(dst) {
                            let address = match item.address() {
                                Some(address) => address,
                                None => bail!("Trace item had no address"),
                            };
                            for i in 0..(dst.bits() / 8) {
                                addresses_read.insert(address + i as u64);
                            }
                            scalars_read.remove(dst);
                            items.push(item.clone());
                        }
                    }
                    il::Operation::Store { src, .. } => {
                        let address = match item.address() {
                            Some(address) => address,
                            None => bail!("Trace item had no address"),
                        };
                        let cond = (0..(src.bits() / 8))
                            .into_iter()
                            .any(|offset| addresses_read.contains(&(address + offset as u64)));
                        if cond {
                            for i in 0..(src.bits() / 8) {
                                addresses_read.remove(&(address + i as u64));
                            }
                            src.scalars().into_iter().for_each(|scalar| {
                                scalars_read.insert(scalar.clone());
                            });
                            items.push(item.clone());
                        }
                    }
                    il::Operation::Intrinsic { intrinsic } => {
                        let cond = intrinsic
                            .scalars_written()
                            .map(|scalars| {
                                scalars
                                    .into_iter()
                                    .any(|scalar| scalars_read.contains(scalar))
                            })
                            .unwrap_or(false);
                        if cond {
                            for scalar in intrinsic.scalars_written().unwrap_or_default() {
                                scalars_read.remove(scalar);
                            }
                            for scalar in intrinsic.scalars_read().unwrap_or_default() {
                                scalars_read.insert(scalar.clone());
                            }
                            items.push(item.clone());
                        }
                    }
                    il::Operation::Branch { .. } | il::Operation::Nop { .. } => {}
                }
            }
        }

        items.reverse();

        let trace = Trace {
            next_index: self.next_index,
            items,
        };

        Ok(trace)
    }
}

impl Default for Trace {
    fn default() -> Trace {
        Trace::new()
    }
}
