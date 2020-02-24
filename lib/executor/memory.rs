use crate::executor::*;
use falcon::architecture::Endian;
use falcon::memory::backing;
use falcon::translator::TranslationMemory;
use falcon::{il, RC};
use std::borrow::Borrow;
use std::collections::HashMap;

pub const PAGE_SIZE: usize = 4096;

#[derive(Clone, Debug)]
pub struct Page {
    cells: HashMap<usize, Option<ExpressionHash>>,
    permissions: Option<MemoryPermissions>,
    size: usize,
}

impl Page {
    fn new(size: usize) -> Page {
        Page {
            cells: HashMap::new(),
            permissions: None,
            size: size,
        }
    }

    fn get(&self, offset: usize) -> Option<&ExpressionHash> {
        self.cells.get(&offset).and_then(|cell| cell.as_ref())
    }

    fn set(&mut self, offset: usize, cell: Option<ExpressionHash>) {
        self.cells.insert(offset, cell);
    }

    fn set_permissions(&mut self, permissions: Option<MemoryPermissions>) {
        self.permissions = permissions;
    }

    fn permissions(&self) -> Option<MemoryPermissions> {
        self.permissions.clone()
    }
}

#[derive(Clone, Debug)]
pub struct Memory {
    pages: HashMap<u64, RC<Page>>,
    backing: Option<RC<backing::Memory>>,
    endian: Endian,
}

impl Memory {
    pub fn new(endian: Endian) -> Memory {
        Memory {
            pages: HashMap::new(),
            backing: None,
            endian: endian.clone(),
        }
    }

    pub fn new_with_backing(endian: Endian, backing: RC<backing::Memory>) -> Memory {
        Memory {
            pages: HashMap::new(),
            backing: Some(backing),
            endian: endian.clone(),
        }
    }

    pub fn endian(&self) -> Endian {
        self.endian.clone()
    }

    pub fn pages(&self) -> Vec<(u64, &Page)> {
        self.pages
            .iter()
            .map(|(address, page)| (*address, page.as_ref()))
            .collect::<Vec<(u64, &Page)>>()
    }

    pub fn set_backing(&mut self, backing: Option<RC<backing::Memory>>) {
        self.backing = backing;
    }

    /// Used by platforms to give a process more memory
    pub fn initialize_blank(&mut self, address: u64, length: u64) -> Result<()> {
        let zero = il::expr_const(0, 8);
        for i in 0..length {
            self.store(address + i, &zero)?;
        }
        Ok(())
    }

    pub fn set_permissions(
        &mut self,
        address: u64,
        length: usize,
        permissions: Option<MemoryPermissions>,
    ) -> Result<()> {
        if address & (PAGE_SIZE as u64 - 1) > 0 {
            Err("permissions addressed not properly aligned".into())
        } else if length & (PAGE_SIZE - 1) > 0 {
            Err("permissions length not page aligned".into())
        } else {
            for i in 0..(length / PAGE_SIZE) {
                RC::make_mut(
                    self.pages
                        .entry(address + (i * PAGE_SIZE) as u64)
                        .or_insert(RC::new(Page::new(PAGE_SIZE))),
                )
                .set_permissions(permissions);
            }
            Ok(())
        }
    }

    pub fn backing(&self) -> Option<&backing::Memory> {
        self.backing.as_ref().map(|b| RC::borrow(b))
    }

    pub fn flatten(&mut self) -> Result<()> {
        let mut flattened: Vec<(u64, Vec<u8>, MemoryPermissions)> = Vec::new();

        // Find out which pages can be flattened
        'pages_loop: for (address, _) in &self.pages {
            let mut page_bytes: Vec<u8> = Vec::new();

            for i in 0..PAGE_SIZE {
                let byte = match self.get_byte(address + i as u64)? {
                    Some(byte) => {
                        if !byte.all_constants() {
                            continue 'pages_loop;
                        } else {
                            eval(&byte)?
                                .value_u64()
                                .expect("Failed to get value_u64 in memory.flatten()")
                                as u8
                        }
                    }
                    None => 0,
                };
                page_bytes.push(byte);
            }

            flattened.push((
                *address,
                page_bytes,
                self.permissions(*address)
                    .unwrap_or(MemoryPermissions::ALL)
                    .clone(),
            ));
        }

        for (address, _, _) in &flattened {
            self.pages.remove(address);
        }

        if self.backing.is_none() {
            self.backing = Some(RC::new(backing::Memory::new(self.endian.clone())));
        }

        {
            let mut backing = self.backing.as_mut().unwrap();
            let backing = RC::make_mut(&mut backing);

            for (address, bytes, permissions) in flattened {
                backing.set_memory(address, bytes, permissions);
            }
        }

        Ok(())
    }

    fn store_byte(&mut self, address: u64, byte: ExpressionHash) {
        RC::make_mut(
            self.pages
                .entry(address & (!(PAGE_SIZE as u64 - 1)))
                .or_insert(RC::new(Page::new(PAGE_SIZE))),
        )
        .set((address % PAGE_SIZE as u64) as usize, Some(byte));
    }

    fn get_byte(&self, address: u64) -> Result<Option<il::Expression>> {
        let byte = self
            .pages
            .get(&(address & (!(PAGE_SIZE as u64 - 1))))
            .and_then(|page| page.get((address % PAGE_SIZE as u64) as usize))
            .map(|byte| HASH_EXPRESSION_STORE.read().unwrap().expression(byte));
        match byte {
            Some(byte) => Ok(Some(byte?)),
            None => {
                let constant = match self.backing().and_then(|backing| backing.get8(address)) {
                    Some(constant) => constant,
                    None => return Ok(None),
                };
                Ok(Some(il::expr_const(constant as u64, 8)))
            }
        }
    }

    pub fn store(&mut self, address: u64, value: &il::Expression) -> Result<()> {
        match self.endian {
            Endian::Big => {
                if value.bits() == 8 {
                    let expression_hash = HASH_EXPRESSION_STORE.write().unwrap().get_hash(value)?;
                    self.store_byte(address, expression_hash);
                } else {
                    for i in 0..(value.bits() / 8) {
                        let byte = if i == 0 {
                            il::Expression::trun(8, value.clone())?
                        } else {
                            il::Expression::trun(
                                8,
                                il::Expression::shr(
                                    value.clone(),
                                    il::expr_const(i as u64 * 8, value.bits()),
                                )?,
                            )?
                        };
                        let a = address + (((value.bits() / 8) - 1) - i) as u64;
                        let expression_hash =
                            HASH_EXPRESSION_STORE.write().unwrap().get_hash(&byte)?;
                        self.store_byte(a, expression_hash);
                    }
                }
            }
            Endian::Little => {
                if value.bits() == 8 {
                    let expression_hash = HASH_EXPRESSION_STORE.write().unwrap().get_hash(value)?;
                    self.store_byte(address, expression_hash);
                } else {
                    for i in 0..(value.bits() / 8) {
                        let byte = if i == 0 {
                            il::Expression::trun(8, value.clone())?
                        } else {
                            il::Expression::trun(
                                8,
                                il::Expression::shr(
                                    value.clone(),
                                    il::expr_const(i as u64 * 8, value.bits()),
                                )?,
                            )?
                        };
                        let a = address + i as u64;
                        let expression_hash =
                            HASH_EXPRESSION_STORE.write().unwrap().get_hash(&byte)?;
                        self.store_byte(a, expression_hash);
                    }
                }
            }
        }
        Ok(())
    }

    pub fn load(&self, address: u64, bits: usize) -> Result<Option<il::Expression>> {
        match self.endian {
            Endian::Big => {
                let word = match self.get_byte(address)? {
                    Some(byte) => byte,
                    None => {
                        return Ok(None);
                    }
                };
                let mut word = if bits / 8 > 1 {
                    il::Expression::shl(
                        il::Expression::zext(bits, word)?,
                        il::expr_const(bits as u64 - 8, bits),
                    )?
                } else {
                    word
                };
                for i in 1..(bits / 8) {
                    let byte = match self.get_byte(address + i as u64)? {
                        Some(byte) => byte,
                        None => {
                            return Ok(None);
                        }
                    };
                    let byte = il::Expression::zext(bits, byte)?;
                    let byte = if i != (bits / 8) - 1 {
                        il::Expression::shl(
                            byte,
                            il::expr_const((bits - 8 - (i * 8)) as u64, bits),
                        )?
                    } else {
                        byte
                    };
                    word = il::Expression::or(word, byte)?;
                }
                Ok(Some(word))
            }
            Endian::Little => {
                let word = match self.get_byte(address)? {
                    Some(byte) => byte,
                    None => {
                        return Ok(None);
                    }
                };
                let mut word = if bits / 8 > 1 {
                    il::Expression::zext(bits, word)?
                } else {
                    word
                };
                for i in 1..(bits / 8) {
                    let byte = match self.get_byte(address + i as u64)? {
                        Some(byte) => byte,
                        None => {
                            return Ok(None);
                        }
                    };
                    let byte = il::Expression::shl(
                        il::Expression::zext(bits, byte)?,
                        il::expr_const((i * 8) as u64, bits),
                    )?;
                    word = il::Expression::or(word, byte)?;
                }
                Ok(Some(word))
            }
        }
    }

    pub fn load_buf(&self, address: u64, len: usize) -> Result<Option<Vec<il::Expression>>> {
        let mut buf = Vec::new();
        for i in 0..(len as u64) {
            match self.load(address + i, 8)? {
                Some(expression) => {
                    buf.push(expression);
                }
                None => {
                    return Ok(None);
                }
            }
        }

        Ok(Some(buf))
    }

    pub fn merge(mut self, other: &Memory, constraints: &il::Expression) -> Result<Memory> {
        let null_byte = il::expr_const(0, 8);

        for other_page in &other.pages {
            for i in 0..PAGE_SIZE {
                let address = other_page.0 + i as u64;
                let other_byte = other.load(address, 8)?;
                let self_byte = self.load(address, 8)?;
                if other_byte != self_byte {
                    let expr = il::Expression::ite(
                        constraints.clone(),
                        other_byte.unwrap_or(null_byte.clone()),
                        self_byte.unwrap_or(null_byte.clone()),
                    )?;
                    self.store(address, &expr)?;
                }
            }
        }

        Ok(self)
    }
}

impl TranslationMemory for Memory {
    fn permissions(&self, address: u64) -> Option<MemoryPermissions> {
        self.pages
            .get(&(address & (!(PAGE_SIZE as u64 - 1))))
            .and_then(|page| page.permissions())
            .or(self
                .backing()
                .and_then(|backing| backing.permissions(address)))
    }

    fn get_u8(&self, address: u64) -> Option<u8> {
        self.backing().and_then(|backing| backing.get8(address))
    }
}
