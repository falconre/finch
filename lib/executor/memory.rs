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
}

impl Page {
    fn new() -> Page {
        Page {
            cells: HashMap::new(),
            permissions: None,
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
        self.permissions
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
            endian,
        }
    }

    pub fn new_with_backing(endian: Endian, backing: RC<backing::Memory>) -> Memory {
        Memory {
            pages: HashMap::new(),
            backing: Some(backing),
            endian,
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
                        .or_insert_with(|| RC::new(Page::new())),
                )
                .set_permissions(permissions);
            }
            Ok(())
        }
    }

    pub fn backing(&self) -> Option<&backing::Memory> {
        self.backing.as_ref().map(RC::borrow)
    }

    pub fn flatten(&mut self) -> Result<()> {
        let mut flattened: Vec<(u64, Vec<u8>, MemoryPermissions)> = Vec::new();

        // Find out which pages can be flattened
        'pages_loop: for address in self.pages.keys() {
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
                self.permissions(*address).unwrap_or(MemoryPermissions::ALL),
            ));
        }

        for (address, _, _) in &flattened {
            self.pages.remove(address);
        }

        if self.backing.is_none() {
            self.backing = Some(RC::new(backing::Memory::new(self.endian.clone())));
        }

        {
            let backing = self.backing.as_mut().unwrap();
            let backing = RC::make_mut(backing);

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
                .or_insert_with(|| RC::new(Page::new())),
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
        let null_byte = || il::expr_const(0, 8);

        for other_page in &other.pages {
            for i in 0..PAGE_SIZE {
                let address = other_page.0 + i as u64;
                let other_byte = other.load(address, 8)?;
                let self_byte = self.load(address, 8)?;
                if other_byte != self_byte {
                    let expr = il::Expression::ite(
                        constraints.clone(),
                        other_byte.unwrap_or_else(null_byte),
                        self_byte.unwrap_or_else(null_byte),
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
            .or_else(|| {
                self.backing()
                    .and_then(|backing| backing.permissions(address))
            })
    }

    fn get_u8(&self, address: u64) -> Option<u8> {
        self.backing().and_then(|backing| backing.get8(address))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use falcon::executor::eval;
    use falcon::memory::MemoryPermissions;

    #[test]
    fn test_32bit_little_endian_byte_order() {
        let mut mem = Memory::new(Endian::Little);
        mem.store(0x1000, &il::expr_const(0xDEADBEEF, 32)).unwrap();

        let b0 = mem.load(0x1000, 8).unwrap().unwrap();
        let b1 = mem.load(0x1001, 8).unwrap().unwrap();
        let b2 = mem.load(0x1002, 8).unwrap().unwrap();
        let b3 = mem.load(0x1003, 8).unwrap().unwrap();

        assert_eq!(eval(&b0).unwrap().value_u64().unwrap(), 0xEF);
        assert_eq!(eval(&b1).unwrap().value_u64().unwrap(), 0xBE);
        assert_eq!(eval(&b2).unwrap().value_u64().unwrap(), 0xAD);
        assert_eq!(eval(&b3).unwrap().value_u64().unwrap(), 0xDE);
    }

    #[test]
    fn test_32bit_big_endian_byte_order() {
        let mut mem = Memory::new(Endian::Big);
        mem.store(0x1000, &il::expr_const(0xDEADBEEF, 32)).unwrap();

        let b0 = mem.load(0x1000, 8).unwrap().unwrap();
        let b1 = mem.load(0x1001, 8).unwrap().unwrap();
        let b2 = mem.load(0x1002, 8).unwrap().unwrap();
        let b3 = mem.load(0x1003, 8).unwrap().unwrap();

        assert_eq!(eval(&b0).unwrap().value_u64().unwrap(), 0xDE);
        assert_eq!(eval(&b1).unwrap().value_u64().unwrap(), 0xAD);
        assert_eq!(eval(&b2).unwrap().value_u64().unwrap(), 0xBE);
        assert_eq!(eval(&b3).unwrap().value_u64().unwrap(), 0xEF);
    }

    #[test]
    fn test_store_load_crossing_page_boundary() {
        let mut mem = Memory::new(Endian::Little);
        let addr = (PAGE_SIZE as u64) - 2; // 4094
        mem.store(addr, &il::expr_const(0xAABBCCDD, 32)).unwrap();
        let loaded = mem.load(addr, 32).unwrap().unwrap();
        assert_eq!(eval(&loaded).unwrap().value_u64().unwrap(), 0xAABBCCDD);
    }

    #[test]
    fn test_load_partially_uninitialized_returns_none() {
        let mut mem = Memory::new(Endian::Little);
        mem.store(0x2000, &il::expr_const(0x42, 8)).unwrap();
        // Second byte at 0x2001 is uninitialized
        let loaded = mem.load(0x2000, 16).unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn test_backing_memory_fallback() {
        let mut backing = backing::Memory::new(Endian::Little);
        backing.set_memory(
            0x3000,
            vec![0x41, 0x42, 0x43, 0x44],
            MemoryPermissions::READ,
        );
        let mem = Memory::new_with_backing(Endian::Little, RC::new(backing));

        let b0 = mem.load(0x3000, 8).unwrap().unwrap();
        let b1 = mem.load(0x3001, 8).unwrap().unwrap();
        let b2 = mem.load(0x3002, 8).unwrap().unwrap();
        let b3 = mem.load(0x3003, 8).unwrap().unwrap();

        assert_eq!(eval(&b0).unwrap().value_u64().unwrap(), 0x41);
        assert_eq!(eval(&b1).unwrap().value_u64().unwrap(), 0x42);
        assert_eq!(eval(&b2).unwrap().value_u64().unwrap(), 0x43);
        assert_eq!(eval(&b3).unwrap().value_u64().unwrap(), 0x44);
    }

    #[test]
    fn test_page_overrides_backing() {
        let mut backing = backing::Memory::new(Endian::Little);
        backing.set_memory(0x3000, vec![0xFF], MemoryPermissions::READ);
        let mut mem = Memory::new_with_backing(Endian::Little, RC::new(backing));

        mem.store(0x3000, &il::expr_const(0x42, 8)).unwrap();
        let loaded = mem.load(0x3000, 8).unwrap().unwrap();
        assert_eq!(eval(&loaded).unwrap().value_u64().unwrap(), 0x42);
    }

    #[test]
    fn test_set_permissions_unaligned_address_errors() {
        let mut mem = Memory::new(Endian::Little);
        let result = mem.set_permissions(0x1, 4096, Some(MemoryPermissions::READ));
        assert!(result.is_err());
    }

    #[test]
    fn test_set_permissions_unaligned_length_errors() {
        let mut mem = Memory::new(Endian::Little);
        let result = mem.set_permissions(0x0, 100, Some(MemoryPermissions::READ));
        assert!(result.is_err());
    }

    #[test]
    fn test_flatten_concrete_to_backing() {
        let mut mem = Memory::new(Endian::Little);
        mem.store(0x0, &il::expr_const(0x41, 8)).unwrap();
        mem.store(0x1, &il::expr_const(0x42, 8)).unwrap();

        // Before flatten, page exists
        assert!(!mem.pages.is_empty());

        mem.flatten().unwrap();

        // After flatten, page removed (all concrete)
        assert!(mem.pages.is_empty());

        // Bytes still accessible via backing
        let b0 = mem.load(0x0, 8).unwrap().unwrap();
        let b1 = mem.load(0x1, 8).unwrap().unwrap();
        assert_eq!(eval(&b0).unwrap().value_u64().unwrap(), 0x41);
        assert_eq!(eval(&b1).unwrap().value_u64().unwrap(), 0x42);
    }

    #[test]
    fn test_flatten_keeps_symbolic_page() {
        let mut mem = Memory::new(Endian::Little);
        let symbolic = il::expr_scalar("x", 8);
        mem.store(0x0, &symbolic).unwrap();

        mem.flatten().unwrap();

        // Page should still exist (symbolic bytes can't flatten)
        assert!(!mem.pages.is_empty());
    }

    #[test]
    fn test_merge_differing_bytes_produce_ite() {
        let mut mem_a = Memory::new(Endian::Little);
        mem_a.store(0x0, &il::expr_const(0x41, 8)).unwrap();

        let mut mem_b = Memory::new(Endian::Little);
        mem_b.store(0x0, &il::expr_const(0x42, 8)).unwrap();

        let constraint = il::expr_scalar("cond", 1);
        let merged = mem_a.merge(&mem_b, &constraint).unwrap();
        let loaded = merged.load(0x0, 8).unwrap().unwrap();

        // Result should be an ITE, not a plain constant
        assert!(!loaded.all_constants());
    }

    #[test]
    fn test_merge_identical_bytes_unchanged() {
        let mut mem_a = Memory::new(Endian::Little);
        mem_a.store(0x0, &il::expr_const(0x41, 8)).unwrap();

        let mut mem_b = Memory::new(Endian::Little);
        mem_b.store(0x0, &il::expr_const(0x41, 8)).unwrap();

        let constraint = il::expr_scalar("cond", 1);
        let merged = mem_a.merge(&mem_b, &constraint).unwrap();
        let loaded = merged.load(0x0, 8).unwrap().unwrap();

        assert_eq!(eval(&loaded).unwrap().value_u64().unwrap(), 0x41);
    }

    #[test]
    fn test_store_load_symbolic_roundtrip() {
        let mut mem = Memory::new(Endian::Little);
        let sym = il::expr_scalar("x", 8);
        mem.store(0x1000, &sym).unwrap();
        let loaded = mem.load(0x1000, 8).unwrap().unwrap();
        assert_eq!(loaded, sym);
    }

    #[test]
    fn test_load_buf_partially_uninitialized() {
        let mut mem = Memory::new(Endian::Little);
        mem.store(0x0, &il::expr_const(0x41, 8)).unwrap();
        mem.store(0x1, &il::expr_const(0x42, 8)).unwrap();
        // Only 2 bytes initialized, try to load 4
        let result = mem.load_buf(0x0, 4).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_initialize_blank_fills_zeros() {
        let mut mem = Memory::new(Endian::Little);
        mem.initialize_blank(0x4000, 4).unwrap();

        for i in 0..4u64 {
            let byte = mem.load(0x4000 + i, 8).unwrap().unwrap();
            assert_eq!(eval(&byte).unwrap().value_u64().unwrap(), 0);
        }
    }
}
