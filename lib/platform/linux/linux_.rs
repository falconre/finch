//! A basic model of the Linux Operating System.

use crate::error::*;
use crate::executor::Memory;
use crate::platform::linux::{Constants, FileSystem, Whence};
use falcon::il;
use falcon::loader::{ElfLinker, Loader};
use falcon::memory::MemoryPermissions;
use log::trace;
use std::path::PathBuf;

const BRK_MAX_SIZE: u64 = 0x1000_0000;
const MMAP_BASE: u64 = 0x6800_0000;

const AT_FDCWD: u32 = 0xFFFF_FF9C;

/// A basic model of the Linux Operating System.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Linux {
    // The base address of the program break.
    brk_base: u64,
    // The current program break.
    brk_address: u64,
    // A pointer to the constants defined for this platform in Linux
    constants: &'static Constants,
    // Our model of the file system.
    file_system: FileSystem,
    // The next address where an MMAP should allocate memory.
    mmap_address: u64,
}

impl Linux {
    /// Create a new basic model of the Linux Operating System.
    pub fn new(
        elf_linker: &ElfLinker,
        base_path: Option<PathBuf>,
        constants: &'static Constants,
    ) -> Result<Linux> {
        // We need to find the address after the "data" segment to start the
        // program break... really just the highest address we can find
        let backing = elf_linker.memory()?;

        let mut address: u64 = 0;

        for (section_address, section) in backing.sections() {
            let high = section_address + section.len() as u64;
            if high > address {
                address = high;
            }
        }

        trace!("brk set to 0x{:x}", address);

        Ok(Linux {
            brk_base: address,
            brk_address: address,
            constants,
            file_system: FileSystem::new(base_path)?,
            mmap_address: MMAP_BASE,
        })
    }

    pub fn file_system(&self) -> &FileSystem {
        &self.file_system
    }

    pub fn file_system_mut(&mut self) -> &mut FileSystem {
        &mut self.file_system
    }

    // TODO: Do real posix file permissions
    pub fn access(&self, path: &str, _mode: u64) -> u64 {
        if self.file_system.exists(path) {
            0
        } else {
            -1i64 as u64
        }
    }

    pub fn brk(&mut self, address: u64, memory: &mut Memory) -> Result<u64> {
        let result = if address < self.brk_address {
            self.brk_address
        } else if address - self.brk_base < BRK_MAX_SIZE {
            let size = address - self.brk_base;
            trace!(
                "brk is mapping more memory address=0x{:x} size=0x{:x}",
                self.brk_address,
                size
            );
            memory.initialize_blank(self.brk_address, size)?;
            self.brk_address = address;
            address
        } else {
            self.brk_address
        };
        trace!("brk(0x{:x}) = 0x{:x}", address, result);
        Ok(result)
    }

    pub fn lseek(&mut self, fd: u64, offset: isize, whence: u64) -> Result<u64> {
        let whence = if whence == self.constants.SEEK_SET {
            Whence::Set
        } else if whence == self.constants.SEEK_CUR {
            Whence::Cursor
        } else if whence == self.constants.SEEK_END {
            Whence::End
        } else {
            return Ok(-1i64 as u64);
        };

        self.file_system
            .fd_seek(fd as usize, offset, whence)
            .map(|off| off as u64)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn mmap(
        &mut self,
        memory: &mut Memory,
        address: u64,
        length: u64,
        prot: u64,
        flags: u64,
        fd: u64,
        offset: u64,
    ) -> Result<u64> {
        let mut permissions: MemoryPermissions = MemoryPermissions::NONE;

        if flags & self.constants.MAP_ANONYMOUS == 0 && !self.file_system.fd_valid(fd as usize) {
            return Ok(-1i64 as u64);
        }

        if prot & self.constants.PROT_READ > 0 {
            permissions |= MemoryPermissions::READ;
        }
        if prot & self.constants.PROT_WRITE > 0 {
            permissions |= MemoryPermissions::WRITE;
        }
        if prot & self.constants.PROT_EXEC > 0 {
            permissions |= MemoryPermissions::EXECUTE;
        }

        let address = if address > 0 {
            if address + length > self.mmap_address {
                self.mmap_address = address + length;
                if self.mmap_address % crate::executor::PAGE_SIZE as u64 > 0 {
                    self.mmap_address += crate::executor::PAGE_SIZE as u64;
                    self.mmap_address &= !(crate::executor::PAGE_SIZE as u64 - 1);
                }
            }
            address
        } else {
            let address = self.mmap_address;
            let permissions_length = if length as usize % crate::executor::PAGE_SIZE > 0 {
                let pl = length as usize + crate::executor::PAGE_SIZE;
                pl & (!(crate::executor::PAGE_SIZE - 1))
            } else {
                length as usize
            };
            self.mmap_address += permissions_length as u64;
            address
        };

        // this straight code-copying, ugly shiz. fix later
        let permissions_length = if length as usize % crate::executor::PAGE_SIZE > 0 {
            let pl = length as usize + crate::executor::PAGE_SIZE;
            pl & (!(crate::executor::PAGE_SIZE - 1))
        } else {
            length as usize
        };

        memory.set_permissions(address, permissions_length, Some(permissions))?;

        if flags & self.constants.MAP_ANONYMOUS == 0 {
            let mut filesize = self.file_system.size_fd(fd as usize).unwrap() as u64 - offset;
            if filesize > length {
                filesize = length;
            }

            let bytes = self.file_system.fd_bytes(fd as usize).unwrap();
            for i in 0..filesize {
                memory.store(address + i, &bytes[(offset + i) as usize])?;
            }
        }

        Ok(address)
    }

    pub fn mprotect(
        &mut self,
        memory: &mut Memory,
        address: u64,
        length: u64,
        prot: u64,
    ) -> Result<u64> {
        let mut permissions: MemoryPermissions = MemoryPermissions::NONE;

        if prot & self.constants.PROT_READ > 0 {
            permissions |= MemoryPermissions::READ;
        }
        if prot & self.constants.PROT_WRITE > 0 {
            permissions |= MemoryPermissions::WRITE;
        }
        if prot & self.constants.PROT_EXEC > 0 {
            permissions |= MemoryPermissions::EXECUTE;
        }

        let permissions_length = if length as usize % crate::executor::PAGE_SIZE > 0 {
            let pl = length as usize + crate::executor::PAGE_SIZE;
            pl & (!(crate::executor::PAGE_SIZE - 1))
        } else {
            length as usize
        };
        memory.set_permissions(address, permissions_length, Some(permissions))?;

        Ok(0)
    }

    pub fn open(&mut self, path: &str, flags: u64, _mode: u64) -> Result<u64> {
        if flags & self.constants.O_CREAT > 0 {
            self.file_system.create(path).map(|fd| fd as u64)
        } else {
            Ok(self
                .file_system
                .open(path)?
                .map(|fd| fd as u64)
                .unwrap_or(-1i64 as u64))
        }
    }

    pub fn openat(&mut self, dirfd: u64, path: &str, flags: u64, mode: u64) -> Result<u64> {
        if dirfd as u32 != AT_FDCWD {
            bail!("openat not implemented for dirfd!=AT_FDCWD")
        }
        self.open(path, flags, mode)
    }

    pub fn read(&mut self, fd: u64, length: u64) -> Result<Option<Vec<il::Expression>>> {
        self.file_system.read_fd(fd as usize, length as usize)
    }

    pub fn write(&mut self, fd: u64, data: Vec<il::Expression>) -> Result<u64> {
        let len = data.len() as u64;
        match self.file_system.write_fd(fd as usize, data) {
            Ok(_) => Ok(len),
            Err(_) => Ok(-1i64 as u64),
        }
    }
}
