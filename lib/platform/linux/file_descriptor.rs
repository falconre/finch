//! A model of a Linux File Descriptor.

use crate::error::*;
use crate::platform::linux::FileSystem;
use falcon::il;

/// A FileDescriptor for Linux.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileDescriptor {
    fd: usize,
    path: String,
    offset: usize,
}

impl FileDescriptor {
    /// Create a new `FileDescriptor` with the given
    pub fn new<S: Into<String>>(fd: usize, path: S) -> FileDescriptor {
        FileDescriptor {
            fd: fd,
            path: path.into(),
            offset: 0,
        }
    }

    /// Get the fd number for this `FileDescriptor`.
    pub fn fd(&self) -> usize {
        self.fd
    }
    /// Get the path for this `FileDescriptor`.
    pub fn path(&self) -> &str {
        &self.path
    }
    /// Get the offset for this `FileDescriptor`.
    pub fn offset(&self) -> usize {
        self.offset
    }
    /// Set the offset for this `FileDescriptor`.
    pub fn set_offset(&mut self, offset: usize) {
        self.offset = offset;
    }

    /// Read the given number of bytes from this `FileDescriptor`.
    ///
    /// Updates the internal offset.
    pub fn read(&mut self, filesystem: &FileSystem, length: usize) -> Result<Vec<il::Expression>> {
        let bytes = filesystem
            .file_bytes(&self.path)
            .ok_or("Failed to get bytes for filedescriptor")?;

        if bytes.len() <= self.offset {
            Ok(Vec::new())
        } else {
            let top = if self.offset + length > bytes.len() {
                self.offset + bytes.len()
            } else {
                self.offset + length
            };

            let data = bytes
                .get(self.offset..top)
                .ok_or("Failed to get bytes for filedescriptor")?;

            self.offset = top;

            Ok(data.to_vec())
        }
    }

    /// Write the given number of bytes to this `FileDescriptor`.
    ///
    /// Updates the internal offset.
    pub fn write(&mut self, filesystem: &mut FileSystem, data: Vec<il::Expression>) -> Result<()> {
        let file_bytes = filesystem
            .file_bytes_mut(&self.path)
            .ok_or(format!("Failed to get bytes for fd {}", self.fd))?;

        let data_len = data.len();

        data.into_iter().enumerate().for_each(|(i, byte)| {
            if self.offset + i >= file_bytes.len() {
                file_bytes.push(byte);
            } else {
                *file_bytes.get_mut(self.offset + i).unwrap() = byte;
            }
        });

        self.offset += data_len;

        Ok(())
    }
}
