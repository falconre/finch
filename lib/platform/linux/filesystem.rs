use crate::error::*;
use crate::platform::linux::FileDescriptor;
use falcon::{il, RC};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

/// A Whence, used when seeking a file descriptor.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Whence {
    Set,
    Cursor,
    End,
}

/// A basic model of the Linux Filesystem
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileSystem {
    file_descriptors: HashMap<usize, FileDescriptor>,
    files: HashMap<String, RC<Vec<il::Expression>>>,
    base_path: Option<PathBuf>,
    next_fd: usize,
}

impl FileSystem {
    /// Create a new model of the Linux Filesystem.
    ///
    /// The filedescriptors 0, 1, and 2 are initialized to files named:
    /// `/stdin`, `/stdout`, and `/stderr` respectively.
    ///
    /// If given an optional path, then this path will be used to look for files
    /// when opening files.
    pub fn new(base_path: Option<PathBuf>) -> Result<FileSystem> {
        let mut fs = FileSystem {
            file_descriptors: HashMap::new(),
            files: HashMap::new(),
            base_path,
            next_fd: 0,
        };

        fs.create("/stdin")?;
        fs.create("/stdout")?;
        fs.create("/stderr")?;

        Ok(fs)
    }

    /// Get a path with the base path prepended, if we have a base path.
    fn get_path(&self, path: &str) -> PathBuf {
        match self.base_path {
            Some(ref base_path) => {
                if path.starts_with('/') {
                    base_path.join(path.get(1..(path.len())).unwrap())
                } else {
                    base_path.join(path)
                }
            }
            None => path.to_string().into(),
        }
    }

    fn next_fd(&mut self) -> usize {
        let next_fd = self.next_fd;
        self.next_fd += 1;
        next_fd
    }

    fn add_file_descriptor(&mut self, path: &str) -> usize {
        let file_descriptor = FileDescriptor::new(self.next_fd(), path);
        let fd = file_descriptor.fd();
        self.file_descriptors.insert(fd, file_descriptor);
        fd
    }

    /// Get a mutable reference to a `FileDescriptor` if it exists.
    pub fn fd_mut(&mut self, fd: usize) -> Option<&mut FileDescriptor> {
        self.file_descriptors.get_mut(&fd)
    }

    /// Seek a file descriptor, according to the whence and offset.
    pub fn fd_seek(&mut self, fd: usize, offset: isize, seek: Whence) -> Result<usize> {
        match seek {
            Whence::Set => {
                self.file_descriptors
                    .get_mut(&fd)
                    .ok_or("Could not find fd for fd_seek")?
                    .set_offset(offset as usize);
            }
            Whence::Cursor => {
                let fd = self
                    .file_descriptors
                    .get_mut(&fd)
                    .ok_or("Could not find fd for fd_seek")?;

                let cur_offset = fd.offset();
                fd.set_offset((cur_offset as isize + offset) as usize);
            }
            Whence::End => {
                let path = self
                    .file_descriptors
                    .get(&fd)
                    .ok_or("Could not find fd for fd_seek")?
                    .path()
                    .to_string(); // kill the borrow
                let filesize = self
                    .files
                    .get(&path)
                    .ok_or("Could not find file for fd_seek SEEK_END")?
                    .len();
                self.file_descriptors
                    .get_mut(&fd)
                    .ok_or("Could not find fd for fd_seek")?
                    .set_offset((filesize as isize + offset) as usize);
            }
        }

        Ok(self
            .file_descriptors
            .get(&fd)
            .ok_or("Could not find fd for fd_seek")?
            .offset())
    }

    /// Returns true if the file descriptor exists.
    pub fn fd_valid(&self, fd: usize) -> bool {
        self.file_descriptors.contains_key(&fd)
    }

    /// Attempt to open a file and read it into the filesystem model. Returns
    /// a file descriptor if the file exists, or None.
    pub fn open(&mut self, path: &str) -> Result<Option<usize>> {
        if self.files.contains_key(path) {
            return Ok(Some(self.add_file_descriptor(path)));
        }

        if self.get_path(path).exists() {
            let mut file = File::open(self.get_path(path))?;

            let mut buf = Vec::new();
            file.read_to_end(&mut buf)?;

            let bytes = buf
                .into_iter()
                .map(|byte| il::expr_const(byte as u64, 8))
                .collect::<Vec<il::Expression>>();

            self.files.insert(path.to_string(), RC::new(bytes));
            Ok(Some(self.add_file_descriptor(path)))
        } else {
            Ok(None)
        }
    }

    /// Open a file, or create it if it does not exist. Returns file descriptor.
    pub fn create(&mut self, path: &str) -> Result<usize> {
        if let Some(fd) = self.open(path)? {
            return Ok(fd);
        }

        self.files.insert(path.to_string(), RC::new(Vec::new()));
        Ok(self.add_file_descriptor(path))
    }

    /// Return true if a file exists, false otherwise
    pub fn exists(&self, path: &str) -> bool {
        self.files.contains_key(path) || PathBuf::from(path.to_string()).exists()
    }

    /// Zeroize the data in a file
    pub fn zeroize(&mut self, path: &str) {
        self.files.insert(path.to_string(), RC::new(Vec::new()));
    }

    /// Get data from a file
    pub fn file_bytes(&self, path: &str) -> Option<&[il::Expression]> {
        self.files.get(path).map(|v| v.as_slice())
    }

    /// Get a mutable reference to the data for a file
    pub fn file_bytes_mut(&mut self, path: &str) -> Option<&mut Vec<il::Expression>> {
        self.files.get_mut(path).map(RC::make_mut)
    }

    /// Get the bytes to a file pointed to by a file descriptor
    pub fn fd_bytes(&self, fd: usize) -> Option<&[il::Expression]> {
        self.file_descriptors
            .get(&fd)
            .and_then(|fd| self.files.get(fd.path()))
            .map(|bytes| bytes.as_ref().as_ref())
    }

    /// Close a file descriptor. Returns true if file descriptor existed, false
    /// otherwise
    pub fn close_fd(&mut self, fd: usize) -> bool {
        if self.file_descriptors.remove(&fd).is_some() {
            while !self.file_descriptors.contains_key(&(self.next_fd - 1)) {
                if self.next_fd == 0 {
                    break;
                }
                self.next_fd -= 1;
            }
            true
        } else {
            false
        }
    }

    /// Read from a file descriptor
    pub fn read_fd(&mut self, fd: usize, length: usize) -> Result<Option<Vec<il::Expression>>> {
        let mut fd: FileDescriptor = match self.file_descriptors.get_mut(&fd) {
            Some(fd) => fd.clone(),
            None => {
                return Ok(None);
            }
        };

        let bytes = fd.read(self, length)?;
        self.file_descriptors.insert(fd.fd(), fd);

        Ok(Some(bytes))
    }

    /// Write to a file descriptor
    pub fn write_fd(&mut self, fd: usize, data: Vec<il::Expression>) -> Result<()> {
        let mut fd: FileDescriptor = match self.file_descriptors.get_mut(&fd) {
            Some(fd) => fd.clone(),
            None => {
                return Err(ErrorKind::BadFileDescriptor.into());
            }
        };

        fd.write(self, data)?;

        Ok(())
    }

    /// Get size of file pointed to by file descriptor
    pub fn size_fd(&self, fd: usize) -> Option<usize> {
        self.file_descriptors
            .get(&fd)
            .and_then(|fd| self.files.get(fd.path()))
            .map(|file_contents| file_contents.len())
    }

    /// Write data into a file at an offset
    pub fn write(
        &mut self,
        path: &str,
        mut write_data: Vec<il::Expression>,
        offset: usize,
    ) -> Result<()> {
        println!("Calling write {}", path);
        if let Some(data) = self.files.get_mut(path) {
            if offset > data.len() {
                for _ in 0..(offset - data.len()) {
                    RC::make_mut(data).push(il::expr_const(0, 8));
                }
            }

            if offset == data.len() {
                RC::make_mut(data).append(&mut write_data);
            } else {
                let mut new_data = data
                    .get(0..offset)
                    .map(|data| data.to_vec())
                    .ok_or("Failed to get data bytes")?;
                new_data.append(&mut write_data);
                if data.len() > offset + write_data.len() {
                    new_data.append(
                        &mut data
                            .get((offset + write_data.len())..data.len())
                            .ok_or("Failed to get data bytes")?
                            .to_vec(),
                    );
                }
                *data = RC::new(new_data);
            }
            return Ok(());
        }

        let mut data: Vec<il::Expression> = Vec::new();
        for _ in 0..offset {
            data.push(il::expr_const(0, 8));
        }
        data.append(&mut write_data);
        self.files.insert(path.to_string(), RC::new(data));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_existing_filesystem_open_read() {
        use std::fs::File;
        use std::io::Write;

        let mut file = File::create("/tmp/test.finch.filesystem").unwrap();
        file.write_all("AAAABBBBCCCCDDDD".as_bytes()).unwrap();

        let mut filesystem = FileSystem::new(Some("/tmp".into())).unwrap();
        let fd = filesystem.open("/test.finch.filesystem").unwrap().unwrap();

        let bytes = filesystem.read_fd(fd, 16).unwrap().unwrap();

        assert_eq!(bytes[1], il::expr_const(0x41, 8));
        assert_eq!(bytes[5], il::expr_const(0x42, 8));
        assert_eq!(bytes[10], il::expr_const(0x43, 8));
        assert_eq!(bytes[12], il::expr_const(0x44, 8));

        assert_eq!(bytes.len(), 16);

        assert_eq!(filesystem.size_fd(fd).unwrap(), 16);
    }

    #[test]
    fn test_new_creates_stdin_stdout_stderr() {
        let fs = FileSystem::new(None).unwrap();
        assert!(fs.fd_valid(0)); // stdin
        assert!(fs.fd_valid(1)); // stdout
        assert!(fs.fd_valid(2)); // stderr
        assert!(!fs.fd_valid(3));
    }

    #[test]
    fn test_create_existing_file_gets_new_fd() {
        let mut fs = FileSystem::new(None).unwrap();
        let fd1 = fs.create("/testfile").unwrap();
        let fd2 = fs.create("/testfile").unwrap();
        assert_ne!(fd1, fd2);
    }

    #[test]
    fn test_read_fd_at_eof_returns_empty() {
        let mut fs = FileSystem::new(None).unwrap();
        let fd = fs.create("/eof_test").unwrap();
        // Write 2 bytes
        fs.write(
            "/eof_test",
            vec![il::expr_const(0x41, 8), il::expr_const(0x42, 8)],
            0,
        )
        .unwrap();
        // Read all bytes
        let bytes = fs.read_fd(fd, 10).unwrap().unwrap();
        assert_eq!(bytes.len(), 2);
        // Read again — at EOF
        let bytes = fs.read_fd(fd, 10).unwrap().unwrap();
        assert!(bytes.is_empty());
    }

    #[test]
    fn test_read_fd_short_read() {
        let mut fs = FileSystem::new(None).unwrap();
        let fd = fs.create("/short").unwrap();
        fs.write(
            "/short",
            vec![
                il::expr_const(0x41, 8),
                il::expr_const(0x42, 8),
                il::expr_const(0x43, 8),
            ],
            0,
        )
        .unwrap();
        // Request 10, only 3 available
        let bytes = fs.read_fd(fd, 10).unwrap().unwrap();
        assert_eq!(bytes.len(), 3);
    }

    #[test]
    fn test_fd_seek_set() {
        let mut fs = FileSystem::new(None).unwrap();
        let fd = fs.create("/seek_test").unwrap();
        fs.write(
            "/seek_test",
            vec![
                il::expr_const(0x41, 8),
                il::expr_const(0x42, 8),
                il::expr_const(0x43, 8),
                il::expr_const(0x44, 8),
            ],
            0,
        )
        .unwrap();
        let offset = fs.fd_seek(fd, 2, Whence::Set).unwrap();
        assert_eq!(offset, 2);
        let bytes = fs.read_fd(fd, 2).unwrap().unwrap();
        assert_eq!(bytes[0], il::expr_const(0x43, 8));
        assert_eq!(bytes[1], il::expr_const(0x44, 8));
    }

    #[test]
    fn test_fd_seek_cursor_forward_and_back() {
        let mut fs = FileSystem::new(None).unwrap();
        let fd = fs.create("/cursor_test").unwrap();
        fs.write(
            "/cursor_test",
            vec![
                il::expr_const(0x41, 8),
                il::expr_const(0x42, 8),
                il::expr_const(0x43, 8),
                il::expr_const(0x44, 8),
                il::expr_const(0x45, 8),
            ],
            0,
        )
        .unwrap();
        // Cursor +3
        let offset = fs.fd_seek(fd, 3, Whence::Cursor).unwrap();
        assert_eq!(offset, 3);
        // Cursor -1
        let offset = fs.fd_seek(fd, -1, Whence::Cursor).unwrap();
        assert_eq!(offset, 2);
        let bytes = fs.read_fd(fd, 1).unwrap().unwrap();
        assert_eq!(bytes[0], il::expr_const(0x43, 8));
    }

    #[test]
    fn test_fd_seek_end() {
        let mut fs = FileSystem::new(None).unwrap();
        let fd = fs.create("/end_test").unwrap();
        fs.write(
            "/end_test",
            vec![
                il::expr_const(0x41, 8),
                il::expr_const(0x42, 8),
                il::expr_const(0x43, 8),
                il::expr_const(0x44, 8),
                il::expr_const(0x45, 8),
            ],
            0,
        )
        .unwrap();
        // Seek to end
        let offset = fs.fd_seek(fd, 0, Whence::End).unwrap();
        assert_eq!(offset, 5);
        // Seek end - 3
        let offset = fs.fd_seek(fd, -3, Whence::End).unwrap();
        assert_eq!(offset, 2);
    }

    #[test]
    fn test_write_at_offset_past_eof_fills_zeros() {
        let mut fs = FileSystem::new(None).unwrap();
        fs.create("/gap_test").unwrap();
        fs.write(
            "/gap_test",
            vec![il::expr_const(0x41, 8), il::expr_const(0x42, 8)],
            0,
        )
        .unwrap();
        // Write at offset 5 (gap of 3 bytes)
        fs.write("/gap_test", vec![il::expr_const(0x99, 8)], 5)
            .unwrap();
        let bytes = fs.file_bytes("/gap_test").unwrap();
        assert_eq!(bytes.len(), 6);
        // Gap bytes should be zero
        assert_eq!(bytes[2], il::expr_const(0, 8));
        assert_eq!(bytes[3], il::expr_const(0, 8));
        assert_eq!(bytes[4], il::expr_const(0, 8));
        assert_eq!(bytes[5], il::expr_const(0x99, 8));
    }

    #[test]
    fn test_write_to_nonexistent_creates_file() {
        let mut fs = FileSystem::new(None).unwrap();
        fs.write("/new_file", vec![il::expr_const(0x41, 8)], 0)
            .unwrap();
        let bytes = fs.file_bytes("/new_file").unwrap();
        assert_eq!(bytes.len(), 1);
        assert_eq!(bytes[0], il::expr_const(0x41, 8));
    }

    #[test]
    fn test_write_to_nonexistent_with_offset() {
        let mut fs = FileSystem::new(None).unwrap();
        fs.write("/offset_new", vec![il::expr_const(0x99, 8)], 3)
            .unwrap();
        let bytes = fs.file_bytes("/offset_new").unwrap();
        assert_eq!(bytes.len(), 4);
        assert_eq!(bytes[0], il::expr_const(0, 8));
        assert_eq!(bytes[1], il::expr_const(0, 8));
        assert_eq!(bytes[2], il::expr_const(0, 8));
        assert_eq!(bytes[3], il::expr_const(0x99, 8));
    }

    #[test]
    fn test_close_fd_reclaims_highest() {
        let mut fs = FileSystem::new(None).unwrap();
        let fd = fs.create("/close_test").unwrap();
        assert_eq!(fd, 3);
        // next_fd should be 4
        assert!(fs.close_fd(fd));
        // After closing the highest fd, next_fd should go back to 3
        let fd2 = fs.create("/close_test2").unwrap();
        assert_eq!(fd2, 3);
    }

    #[test]
    fn test_close_fd_gap_no_reclaim() {
        let mut fs = FileSystem::new(None).unwrap();
        let _fd3 = fs.create("/a").unwrap(); // fd 3
        let _fd4 = fs.create("/b").unwrap(); // fd 4
                                             // Close fd 3 (middle), fd 4 still exists
        assert!(fs.close_fd(3));
        // next_fd should stay at 5 since fd 4 still exists
        let fd_next = fs.create("/c").unwrap();
        assert_eq!(fd_next, 5);
    }

    #[test]
    fn test_close_fd_invalid_returns_false() {
        let mut fs = FileSystem::new(None).unwrap();
        assert!(!fs.close_fd(99));
    }

    #[test]
    fn test_fd_valid_after_close() {
        let mut fs = FileSystem::new(None).unwrap();
        let fd = fs.create("/valid_test").unwrap();
        assert!(fs.fd_valid(fd));
        fs.close_fd(fd);
        assert!(!fs.fd_valid(fd));
    }

    #[test]
    fn test_zeroize_empties_file() {
        let mut fs = FileSystem::new(None).unwrap();
        fs.create("/zero_test").unwrap();
        fs.write(
            "/zero_test",
            vec![il::expr_const(0x41, 8), il::expr_const(0x42, 8)],
            0,
        )
        .unwrap();
        assert_eq!(fs.file_bytes("/zero_test").unwrap().len(), 2);
        fs.zeroize("/zero_test");
        assert!(fs.file_bytes("/zero_test").unwrap().is_empty());
    }

    #[test]
    fn test_size_fd_invalid() {
        let fs = FileSystem::new(None).unwrap();
        assert!(fs.size_fd(99).is_none());
    }

    #[test]
    fn test_write_fd_extends_file() {
        let mut fs = FileSystem::new(None).unwrap();
        let fd = fs.create("/extend_test").unwrap();
        fs.write(
            "/extend_test",
            vec![il::expr_const(0x41, 8), il::expr_const(0x42, 8)],
            0,
        )
        .unwrap();
        // Seek to end via Set
        fs.fd_seek(fd, 2, Whence::Set).unwrap();
        // Write via fd past end
        fs.write_fd(fd, vec![il::expr_const(0x43, 8), il::expr_const(0x44, 8)])
            .unwrap();
        let bytes = fs.file_bytes("/extend_test").unwrap();
        assert_eq!(bytes.len(), 4);
        assert_eq!(bytes[2], il::expr_const(0x43, 8));
        assert_eq!(bytes[3], il::expr_const(0x44, 8));
    }
}
