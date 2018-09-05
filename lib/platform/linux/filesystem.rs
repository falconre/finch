use error::*;
use falcon::{il, RC};
use platform::linux::FileDescriptor;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;


/// A Whence, used when seeking a file descriptor.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Whence {
    Set,
    Cursor,
    End
}


/// A basic model of the Linux Filesystem
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FileSystem {
    file_descriptors: HashMap<usize, FileDescriptor>,
    files: HashMap<String, RC<Vec<il::Expression>>>,
    base_path: Option<PathBuf>,
    next_fd: usize
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
            base_path: base_path,
            next_fd: 0
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
                if path.starts_with("/") {
                    base_path.join(path.get(1..(path.len())).unwrap())
                }
                else {
                    base_path.join(path)
                }
            },
            None => path.to_string().into()
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
    pub fn fd_seek(&mut self, fd: usize, offset: isize, seek: Whence)
        -> Result<usize> {

        match seek {
            Whence::Set => {
                self.file_descriptors.get_mut(&fd)
                    .ok_or("Could not find fd for fd_seek")?
                    .set_offset(offset as usize);
            },
            Whence::Cursor => {
                let mut fd = self.file_descriptors.get_mut(&fd)
                    .ok_or("Could not find fd for fd_seek")?;

                let cur_offset = fd.offset();
                fd.set_offset((cur_offset as isize + offset) as usize);
            },
            Whence::End => {
                let path = self.file_descriptors.get(&fd)
                    .ok_or("Could not find fd for fd_seek")?
                    .path()
                    .to_string(); // kill the borrow
                let filesize = self.files.get(&path)
                    .ok_or("Could not find file for fd_seek SEEK_END")?
                    .len();
                self.file_descriptors.get_mut(&fd)
                    .ok_or("Could not find fd for fd_seek")?
                    .set_offset((filesize as isize + offset) as usize);
            }
        }

        Ok(self.file_descriptors
            .get(&fd)
            .ok_or("Could not find fd for fd_seek")?
            .offset())
    }


    /// Returns true if the file descriptor exists.
    pub fn fd_valid(&self, fd: usize) -> bool {
        self.file_descriptors.get(&fd).is_some()
    }


    /// Attempt to open a file and read it into the filesystem model. Returns
    /// a file descriptor if the file exists, or None.
    pub fn open(&mut self, path: &str) -> Result<Option<usize>> {
        if self.files.get(path).is_some() {
            return Ok(Some(self.add_file_descriptor(path)));
        }

        if self.get_path(path).exists() {
            let mut file = File::open(&self.get_path(path))?;

            let mut buf = Vec::new();
            file.read_to_end(&mut buf)?;

            let bytes =
                buf.into_iter()
                    .map(|byte| il::expr_const(byte as u64, 8))
                    .collect::<Vec<il::Expression>>();

            self.files.insert(path.to_string(), RC::new(bytes));
            Ok(Some(self.add_file_descriptor(path)))
        }
        else {
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
        self.files.get(path).is_some() || PathBuf::from(path.to_string()).exists()
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
    pub fn file_bytes_mut(&mut self, path: &str)
        -> Option<&mut Vec<il::Expression>> {

        self.files.get_mut(path).map(|v| RC::make_mut(v))
    }


    /// Get the bytes to a file pointed to by a file descriptor
    pub fn fd_bytes(&self, fd: usize) -> Option<&[il::Expression]> {
        self.file_descriptors.get(&fd)
            .and_then(|fd| self.files.get(fd.path()))
            .map(|bytes| bytes.as_ref().as_ref())
    }


    /// Close a file descriptor. Returns true if file descriptor existed, false
    /// otherwise
    pub fn close_fd(&mut self, fd: usize) -> bool {
        if self.file_descriptors.remove(&fd).is_some() {
            while self.file_descriptors.get(&(self.next_fd - 1)).is_none() {
                if self.next_fd == 0 {
                    break;
                }
                self.next_fd = self.next_fd - 1;
            }
            true
        }
        else {
            false
        }
    }


    /// Read from a file descriptor
    pub fn read_fd(&mut self, fd: usize, length: usize)
        -> Result<Option<Vec<il::Expression>>> {

        let mut fd: FileDescriptor = match self.file_descriptors.get_mut(&fd) {
            Some(fd) => fd.clone(),
            None => { 
                return Ok(None); 
            }
        };

        let bytes = fd.read(&self, length)?;
        self.file_descriptors.insert(fd.fd(), fd);

        Ok(Some(bytes))
    }


    /// Write to a file descriptor
    pub fn write_fd(&mut self, fd: usize, data: Vec<il::Expression>)
        -> Result<()> {

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
        self.file_descriptors.get(&fd)
            .and_then(|fd| self.files.get(fd.path()))
            .map(|file_contents| file_contents.len())
    }


    /// Write data into a file at an offset
    pub fn write(
        &mut self,
        path: &str,
        mut write_data: Vec<il::Expression>,
        offset: usize
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
            }
            else {
                let mut new_data =
                    data.get(0..offset)
                        .map(|data| data.to_vec())
                        .ok_or("Failed to get data bytes")?;
                new_data.append(&mut write_data);
                if data.len() > offset + write_data.len() {
                    new_data.append(
                        &mut data.get(
                            (offset + write_data.len())..data.len())
                            .ok_or("Failed to get data bytes")?
                            .to_vec());
                }
                *data = RC::new(new_data);
            }
            return Ok(())
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


#[test]
fn test() {
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