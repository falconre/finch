//! Constant values for the Linux Operating System.
//!
//! These are used and set by architecture-specific implementations of Linux.

/// Constants used and set by architecture-specific models of the Linux
/// Operating System.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[allow(non_snake_case)]
pub struct Constants {
    pub PAGE_SIZE: u64,

    pub MAP_SHARED: u64,
    pub MAP_PRIVATE: u64,
    pub MAP_FIXED: u64,
    pub MAP_LOCAL: u64,
    pub MAP_ANONYMOUS: u64,
    pub O_CREAT: u64,
    pub PROT_READ: u64,
    pub PROT_WRITE: u64,
    pub PROT_EXEC: u64,
    pub SEEK_SET: u64,
    pub SEEK_CUR: u64,
    pub SEEK_END: u64
}