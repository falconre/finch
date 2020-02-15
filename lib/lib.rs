//! Finch: A Symbolic Executor Built With Falcon
extern crate byteorder;
#[macro_use]
extern crate error_chain;
extern crate falcon;
extern crate falcon_capstone;
extern crate falcon_z3;
extern crate goblin;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;
// extern crate unicorn;

pub mod executor;
pub mod platform;
// pub mod unicorn_verify_amd64;
// pub mod unicorn_verify_mips;
// pub mod unicorn_verify_x86;

pub mod error {
    error_chain! {
        types {
            Error, ErrorKind, ResultExt, Result;
        }

        foreign_links {
            Falcon(::falcon::error::Error);
            FalconZ3(::falcon_z3::error::Error);
            FromUtf8Error(::std::string::FromUtf8Error);
            IoError(::std::io::Error);
        }

        errors {
            BadFileDescriptor {
                description("Bad file descriptor")
                display("Bad file descriptor")
            }
            HeapInvalidFree(address: u64) {
                description("Free called on invalid address")
                display("Free called on invalid address: 0x{:x}", address)
            }
            RegionOutOfBounds {
                description("Out of bounds index into region")
                display("Out of bounds index into region")
            }
            UnhandledIntrinsic(intrinsic_string: String) {
                description("Unhandled intrinsic")
                display("Unhandled intrinsic: {}", intrinsic_string)
            }
        }
    }
}
