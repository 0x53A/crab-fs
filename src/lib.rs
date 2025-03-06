#![allow(clippy::needless_return)]
#![allow(clippy::unnecessary_cast)] // libc::S_* are u16 or u32 depending on the platform
#![feature(path_add_extension)]
#![feature(let_chains)]
#![feature(assert_matches)]

pub mod crypt;
pub mod cuttlefish;
pub mod entropy;
pub mod errors;
pub mod io;
pub mod repository;
