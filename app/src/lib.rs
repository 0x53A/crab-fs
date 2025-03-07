#![allow(clippy::needless_return)]
#![allow(clippy::unnecessary_cast)] // libc::S_* are u16 or u32 depending on the platform
#![feature(path_add_extension)]
#![feature(let_chains)]
#![feature(assert_matches)]

pub mod crypt {
    pub use crab_fs_common::crypt::*;
}
pub mod cuttlefish;
pub mod entropy {
    pub use crab_fs_common::entropy::*;
}
pub mod errors {
    pub use crab_fs_common::errors::*;
}
pub mod io {
    pub mod fs {
        pub use crab_fs_backend::io::fs::*;
        pub use crab_fs_common::io::fs::*;
    }
}
pub mod repository {
    pub use crab_fs_repository::*;
}
