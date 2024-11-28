use std::{io, ops::Deref};

use libc::c_int;

// --------------------------------------------------------------

pub enum ErrorKinds {
    IOError(io::Error),
    BincodeError(bincode::ErrorKind),
    C_Int(c_int)
}

impl From<io::Error> for ErrorKinds {
    fn from(error: io::Error) -> Self {
        ErrorKinds::IOError(error)
    }
}

impl From<bincode::ErrorKind> for ErrorKinds {
    fn from(error: bincode::ErrorKind) -> Self {
        ErrorKinds::BincodeError(error)
    }
}

impl From<Box<bincode::ErrorKind>> for ErrorKinds {
    fn from(error: Box<bincode::ErrorKind>) -> Self {
        ErrorKinds::BincodeError(*error)
    }
}

impl From<i32> for ErrorKinds {
    fn from(c_int: i32) -> Self {
        ErrorKinds::C_Int(c_int)
    }
}

// ----------------------------------------------------------------

impl ErrorKinds {


}

impl Deref for ErrorKinds {
    type Target = c_int;

    fn deref(&self) -> &Self::Target {
        todo!()
    }
}


// ----------------------------------------------------------------

pub type MyResult<T> = Result<T, ErrorKinds>;

