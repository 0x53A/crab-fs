use std::{io, ops::Deref, sync::PoisonError};
use libc::c_int;
use backtrace::Backtrace;
use remotefs::RemoteError;

// --------------------------------------------------------------

#[derive(Debug)]
pub enum ErrorKinds {
    IOError(io::Error),
    BincodeError(bincode::ErrorKind),
    PoisonError,
    C_Int(c_int),
    RemoteError(RemoteError)
}

#[derive(Debug)]
pub struct MyError {
    err: ErrorKinds,
    trace: Backtrace
}

impl From<io::Error> for MyError {
    fn from(error: io::Error) -> Self {
        MyError{err:ErrorKinds::IOError(error), trace: Backtrace::new()}
    }
}

impl From<bincode::ErrorKind> for MyError {
    fn from(error: bincode::ErrorKind) -> Self {
        MyError{err:ErrorKinds::BincodeError(error), trace: Backtrace::new()}
    }
}

impl From<Box<bincode::ErrorKind>> for MyError {
    fn from(error: Box<bincode::ErrorKind>) -> Self {
        MyError{err:ErrorKinds::BincodeError(*error), trace: Backtrace::new()}
    }
}

impl From<i32> for MyError {
    fn from(c_int: i32) -> Self {
        MyError{err:ErrorKinds::C_Int(c_int), trace: Backtrace::new()}
    }
}

impl From<RemoteError> for MyError {
    fn from(error: RemoteError) -> Self {
        MyError{err:ErrorKinds::RemoteError(error), trace: Backtrace::new()}
    }
}

impl<T> From<PoisonError<T>> for MyError {
    fn from(p: PoisonError<T>) -> Self {
        MyError{err:ErrorKinds::PoisonError, trace: Backtrace::new()}
    }
}
// ----------------------------------------------------------------

impl ErrorKinds {


}

impl Deref for ErrorKinds {
    type Target = c_int;

    fn deref(&self) -> &Self::Target {
        // Keep a static c_int for each error case that we can return a reference to
        static IO_ERROR: c_int = libc::EIO;
        static ENCODE_ERROR: c_int = libc::EINVAL;
        
        // Map different error kinds to appropriate error codes
        match self {
            ErrorKinds::BincodeError(bincode::ErrorKind::Io(e)) |
            ErrorKinds::IOError(e) => {
                // For IO errors, try to map the OS error code if available
                if let Some(err_code) = e.raw_os_error() {
                    // Need to store in a static to return reference
                    static mut OS_ERROR: c_int = 0;
                    // SAFETY: This is safe because we're the only ones accessing this static
                    // and it's only used to return an immutable reference
                    unsafe {
                        OS_ERROR = err_code;
                        &OS_ERROR
                    }
                } else {
                    return &IO_ERROR
                }
            },
            ErrorKinds::BincodeError(b) => return &ENCODE_ERROR,
            ErrorKinds::C_Int(c) => {
                // For direct c_int errors, we already have the error code
                // Need to store in a static to return reference
                static mut DIRECT_ERROR: c_int = 0;
                // SAFETY: This is safe because we're the only ones accessing this static
                // and it's only used to return an immutable reference
                unsafe {
                    DIRECT_ERROR = *c;
                    &DIRECT_ERROR
                }
            }
            ErrorKinds::PoisonError => return &IO_ERROR,
            ErrorKinds::RemoteError(_e) => return &IO_ERROR,
        }
    }
}

impl Deref for MyError {
    
    type Target = c_int;

    fn deref(&self) -> &Self::Target {
        println!("[Error] {:?}", self);
        self.err.deref()
    }
}

// ----------------------------------------------------------------

pub type MyResult<T> = Result<T, MyError>;

