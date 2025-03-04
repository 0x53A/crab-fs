use std::cell::RefCell;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::errors::MyResult;

pub trait Len {
    fn len(&mut self) -> MyResult<u64>;
}

pub trait SetLen {
    fn set_len(&mut self, size: u64) -> MyResult<()>;
}

pub trait Finalize {
    fn finalize(&mut self) -> MyResult<()>;
}

pub trait Capabilities {
    /// can files be mutated? This includes writing data in the middle.
    fn can_mutate(&self) -> bool;
    /// can files be truncated?
    fn can_truncate(&self) -> bool;
    /// can files be renamed? This is probably implemented using 'move'.
    fn can_rename(&self) -> bool;
    /// can data be appended at the end?
    fn can_append(&self) -> bool;
}

pub trait FS: Clone + Capabilities {
    type File: Read + Write + Seek + Len + SetLen + Finalize;

    /// create all missing directories in the path, it does not fail if the dir already exists
    fn create_dir_all<P: AsRef<Path>>(&self, path: P) -> MyResult<()>;
    /// renames a file or directory, undefined behavior if `to` already exists.
    fn rename<P: AsRef<Path>, Q: AsRef<Path>>(&self, from: P, to: Q) -> MyResult<()>;
    /// create a new file, truncating it if it already exists. The parent folder must already exist.
    fn create<P: AsRef<Path>>(&self, path: P) -> MyResult<Self::File>;
    fn open_read<P: AsRef<Path>>(&self, path: P) -> MyResult<Self::File>;
    fn open_write<P: AsRef<Path>>(&self, path: P) -> MyResult<Self::File>;

    /// zero a file range, extending the file if necessary, but failing if the start offset is after the current end of the file.
    fn zero_file_range(&self, file: &Self::File, offset: u64, len: u64) -> MyResult<()>;
    /// copy data from the other file into this file
    fn copy_file_range(
        &self,
        src_file: &Self::File,
        src_offset: u64,
        dst_file: &Self::File,
        dst_offset: u64,
        len: u64,
    ) -> MyResult<u64>;
}
