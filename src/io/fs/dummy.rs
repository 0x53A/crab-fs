use std::cell::RefCell;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::errors::MyResult;

use super::{Capabilities, Finalize, Len, SetLen, TFile, FS};

#[derive(Clone)]
pub struct DummyFile {}

impl DummyFile {
    fn new() -> Self {
        Self {}
    }
}

impl Read for DummyFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Other,
            "This is a dummy file and can't be used",
        ))
    }
}

impl Write for DummyFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Other,
            "This is a dummy file and can't be used",
        ))
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Other,
            "This is a dummy file and can't be used",
        ))
    }
}

impl Seek for DummyFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        Err(io::Error::new(
            io::ErrorKind::Other,
            "This is a dummy file and can't be used",
        ))
    }
}

impl Len for DummyFile {
    fn len(&mut self) -> MyResult<u64> {
        Err(io::Error::new(
            io::ErrorKind::Other,
            "This is a dummy file and can't be used",
        ))?
    }
}

impl SetLen for DummyFile {
    fn set_len(&mut self, size: u64) -> MyResult<()> {
        Err(io::Error::new(
            io::ErrorKind::Other,
            "This is a dummy file and can't be used",
        ))?
    }
}

impl Finalize for DummyFile {
    fn finalize(&mut self) -> MyResult<()> {
        Ok(())
    }
}

impl TFile for DummyFile {}

#[derive(Copy, Clone)]
pub struct DummyFS;

impl Capabilities for DummyFS {
    fn can_mutate(&self) -> bool {
        false
    }

    fn can_truncate(&self) -> bool {
        false
    }

    fn can_rename(&self) -> bool {
        false
    }

    fn can_append(&self) -> bool {
        false
    }
}

impl FS for DummyFS {
    type File = DummyFile;

    fn create_dir_all<P: AsRef<Path>>(&self, _path: P) -> MyResult<()> {
        Ok(())
    }

    fn rename<P: AsRef<Path>, Q: AsRef<Path>>(&self, _from: P, _to: Q) -> MyResult<()> {
        Ok(())
    }

    fn create<P: AsRef<Path>>(&self, _path: P) -> MyResult<Self::File> {
        Ok(DummyFile::new())
    }

    fn open_read<P: AsRef<Path>>(&self, _path: P) -> MyResult<Self::File> {
        Ok(DummyFile::new())
    }

    fn open_write<P: AsRef<Path>>(&self, _path: P) -> MyResult<Self::File> {
        Ok(DummyFile::new())
    }

    fn zero_file_range(&self, file: &Self::File, offset: u64, len: u64) -> MyResult<()> {
        Ok(())
    }

    fn copy_file_range(
        &self,
        _src_file: &Self::File,
        _src_offset: u64,
        dst_file: &Self::File,
        dst_offset: u64,
        len: u64,
    ) -> MyResult<u64> {
        Ok(len)
    }
}
