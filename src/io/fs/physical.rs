use std::cell::RefCell;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::errors::MyResult;

use super::{Capabilities, Finalize, Len, SetLen, FS};

// ------------------------

#[cfg(target_os = "linux")]
fn zero_file_range_linux(file: &File, offset: u64, len: u64) -> io::Result<()> {
    use std::{io, os::unix::io::AsRawFd};

    let ret = unsafe {
        libc::fallocate(
            file.as_raw_fd(),
            libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
            offset as libc::off_t,
            len as libc::off_t,
        )
    };

    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

// Fallback implementation for other platforms or if fallocate fails
fn zero_file_range_fallback(file: &File, offset: u64, len: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;

    // Write in chunks to avoid large allocations
    const CHUNK_SIZE: usize = 64 * 1024; // 64KB chunks
    let zeros = vec![0u8; CHUNK_SIZE];

    let mut remaining = len;
    let mut current_offset = offset;

    while remaining > 0 {
        let write_size = std::cmp::min(remaining, CHUNK_SIZE as u64) as usize;
        file.write_at(&zeros[..write_size], current_offset)?;
        remaining -= write_size as u64;
        current_offset += write_size as u64;
    }

    Ok(())
}

// Combined function that tries fallocate first, then falls back
fn zero_file_range(file: &File, offset: u64, len: u64) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        match zero_file_range_linux(file, offset, len) {
            Ok(()) => return Ok(()),
            Err(_) => {} // Fall through to fallback
        }
    }

    zero_file_range_fallback(file, offset, len)
}

// ------------------------

#[cfg(target_os = "linux")]
fn copy_file_range_linux(
    src_file: &File,
    src_offset: u64,
    dst_file: &File,
    dst_offset: u64,
    len: u64,
) -> io::Result<u64> {
    use std::os::unix::io::AsRawFd;

    let mut src_off = src_offset as i64;
    let mut dst_off = dst_offset as i64;
    let ret = unsafe {
        libc::copy_file_range(
            src_file.as_raw_fd(),
            &mut src_off,
            dst_file.as_raw_fd(),
            &mut dst_off,
            len as usize,
            0, // flags
        )
    };

    if ret >= 0 {
        Ok(ret as u64)
    } else {
        Err(io::Error::last_os_error())
    }
}

fn copy_file_range(
    mut src_file: &File,
    src_offset: u64,
    mut dst_file: &File,
    dst_offset: u64,
    len: u64,
) -> io::Result<u64> {
    #[cfg(target_os = "linux")]
    {
        match copy_file_range_linux(src_file, src_offset, dst_file, dst_offset, len) {
            Ok(n) => return Ok(n),
            Err(_) => {} // Fall through to fallback
        }
    }

    // Fallback implementation
    let mut buffer = vec![0u8; std::cmp::min(len as usize, 64 * 1024)]; // 64KB chunks
    let mut total_copied = 0u64;
    let mut remaining = len;

    while remaining > 0 {
        let to_copy = std::cmp::min(remaining, buffer.len() as u64);
        src_file.seek(SeekFrom::Start(src_offset + total_copied))?;
        src_file.read_exact(&mut buffer[..to_copy as usize])?;

        dst_file.seek(SeekFrom::Start(dst_offset + total_copied))?;
        dst_file.write_all(&buffer[..to_copy as usize])?;

        total_copied += to_copy;
        remaining -= to_copy;
    }

    Ok(total_copied)
}

// ------------------------

#[derive(Copy, Clone)]
pub struct PhysicalFS;

impl Len for std::fs::File {
    fn len(&mut self) -> MyResult<u64> {
        return Ok(self.metadata()?.len());
    }
}

impl SetLen for std::fs::File {
    fn set_len(&mut self, size: u64) -> MyResult<()> {
        self.set_len(size)?;
        Ok(())
    }
}

impl Finalize for std::fs::File {
    fn finalize(&mut self) -> MyResult<()> {
        self.flush()?;
        Ok(())
    }
}

impl Capabilities for PhysicalFS {
    fn can_mutate(&self) -> bool {
        true
    }

    fn can_truncate(&self) -> bool {
        true
    }

    fn can_rename(&self) -> bool {
        true
    }

    fn can_append(&self) -> bool {
        true
    }
}

impl FS for PhysicalFS {
    type File = std::fs::File;

    fn create_dir_all<P: AsRef<Path>>(&self, path: P) -> MyResult<()> {
        fs::create_dir_all(path)?;
        Ok(())
    }

    fn rename<P: AsRef<Path>, Q: AsRef<Path>>(&self, from: P, to: Q) -> MyResult<()> {
        fs::rename(from, to)?;
        Ok(())
    }

    fn create<P: AsRef<Path>>(&self, path: P) -> MyResult<Self::File> {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        Ok(file)
    }

    fn open_read<P: AsRef<Path>>(&self, path: P) -> MyResult<Self::File> {
        let file = OpenOptions::new().read(true).open(path)?;
        Ok(file)
    }

    fn open_write<P: AsRef<Path>>(&self, path: P) -> MyResult<Self::File> {
        let file = OpenOptions::new().write(true).open(path)?;
        Ok(file)
    }

    fn zero_file_range(&self, file: &Self::File, offset: u64, len: u64) -> MyResult<()> {
        return Ok(zero_file_range(file, offset, len)?);
    }

    fn copy_file_range(
        &self,
        src_file: &Self::File,
        src_offset: u64,
        dst_file: &Self::File,
        dst_offset: u64,
        len: u64,
    ) -> MyResult<u64> {
        return Ok(copy_file_range(
            src_file, src_offset, dst_file, dst_offset, len,
        )?);
    }
}
