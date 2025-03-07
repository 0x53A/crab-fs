use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crab_fs_common::errors::{MyError, MyResult};

use crab_fs_common::io::fs::{
    Capabilities, Finalize, Len, SetLen, SimpleSnapshot, Snapshottable, TFile, FS,
};

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

#[derive(Clone)]
pub struct PhysicalFS {
    // todo: actually use root
    root: Box<std::path::Path>,
}

impl PhysicalFS {
    pub fn new<P: AsRef<Path>>(root: P) -> Self {
        Self {
            root: root.as_ref().to_owned().into_boxed_path(),
        }
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

impl PhysicalFS {
    pub fn to_host_path<P: AsRef<Path>>(&self, path: P) -> MyResult<PathBuf> {
        let path = path.as_ref();

        let path = if path.is_relative() {
            self.root.join(path)
        } else {
            let relative = path
                .strip_prefix("/")
                .map_err(|e| MyError::new_io(io::ErrorKind::InvalidInput, e))?;
            self.root.join(relative)
        };

        let path = Self::normalize_path(&path);

        match path.strip_prefix(&self.root) {
            Ok(_) => Ok(path),
            Err(_) => Err(MyError::new_io(
                io::ErrorKind::InvalidInput,
                "Path is outside of root",
            )),
        }
    }

    fn normalize_path(path: &Path) -> PathBuf {
        let mut result = PathBuf::new();

        for component in path.components() {
            match component {
                std::path::Component::ParentDir => {
                    if !result.pop() {
                        // If we can't pop, we might be at root or trying to escape
                        // Just keep the parent dir in this case
                        result.push(component);
                    }
                }
                std::path::Component::CurDir => {
                    // Skip current directory components
                }
                _ => result.push(component),
            }
        }

        result
    }

    // pub fn from_host_path<P: AsRef<Path>>(&self, path: P) -> MyResult<PathBuf> {
    //     todo!()
    // }
}

pub fn test_to_host_path_case(expected: Option<&str>, input: &str) {
    let fs = PhysicalFS::new("/data");
    let result = fs.to_host_path(input);
    match (expected, &result) {
        (Some(exp), Ok(path)) => assert_eq!(exp, path.to_str().unwrap()),
        (None, Err(_)) => {} // Expected when input should fail
        _ => panic!(
            "Unexpected result: expected {:?} but got {:?}",
            expected, result
        ),
    }
}

#[test]
pub fn test_to_host_path() {
    // Test absolute paths
    test_to_host_path_case(Some("/data/test.txt"), "/test.txt");
    test_to_host_path_case(Some("/data/dir/test.txt"), "/dir/test.txt");

    // Test relative paths
    test_to_host_path_case(Some("/data/test.txt"), "test.txt");
    test_to_host_path_case(Some("/data/dir/test.txt"), "dir/test.txt");

    // Test path normalization
    test_to_host_path_case(Some("/data/dir/test.txt"), "/dir/./test.txt");
    test_to_host_path_case(Some("/data/test.txt"), "/dir/../test.txt");

    // Test edge cases
    test_to_host_path_case(Some("/data"), "");
    test_to_host_path_case(Some("/data"), "/");

    // Test paths that should fail (attempts to escape root directory)
    test_to_host_path_case(None, "../outside.txt");
    test_to_host_path_case(None, "/../outside.txt");
    test_to_host_path_case(None, "/dir/../../outside.txt");
}

#[cfg(target_os = "windows")]
#[test]
pub fn test_to_host_path() {
    let fs = PhysicalFS::new("C:\\data");
    assert_eq!("C:\\data", to_host_path(""));
}

impl FS for PhysicalFS {
    type File = std::fs::File;

    fn create_dir_all<P: AsRef<Path>>(&self, path: P) -> MyResult<()> {
        fs::create_dir_all(self.to_host_path(path)?)?;
        Ok(())
    }

    fn rename<P: AsRef<Path>, Q: AsRef<Path>>(&self, from: P, to: Q) -> MyResult<()> {
        fs::rename(self.to_host_path(from)?, self.to_host_path(to)?)?;
        Ok(())
    }

    fn create<P: AsRef<Path>>(&self, path: P) -> MyResult<Self::File> {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(self.to_host_path(path)?)?;
        Ok(file)
    }

    fn open_read<P: AsRef<Path>>(&self, path: P) -> MyResult<Self::File> {
        let file = OpenOptions::new()
            .read(true)
            .open(self.to_host_path(path)?)?;
        Ok(file)
    }

    fn open_write<P: AsRef<Path>>(&self, path: P) -> MyResult<Self::File> {
        let file = OpenOptions::new()
            .write(true)
            .open(self.to_host_path(path)?)?;
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

impl Snapshottable for PhysicalFS {
    type Snapshot = SimpleSnapshot;

    fn create_snapshot(&self) -> Self::Snapshot {
        let mut files = HashMap::new();
        let mut dirs = Vec::new();

        // Function to recursively visit directories
        fn visit_dirs(
            dir: &Path,
            root: &Path,
            files: &mut HashMap<Box<Path>, Box<[u8]>>,
            dirs: &mut Vec<Box<Path>>,
        ) -> io::Result<()> {
            // Get relative path to root
            let rel_path = match dir.strip_prefix(root) {
                Ok(p) => p,
                Err(_) => dir, // Fallback to absolute path if strip_prefix fails
            };

            // Add this directory to the dirs list (skip the root directory itself)
            if !rel_path.as_os_str().is_empty() {
                dirs.push(rel_path.to_path_buf().into_boxed_path());
            }

            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();

                // Get relative path for this entry
                let entry_rel_path = match path.strip_prefix(root) {
                    Ok(p) => p,
                    Err(_) => &path, // Fallback to absolute path if strip_prefix fails
                };

                if path.is_dir() {
                    visit_dirs(&path, root, files, dirs)?;
                } else {
                    // Read file content
                    let content = fs::read(&path)?;
                    files.insert(
                        entry_rel_path.to_path_buf().into_boxed_path(),
                        content.into_boxed_slice(),
                    );
                }
            }

            Ok(())
        }

        visit_dirs(&self.root, &self.root, &mut files, &mut dirs).unwrap();

        SimpleSnapshot::new(files, dirs.into_boxed_slice())
    }
}
