use std::collections::HashMap;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use crate::errors::{MyError, MyResult};
use crate::io::fs::{Capabilities, Finalize, Len, SetLen, FS};

type InMemoryPathSegment = Box<[u8]>;
type InMemoryPath = [InMemoryPathSegment];

// Helper function to convert Path to InMemoryPath segments
fn path_to_segments<P: AsRef<Path>>(path: P) -> Vec<InMemoryPathSegment> {
    path.as_ref()
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(s) => Some(
                s.to_string_lossy()
                    .into_owned()
                    .into_bytes()
                    .into_boxed_slice(),
            ),
            _ => None,
        })
        .collect()
}

pub struct FileEntry {
    pub data: Vec<u8>,
    pub created: SystemTime,
    pub last_modified: SystemTime,
}

impl FileEntry {
    fn new() -> Self {
        let now = SystemTime::now();
        FileEntry {
            data: Vec::new(),
            created: now,
            last_modified: now,
        }
    }

    fn update_modified_time(&mut self) {
        self.last_modified = SystemTime::now();
    }
}

pub struct DirectoryEntry {
    files: HashMap<InMemoryPathSegment, FileEntry>,
    directories: HashMap<InMemoryPathSegment, DirectoryEntry>,
}

impl DirectoryEntry {
    fn new() -> Self {
        DirectoryEntry {
            files: HashMap::new(),
            directories: HashMap::new(),
        }
    }
}

pub enum Entry {
    Directory(DirectoryEntry),
    FileEntry(FileEntry),
}

pub struct InMemoryFsData {
    root: DirectoryEntry,
    open_handles: HashMap<u32, InMemoryFileHandleData>,
    next_handle_id: u32,
}

impl InMemoryFsData {
    fn get_file_entry(&self, path: &[InMemoryPathSegment]) -> MyResult<&FileEntry> {
        if path.is_empty() {
            return Err(io::Error::new(io::ErrorKind::NotFound, "Path is empty").into());
        }

        let dir_path = &path[0..path.len() - 1];
        let file_name = &path[path.len() - 1];

        let dir = self.get_directory_entry(dir_path)?;

        dir.files
            .get(file_name)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "File not found").into())
    }

    fn get_file_entry_mut(&mut self, path: &[InMemoryPathSegment]) -> MyResult<&mut FileEntry> {
        if path.is_empty() {
            return Err(io::Error::new(io::ErrorKind::NotFound, "Path is empty").into());
        }

        let dir_path = &path[0..path.len() - 1];
        let file_name = &path[path.len() - 1];

        let dir = self.get_directory_entry_mut(dir_path)?;

        dir.files
            .get_mut(file_name)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "File not found").into())
    }

    fn get_directory_entry(&self, path: &[InMemoryPathSegment]) -> MyResult<&DirectoryEntry> {
        if path.is_empty() {
            return Ok(&self.root);
        }

        let mut current_dir = &self.root;

        for segment in path {
            current_dir = current_dir
                .directories
                .get(segment)
                .ok_or_else(|| MyError::new_io(io::ErrorKind::NotFound, "Directory not found"))?;
        }

        Ok(current_dir)
    }

    fn get_directory_entry_mut(
        &mut self,
        path: &[InMemoryPathSegment],
    ) -> MyResult<&mut DirectoryEntry> {
        if path.is_empty() {
            return Ok(&mut self.root);
        }

        let mut current_dir = &mut self.root;

        for segment in path {
            current_dir = current_dir
                .directories
                .get_mut(segment)
                .ok_or_else(|| MyError::new_io(io::ErrorKind::NotFound, "Directory not found"))?;
        }

        Ok(current_dir)
    }

    // Create directories recursively
    fn create_directories(&mut self, path: &[InMemoryPathSegment]) -> MyResult<()> {
        if path.is_empty() {
            return Ok(());
        }

        let mut current_dir = &mut self.root;

        for segment in path {
            current_dir = current_dir
                .directories
                .entry(segment.clone())
                .or_insert_with(DirectoryEntry::new);
        }

        Ok(())
    }

    fn create_file(&mut self, path: &[InMemoryPathSegment]) -> MyResult<&mut FileEntry> {
        if path.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Cannot create file with empty path",
            )
            .into());
        }

        let dir_path = &path[0..path.len() - 1];
        let file_name = &path[path.len() - 1];

        // Get the parent directory
        let dir = self.get_directory_entry_mut(dir_path)?;

        // Create the file if it doesn't exist
        let mut file_entry = dir
            .files
            .entry(file_name.clone());

        match &mut file_entry {
            std::collections::hash_map::Entry::Occupied(ref mut occupied_entry) => {
                let entry = occupied_entry.get_mut();
                entry.data.clear();
                entry.update_modified_time();
            },
            std::collections::hash_map::Entry::Vacant(_) => {
                
            }
        };

        Ok(file_entry.or_insert_with(FileEntry::new))
    }

    // Rename a file from one path to another
    fn rename_file(
        &mut self,
        from_path: &[InMemoryPathSegment],
        to_path: &[InMemoryPathSegment],
    ) -> MyResult<()> {
        if from_path.is_empty() || to_path.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Cannot rename with empty path",
            )
            .into());
        }

        // Extract the file entry from the source
        let file_entry = {
            let from_dir_path = &from_path[0..from_path.len() - 1];
            let from_file_name = &from_path[from_path.len() - 1];

            let from_dir = self.get_directory_entry_mut(from_dir_path)?;

            // Remove the file from source
            from_dir
                .files
                .remove(from_file_name)
                .ok_or_else(|| MyError::new_io(io::ErrorKind::NotFound, "Source file not found"))?
        };

        // Create the destination's parent directories if needed
        let to_dir_path = &to_path[0..to_path.len() - 1];
        let to_file_name = &to_path[to_path.len() - 1];

        // Get the destination directory and insert the file
        let to_dir = self.get_directory_entry_mut(to_dir_path)?;

        // Check if destination already exists
        if to_dir.files.contains_key(to_file_name) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Destination file already exists",
            )
            .into());
        }

        to_dir.files.insert(to_file_name.clone(), file_entry);

        Ok(())
    }
}

pub struct FileHandlePermissions {
    pub read: bool,
    pub write: bool,
}

#[derive(Clone)]
pub struct InMemoryFS {
    fs_data: Arc<Mutex<InMemoryFsData>>,
}

struct InMemoryFileHandleData {
    path: Vec<InMemoryPathSegment>,
    position: u64,
    permissions: FileHandlePermissions,
}

pub struct InMemoryFileHandle {
    id: u32,
    fs: Arc<Mutex<InMemoryFS>>,
}

impl InMemoryFS {
    pub fn new() -> Self {
        let root = DirectoryEntry::new();
        let fs_data = InMemoryFsData {
            root,
            open_handles: HashMap::new(),
            next_handle_id: 0,
        };

        InMemoryFS {
            fs_data: Arc::new(Mutex::new(fs_data)),
        }
    }
}

impl InMemoryFS {
    fn read(&mut self, handle_id: u32, buf: &mut [u8]) -> io::Result<usize> {
        let mut fs_data = self
            .fs_data
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to lock filesystem"))?;

        let handle_data = fs_data
            .open_handles
            .get(&handle_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid handle"))?;

        if !handle_data.permissions.read {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "File not opened for reading",
            ));
        }

        let position = handle_data.position;
        let path = &handle_data.path;

        let file = fs_data
            .get_file_entry(path)
            .map_err(|_| io::Error::new(io::ErrorKind::NotFound, "File not found"))?;

        let available = if position >= file.data.len() as u64 {
            0
        } else {
            file.data.len() as u64 - position
        };

        let bytes_to_read = std::cmp::min(available as usize, buf.len());

        if bytes_to_read > 0 {
            let start = position as usize;
            let end = start + bytes_to_read;
            buf[..bytes_to_read].copy_from_slice(&file.data[start..end]);

            // Update position
            let handle_data = fs_data.open_handles.get_mut(&handle_id).unwrap();
            handle_data.position += bytes_to_read as u64;
        }

        Ok(bytes_to_read)
    }

    fn write(&mut self, handle_id: u32, buf: &[u8]) -> io::Result<usize> {
        let mut fs_data = self
            .fs_data
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to lock filesystem"))?;

        let handle_data = fs_data
            .open_handles
            .get(&handle_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid handle"))?;

        if !handle_data.permissions.write {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "File not opened for writing",
            ));
        }

        let position = handle_data.position;
        let path = &handle_data.path.clone();

        let file = fs_data
            .get_file_entry_mut(path)
            .map_err(|_| io::Error::new(io::ErrorKind::NotFound, "File not found"))?;

        // Ensure file size is adequate
        if position > file.data.len() as u64 {
            file.data.resize(position as usize, 0);
        }

        let start = position as usize;
        let end = start + buf.len();

        // If writing past end of file, resize it
        if end > file.data.len() {
            file.data.resize(end, 0);
        }

        // Write the data
        file.data[start..end].copy_from_slice(buf);

        // Update modified time
        file.update_modified_time();

        // Update position
        let handle_data = fs_data.open_handles.get_mut(&handle_id).unwrap();
        handle_data.position += buf.len() as u64;

        Ok(buf.len())
    }

    fn seek(&mut self, handle_id: u32, pos: SeekFrom) -> io::Result<u64> {
        let mut fs_data = self
            .fs_data
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to lock filesystem"))?;

        let handle_data = fs_data
            .open_handles
            .get_mut(&handle_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid handle"))?;

        let path = &handle_data.path.clone();
        let current_pos = handle_data.position;

        let file = fs_data
            .get_file_entry(path)
            .map_err(|_| io::Error::new(io::ErrorKind::NotFound, "File not found"))?;

        let file_len = file.data.len() as u64;

        let new_pos = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::End(offset) => {
                if offset > 0 {
                    file_len + offset as u64
                } else if offset.unsigned_abs() > file_len {
                    0
                } else {
                    file_len - offset.unsigned_abs()
                }
            }
            SeekFrom::Current(offset) => {
                if offset >= 0 {
                    current_pos + offset as u64
                } else if offset.unsigned_abs() > current_pos {
                    0
                } else {
                    current_pos - offset.unsigned_abs()
                }
            }
        };

        // Update position in handle data
        let handle_data = fs_data
            .open_handles
            .get_mut(&handle_id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid handle"))?;
        handle_data.position = new_pos;

        Ok(new_pos)
    }

    fn len(&mut self, handle_id: u32) -> MyResult<u64> {
        let fs_data = self.fs_data.lock()?;
        let handle_data = fs_data
            .open_handles
            .get(&handle_id)
            .ok_or_else(|| MyError::new_io(io::ErrorKind::InvalidInput, "Invalid handle"))?;

        let path = &handle_data.path;

        let file = fs_data.get_file_entry(path)?;

        Ok(file.data.len() as u64)
    }

    fn set_len(&mut self, handle_id: u32, size: u64) -> MyResult<()> {
        let mut fs_data = self.fs_data.lock()?;
        let handle_data = fs_data
            .open_handles
            .get(&handle_id)
            .ok_or_else(|| MyError::new_io(io::ErrorKind::InvalidInput, "Invalid handle"))?;

        if !handle_data.permissions.write {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "File not opened for writing",
            )
            .into());
        }

        let path = &handle_data.path.clone();

        let file = fs_data.get_file_entry_mut(path)?;

        file.data.resize(size as usize, 0);
        file.update_modified_time();

        Ok(())
    }
}

impl Read for InMemoryFileHandle {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut fs = self
            .fs
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to lock filesystem"))?;

        fs.read(self.id, buf)
    }
}

impl Write for InMemoryFileHandle {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut fs = self
            .fs
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to lock filesystem"))?;

        fs.write(self.id, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        // No buffering in this implementation, so flush is a no-op
        Ok(())
    }
}

impl Seek for InMemoryFileHandle {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let mut fs = self
            .fs
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to lock filesystem"))?;

        fs.seek(self.id, pos)
    }
}

impl Len for InMemoryFileHandle {
    fn len(&mut self) -> MyResult<u64> {
        let mut fs = self.fs.lock()?;
        fs.len(self.id)
    }
}

impl SetLen for InMemoryFileHandle {
    fn set_len(&mut self, size: u64) -> MyResult<()> {
        let mut fs = self.fs.lock()?;
        fs.set_len(self.id, size)
    }
}

impl Finalize for InMemoryFileHandle {
    fn finalize(&mut self) -> MyResult<()> {
        // Could implement cleanup here, but we'll keep it simple for now
        Ok(())
    }
}

impl Capabilities for InMemoryFS {
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

impl FS for InMemoryFS {
    type File = InMemoryFileHandle;

    fn create_dir_all<P: AsRef<Path>>(&self, path: P) -> MyResult<()> {
        let segments = path_to_segments(path);
        let mut fs_data = self.fs_data.lock()?;
        fs_data.create_directories(&segments)
    }

    fn rename<P: AsRef<Path>, Q: AsRef<Path>>(&self, from: P, to: Q) -> MyResult<()> {
        let from_segments = path_to_segments(from);
        let to_segments = path_to_segments(to);

        let mut fs_data = self.fs_data.lock()?;
        fs_data.rename_file(&from_segments, &to_segments)
    }

    fn create<P: AsRef<Path>>(&self, path: P) -> MyResult<Self::File> {
        let segments = path_to_segments(path);
        let mut fs_data = self.fs_data.lock()?;

        // Create the file
        fs_data.create_file(&segments)?;

        // Get next handle ID
        let handle_id = fs_data.next_handle_id;
        fs_data.next_handle_id += 1;

        // Create handle data
        fs_data.open_handles.insert(
            handle_id,
            InMemoryFileHandleData {
                path: segments,
                position: 0,
                permissions: FileHandlePermissions {
                    read: true,
                    write: true,
                },
            },
        );

        Ok(InMemoryFileHandle {
            id: handle_id,
            fs: Arc::new(Mutex::new(self.clone())),
        })
    }

    fn open_read<P: AsRef<Path>>(&self, path: P) -> MyResult<Self::File> {
        let segments = path_to_segments(path);
        let mut fs_data = self.fs_data.lock()?;

        // Verify file exists
        let _ = fs_data.get_file_entry(&segments)?;

        // Get next handle ID
        let handle_id = fs_data.next_handle_id;
        fs_data.next_handle_id += 1;

        // Create handle data
        fs_data.open_handles.insert(
            handle_id,
            InMemoryFileHandleData {
                path: segments,
                position: 0,
                permissions: FileHandlePermissions {
                    read: true,
                    write: false,
                },
            },
        );

        Ok(InMemoryFileHandle {
            id: handle_id,
            fs: Arc::new(Mutex::new(self.clone())),
        })
    }

    fn open_write<P: AsRef<Path>>(&self, path: P) -> MyResult<Self::File> {
        let segments = path_to_segments(path);
        let mut fs_data = self.fs_data.lock()?;

        // Verify file exists
        let _ = fs_data.get_file_entry(&segments)?;

        // Get next handle ID
        let handle_id = fs_data.next_handle_id;
        fs_data.next_handle_id += 1;

        // Create handle data
        fs_data.open_handles.insert(
            handle_id,
            InMemoryFileHandleData {
                path: segments,
                position: 0,
                permissions: FileHandlePermissions {
                    read: false,
                    write: true,
                },
            },
        );

        Ok(InMemoryFileHandle {
            id: handle_id,
            fs: Arc::new(Mutex::new(self.clone())),
        })
    }

    fn zero_file_range(&self, file: &Self::File, offset: u64, len: u64) -> MyResult<()> {
        let mut fs_data = self.fs_data.lock()?;
        let handle_id = file.id;

        // Get handle data
        let handle_data = fs_data
            .open_handles
            .get(&handle_id)
            .ok_or_else(|| MyError::new_io(io::ErrorKind::InvalidInput, "Invalid handle"))?;

        if !handle_data.permissions.write {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "File not opened for writing",
            )
            .into());
        }

        let path = &handle_data.path.clone();

        // Get file and zero range
        let file = fs_data.get_file_entry_mut(path)?;

        let end_offset = offset + len;

        // Ensure file is large enough
        if file.data.len() < end_offset as usize {
            file.data.resize(end_offset as usize, 0);
        }

        // Zero the range
        for i in offset..end_offset {
            file.data[i as usize] = 0;
        }

        file.update_modified_time();

        Ok(())
    }

    fn copy_file_range(
        &self,
        src_file: &Self::File,
        src_offset: u64,
        dst_file: &Self::File,
        dst_offset: u64,
        len: u64,
    ) -> MyResult<u64> {
        let mut fs_data = self.fs_data.lock()?;

        // Get source handle data
        let src_handle_data = fs_data
            .open_handles
            .get(&src_file.id)
            .ok_or_else(|| MyError::new_io(io::ErrorKind::InvalidInput, "Invalid source handle"))?;

        if !src_handle_data.permissions.read {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Source file not opened for reading",
            )
            .into());
        }

        // Get dest handle data
        let dst_handle_data = fs_data.open_handles.get(&dst_file.id).ok_or_else(|| {
            MyError::new_io(io::ErrorKind::InvalidInput, "Invalid destination handle")
        })?;

        if !dst_handle_data.permissions.write {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Destination file not opened for writing",
            )
            .into());
        }

        let src_path = &src_handle_data.path.clone();
        let dst_path = &dst_handle_data.path.clone();

        // Get files and copy range
        let src_file = fs_data.get_file_entry(src_path)?;
        let src_len = src_file.data.len() as u64;

        // Calculate how much we can copy
        if src_offset >= src_len {
            return Ok(0); // Source offset is past EOF
        }

        let available = src_len - src_offset;
        let bytes_to_copy = std::cmp::min(available, len);

        if bytes_to_copy == 0 {
            return Ok(0);
        }

        // Get the source data
        let src_data =
            &src_file.data[src_offset as usize..(src_offset + bytes_to_copy) as usize].to_vec();

        // Get destination file
        let dst_file = fs_data.get_file_entry_mut(dst_path)?;

        // Ensure destination file is large enough
        let dst_end = dst_offset + bytes_to_copy;
        if dst_file.data.len() < dst_end as usize {
            dst_file.data.resize(dst_end as usize, 0);
        }

        // Copy the data
        dst_file.data[dst_offset as usize..(dst_offset + bytes_to_copy) as usize]
            .copy_from_slice(src_data);

        dst_file.update_modified_time();

        Ok(bytes_to_copy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, Write};

    #[test]
    fn test_create_and_read_file() -> MyResult<()> {
        let fs = InMemoryFS::new();

        // Create and write to a file
        let mut file = fs.create("test.txt")?;
        file.write_all(b"Hello, World!")?;
        file.finalize()?;

        // Read the file back
        let mut file = fs.open_read("test.txt")?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        assert_eq!(contents, "Hello, World!");
        Ok(())
    }

    #[test]
    fn test_seek_and_partial_read() -> MyResult<()> {
        let fs = InMemoryFS::new();

        // Create test data
        let mut file = fs.create("seek_test.txt")?;
        file.write_all(b"0123456789")?;
        file.finalize()?;

        // Test seeking and partial reading
        let mut file = fs.open_read("seek_test.txt")?;
        file.seek(SeekFrom::Start(5))?;

        let mut buffer = [0u8; 3];
        file.read_exact(&mut buffer)?;

        assert_eq!(&buffer, b"567");
        Ok(())
    }

    #[test]
    fn test_create_directory_structure() -> MyResult<()> {
        let fs = InMemoryFS::new();

        // Create nested directories
        fs.create_dir_all("a/b/c")?;

        // Create a file in the nested directory
        let mut file = fs.create("a/b/c/test.txt")?;
        file.write_all(b"test content")?;
        file.finalize()?;

        // Read it back
        let mut file = fs.open_read("a/b/c/test.txt")?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        assert_eq!(contents, "test content");
        Ok(())
    }

    #[test]
    fn test_file_length() -> MyResult<()> {
        let fs = InMemoryFS::new();

        // Create a file with known content
        let mut file = fs.create("length_test.txt")?;
        file.write_all(b"12345")?;

        assert_eq!(file.len()?, 5);

        // Extend the file
        file.set_len(10)?;
        assert_eq!(file.len()?, 10);

        // Truncate the file
        file.set_len(3)?;
        assert_eq!(file.len()?, 3);

        Ok(())
    }

    #[test]
    fn test_rename_file() -> MyResult<()> {
        let fs = InMemoryFS::new();

        // Create and write to a file
        let mut file = fs.create("old.txt")?;
        file.write_all(b"content")?;
        file.finalize()?;

        // Rename the file
        fs.rename("old.txt", "new.txt")?;

        // Try to read from old path (should fail)
        assert!(fs.open_read("old.txt").is_err());

        // Read from new path
        let mut file = fs.open_read("new.txt")?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        assert_eq!(contents, "content");
        Ok(())
    }

    #[test]
    fn test_zero_file_range() -> MyResult<()> {
        let fs = InMemoryFS::new();

        // Create a file with known content
        let mut file = fs.create("zero_test.txt")?;
        file.write_all(b"Hello World!")?;

        // Zero out "World"
        fs.zero_file_range(&file, 6, 5)?;

        // Read the content back
        let mut file = fs.open_read("zero_test.txt")?;
        let mut contents = vec![0u8; 12];
        file.read_exact(&mut contents)?;

        assert_eq!(&contents[0..6], b"Hello ");
        assert_eq!(&contents[6..11], &[0, 0, 0, 0, 0]);
        assert_eq!(contents[11], b'!');

        Ok(())
    }

    #[test]
    fn test_copy_file_range() -> MyResult<()> {
        let fs = InMemoryFS::new();

        // Create source file
        let mut src_file = fs.create("source.txt")?;
        src_file.write_all(b"Hello World!")?;

        // Create destination file
        let mut dst_file = fs.create("dest.txt")?;
        dst_file.write_all(b"XXXXXXXXXXXXX")?;

        // Copy "World" from source to destination
        fs.copy_file_range(&src_file, 6, &dst_file, 3, 5)?;

        // Read destination content
        let mut file = fs.open_read("dest.txt")?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        assert_eq!(contents, "XXXWorldXXXXX");
        Ok(())
    }

    #[test]
    fn test_concurrent_access() -> MyResult<()> {
        use std::thread;

        let fs = InMemoryFS::new();
        let fs_clone = fs.clone();

        // Create initial file
        let mut file = fs.create("concurrent.txt")?;
        file.write_all(b"Initial")?;
        file.finalize()?;

        // Spawn thread to modify file
        let handle = thread::spawn(move || -> MyResult<()> {
            let mut file = fs_clone.open_write("concurrent.txt")?;
            file.write_all(b" Content")?;
            file.finalize()?;
            Ok(())
        });

        // Wait for thread to complete
        handle.join().unwrap()?;

        // Read final content
        let mut file = fs.open_read("concurrent.txt")?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        assert_eq!(contents, "Initial Content");
        Ok(())
    }

    #[test]
    fn test_capabilities() {
        let fs = InMemoryFS::new();

        assert!(fs.can_mutate());
        assert!(fs.can_truncate());
        assert!(fs.can_rename());
        assert!(fs.can_append());
    }

    #[test]
    fn test_large_file() -> MyResult<()> {
        let fs = InMemoryFS::new();

        // Create a large file (1MB)
        let mut file = fs.create("large.txt")?;
        let data = vec![b'X'; 1_000_000];
        file.write_all(&data)?;

        assert_eq!(file.len()?, 1_000_000);

        // Read back in chunks
        let mut file = fs.open_read("large.txt")?;
        let mut buffer = vec![0u8; 1024];
        let mut total_read = 0;

        loop {
            match file.read(&mut buffer)? {
                0 => break,
                n => {
                    total_read += n;
                    assert!(buffer[..n].iter().all(|&b| b == b'X'));
                }
            }
        }

        assert_eq!(total_read, 1_000_000);
        Ok(())
    }

    #[test]
    fn test_error_cases() {
        let fs = InMemoryFS::new();

        // Try to read non-existent file
        assert!(fs.open_read("nonexistent.txt").is_err());

        // Try to rename non-existent file
        assert!(fs.rename("nonexistent.txt", "new.txt").is_err());

        // Try to create file in non-existent directory
        assert!(fs.create("nonexistent_dir/file.txt").is_err());
    }
}

#[cfg(test)]
mod additional_tests {
    use super::*;

    #[test]
    fn test_write_at_offset() -> MyResult<()> {
        let fs = InMemoryFS::new();
        
        // Create a file with initial content
        let mut file = fs.create("offset_write.txt")?;
        file.write_all(b"Hello, Rust")?;
        file.seek(SeekFrom::Start(7))?;
        file.write_all(b"World!")?;
        file.finalize()?;
        
        // Read the file back
        let mut file = fs.open_read("offset_write.txt")?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        
        assert_eq!(contents, "Hello, World!");
        Ok(())
    }
    
    #[test]
    fn test_read_beyond_eof() -> MyResult<()> {
        let fs = InMemoryFS::new();
        
        // Create a file with some content
        let mut file = fs.create("small.txt")?;
        file.write_all(b"abc")?;
        file.finalize()?;
        
        // Try to read beyond EOF
        let mut file = fs.open_read("small.txt")?;
        file.seek(SeekFrom::Start(5))?; // Beyond EOF
        
        let mut buffer = [0u8; 10];
        let bytes_read = file.read(&mut buffer)?;
        
        assert_eq!(bytes_read, 0); // Should read 0 bytes
        Ok(())
    }
    
    #[test]
    fn test_file_truncate() -> MyResult<()> {
        let fs = InMemoryFS::new();
        
        // Create a file with content
        let mut file = fs.create("truncate.txt")?;
        file.write_all(b"1234567890")?;
        
        // Truncate to shorter length
        file.set_len(5)?;
        
        // Read back and verify
        let mut file = fs.open_read("truncate.txt")?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        
        assert_eq!(contents, "12345");
        
        // Truncate to longer length (should zero-fill)
        let mut file = fs.open_write("truncate.txt")?;
        file.set_len(8)?;
        
        // Read back and verify
        let mut file = fs.open_read("truncate.txt")?;
        let mut buffer = vec![0u8; 8];
        file.read_exact(&mut buffer)?;
        
        assert_eq!(&buffer[0..5], b"12345");
        assert_eq!(&buffer[5..8], &[0, 0, 0]);
        
        Ok(())
    }
    
    #[test]
    fn test_append_mode() -> MyResult<()> {
        let fs = InMemoryFS::new();
        
        // Create a file with initial content
        let mut file = fs.create("append.txt")?;
        file.write_all(b"Hello")?;
        file.finalize()?;
        
        // Open file for writing and move to end
        let mut file = fs.open_write("append.txt")?;
        file.seek(SeekFrom::End(0))?;
        file.write_all(b" World")?;
        file.finalize()?;
        
        // Read and verify
        let mut file = fs.open_read("append.txt")?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        
        assert_eq!(contents, "Hello World");
        Ok(())
    }
    
    #[test]
    fn test_nested_directory_creation() -> MyResult<()> {
        let fs = InMemoryFS::new();
        
        // Create deeply nested directories
        fs.create_dir_all("a/b/c/d/e/f/g")?;
        
        // Create a file in the deepest directory
        let mut file = fs.create("a/b/c/d/e/f/g/test.txt")?;
        file.write_all(b"deep file")?;
        file.finalize()?;
        
        // Read it back
        let mut file = fs.open_read("a/b/c/d/e/f/g/test.txt")?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        
        assert_eq!(contents, "deep file");
        Ok(())
    }
    
    #[test]
    fn test_multiple_handles_same_file() -> MyResult<()> {
        let fs = InMemoryFS::new();
        
        // Create file
        let mut file1 = fs.create("shared.txt")?;
        file1.write_all(b"Initial content")?;
        
        // Open another handle to the same file
        let mut file2 = fs.open_read("shared.txt")?;
        
        // Read from second handle
        let mut contents = String::new();
        file2.read_to_string(&mut contents)?;
        assert_eq!(contents, "Initial content");
        
        // Modify file through first handle
        file1.seek(SeekFrom::Start(0))?;
        file1.write_all(b"Modified")?;
        
        // Read through second handle should see the changes
        file2.seek(SeekFrom::Start(0))?;
        contents.clear();
        file2.read_to_string(&mut contents)?;
        assert_eq!(contents, "Modified");
        
        Ok(())
    }
    
    #[test]
    fn test_create_with_parent_dirs() -> MyResult<()> {
        let fs = InMemoryFS::new();
        
        // Try creating a file with parent directories that don't exist yet
        let mut file = fs.create("parent/dir/structure/file.txt")?;
        file.write_all(b"test content")?;
        file.finalize()?;
        
        // Read it back
        let mut file = fs.open_read("parent/dir/structure/file.txt")?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        
        assert_eq!(contents, "test content");
        Ok(())
    }
    
    #[test]
    fn test_overwrite_file() -> MyResult<()> {
        let fs = InMemoryFS::new();
        
        // Create initial file
        let mut file = fs.create("overwrite.txt")?;
        file.write_all(b"initial content")?;
        file.finalize()?;
        
        // Create with same name to overwrite
        let mut file = fs.create("overwrite.txt")?;
        file.write_all(b"overwritten")?;
        file.finalize()?;
        
        // Verify content was overwritten
        let mut file = fs.open_read("overwrite.txt")?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        
        assert_eq!(contents, "overwritten");
        Ok(())
    }
    
    #[test]
    fn test_seek_current_negative() -> MyResult<()> {
        let fs = InMemoryFS::new();
        
        let mut file = fs.create("seek_test.txt")?;
        file.write_all(b"0123456789")?;
        
        // Seek forward, then backward
        file.seek(SeekFrom::Start(7))?;
        file.seek(SeekFrom::Current(-5))?;
        
        // Read and verify position
        let mut buf = [0u8; 1];
        file.read_exact(&mut buf)?;
        assert_eq!(buf[0], b'2');
        
        Ok(())
    }
}