use std::collections::HashMap;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{PathBuf};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use crate::errors::MyResult;
use crate::io::fs::{Capabilities, FS, Finalize, Len, SetLen};

type InMemoryPathSegment = Box<[u8]>;
type InMemoryPath = [InMemoryPathSegment];

pub struct FileEntry {
    pub data: Vec<u8>,
    pub created: SystemTime,
    pub last_modified: SystemTime
}

pub struct DirectoryEntry {
    files: HashMap<InMemoryPathSegment, FileEntry>,
    directories: HashMap<InMemoryPathSegment, DirectoryEntry>
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
    FileEntry(FileEntry)
}

pub struct InMemoryFsData {
    root: DirectoryEntry
}

impl InMemoryFsData {
    fn get_file_entry(&self, path: &InMemoryPath) -> MyResult<&FileEntry> {
        todo!()
    }

    fn get_file_entry_mut(&mut self, path: &InMemoryPath) -> MyResult<&mut FileEntry> {
        todo!()
    }

    fn get_directory_entry(&self, path: &InMemoryPath) -> MyResult<&DirectoryEntry> {
        todo!()
    }

    fn get_directory_entry_mut(&mut self, path: &InMemoryPath) -> MyResult<&mut DirectoryEntry> {
        todo!()
    }
}

pub struct FileHandlePermissions {
    pub read: bool,
    pub write: bool
}

pub struct InMemoryFS {
    fs_data: Arc<Mutex<InMemoryFsData>>,
    open_handles: HashMap<u32, InMemoryFileHandleData>
}

struct InMemoryFileHandleData {
    path: Box<Path>,
    position: u64,
    permissions: FileHandlePermissions
}

struct InMemoryFileHandle {
    id: u32,
    fs: Arc<Mutex<InMemoryFS>>
}

impl InMemoryFS {
    pub fn new() -> Self {
        let root = DirectoryEntry::new();
        let data = Arc::new(Mutex::new(InMemoryFsData { root }));
        InMemoryFS { fs_data: data, open_handles: HashMap::new() }
    }
}

impl InMemoryFS {
    fn read(&self, handle_id: u32, buf: &mut [u8]) -> io::Result<usize> {
        todo!()
    }
    // todo: implement all the functions used by 'InMemoryFileHandle', read, write, etc
}

impl Read for InMemoryFileHandle {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.fs.read(self.id, buf)
    }
}

impl Write for InMemoryFileHandle {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.fs.read(self.id, buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Seek for InMemoryFileHandle {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.fs.seek(self.id, pos)
    }
}

impl Len for InMemoryFileHandle {
    fn len(&mut self) -> MyResult<u64> {
        self.fs.len(self.id)
    }
}

impl SetLen for InMemoryFileHandle {
    fn set_len(&mut self, size: u64) -> MyResult<()> {
        self.fs.set_len(self.id, size)
    }
}

impl Finalize for InMemoryFileHandle {
    fn finalize(&mut self) -> MyResult<()> {
        Ok(())
    }
}

impl Capabilities for InMemoryFS {
    fn can_mutate(&self) -> bool { true }
    fn can_truncate(&self) -> bool { true }
    fn can_rename(&self) -> bool { true }
    fn can_append(&self) -> bool { true }
}

impl FS for InMemoryFS {
    type File = InMemoryFileHandle;

    fn create_dir_all<P: AsRef<Path>>(&self, path: P) -> MyResult<()> {
        todo!()
    }

    fn rename<P: AsRef<Path>, Q: AsRef<Path>>(&self, from: P, to: Q) -> MyResult<()> {
        todo!()
    }

    fn create<P: AsRef<Path>>(&self, path: P) -> MyResult<Self::File> {
        todo!()
    }

    fn open_read<P: AsRef<Path>>(&self, path: P) -> MyResult<Self::File> {
        todo!()
    }

    fn open_write<P: AsRef<Path>>(&self, path: P) -> MyResult<Self::File> {
        todo!()
    }

    fn zero_file_range(&self, file: &Self::File, offset: u64, len: u64) -> MyResult<()> {
        todo!()
    }

    fn copy_file_range(
        &self,
        src_file: &Self::File,
        src_offset: u64,
        dst_file: &Self::File,
        dst_offset: u64,
        len: u64,
    ) -> MyResult<u64> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write, Seek};

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