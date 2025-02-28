use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::errors::{MyError, MyResult};
use crate::io::fs::{Capabilities, FS, Finalize, Len, SetLen};

// File data structure with last modified time
struct InMemoryFileData {
    content: Vec<u8>,
    last_modified: SystemTime,
}

impl InMemoryFileData {
    fn new() -> Self {
        Self {
            content: Vec::new(),
            last_modified: SystemTime::now(),
        }
    }

    fn update_modified_time(&mut self) {
        self.last_modified = SystemTime::now();
    }

    fn with_content(content: Vec<u8>) -> Self {
        Self {
            content,
            last_modified: SystemTime::now(),
        }
    }

    fn len(&self) -> u64 {
        self.content.len() as u64
    }
}

// File node structure representing either a file or directory
#[derive(Clone)]
enum FileNode {
    File(Arc<Mutex<InMemoryFileData>>),
    Directory,
}

// In-memory file handle
pub struct InMemoryFile {
    data: Arc<Mutex<InMemoryFileData>>,
    position: RefCell<u64>,
}

impl InMemoryFile {
    fn new(data: Arc<Mutex<InMemoryFileData>>) -> Self {
        Self {
            data,
            position: RefCell::new(0),
        }
    }

    fn get_position(&self) -> u64 {
        *self.position.borrow()
    }

    fn set_position(&self, pos: u64) -> io::Result<()> {
        let len = self.data.lock().unwrap().len();
        if pos > len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Seek position beyond end of file",
            ));
        }
        *self.position.borrow_mut() = pos;
        Ok(())
    }
}

impl Read for InMemoryFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut pos = self.position.borrow_mut();
        let data = self.data.lock().unwrap();
        
        if *pos >= data.len() {
            return Ok(0); // EOF
        }
        
        let available = data.len() - *pos;
        let to_read = buf.len().min(available as usize);
        
        buf[..to_read].copy_from_slice(&data.content[*pos as usize..*pos as usize + to_read]);
        *pos += to_read as u64;
        
        Ok(to_read)
    }
}

impl Write for InMemoryFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut pos = self.position.borrow_mut();
        let mut data = self.data.lock().unwrap();
        
        // If writing past the end, extend the file with zeros
        if *pos > data.content.len() as u64 {
            data.content.resize(*pos as usize, 0);
        }
        
        let write_pos = *pos as usize;
        let write_end = write_pos + buf.len();
        
        // Extend if necessary
        if write_end > data.content.len() {
            data.content.resize(write_end, 0);
        }
        
        // Copy data into the buffer
        data.content[write_pos..write_end].copy_from_slice(buf);
        data.update_modified_time();
        
        *pos += buf.len() as u64;
        Ok(buf.len())
    }
    
    fn flush(&mut self) -> io::Result<()> {
        // No-op for in-memory file
        Ok(())
    }
}

impl Seek for InMemoryFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let mut current = self.get_position();
        let data_len = self.data.lock().unwrap().len();
        
        let new_pos = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::End(offset) => {
                if offset > 0 {
                    data_len + offset as u64
                } else {
                    let offset_abs = (-offset) as u64;
                    if offset_abs > data_len {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "Seek before start of file",
                        ));
                    }
                    data_len - offset_abs
                }
            }
            SeekFrom::Current(offset) => {
                if offset >= 0 {
                    current + offset as u64
                } else {
                    let offset_abs = (-offset) as u64;
                    if offset_abs > current {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "Seek before start of file",
                        ));
                    }
                    current - offset_abs
                }
            }
        };
        
        self.set_position(new_pos)?;
        Ok(new_pos)
    }
}

impl Len for InMemoryFile {
    fn len(&mut self) -> MyResult<u64> {
        Ok(self.data.lock().unwrap().len())
    }
}

impl SetLen for InMemoryFile {
    fn set_len(&mut self, size: u64) -> MyResult<()> {
        let mut data = self.data.lock().unwrap();
        data.content.resize(size as usize, 0);
        data.update_modified_time();
        Ok(())
    }
}

impl Finalize for InMemoryFile {
    fn finalize(&mut self) -> MyResult<()> {
        Ok(())
    }
}

// Snapshot of the filesystem
#[derive(Clone)]
pub struct Snapshot {
    files: HashMap<PathBuf, (Vec<u8>, SystemTime)>,
    directories: Vec<PathBuf>,
}

impl Snapshot {
    // Compare two snapshots and return differences
    pub fn diff(&self, other: &Snapshot) -> SnapshotDiff {
        let mut created = Vec::new();
        let mut modified = Vec::new();
        let mut deleted = Vec::new();
        
        // Find created and modified files
        for (path, (content, modified_time)) in &self.files {
            if let Some((other_content, other_time)) = other.files.get(path) {
                if content != other_content || modified_time != other_time {
                    modified.push(path.clone());
                }
            } else {
                created.push(path.clone());
            }
        }
        
        // Find deleted files
        for path in other.files.keys() {
            if !self.files.contains_key(path) {
                deleted.push(path.clone());
            }
        }
        
        // Find created directories
        let mut created_dirs = Vec::new();
        for dir in &self.directories {
            if !other.directories.contains(dir) {
                created_dirs.push(dir.clone());
            }
        }
        
        // Find deleted directories
        let mut deleted_dirs = Vec::new();
        for dir in &other.directories {
            if !self.directories.contains(dir) {
                deleted_dirs.push(dir.clone());
            }
        }
        
        SnapshotDiff {
            files_created: created,
            files_modified: modified,
            files_deleted: deleted,
            directories_created: created_dirs,
            directories_deleted: deleted_dirs,
        }
    }
}

// Result of comparing two snapshots
pub struct SnapshotDiff {
    pub files_created: Vec<PathBuf>,
    pub files_modified: Vec<PathBuf>,
    pub files_deleted: Vec<PathBuf>,
    pub directories_created: Vec<PathBuf>,
    pub directories_deleted: Vec<PathBuf>,
}

// The in-memory filesystem
#[derive(Clone)]
pub struct InMemoryFS {
    // Using Arc<Mutex<>> for interior mutability while allowing external reference counting
    fs_data: Arc<Mutex<HashMap<PathBuf, FileNode>>>,
}

impl InMemoryFS {
    pub fn new() -> Self {
        let mut fs_data = HashMap::new();
        // Initialize with root directory
        fs_data.insert(PathBuf::from("/"), FileNode::Directory);
        
        Self {
            fs_data: Arc::new(Mutex::new(fs_data)),
        }
    }
    
    // Get a snapshot of the current filesystem state
    pub fn snapshot(&self) -> Snapshot {
        let fs = self.fs_data.lock().unwrap();
        let mut files = HashMap::new();
        let mut directories = Vec::new();
        
        for (path, node) in fs.iter() {
            match node {
                FileNode::File(file_data) => {
                    let data = file_data.lock().unwrap();
                    files.insert(path.clone(), (data.content.clone(), data.last_modified));
                }
                FileNode::Directory => {
                    directories.push(path.clone());
                }
            }
        }
        
        Snapshot { files, directories }
    }
    
    // Get file information for inspection
    pub fn file_info(&self, path: &Path) -> Option<(u64, SystemTime)> {
        let fs = self.fs_data.lock().unwrap();
        
        match fs.get(path) {
            Some(FileNode::File(file_data)) => {
                let data = file_data.lock().unwrap();
                Some((data.len(), data.last_modified))
            }
            _ => None,
        }
    }
    
    // List all files and directories in the filesystem
    pub fn list_all(&self) -> (Vec<PathBuf>, Vec<PathBuf>) {
        let fs = self.fs_data.lock().unwrap();
        let mut files = Vec::new();
        let mut directories = Vec::new();
        
        for (path, node) in fs.iter() {
            match node {
                FileNode::File(_) => files.push(path.clone()),
                FileNode::Directory => directories.push(path.clone()),
            }
        }
        
        (files, directories)
    }
    
    // Check if a path exists and what type it is
    fn path_exists(&self, path: &Path) -> Option<bool> { // Some(true) for file, Some(false) for dir, None if not exists
        let fs = self.fs_data.lock().unwrap();
        match fs.get(path) {
            Some(FileNode::File(_)) => Some(true),
            Some(FileNode::Directory) => Some(false),
            None => None,
        }
    }
    
    // Create all parent directories for a given path
    fn ensure_parent_dirs(&self, path: &Path) -> MyResult<()> {
        if let Some(parent) = path.parent() {
            if parent.as_os_str().is_empty() {
                return Ok(());
            }
            
            match self.path_exists(parent) {
                Some(true) => return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists, 
                    format!("Cannot create directory: A file exists at path: {:?}", parent)
                ).into()),
                Some(false) => return Ok(()), // Directory already exists
                None => {}
            }
            
            // Recursively create parent directories
            self.ensure_parent_dirs(parent)?;
            
            // Create this directory
            let mut fs = self.fs_data.lock().unwrap();
            fs.insert(parent.to_path_buf(), FileNode::Directory);
        }
        
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
    type File = InMemoryFile;

    fn create_dir_all<P: AsRef<Path>>(&self, path: P) -> MyResult<()> {
        let path = path.as_ref();
        let mut current = PathBuf::new();
        
        // Create each directory in the path
        for component in path.components() {
            current.push(component);
            
            match self.path_exists(&current) {
                Some(true) => return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists, 
                    format!("Cannot create directory: A file exists at path: {:?}", current)
                ).into()),
                Some(false) => continue, // Directory already exists, continue to next component
                None => {
                    // Create directory
                    let mut fs = self.fs_data.lock().unwrap();
                    fs.insert(current.clone(), FileNode::Directory);
                }
            }
        }
        
        Ok(())
    }

    fn rename<P: AsRef<Path>, Q: AsRef<Path>>(&self, from: P, to: Q) -> MyResult<()> {
        let from = from.as_ref();
        let to = to.as_ref();
        
        let mut fs = self.fs_data.lock().unwrap();
        
        // Check if source exists
        let node = match fs.remove(from) {
            Some(node) => node,
            None => return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Source path does not exist: {:?}", from)
            ).into()),
        };
        
        // Check destination parent exists
        if let Some(parent) = to.parent() {
            if !parent.as_os_str().is_empty() && !fs.contains_key(parent) {
                // Put the source back and return error
                fs.insert(from.to_path_buf(), node);
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("Destination parent directory does not exist: {:?}", parent)
                ).into());
            }
        }
        
        // Insert at new location
        fs.insert(to.to_path_buf(), node);
        Ok(())
    }

    fn create<P: AsRef<Path>>(&self, path: P) -> MyResult<Self::File> {
        let path = path.as_ref();
        
        // Ensure parent directories exist
        self.ensure_parent_dirs(path)?;
        
        let file_data = Arc::new(Mutex::new(InMemoryFileData::new()));
        
        // Update filesystem map
        let mut fs = self.fs_data.lock().unwrap();
        fs.insert(path.to_path_buf(), FileNode::File(Arc::clone(&file_data)));
        
        Ok(InMemoryFile::new(file_data))
    }

    fn open_read<P: AsRef<Path>>(&self, path: P) -> MyResult<Self::File> {
        let path = path.as_ref();
        let fs = self.fs_data.lock().unwrap();
        
        match fs.get(path) {
            Some(FileNode::File(file_data)) => {
                Ok(InMemoryFile::new(Arc::clone(file_data)))
            },
            Some(FileNode::Directory) => {
                Err(io::Error::new(
                    io::ErrorKind::IsADirectory,
                    format!("Cannot open directory for reading: {:?}", path)
                ).into())
            },
            None => {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("File not found: {:?}", path)
                ).into())
            }
        }
    }

    fn open_write<P: AsRef<Path>>(&self, path: P) -> MyResult<Self::File> {
        let path = path.as_ref();
        let fs = self.fs_data.lock().unwrap();
        
        match fs.get(path) {
            Some(FileNode::File(file_data)) => {
                Ok(InMemoryFile::new(Arc::clone(file_data)))
            },
            Some(FileNode::Directory) => {
                Err(io::Error::new(
                    io::ErrorKind::IsADirectory,
                    format!("Cannot open directory for writing: {:?}", path)
                ).into())
            },
            None => {
                Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("File not found: {:?}", path)
                ).into())
            }
        }
    }

    fn zero_file_range(&self, file: &Self::File, offset: u64, len: u64) -> MyResult<()> {
        let mut data = file.data.lock().unwrap();
        
        // Make sure file is long enough
        if offset + len > data.content.len() as u64 {
            data.content.resize((offset + len) as usize, 0);
        }
        
        // Zero out the range
        for i in offset as usize..(offset + len) as usize {
            data.content[i] = 0;
        }
        
        data.update_modified_time();
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
        let src_data = src_file.data.lock().unwrap();
        let mut dst_data = dst_file.data.lock().unwrap();
        
        let src_len = src_data.content.len() as u64;
        if src_offset >= src_len {
            return Ok(0); // Nothing to copy
        }
        
        let actual_len = std::cmp::min(len, src_len - src_offset);
        
        // Ensure destination file is large enough
        if dst_offset + actual_len > dst_data.content.len() as u64 {
            dst_data.content.resize((dst_offset + actual_len) as usize, 0);
        }
        
        // Copy data
        dst_data.content[dst_offset as usize..(dst_offset + actual_len) as usize]
            .copy_from_slice(&src_data.content[src_offset as usize..(src_offset + actual_len) as usize]);
        
        dst_data.update_modified_time();
        Ok(actual_len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write, Seek, SeekFrom};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_basic_operations() {
        let fs = InMemoryFS::new();
        
        // Create a file and write to it
        let mut file = fs.create(Path::new("/test.txt")).unwrap();
        file.write_all(b"Hello, world!").unwrap();
        file.flush().unwrap();
        
        // Read the file back
        let mut file = fs.open_read(Path::new("/test.txt")).unwrap();
        let mut content = String::new();
        file.read_to_string(&mut content).unwrap();
        assert_eq!(content, "Hello, world!");
    }

    #[test]
    fn test_directory_operations() {
        let fs = InMemoryFS::new();
        
        // Create directories
        fs.create_dir_all(Path::new("/dir1/dir2")).unwrap();
        
        // Create a file in the directory
        let mut file = fs.create(Path::new("/dir1/dir2/test.txt")).unwrap();
        file.write_all(b"Hello from nested dir").unwrap();
        
        // Read it back
        let mut file = fs.open_read(Path::new("/dir1/dir2/test.txt")).unwrap();
        let mut content = String::new();
        file.read_to_string(&mut content).unwrap();
        assert_eq!(content, "Hello from nested dir");
    }

    #[test]
    fn test_rename() {
        let fs = InMemoryFS::new();
        
        // Create a file
        let mut file = fs.create(Path::new("/original.txt")).unwrap();
        file.write_all(b"Test content").unwrap();
        
        // Rename it
        fs.rename(Path::new("/original.txt"), Path::new("/renamed.txt")).unwrap();
        
        // Old file should be gone
        assert!(fs.open_read(Path::new("/original.txt")).is_err());
        
        // New file should have content
        let mut file = fs.open_read(Path::new("/renamed.txt")).unwrap();
        let mut content = String::new();
        file.read_to_string(&mut content).unwrap();
        assert_eq!(content, "Test content");
    }

    #[test]
    fn test_seek_and_tell() {
        let fs = InMemoryFS::new();
        
        // Create a file with content
        let mut file = fs.create(Path::new("/seektest.txt")).unwrap();
        file.write_all(b"0123456789").unwrap();
        
        // Seek to middle and read
        file.seek(SeekFrom::Start(5)).unwrap();
        let mut buffer = [0; 2];
        file.read_exact(&mut buffer).unwrap();
        assert_eq!(&buffer, b"56");
        
        // Seek from current position
        file.seek(SeekFrom::Current(1)).unwrap();
        file.read_exact(&mut buffer).unwrap();
        assert_eq!(&buffer, b"89");
        
        // Seek from end
        file.seek(SeekFrom::End(-5)).unwrap();
        file.read_exact(&mut buffer).unwrap();
        assert_eq!(&buffer, b"56");
    }

    #[test]
    fn test_snapshot_and_diff() {
        let fs = InMemoryFS::new();
        
        // Create initial state
        fs.create_dir_all(Path::new("/dir1")).unwrap();
        let mut file = fs.create(Path::new("/dir1/file1.txt")).unwrap();
        file.write_all(b"Initial content").unwrap();
        
        // Take first snapshot
        let snapshot1 = fs.snapshot();
        
        // Modify filesystem
        thread::sleep(Duration::from_millis(10)); // Ensure timestamp changes
        fs.create_dir_all(Path::new("/dir2")).unwrap();
        let mut file = fs.open_write(Path::new("/dir1/file1.txt")).unwrap();
        file.write_all(b" with modifications").unwrap();
        let mut file = fs.create(Path::new("/dir2/file2.txt")).unwrap();
        file.write_all(b"New file").unwrap();
        
        // Take second snapshot
        let snapshot2 = fs.snapshot();
        
        // Get differences
        let diff = snapshot2.diff(&snapshot1);
        
        assert_eq!(diff.directories_created.len(), 1);
        assert_eq!(diff.files_created.len(), 1);
        assert_eq!(diff.files_modified.len(), 1);
        assert!(diff.directories_created.contains(&PathBuf::from("/dir2")));
        assert!(diff.files_created.contains(&PathBuf::from("/dir2/file2.txt")));
        assert!(diff.files_modified.contains(&PathBuf::from("/dir1/file1.txt")));
    }

    #[test]
    fn test_file_info() {
        let fs = InMemoryFS::new();
        
        // Create a file
        let mut file = fs.create(Path::new("/info_test.txt")).unwrap();
        file.write_all(b"Test content").unwrap();
        
        // Get file info
        let (size, _) = fs.file_info(Path::new("/info_test.txt")).unwrap();
        assert_eq!(size, 12); // "Test content" is 12 bytes
    }
}
